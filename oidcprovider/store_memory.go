package oidcprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// providerStores are the stores a provider settled on.
type providerStores struct {
	pendingRequests PendingRequestStore
	codes           CodeStore
	consents        ConsentStore
	grants          GrantStore
	codeTokens      onetime.Store
	accessTokens    AccessTokenStore
	assertionIDs    AssertionIDStore
	browserSessions BrowserSessionStore
	lineage         RefreshTokenStore
}

// buildStores returns the stores the options gave, with an in-memory default for each
// left out, and joins the grants to the codes, so an operation on grants reaches the
// codes still outstanding (R7). The join is permanent, so it must stay the last thing
// that can fail: a New refused later would leave a consumer's grant store joined to a
// default code store nothing else can reach, and refuse the retry.
func (c *config) buildStores() (providerStores, error) {
	stores := providerStores{
		pendingRequests: c.pendingRequests,
		codes:           c.codes,
		consents:        c.consents,
		grants:          c.grants,
		codeTokens:      c.codeTokens,
		accessTokens:    c.accessTokens,
		assertionIDs:    c.assertionIDs,
		browserSessions: c.browserStore,
		lineage:         c.lineage,
	}
	clk := WithMemoryStoreClock(c.clock)

	var err error
	if !c.pendingRequestsSet {
		if stores.pendingRequests, err = NewMemoryPendingRequestStore(clk); err != nil {
			return providerStores{}, err
		}
	}
	if !c.codesSet {
		if stores.codes, err = NewMemoryCodeStore(clk); err != nil {
			return providerStores{}, err
		}
	}
	if !c.consentsSet {
		if stores.consents, err = NewMemoryConsentStore(clk); err != nil {
			return providerStores{}, err
		}
	}
	if !c.grantsSet {
		if stores.grants, err = NewMemoryGrantStore(clk); err != nil {
			return providerStores{}, err
		}
	}
	if !c.codeTokensSet {
		if stores.codeTokens, err = newDefaultCodeTokens(c.clock); err != nil {
			return providerStores{}, err
		}
	}
	if !c.accessTokensSet {
		if stores.accessTokens, err = NewMemoryAccessTokenStore(clk); err != nil {
			return providerStores{}, err
		}
	}
	if !c.assertionIDsSet {
		stores.assertionIDs = newDefaultAssertionIDs(c.clock)
	}
	if !c.browserStoreSet {
		if stores.browserSessions, err = NewMemoryBrowserSessionStore(clk); err != nil {
			return providerStores{}, err
		}
	}
	if !c.lineageSet {
		if stores.lineage, err = newDefaultLineages(c.clock); err != nil {
			return providerStores{}, err
		}
	}
	if err := stores.grants.UseCodes(stores.codes); err != nil {
		return providerStores{}, err
	}

	return stores, nil
}

// MemoryStoreOption configures an in-memory store.
type MemoryStoreOption func(*memoryConfig)

type memoryConfig struct {
	clock clock.Clock
}

// WithMemoryStoreClock replaces the time source an in-memory store reads when it
// sweeps what has expired. The default is clock.System(), and a nil clock, typed nil
// included, fails the constructor with an error matching ErrConfig. It decides only
// what is forgotten: every time a store judges a caller's request by is the caller's.
// A MemoryConsentStore and a MemoryAssertionIDStore forget nothing of their own accord,
// so neither reads it, and each accepts it like the other stores.
func WithMemoryStoreClock(clk clock.Clock) MemoryStoreOption {
	return func(c *memoryConfig) { c.clock = clk }
}

func newMemoryConfig(opts []MemoryStoreOption) (memoryConfig, error) {
	cfg := memoryConfig{clock: clock.System()}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if nilcheck.IsNil(cfg.clock) {
		return cfg, fmt.Errorf("%w: WithMemoryStoreClock: must not be nil", ErrConfig)
	}

	return cfg, nil
}

// memorySweepEvery is how often an in-memory store forgets what has expired, on a
// write that would otherwise add to it.
const memorySweepEvery = time.Minute

// memorySweep says when a store's next sweep is due. Its owner's lock guards it.
type memorySweep struct {
	clock clock.Clock
	next  time.Time
}

// due returns the current time, and whether a sweep should run now.
func (m *memorySweep) due() (time.Time, bool) {
	now := m.clock.Now()
	if now.Before(m.next) {
		return now, false
	}
	m.next = now.Add(memorySweepEvery)

	return now, true
}

// cloneSignIn returns a sign-in sharing nothing with s.
func cloneSignIn(s SignIn) SignIn {
	s.AMR = slices.Clone(s.AMR)

	return s
}

// clonePending returns a record sharing nothing with r.
func clonePending(r *PendingRequest) *PendingRequest {
	out := *r
	out.HandleDigest = bytes.Clone(r.HandleDigest)
	out.FlowDigest = bytes.Clone(r.FlowDigest)
	out.Scopes = slices.Clone(r.Scopes)
	out.Resources = slices.Clone(r.Resources)
	out.Prompt = slices.Clone(r.Prompt)
	out.UILocales = slices.Clone(r.UILocales)
	out.ClaimsLocales = slices.Clone(r.ClaimsLocales)
	out.ACRValues = slices.Clone(r.ACRValues)
	if r.MaxAge != nil {
		maxAge := *r.MaxAge
		out.MaxAge = &maxAge
	}
	if r.SignIn != nil {
		s := cloneSignIn(*r.SignIn)
		out.SignIn = &s
	}

	return &out
}

// errPendingHeld is fixed text, so it can carry no digest.
var errPendingHeld = errors.New("oidcprovider: a pending request with this handle is already stored")

// MemoryPendingRequestStore is the default PendingRequestStore, safe for concurrent
// use. It holds its own copies of records, on the way in and on the way out.
//
// It is per process and not durable, so a parked request does not survive a restart,
// and a deployment of more than one instance needs a shared store. Anyone can park a
// request, so what it holds must stay bounded: a Create forgets every record already
// expired by the store's clock, at most once per minute, and so does DeleteExpired,
// with the caller's time.
type MemoryPendingRequestStore struct {
	mu      sync.Mutex
	sweep   memorySweep
	records map[string]*PendingRequest
}

// NewMemoryPendingRequestStore returns an empty store on the system clock, unless
// WithMemoryStoreClock replaces it.
func NewMemoryPendingRequestStore(opts ...MemoryStoreOption) (*MemoryPendingRequestStore, error) {
	cfg, err := newMemoryConfig(opts)
	if err != nil {
		return nil, err
	}

	return &MemoryPendingRequestStore{
		sweep:   memorySweep{clock: cfg.clock},
		records: make(map[string]*PendingRequest),
	}, nil
}

// Create implements PendingRequestStore.
func (m *MemoryPendingRequestStore) Create(_ context.Context, r *PendingRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if now, due := m.sweep.due(); due {
		m.deleteExpiredLocked(now)
	}
	key := string(r.HandleDigest)
	if _, held := m.records[key]; held {
		return errPendingHeld
	}
	m.records[key] = clonePending(r)

	return nil
}

// Load implements PendingRequestStore.
func (m *MemoryPendingRequestStore) Load(_ context.Context, handleDigest []byte) (*PendingRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.records[string(handleDigest)]
	if !ok {
		return nil, ErrNotFound
	}

	return clonePending(r), nil
}

// Advance implements PendingRequestStore.
func (m *MemoryPendingRequestStore) Advance(_ context.Context, handleDigest []byte, from, to Stage, s *SignIn) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.records[string(handleDigest)]
	if !ok || r.Stage != from || !from.advancesTo(to) {
		return ErrNotFound
	}
	r.Stage = to
	if s != nil {
		signIn := cloneSignIn(*s)
		r.SignIn = &signIn
	}

	return nil
}

// DeleteExpired implements PendingRequestStore.
func (m *MemoryPendingRequestStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.deleteExpiredLocked(before), nil
}

func (m *MemoryPendingRequestStore) deleteExpiredLocked(before time.Time) int {
	held := len(m.records)
	maps.DeleteFunc(m.records, func(_ string, r *PendingRequest) bool { return r.ExpiresAt.Before(before) })

	return held - len(m.records)
}

// cloneCode returns a record sharing nothing with r.
func cloneCode(r *CodeRecord) *CodeRecord {
	out := *r
	out.Scopes = slices.Clone(r.Scopes)
	out.Resources = slices.Clone(r.Resources)
	out.SignIn = cloneSignIn(r.SignIn)

	return &out
}

// codeKeptPastExpiry is how long the default code stores keep a code past its expiry. It is
// the window in which a valid replay still revokes what the code issued, and an end of the
// sign-in still reaches an exchange in flight. The minute is the floor the provider promises
// of its defaults, and no option: a store given through WithCodeStore and WithCodeTokenStore
// that keeps spent codes longer detects a replay for as long as it holds them.
const codeKeptPastExpiry = time.Minute

// errCodeHeld reports a token identifier already held.
var errCodeHeld = errors.New("oidcprovider: a code record with this identifier is already stored")

// MemoryCodeStore is the default CodeStore, safe for concurrent use. It holds its own
// copies of records, on the way in and on the way out.
//
// It is per process and not durable, so a code does not survive a restart, and a
// deployment of more than one instance needs a shared store. What it holds stays
// bounded: a Create forgets every record expired more than a minute ago by the store's
// clock, at most once per minute. DeleteExpired forgets what expired before the caller's
// time, which is all it is told.
//
// That minute is the detection window. A valid replay of a spent code revokes what the code
// issued until at least a minute past the code's expiry, and past that is refused with
// nothing revoked. A store of a consumer's own that keeps spent codes longer, with a token
// store that does too, detects a replay for as long as it holds them.
type MemoryCodeStore struct {
	mu      sync.Mutex
	sweep   memorySweep
	records map[id.ID]*CodeRecord
}

// NewMemoryCodeStore returns an empty store on the system clock, unless
// WithMemoryStoreClock replaces it.
func NewMemoryCodeStore(opts ...MemoryStoreOption) (*MemoryCodeStore, error) {
	cfg, err := newMemoryConfig(opts)
	if err != nil {
		return nil, err
	}

	return &MemoryCodeStore{
		sweep:   memorySweep{clock: cfg.clock},
		records: make(map[id.ID]*CodeRecord),
	}, nil
}

// Create implements CodeStore.
func (m *MemoryCodeStore) Create(_ context.Context, r *CodeRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if now, due := m.sweep.due(); due {
		m.deleteExpiredLocked(now.Add(-codeKeptPastExpiry))
	}
	if _, held := m.records[r.TokenID]; held {
		return errCodeHeld
	}
	m.records[r.TokenID] = cloneCode(r)

	return nil
}

// Load implements CodeStore.
func (m *MemoryCodeStore) Load(_ context.Context, tokenID id.ID) (*CodeRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.records[tokenID]
	if !ok {
		return nil, ErrNotFound
	}

	return cloneCode(r), nil
}

// DeleteExpired implements CodeStore.
func (m *MemoryCodeStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.deleteExpiredLocked(before), nil
}

func (m *MemoryCodeStore) deleteExpiredLocked(before time.Time) int {
	held := len(m.records)
	maps.DeleteFunc(m.records, func(_ id.ID, r *CodeRecord) bool { return r.ExpiresAt.Before(before) })

	return held - len(m.records)
}

// UnspentBySignIn implements UnspentCodes.
func (m *MemoryCodeStore) UnspentBySignIn(_ context.Context, sel SignInSelector, includeOffline bool) ([]id.ID, error) {
	if err := sel.Validate(); err != nil {
		return nil, err
	}

	return m.families(func(r *CodeRecord) bool {
		return (includeOffline || !r.Offline || r.EndsWithSignIn) &&
			sel.matches(r.SignIn.User, r.SignIn.Family, r.SignIn.ExternalIssuer, r.SignIn.ExternalSessionID)
	}), nil
}

// UnspentByClient implements UnspentCodes.
func (m *MemoryCodeStore) UnspentByClient(_ context.Context, user identity.UserID, clientID string) ([]id.ID, error) {
	return m.families(func(r *CodeRecord) bool { return r.SignIn.User == user && r.ClientID == clientID }), nil
}

// families returns the grant family of each record selected.
func (m *MemoryCodeStore) families(selected func(*CodeRecord) bool) []id.ID {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []id.ID
	for _, r := range m.records {
		if selected(r) {
			out = append(out, r.GrantFamily)
		}
	}

	return out
}

// consentKey keeps user and client apart, whatever their text.
type consentKey struct {
	user   identity.UserID
	client string
}

// cloneConsent returns a consent sharing nothing with c.
func cloneConsent(c *Consent) Consent {
	out := *c
	out.Scopes = slices.Clone(c.Scopes)

	return out
}

// MemoryConsentStore is the default ConsentStore, safe for concurrent use. It holds
// its own copies of records, on the way in and on the way out.
//
// It is per process and not durable, so a restart asks every user again, and a
// deployment of more than one instance needs a shared store. Consents do not expire,
// and each is one record per user and client, written only for a signed-in user.
type MemoryConsentStore struct {
	mu       sync.Mutex
	consents map[consentKey]*Consent
}

// NewMemoryConsentStore returns an empty store. Nothing in it reads a clock, as
// consents do not expire; WithMemoryStoreClock is accepted, like the other stores', and
// a nil clock is refused all the same.
func NewMemoryConsentStore(opts ...MemoryStoreOption) (*MemoryConsentStore, error) {
	if _, err := newMemoryConfig(opts); err != nil {
		return nil, err
	}

	return &MemoryConsentStore{consents: make(map[consentKey]*Consent)}, nil
}

// Give implements ConsentStore.
func (m *MemoryConsentStore) Give(
	_ context.Context, user identity.UserID, clientID string, scopes []string, offline bool, at time.Time,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := consentKey{user: user, client: clientID}
	c, ok := m.consents[key]
	if !ok {
		c = &Consent{User: user, ClientID: clientID}
		m.consents[key] = c
	}
	for _, scope := range scopes {
		if !slices.Contains(c.Scopes, scope) {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	c.Offline = c.Offline || offline
	c.LastGivenAt = at

	return nil
}

// Load implements ConsentStore.
func (m *MemoryConsentStore) Load(_ context.Context, user identity.UserID, clientID string) (*Consent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.consents[consentKey{user: user, client: clientID}]
	if !ok {
		return nil, ErrNotFound
	}
	out := cloneConsent(c)

	return &out, nil
}

// Revoke implements ConsentStore.
func (m *MemoryConsentStore) Revoke(_ context.Context, user identity.UserID, clientID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := consentKey{user: user, client: clientID}
	_, ok := m.consents[key]
	delete(m.consents, key)

	return ok, nil
}

// ListByUser implements ConsentStore.
func (m *MemoryConsentStore) ListByUser(_ context.Context, user identity.UserID) ([]Consent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []Consent
	for _, c := range m.consents {
		if c.User == user {
			out = append(out, cloneConsent(c))
		}
	}

	return out, nil
}

// memoryKeepRevoked is how long a MemoryGrantStore's own sweep keeps a revocation. It
// covers the longest code lifetime WithCodeLifetime allows, whatever the provider
// chose, with a minute more for an exchange that spent its code just before it expired.
// It has no option, because a shorter value would let a code outlive its revocation
// and a longer one buys nothing: DeleteExpired takes any value, and WithGrantStore
// replaces the store.
const memoryKeepRevoked = maxCodeLifetime + time.Minute

// memoryGrant is a stored grant, and whether an exchange has stored it, or only a
// revocation recorded first.
type memoryGrant struct {
	Grant

	stored bool
}

// cloneGrant returns a grant sharing nothing with g.
func cloneGrant(g *Grant) Grant {
	out := *g
	out.Scopes = slices.Clone(g.Scopes)
	out.Resources = slices.Clone(g.Resources)
	out.AMR = slices.Clone(g.AMR)

	return out
}

// revokeGrant marks g revoked, unless it already is, and reports whether it did.
func revokeGrant(g *Grant, cause RevocationCause, at time.Time) bool {
	if g.Revoked {
		return false
	}
	g.Revoked, g.RevokedAt, g.RevokeCause = true, at, cause

	return true
}

var (
	// errGrantHeld reports a Create over a grant already stored.
	errGrantHeld = errors.New("oidcprovider: a grant with this family is already stored")

	// errNoCodes reports a store nothing told where the outstanding codes are.
	errNoCodes = fmt.Errorf("%w: GrantStore: UseCodes was never called, so a code could outlive this operation", ErrConfig)

	// errCodesJoined reports a store already reading another provider's codes.
	errCodesJoined = fmt.Errorf("%w: GrantStore: UseCodes: this store already reads another code store, "+
		"so two providers sharing a grant store must share their code store too", ErrConfig)
)

// MemoryGrantStore is the default GrantStore, safe for concurrent use. It holds its
// own copies of records, on the way in and on the way out.
//
// It is per process and not durable, so a restart forgets every grant, which refuses
// every refresh token issued before it, and a deployment of more than one instance
// needs a shared store. What it holds stays bounded: a write that adds a record
// forgets each grant expired by the store's clock, and each revocation older than the
// longest code lifetime plus a minute, at most once per minute. DeleteExpired does
// the same at the caller's time and with the caller's retention.
type MemoryGrantStore struct {
	mu     sync.Mutex
	sweep  memorySweep
	grants map[id.ID]*memoryGrant
	codes  UnspentCodes
}

// NewMemoryGrantStore returns an empty store on the system clock, unless
// WithMemoryStoreClock replaces it.
func NewMemoryGrantStore(opts ...MemoryStoreOption) (*MemoryGrantStore, error) {
	cfg, err := newMemoryConfig(opts)
	if err != nil {
		return nil, err
	}

	return &MemoryGrantStore{
		sweep:  memorySweep{clock: cfg.clock},
		grants: make(map[id.ID]*memoryGrant),
	}, nil
}

// UseCodes implements GrantStore.
func (m *MemoryGrantStore) UseCodes(codes UnspentCodes) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.codes != nil && !sameCodes(m.codes, codes) {
		return errCodesJoined
	}
	m.codes = codes

	return nil
}

// sameCodes reports whether a and b are one code source. Values that cannot be compared
// are not known to be one, and == on them would panic.
func sameCodes(a, b UnspentCodes) bool {
	return reflect.ValueOf(a).Comparable() && reflect.ValueOf(b).Comparable() && a == b
}

// codeSource returns where the outstanding codes are read from, which is called
// without the store's lock, as a consumer's may be slow.
func (m *MemoryGrantStore) codeSource() (UnspentCodes, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.codes == nil {
		return nil, errNoCodes
	}

	return m.codes, nil
}

// sweepIfDue forgets what the store's clock says has ended. The caller holds m.mu.
func (m *MemoryGrantStore) sweepIfDue() {
	if now, due := m.sweep.due(); due {
		m.deleteExpiredLocked(now, memoryKeepRevoked)
	}
}

// Create implements GrantStore.
func (m *MemoryGrantStore) Create(_ context.Context, g *Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sweepIfDue()

	next := &memoryGrant{Grant: cloneGrant(g), stored: true}
	if held, ok := m.grants[g.Family]; ok {
		if held.stored {
			return errGrantHeld
		}
		next.Revoked, next.RevokedAt, next.RevokeCause = true, held.RevokedAt, held.RevokeCause
		next.SignInEndedAt = held.SignInEndedAt
	}
	m.grants[g.Family] = next

	return nil
}

// Load implements GrantStore.
func (m *MemoryGrantStore) Load(_ context.Context, family id.ID) (*Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	held, ok := m.grants[family]
	if !ok {
		return nil, ErrNotFound
	}
	out := cloneGrant(&held.Grant)

	return &out, nil
}

// Revoke implements GrantStore.
func (m *MemoryGrantStore) Revoke(_ context.Context, family id.ID, cause RevocationCause, at time.Time) (bool, error) {
	if err := requireTime("Revoke", at); err != nil {
		return false, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	held, ok := m.grants[family]
	if !ok {
		m.sweepIfDue()
		held = &memoryGrant{Grant: Grant{Family: family}}
		m.grants[family] = held
	}

	return revokeGrant(&held.Grant, cause, at), nil
}

// requireTime refuses a zero time, which could not be told from no time at all.
func requireTime(op string, at time.Time) error {
	if at.IsZero() {
		return fmt.Errorf("%w: GrantStore.%s: the time must not be zero", ErrConfig, op)
	}

	return nil
}

// RevokeByUser implements GrantStore.
func (m *MemoryGrantStore) RevokeByUser(ctx context.Context, user identity.UserID, cause RevocationCause, at time.Time) ([]Grant, error) {
	if user == "" {
		return nil, fmt.Errorf("%w: GrantStore.RevokeByUser: the user must not be empty", ErrConfig)
	}
	if err := requireTime("RevokeByUser", at); err != nil {
		return nil, err
	}
	codes, err := m.codeSource()
	if err != nil {
		return nil, err
	}
	families, err := codes.UnspentBySignIn(ctx, SignInSelector{User: user}, true)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: reading a user's outstanding codes: %w", err)
	}

	return m.revokeMatching(ctx, func(g *Grant) bool { return g.User == user }, families, cause, at)
}

// RevokeByUserAndClient implements GrantStore.
func (m *MemoryGrantStore) RevokeByUserAndClient(
	ctx context.Context, user identity.UserID, clientID string, cause RevocationCause, at time.Time,
) ([]Grant, error) {
	if user == "" || clientID == "" {
		return nil, fmt.Errorf("%w: GrantStore.RevokeByUserAndClient: the user and the client must not be empty", ErrConfig)
	}
	if err := requireTime("RevokeByUserAndClient", at); err != nil {
		return nil, err
	}
	codes, err := m.codeSource()
	if err != nil {
		return nil, err
	}
	families, err := codes.UnspentByClient(ctx, user, clientID)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: reading a client's outstanding codes: %w", err)
	}

	return m.revokeMatching(ctx, func(g *Grant) bool { return g.User == user && g.ClientID == clientID }, families, cause, at)
}

// revokeMatching revokes the grants selected, then records a revocation for each
// family. The grants go first, because a family's Revoke could revoke a stored grant
// and hide it from what this call returns.
func (m *MemoryGrantStore) revokeMatching(
	ctx context.Context, selected func(*Grant) bool, families []id.ID, cause RevocationCause, at time.Time,
) ([]Grant, error) {
	revoked := m.revokeSelected(selected, cause, at)
	for _, family := range families {
		if _, err := m.Revoke(ctx, family, cause, at); err != nil {
			return nil, err
		}
	}

	return revoked, nil
}

func (m *MemoryGrantStore) revokeSelected(selected func(*Grant) bool, cause RevocationCause, at time.Time) []Grant {
	m.mu.Lock()
	defer m.mu.Unlock()

	var revoked []Grant
	for _, held := range m.grants {
		if held.stored && !held.Revoked && selected(&held.Grant) {
			revokeGrant(&held.Grant, cause, at)
			revoked = append(revoked, cloneGrant(&held.Grant))
		}
	}

	return revoked
}

// EndSignIns implements GrantStore.
func (m *MemoryGrantStore) EndSignIns(ctx context.Context, sel SignInSelector, at time.Time) ([]Grant, error) {
	if err := sel.Validate(); err != nil {
		return nil, err
	}
	if err := requireTime("EndSignIns", at); err != nil {
		return nil, err
	}
	codes, err := m.codeSource()
	if err != nil {
		return nil, err
	}
	families, err := codes.UnspentBySignIn(ctx, sel, false)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: reading a sign-in's outstanding codes: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// The revocations go first, because a family's grant, if stored, must still count
	// as newly marked below.
	for _, family := range families {
		m.endFamilyLocked(family, at)
	}

	var ended []Grant
	for _, held := range m.grants {
		g := &held.Grant
		if !held.stored || !g.SignInEndedAt.IsZero() ||
			!sel.matches(g.User, g.SignInFamily, g.ExternalIssuer, g.ExternalSessionID) {
			continue
		}
		g.SignInEndedAt = at
		if !g.Offline || g.EndsWithSignIn {
			revokeGrant(g, CauseSignInEnded, at)
		}
		ended = append(ended, cloneGrant(g))
	}

	return ended, nil
}

// endFamilyLocked revokes family for an end, leaving the mark on a record this creates
// and on nothing else: a stored grant is marked by the caller, and a revocation already
// recorded was not this end's. The caller holds m.mu.
func (m *MemoryGrantStore) endFamilyLocked(family id.ID, at time.Time) {
	held, ok := m.grants[family]
	if !ok {
		m.sweepIfDue()
		held = &memoryGrant{Grant: Grant{Family: family, SignInEndedAt: at}}
		m.grants[family] = held
	}
	revokeGrant(&held.Grant, CauseSignInEnded, at)
}

// DeleteExpired implements GrantStore.
func (m *MemoryGrantStore) DeleteExpired(_ context.Context, now time.Time, keepRevoked time.Duration) (int, error) {
	if keepRevoked <= 0 {
		return 0, fmt.Errorf("%w: GrantStore.DeleteExpired: keepRevoked must be positive, got %s", ErrConfig, keepRevoked)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return m.deleteExpiredLocked(now, keepRevoked), nil
}

func (m *MemoryGrantStore) deleteExpiredLocked(now time.Time, keepRevoked time.Duration) int {
	held := len(m.grants)
	maps.DeleteFunc(m.grants, func(_ id.ID, g *memoryGrant) bool {
		if g.Revoked {
			return g.RevokedAt.Add(keepRevoked).Before(now)
		}

		return g.ExpiresAt.Before(now)
	})

	return held - len(m.grants)
}

// codeTokenPurpose is the token/onetime purpose an authorization code's token is issued
// under.
const codeTokenPurpose = "oidc-provider.code" //nolint:gosec // a purpose's name, and no credential

// sweepingCodeTokens is the provider's default code-token store: an onetime.MemoryStore
// of its own, which no consumer can reach to purge, kept bounded by its writes. A write
// that adds a record forgets the codes expired more than a minute ago by the provider's
// clock, at most once per minute. The default code record store keeps a code just as long,
// so a valid replay revokes what the code issued until at least a minute past its expiry,
// and past that finds nothing to revoke. A token store of a consumer's own that keeps spent
// codes longer, with a record store that does too, detects a replay for as long as it holds
// them.
type sweepingCodeTokens struct {
	*onetime.MemoryStore

	mu    sync.Mutex
	sweep memorySweep
}

// laggingClock reads a fixed time behind the clock it follows.
type laggingClock struct {
	clock.Clock

	behind time.Duration
}

// Now implements clock.Clock.
func (c laggingClock) Now() time.Time { return c.Clock.Now().Add(-c.behind) }

// newDefaultCodeTokens builds the default code-token store on clk. The memory store judges
// expiry by its own clock when it sweeps, and by nothing else, so it reads a lagging one. Its
// cutoff alone could not keep a code past its expiry, because it goes by when a record was
// issued: a code living 60 seconds, issued over a minute ago, would go as soon as it expired.
func newDefaultCodeTokens(clk clock.Clock) (*sweepingCodeTokens, error) {
	// The memory store deletes a token once its lagged now reaches ExpiresAt, while the record
	// store deletes only a record strictly past the cutoff. A nanosecond more of lag makes the
	// token go at the same instant the record does, so at exactly a minute past expiry both
	// still hold the code.
	lag := codeKeptPastExpiry + time.Nanosecond
	memory, err := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(laggingClock{Clock: clk, behind: lag}))
	if err != nil {
		return nil, err
	}

	return &sweepingCodeTokens{MemoryStore: memory, sweep: memorySweep{clock: clk}}, nil
}

// sweepIfDue forgets what expired more than a minute ago, when a sweep is due. The memory store
// keeps the minute itself, by the lagging clock it judges expiry with. The cutoff only bounds
// what was issued, and nothing expired was issued after now, so it is now and carries no margin.
func (s *sweepingCodeTokens) sweepIfDue(ctx context.Context) error {
	s.mu.Lock()
	now, due := s.sweep.due()
	s.mu.Unlock()
	if !due {
		return nil
	}
	_, err := s.DeleteExpiredBefore(ctx, codeTokenPurpose, now)

	return err
}

// Insert implements onetime.Store.
func (s *sweepingCodeTokens) Insert(ctx context.Context, tok onetime.Token) error {
	if err := s.sweepIfDue(ctx); err != nil {
		return err
	}

	return s.MemoryStore.Insert(ctx, tok)
}

// InsertWithin implements onetime.Store.
func (s *sweepingCodeTokens) InsertWithin(ctx context.Context, tok onetime.Token, since time.Time, limit int) (bool, error) {
	if err := s.sweepIfDue(ctx); err != nil {
		return false, err
	}

	return s.MemoryStore.InsertWithin(ctx, tok, since, limit)
}

// cloneAccessToken returns a record sharing nothing with r.
func cloneAccessToken(r *AccessTokenRecord) *AccessTokenRecord {
	out := *r
	out.Digest = bytes.Clone(r.Digest)
	out.Scopes = slices.Clone(r.Scopes)
	out.Audience = slices.Clone(r.Audience)
	out.Confirmation = maps.Clone(r.Confirmation)

	return &out
}

// errAccessTokenHeld is fixed text, so it can carry no digest.
var errAccessTokenHeld = errors.New("oidcprovider: an access token with this identifier is already stored")

// MemoryAccessTokenStore is the default AccessTokenStore, safe for concurrent use. It
// holds its own copies of records, on the way in and on the way out.
//
// It is per process and not durable, so a restart ends every opaque token, and a
// deployment of more than one instance needs a shared store. What it holds stays
// bounded: a Create forgets every token already expired by the store's clock, at most
// once per minute, and so does DeleteExpired, with the caller's time.
type MemoryAccessTokenStore struct {
	mu      sync.Mutex
	sweep   memorySweep
	records map[id.ID]*AccessTokenRecord
}

// NewMemoryAccessTokenStore returns an empty store on the system clock, unless
// WithMemoryStoreClock replaces it.
func NewMemoryAccessTokenStore(opts ...MemoryStoreOption) (*MemoryAccessTokenStore, error) {
	cfg, err := newMemoryConfig(opts)
	if err != nil {
		return nil, err
	}

	return &MemoryAccessTokenStore{
		sweep:   memorySweep{clock: cfg.clock},
		records: make(map[id.ID]*AccessTokenRecord),
	}, nil
}

// Create implements AccessTokenStore.
func (m *MemoryAccessTokenStore) Create(_ context.Context, r *AccessTokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if now, due := m.sweep.due(); due {
		m.deleteExpiredLocked(now)
	}
	if _, held := m.records[r.ID]; held {
		return errAccessTokenHeld
	}
	m.records[r.ID] = cloneAccessToken(r)

	return nil
}

// Load implements AccessTokenStore.
func (m *MemoryAccessTokenStore) Load(_ context.Context, tokenID id.ID) (*AccessTokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.records[tokenID]
	if !ok {
		return nil, ErrNotFound
	}

	return cloneAccessToken(r), nil
}

// Revoke implements AccessTokenStore.
func (m *MemoryAccessTokenStore) Revoke(_ context.Context, tokenID id.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.records[tokenID]
	if !ok {
		return ErrNotFound
	}
	r.Revoked = true

	return nil
}

// DeleteExpired implements AccessTokenStore.
func (m *MemoryAccessTokenStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.deleteExpiredLocked(before), nil
}

func (m *MemoryAccessTokenStore) deleteExpiredLocked(before time.Time) int {
	held := len(m.records)
	maps.DeleteFunc(m.records, func(_ id.ID, r *AccessTokenRecord) bool { return r.ExpiresAt.Before(before) })

	return held - len(m.records)
}

// assertionSweepMargin is how long past its until the provider's default store keeps a
// pair. A request can stall between its exp check and its Record, and one whose pair had
// been swept would be told new. Keeping the pair this much longer means such a request
// still finds it, and is refused by the store, for any ordinary stall; the provider's own
// second read of its clock answers a longer one.
const assertionSweepMargin = time.Minute

// assertionIDKey is what a recorded identifier is held under, so one client's jti is
// never another's.
type assertionIDKey struct {
	client, jti string
}

// MemoryAssertionIDStore is the default AssertionIDStore, safe for concurrent use.
//
// It is per process and not durable, so a restart forgets what was accepted, and a
// deployment of more than one instance needs a shared store to refuse a replay across
// them. A pair stays held, whatever its until and whatever any clock says, until
// DeleteExpired removes it at the caller's time. Only assertions that passed every check
// reach it, so it grows with accepted requests until then: a consumer supplying one
// through WithAssertionIDStore calls DeleteExpired. The provider's own default, which no
// consumer can reach, is kept bounded by its writes instead.
type MemoryAssertionIDStore struct {
	mu sync.Mutex
	// sweep is set only on the provider's own default.
	sweep *memorySweep
	held  map[assertionIDKey]time.Time
}

// NewMemoryAssertionIDStore returns an empty store. Nothing in it reads a clock, as a
// pair goes only when DeleteExpired removes it; WithMemoryStoreClock is accepted, like
// the other stores', and a nil clock is refused all the same.
func NewMemoryAssertionIDStore(opts ...MemoryStoreOption) (*MemoryAssertionIDStore, error) {
	if _, err := newMemoryConfig(opts); err != nil {
		return nil, err
	}

	return &MemoryAssertionIDStore{held: make(map[assertionIDKey]time.Time)}, nil
}

// newDefaultAssertionIDs builds the provider's default: a store which, since no consumer
// can reach it to call DeleteExpired, sweeps itself on a Record, by the provider's clock
// and at most once per minute, removing the pairs more than assertionSweepMargin past
// their until.
func newDefaultAssertionIDs(clk clock.Clock) *MemoryAssertionIDStore {
	return &MemoryAssertionIDStore{
		sweep: &memorySweep{clock: clk},
		held:  make(map[assertionIDKey]time.Time),
	}
}

// Record implements AssertionIDStore.
func (m *MemoryAssertionIDStore) Record(_ context.Context, clientID, jti string, until time.Time) (bool, error) {
	key := assertionIDKey{client: clientID, jti: jti}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.sweep != nil {
		m.sweepIfDue()
	}
	if _, ok := m.held[key]; ok {
		return false, nil
	}
	m.held[key] = until

	return true, nil
}

// DeleteExpired implements AssertionIDStore.
func (m *MemoryAssertionIDStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.deleteExpiredLocked(before), nil
}

// sweepIfDue is the provider's default forgetting by the provider's clock, before a
// Record. The caller holds m.mu.
func (m *MemoryAssertionIDStore) sweepIfDue() {
	if now, due := m.sweep.due(); due {
		m.deleteExpiredLocked(now.Add(-assertionSweepMargin))
	}
}

func (m *MemoryAssertionIDStore) deleteExpiredLocked(before time.Time) int {
	held := len(m.held)
	maps.DeleteFunc(m.held, func(_ assertionIDKey, until time.Time) bool { return until.Before(before) })

	return held - len(m.held)
}

// cloneBrowserSession returns a session sharing nothing with s.
func cloneBrowserSession(s *BrowserSession) *BrowserSession {
	out := *s
	out.Digest = bytes.Clone(s.Digest)
	out.SignIn = cloneSignIn(s.SignIn)

	return &out
}

// errBrowserSessionHeld is fixed text, so it can carry no digest.
var errBrowserSessionHeld = errors.New("oidcprovider: a browser session with this digest is already stored")

// MemoryBrowserSessionStore is the default BrowserSessionStore, safe for concurrent
// use. It holds its own copies of records, on the way in and on the way out.
//
// It is per process and not durable, so a restart asks every browser to sign in again,
// and a deployment of more than one instance needs a shared store. What it holds stays
// bounded: a Put forgets every session already expired by the store's clock, at most
// once per minute, and so does DeleteExpired, with the caller's time. That clock decides
// only what is forgotten: a Load is judged at the time its caller gives.
type MemoryBrowserSessionStore struct {
	mu      sync.Mutex
	sweep   memorySweep
	records map[string]*BrowserSession
}

// NewMemoryBrowserSessionStore returns an empty store on the system clock, unless
// WithMemoryStoreClock replaces it.
func NewMemoryBrowserSessionStore(opts ...MemoryStoreOption) (*MemoryBrowserSessionStore, error) {
	cfg, err := newMemoryConfig(opts)
	if err != nil {
		return nil, err
	}

	return &MemoryBrowserSessionStore{
		sweep:   memorySweep{clock: cfg.clock},
		records: make(map[string]*BrowserSession),
	}, nil
}

// Put implements BrowserSessionStore.
func (m *MemoryBrowserSessionStore) Put(_ context.Context, s *BrowserSession) error {
	if len(s.Digest) == 0 {
		return fmt.Errorf("%w: BrowserSessionStore.Put: the digest must not be empty", ErrConfig)
	}
	if s.IdleExpiresAt.IsZero() || s.AbsoluteExpiresAt.IsZero() {
		return fmt.Errorf("%w: BrowserSessionStore.Put: a deadline must not be zero", ErrConfig)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if now, due := m.sweep.due(); due {
		m.deleteExpiredLocked(now)
	}
	key := string(s.Digest)
	if _, held := m.records[key]; held {
		return errBrowserSessionHeld
	}
	stored := cloneBrowserSession(s)
	if stored.IdleExpiresAt.After(stored.AbsoluteExpiresAt) {
		stored.IdleExpiresAt = stored.AbsoluteExpiresAt
	}
	m.records[key] = stored

	return nil
}

// Load implements BrowserSessionStore.
func (m *MemoryBrowserSessionStore) Load(_ context.Context, digest []byte, now time.Time) (*BrowserSession, error) {
	if now.IsZero() {
		return nil, fmt.Errorf("%w: BrowserSessionStore.Load: the time must not be zero", ErrConfig)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.records[string(digest)]
	if !ok || !now.Before(s.IdleExpiresAt) || !now.Before(s.AbsoluteExpiresAt) {
		return nil, ErrNotFound
	}

	return cloneBrowserSession(s), nil
}

// Touch implements BrowserSessionStore.
func (m *MemoryBrowserSessionStore) Touch(_ context.Context, digest []byte, idleUntil time.Time) error {
	if idleUntil.IsZero() {
		return fmt.Errorf("%w: BrowserSessionStore.Touch: the time must not be zero", ErrConfig)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.records[string(digest)]
	if !ok {
		return ErrNotFound
	}
	if idleUntil.After(s.AbsoluteExpiresAt) {
		idleUntil = s.AbsoluteExpiresAt
	}
	if idleUntil.After(s.IdleExpiresAt) {
		s.IdleExpiresAt = idleUntil
	}

	return nil
}

// Delete implements BrowserSessionStore.
func (m *MemoryBrowserSessionStore) Delete(_ context.Context, digest []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.records, string(digest))

	return nil
}

// DeleteBySignIn implements BrowserSessionStore.
func (m *MemoryBrowserSessionStore) DeleteBySignIn(_ context.Context, sel SignInSelector) (int, error) {
	if err := sel.Validate(); err != nil {
		return 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	held := len(m.records)
	maps.DeleteFunc(m.records, func(_ string, s *BrowserSession) bool {
		return sel.matches(s.SignIn.User, s.SignIn.Family, s.SignIn.ExternalIssuer, s.SignIn.ExternalSessionID)
	})

	return held - len(m.records), nil
}

// DeleteExpired implements BrowserSessionStore.
func (m *MemoryBrowserSessionStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.deleteExpiredLocked(before), nil
}

func (m *MemoryBrowserSessionStore) deleteExpiredLocked(before time.Time) int {
	held := len(m.records)
	maps.DeleteFunc(m.records, func(_ string, s *BrowserSession) bool {
		return s.IdleExpiresAt.Before(before) || s.AbsoluteExpiresAt.Before(before)
	})

	return held - len(m.records)
}
