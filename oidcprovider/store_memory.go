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
)

// providerStores are the stores a provider settled on.
type providerStores struct {
	pendingRequests PendingRequestStore
	codes           CodeStore
	consents        ConsentStore
	grants          GrantStore
}

// buildStores returns the stores the options gave, with an in-memory default for each
// left out, and joins the grants to the codes, so an operation on grants reaches the
// codes still outstanding (R7). The join is permanent, so it must stay the last thing
// that can fail: a New refused later would leave a consumer's grant store joined to a
// default code store nothing else can reach, and refuse the retry.
func (c *config) buildStores() (providerStores, error) {
	stores := providerStores{pendingRequests: c.pendingRequests, codes: c.codes, consents: c.consents, grants: c.grants}
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

// errCodeHeld reports a token identifier already held.
var errCodeHeld = errors.New("oidcprovider: a code record with this identifier is already stored")

// MemoryCodeStore is the default CodeStore, safe for concurrent use. It holds its own
// copies of records, on the way in and on the way out.
//
// It is per process and not durable, so a code does not survive a restart, and a
// deployment of more than one instance needs a shared store. What it holds stays
// bounded: a Create forgets every record already expired by the store's clock, at most
// once per minute, and so does DeleteExpired, with the caller's time.
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
		m.deleteExpiredLocked(now)
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

// revokeGrant marks g revoked, unless it already is.
func revokeGrant(g *Grant, cause RevocationCause, at time.Time) {
	if !g.Revoked {
		g.Revoked, g.RevokedAt, g.RevokeCause = true, at, cause
	}
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
func (m *MemoryGrantStore) Revoke(_ context.Context, family id.ID, cause RevocationCause, at time.Time) error {
	if err := requireTime("Revoke", at); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	held, ok := m.grants[family]
	if !ok {
		m.sweepIfDue()
		held = &memoryGrant{Grant: Grant{Family: family}}
		m.grants[family] = held
	}
	revokeGrant(&held.Grant, cause, at)

	return nil
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
		if err := m.Revoke(ctx, family, cause, at); err != nil {
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

// DeleteOrphans implements GrantStore. lineageExists runs without the store's lock, as
// it reads another store.
func (m *MemoryGrantStore) DeleteOrphans(_ context.Context, lineageExists func(id.ID) (bool, error), olderThan time.Time) (int, error) {
	if lineageExists == nil {
		return 0, fmt.Errorf("%w: GrantStore.DeleteOrphans: lineageExists must not be nil", ErrConfig)
	}

	deleted := 0
	for _, family := range m.orphanCandidates(olderThan) {
		exists, err := lineageExists(family)
		if err != nil {
			return deleted, fmt.Errorf("oidcprovider: checking a grant's lineage: %w", err)
		}
		if !exists && m.deleteOrphan(family, olderThan) {
			deleted++
		}
	}

	return deleted, nil
}

func (m *MemoryGrantStore) orphanCandidates(olderThan time.Time) []id.ID {
	m.mu.Lock()
	defer m.mu.Unlock()

	var families []id.ID
	for family, held := range m.grants {
		if held.orphanable(olderThan) {
			families = append(families, family)
		}
	}

	return families
}

// deleteOrphan removes family if it is still a candidate, as a revocation may have
// arrived while its lineage was being checked.
func (m *MemoryGrantStore) deleteOrphan(family id.ID, olderThan time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	held, ok := m.grants[family]
	if !ok || !held.orphanable(olderThan) {
		return false
	}
	delete(m.grants, family)

	return true
}

// orphanable reports whether the orphan pass may look at this record at all. A
// revocation is delete expired's, because it must outlive any code naming it.
func (g *memoryGrant) orphanable(olderThan time.Time) bool {
	return g.stored && !g.Revoked && g.HoldsLineage && g.CreatedAt.Before(olderThan)
}
