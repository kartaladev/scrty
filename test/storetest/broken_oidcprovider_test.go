package storetest_test

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
	"github.com/kartaladev/scrty/token/onetime"
)

// raceGapTimeout bounds how long a fake holds a racer for the other side of its race. It
// is reached only where no other side comes, as an end with no second end to meet, and
// then only delays the record, so nothing can deadlock on it.
const raceGapTimeout = 2 * time.Second

// raceGate forces a fake's bad interleaving, so that a defect is shown by every run and
// not only by the runs a scheduler favours. A racer is held in the gap between the fake's
// read and its write until the other side has done what makes that gap matter. A fake
// with no defect never touches its gate, and neither does any real store, whose own round
// trips open the gap. The zero value is ready to use.
//
// It holds only racers: the race engine gives an attempt a context with the race's
// deadline, and a seed or a check runs on the test's own context, which has none, and has
// no other side to wait for.
type raceGate struct {
	mu      sync.Mutex
	latches map[string]chan struct{}
	arrived map[string]int
}

// latch returns the channel closed by signal(key). The caller holds g.mu.
func (g *raceGate) latch(key string) chan struct{} {
	if g.latches == nil {
		g.latches = make(map[string]chan struct{})
	}
	ch, ok := g.latches[key]
	if !ok {
		ch = make(chan struct{})
		g.latches[key] = ch
	}

	return ch
}

// signal records that key has happened, for whoever awaits it now or later.
func (g *raceGate) signal(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	ch := g.latch(key)
	select {
	case <-ch:
	default:
		close(ch)
	}
}

// await holds a racer until key has happened, or raceGapTimeout has passed.
func (g *raceGate) await(ctx context.Context, key string) {
	if _, racing := ctx.Deadline(); !racing {
		return
	}

	g.mu.Lock()
	ch := g.latch(key)
	g.mu.Unlock()

	timeout := time.NewTimer(raceGapTimeout)
	defer timeout.Stop()

	select {
	case <-ch:
	case <-timeout.C:
	case <-ctx.Done():
	}
}

// meet holds the first racer to reach key until a second has reached it too, so that two
// racers are in the gap at once, having read the same thing. Any later racer passes.
func (g *raceGate) meet(ctx context.Context, key string) {
	g.mu.Lock()
	if g.arrived == nil {
		g.arrived = make(map[string]int)
	}
	g.arrived[key]++
	first := g.arrived[key] == 1
	g.mu.Unlock()

	if first {
		g.await(ctx, key)

		return
	}
	g.signal(key)
}

// providerHarness is one store shared by both instances, as wide as the provider's races.
func providerHarness[S any](newStore func() S) storetest.DurableHarness[S] {
	h := sharedHarness(newStore)
	h.PoolSize = storetest.ProviderRaceRacers

	return h
}

// pendingFake is a pending-request store, for the advance race alone. It embeds the port
// for what that race never calls.
type pendingFake struct {
	oidcprovider.PendingRequestStore

	readThenWrite bool
	gate          raceGate

	mu     sync.Mutex
	stages map[string]oidcprovider.Stage
}

func newPendingFake(readThenWrite bool) *pendingFake {
	return &pendingFake{readThenWrite: readThenWrite, stages: make(map[string]oidcprovider.Stage)}
}

func (f *pendingFake) Create(_ context.Context, r *oidcprovider.PendingRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.stages[string(r.HandleDigest)] = r.Stage

	return nil
}

func (f *pendingFake) Load(_ context.Context, digest []byte) (*oidcprovider.PendingRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	stage, ok := f.stages[string(digest)]
	if !ok {
		return nil, oidcprovider.ErrNotFound
	}

	return &oidcprovider.PendingRequest{HandleDigest: digest, Stage: stage, SignIn: &oidcprovider.SignIn{}}, nil
}

func (f *pendingFake) Advance(ctx context.Context, digest []byte, from, to oidcprovider.Stage, _ *oidcprovider.SignIn) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.stages[string(digest)] != from {
		return oidcprovider.ErrNotFound
	}
	if f.readThenWrite {
		f.mu.Unlock()
		f.gate.meet(ctx, string(digest))
		f.mu.Lock()
	}
	f.stages[string(digest)] = to

	return nil
}

// consumeReadsThenWrites is a one-time store whose Consume reads the record, and then
// writes whatever it found.
type consumeReadsThenWrites struct {
	onetime.Store

	gate raceGate
}

func (s *consumeReadsThenWrites) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	tok, err := s.FindByID(ctx, tokenID)
	if err != nil {
		return err
	}
	if !tok.ConsumedAt.IsZero() {
		return onetime.ErrTokenNotFound
	}
	s.gate.meet(ctx, tokenID.String())
	// The write is unconditional in this store's mind: a second writer's refusal by the
	// store beneath is not reported.
	_ = s.Store.Consume(ctx, tokenID, at)

	return nil
}

// assertionDefect is what an assertionFake gets wrong.
type assertionDefect int

const (
	assertionConforming assertionDefect = iota
	assertionReadThenWrite
	assertionIgnoresClient
	assertionJoinsKey
	assertionKeepsLastExpiry
	assertionKeepsLatestExpiry
	assertionDeletesByWallClock
	assertionDeletesByLaterOfWallClock
	assertionJoinsWithPipe
	assertionFoldsCaseAndPadding
)

type assertionKey struct{ client, jti string }

// assertionFake is a conforming assertion-identifier store but for its defect.
type assertionFake struct {
	defect assertionDefect
	gate   raceGate

	mu   sync.Mutex
	held map[assertionKey]time.Time
}

func newAssertionFake(d assertionDefect) *assertionFake {
	return &assertionFake{defect: d, held: make(map[assertionKey]time.Time)}
}

func (f *assertionFake) Record(ctx context.Context, clientID, jti string, until time.Time) (bool, error) {
	key := assertionKey{client: clientID, jti: jti}
	switch f.defect {
	case assertionIgnoresClient:
		key.client = ""
	case assertionJoinsKey:
		key = assertionKey{jti: clientID + ":" + jti}
	case assertionJoinsWithPipe:
		key = assertionKey{jti: clientID + "|" + jti}
	case assertionFoldsCaseAndPadding:
		key = assertionKey{client: collated(clientID), jti: collated(jti)}
	default:
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	first, ok := f.held[key]
	if ok {
		switch {
		case f.defect == assertionKeepsLastExpiry:
			f.held[key] = until
		case f.defect == assertionKeepsLatestExpiry && until.After(first):
			f.held[key] = until
		}

		return false, nil
	}
	if f.defect == assertionReadThenWrite {
		f.mu.Unlock()
		f.gate.meet(ctx, clientID+"\x00"+jti)
		f.mu.Lock()
	}
	f.held[key] = until

	return true, nil
}

func (f *assertionFake) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	switch f.defect {
	case assertionDeletesByWallClock:
		before = time.Now()
	case assertionDeletesByLaterOfWallClock:
		before = laterOfWallClock(before)
	default:
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	held := len(f.held)
	maps.DeleteFunc(f.held, func(_ assertionKey, until time.Time) bool { return until.Before(before) })

	return held - len(f.held), nil
}

// collated returns s as a case-insensitive collation that ignores trailing spaces would
// compare it.
func collated(s string) string { return strings.TrimRight(strings.ToLower(s), " ") }

// laterOfWallClock is the time a store sweeps by when it trusts the caller's time only so
// far as the wall clock agrees: harmless to any fixture dated after the wall clock, so a
// suite must also date one long before it.
func laterOfWallClock(before time.Time) time.Time {
	if now := time.Now(); now.After(before) {
		return now
	}

	return before
}

// accessDefect is what a brokenAccess gets wrong.
type accessDefect int

const (
	accessRevokesAll accessDefect = iota
	accessRevokeInserts
	accessRewritesDigest
	accessHidesRevoked
	accessDeleteInclusive
	accessDeletesByLaterOfWallClock
)

// brokenAccess carries one defect over the in-memory default.
type brokenAccess struct {
	*oidcprovider.MemoryAccessTokenStore

	defect accessDefect

	mu  sync.Mutex
	ids []id.ID
}

func newBrokenAccess(d accessDefect) *brokenAccess {
	return &brokenAccess{MemoryAccessTokenStore: must.Must(oidcprovider.NewMemoryAccessTokenStore()), defect: d}
}

func (b *brokenAccess) Create(ctx context.Context, r *oidcprovider.AccessTokenRecord) error {
	b.mu.Lock()
	b.ids = append(b.ids, r.ID)
	b.mu.Unlock()

	if b.defect == accessRewritesDigest {
		rewritten := *r
		rewritten.Digest = append([]byte("sha256:"), r.Digest...)
		r = &rewritten
	}

	return b.MemoryAccessTokenStore.Create(ctx, r)
}

func (b *brokenAccess) Load(ctx context.Context, tokenID id.ID) (*oidcprovider.AccessTokenRecord, error) {
	r, err := b.MemoryAccessTokenStore.Load(ctx, tokenID)
	if err == nil && r.Revoked && b.defect == accessHidesRevoked {
		return nil, oidcprovider.ErrNotFound
	}

	return r, err
}

func (b *brokenAccess) Revoke(ctx context.Context, tokenID id.ID) error {
	switch b.defect {
	case accessRevokesAll:
		b.mu.Lock()
		defer b.mu.Unlock()
		for _, other := range b.ids {
			if err := b.MemoryAccessTokenStore.Revoke(ctx, other); err != nil {
				return err
			}
		}

		return nil
	case accessRevokeInserts:
		if err := b.MemoryAccessTokenStore.Revoke(ctx, tokenID); !errors.Is(err, oidcprovider.ErrNotFound) {
			return err
		}

		return nil
	default:
		return b.MemoryAccessTokenStore.Revoke(ctx, tokenID)
	}
}

func (b *brokenAccess) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	switch b.defect {
	case accessDeleteInclusive:
		before = before.Add(time.Nanosecond)
	case accessDeletesByLaterOfWallClock:
		before = laterOfWallClock(before)
	default:
	}

	return b.MemoryAccessTokenStore.DeleteExpired(ctx, before)
}

// browserDefect is what a browserFake gets wrong.
type browserDefect int

const (
	browserConforming browserDefect = iota
	browserTouchPastAbsolute
	browserTouchShortens
	browserTouchInserts
	browserLoadIgnoresIdle
	browserLoadByWallClock
	browserLoadAcceptsZero
	browserPutReplaces
	browserPutKeepsLongIdle
	browserPutAcceptsEmpty
	browserPutAcceptsZero
	browserSharesRecords
	browserDeleteIgnoresExcept
	browserDeleteAcceptsAnyShape
	browserDeleteIgnoresUser
	browserExpiredInclusive
	browserExpiredByLaterOfWallClock
	browserSelectorIgnoresIssuer
	browserTouchReadsThenWrites
)

// browserFake is a conforming browser-session store but for its defect.
type browserFake struct {
	defect browserDefect
	gate   raceGate

	mu      sync.Mutex
	records map[string]*oidcprovider.BrowserSession
	// highest is the latest deadline a touch has read and decided to write, per digest.
	highest map[string]time.Time
}

func newBrowserFake(d browserDefect) *browserFake {
	return &browserFake{
		defect:  d,
		records: make(map[string]*oidcprovider.BrowserSession),
		highest: make(map[string]time.Time),
	}
}

func (f *browserFake) copyOf(s *oidcprovider.BrowserSession) *oidcprovider.BrowserSession {
	if f.defect == browserSharesRecords {
		return s
	}
	out := *s
	out.Digest = bytes.Clone(s.Digest)
	out.SignIn.AMR = slices.Clone(s.SignIn.AMR)

	return &out
}

func (f *browserFake) Put(_ context.Context, s *oidcprovider.BrowserSession) error {
	if len(s.Digest) == 0 && f.defect != browserPutAcceptsEmpty {
		return oidcprovider.ErrConfig
	}
	if (s.IdleExpiresAt.IsZero() || s.AbsoluteExpiresAt.IsZero()) && f.defect != browserPutAcceptsZero {
		return oidcprovider.ErrConfig
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, held := f.records[string(s.Digest)]; held && f.defect != browserPutReplaces {
		return errors.New("already stored")
	}
	stored := f.copyOf(s)
	if stored.IdleExpiresAt.After(stored.AbsoluteExpiresAt) && f.defect != browserPutKeepsLongIdle {
		stored.IdleExpiresAt = stored.AbsoluteExpiresAt
	}
	f.records[string(s.Digest)] = stored

	return nil
}

func (f *browserFake) Load(_ context.Context, digest []byte, now time.Time) (*oidcprovider.BrowserSession, error) {
	if now.IsZero() && f.defect != browserLoadAcceptsZero {
		return nil, oidcprovider.ErrConfig
	}
	if f.defect == browserLoadByWallClock {
		now = time.Now()
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	s, ok := f.records[string(digest)]
	switch {
	case !ok:
		return nil, oidcprovider.ErrNotFound
	case f.defect != browserLoadIgnoresIdle && !now.Before(s.IdleExpiresAt):
		return nil, oidcprovider.ErrNotFound
	case !now.Before(s.AbsoluteExpiresAt):
		return nil, oidcprovider.ErrNotFound
	}

	return f.copyOf(s), nil
}

func (f *browserFake) Touch(ctx context.Context, digest []byte, idleUntil time.Time) error {
	if idleUntil.IsZero() {
		return oidcprovider.ErrConfig
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	s, ok := f.records[string(digest)]
	if !ok {
		if f.defect == browserTouchInserts {
			f.records[string(digest)] = &oidcprovider.BrowserSession{
				Digest: bytes.Clone(digest), IdleExpiresAt: idleUntil, AbsoluteExpiresAt: idleUntil,
			}

			return nil
		}

		return oidcprovider.ErrNotFound
	}
	if idleUntil.After(s.AbsoluteExpiresAt) && f.defect != browserTouchPastAbsolute {
		idleUntil = s.AbsoluteExpiresAt
	}
	if f.defect == browserTouchReadsThenWrites {
		f.touchInTheGap(ctx, s, idleUntil)

		return nil
	}
	if idleUntil.After(s.IdleExpiresAt) || f.defect == browserTouchShortens {
		s.IdleExpiresAt = idleUntil
	}

	return nil
}

// touchInTheGap decides by what it read and then writes with no condition, as a SELECT
// followed by an UPDATE would. It holds both racers past their read, and the one with the
// earlier deadline until the other has written, which is the order that shortens the
// session. The caller holds f.mu, which it gives up across the gap.
func (f *browserFake) touchInTheGap(ctx context.Context, s *oidcprovider.BrowserSession, idleUntil time.Time) {
	if !idleUntil.After(s.IdleExpiresAt) {
		return
	}
	key := string(s.Digest)
	if idleUntil.After(f.highest[key]) {
		f.highest[key] = idleUntil
	}

	f.mu.Unlock()
	f.gate.meet(ctx, key)
	f.mu.Lock()

	if idleUntil.Before(f.highest[key]) {
		f.mu.Unlock()
		f.gate.await(ctx, key+"/written")
		f.mu.Lock()
	}
	s.IdleExpiresAt = idleUntil
	f.gate.signal(key + "/written")
}

func (f *browserFake) Delete(_ context.Context, digest []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.records, string(digest))

	return nil
}

func (f *browserFake) DeleteBySignIn(_ context.Context, sel oidcprovider.SignInSelector) (int, error) {
	if f.defect != browserDeleteAcceptsAnyShape {
		if err := sel.Validate(); err != nil {
			return 0, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	held := len(f.records)
	maps.DeleteFunc(f.records, func(_ string, s *oidcprovider.BrowserSession) bool { return f.selected(sel, s.SignIn) })

	return held - len(f.records), nil
}

func (f *browserFake) selected(sel oidcprovider.SignInSelector, s oidcprovider.SignIn) bool {
	switch {
	case sel.Family != id.Nil && sel.Family != s.Family,
		sel.User != "" && sel.User != s.User && f.defect != browserDeleteIgnoresUser,
		sel.ExceptFamily != id.Nil && sel.ExceptFamily == s.Family && f.defect != browserDeleteIgnoresExcept,
		sel.ExternalIssuer != "" && sel.ExternalIssuer != s.ExternalIssuer &&
			(f.defect != browserSelectorIgnoresIssuer || sel.ExternalSessionID == ""),
		sel.ExternalSessionID != "" && sel.ExternalSessionID != s.ExternalSessionID:
		return false
	default:
		return true
	}
}

func (f *browserFake) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	switch f.defect {
	case browserExpiredInclusive:
		before = before.Add(time.Nanosecond)
	case browserExpiredByLaterOfWallClock:
		before = laterOfWallClock(before)
	default:
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	held := len(f.records)
	maps.DeleteFunc(f.records, func(_ string, s *oidcprovider.BrowserSession) bool {
		return s.IdleExpiresAt.Before(before) || s.AbsoluteExpiresAt.Before(before)
	})

	return held - len(f.records), nil
}

// clearsRevocation is the store the conformance spec names: a grant stored over a
// revocation recorded first loads as though nothing had been revoked.
type clearsRevocation struct {
	*oidcprovider.MemoryGrantStore

	mu      sync.Mutex
	cleared map[id.ID]bool
}

func newClearsRevocation() *clearsRevocation {
	return &clearsRevocation{
		MemoryGrantStore: must.Must(oidcprovider.NewMemoryGrantStore()),
		cleared:          make(map[id.ID]bool),
	}
}

func (s *clearsRevocation) Create(ctx context.Context, g *oidcprovider.Grant) error {
	if _, err := s.MemoryGrantStore.Load(ctx, g.Family); err == nil {
		s.mu.Lock()
		s.cleared[g.Family] = true
		s.mu.Unlock()
	}

	return s.MemoryGrantStore.Create(ctx, g)
}

func (s *clearsRevocation) Load(ctx context.Context, family id.ID) (*oidcprovider.Grant, error) {
	g, err := s.MemoryGrantStore.Load(ctx, family)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cleared[family] {
		g.Revoked = false
	}

	return g, nil
}

// grantDefect is what a grantFake gets wrong.
type grantDefect int

const (
	grantConforming grantDefect = iota
	// grantCreateReadThenWrite decides a create by what it read before writing, as a
	// SELECT followed by an INSERT would.
	grantCreateReadThenWrite
	// grantEndReadThenWrite picks the grants it ends, then marks them all, as a SELECT
	// followed by an UPDATE with no condition would.
	grantEndReadThenWrite
	grantEndSkipsCodes
	grantCreateDropsMark
	grantRevokeOverwrites
)

// grantEntry is what a grantFake holds, and whether a create has stored it.
type grantEntry struct {
	oidcprovider.Grant

	stored bool
}

// grantFake is a grant store for the races alone, conforming but for its defect. It
// embeds the port for what the races never call.
type grantFake struct {
	oidcprovider.GrantStore

	defect grantDefect
	gate   raceGate

	mu     sync.Mutex
	codes  oidcprovider.UnspentCodes
	grants map[id.ID]*grantEntry
}

func newGrantFake(d grantDefect) *grantFake {
	return &grantFake{defect: d, grants: make(map[id.ID]*grantEntry)}
}

func (f *grantFake) UseCodes(codes oidcprovider.UnspentCodes) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.codes = codes

	return nil
}

// The moments of a grant's race the gate is told of, per family.
func grantRead(family id.ID) string    { return family.String() + "/read" }
func grantActed(family id.ID) string   { return family.String() + "/acted" }
func grantCreated(family id.ID) string { return family.String() + "/created" }

func (f *grantFake) Create(ctx context.Context, g *oidcprovider.Grant) error {
	// A create over a record an end left behind is what these two get wrong, so the end
	// goes first.
	if f.defect == grantEndSkipsCodes || f.defect == grantCreateDropsMark {
		f.gate.await(ctx, grantActed(g.Family))
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	next := &grantEntry{Grant: *g, stored: true}
	if held, ok := f.grants[g.Family]; ok {
		if held.stored {
			return errors.New("already stored")
		}
		next.Revoked, next.RevokedAt, next.RevokeCause = true, held.RevokedAt, held.RevokeCause
		if f.defect != grantCreateDropsMark {
			next.SignInEndedAt = held.SignInEndedAt
		}
	}
	if f.defect == grantCreateReadThenWrite {
		// The other side acts after this read and before this write, and is lost.
		f.mu.Unlock()
		f.gate.signal(grantRead(g.Family))
		f.gate.await(ctx, grantActed(g.Family))
		f.mu.Lock()
	}
	f.grants[g.Family] = next
	f.gate.signal(grantCreated(g.Family))

	return nil
}

func (f *grantFake) Load(_ context.Context, family id.ID) (*oidcprovider.Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	held, ok := f.grants[family]
	if !ok {
		return nil, oidcprovider.ErrNotFound
	}
	out := held.Grant

	return &out, nil
}

func (f *grantFake) Revoke(ctx context.Context, family id.ID, cause oidcprovider.RevocationCause, at time.Time) error {
	switch f.defect {
	case grantCreateReadThenWrite:
		f.gate.await(ctx, grantRead(family))
	case grantRevokeOverwrites:
		// Overwriting a stored grant is the defect, so the create goes first.
		f.gate.await(ctx, grantCreated(family))
	default:
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	defer f.gate.signal(grantActed(family))

	held, ok := f.grants[family]
	if !ok || f.defect == grantRevokeOverwrites {
		held = &grantEntry{Grant: oidcprovider.Grant{Family: family}}
		f.grants[family] = held
	}
	if !held.Revoked {
		held.Revoked, held.RevokedAt, held.RevokeCause = true, at, cause
	}

	return nil
}

func (f *grantFake) EndSignIns(ctx context.Context, sel oidcprovider.SignInSelector, at time.Time) ([]oidcprovider.Grant, error) {
	families, err := f.codes.UnspentBySignIn(ctx, sel, false)
	if err != nil {
		return nil, err
	}
	if f.defect == grantCreateReadThenWrite {
		for _, family := range families {
			f.gate.await(ctx, grantRead(family))
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	defer func() {
		for _, family := range families {
			f.gate.signal(grantActed(family))
		}
	}()

	if f.defect != grantEndSkipsCodes {
		for _, family := range families {
			held, ok := f.grants[family]
			if !ok {
				held = &grantEntry{Grant: oidcprovider.Grant{Family: family, SignInEndedAt: at}}
				f.grants[family] = held
			}
			if !held.Revoked {
				held.Revoked, held.RevokedAt, held.RevokeCause = true, at, oidcprovider.CauseSignInEnded
			}
		}
	}

	var selected []*grantEntry
	for _, held := range f.grants {
		if held.stored && held.SignInEndedAt.IsZero() && held.SignInFamily == sel.Family {
			selected = append(selected, held)
		}
	}
	if f.defect == grantEndReadThenWrite && len(selected) > 0 {
		f.mu.Unlock()
		f.gate.meet(ctx, sel.Family.String())
		f.mu.Lock()
	}

	var ended []oidcprovider.Grant
	for _, held := range selected {
		held.SignInEndedAt = at
		if !held.Offline || held.EndsWithSignIn {
			if !held.Revoked {
				held.Revoked, held.RevokedAt, held.RevokeCause = true, at, oidcprovider.CauseSignInEnded
			}
		}
		ended = append(ended, held.Grant)
	}

	return ended, nil
}

const providerBackend = "fake"

// inBackend runs a suite in the subtest the guard reads its failed cases under.
func inBackend(run func(t *testing.T)) func(t *testing.T) {
	return func(t *testing.T) { t.Run(providerBackend, run) }
}

// providerRaceVariant is a variant racing a fake carrying a defect.
func providerRaceVariant(name string, run func(t *testing.T), failsCase, failsWith string) storefix.BrokenVariant {
	return storefix.BrokenVariant{Name: "race-" + name, Run: inBackend(run), FailsCase: failsCase, FailsWith: failsWith}
}

// grantRaceVariant races a grant fake carrying d.
func grantRaceVariant(name string, d grantDefect, failsCase, failsWith string) storefix.BrokenVariant {
	return providerRaceVariant(name, func(t *testing.T) {
		storetest.RunGrantRaces(t, providerHarness(func() oidcprovider.GrantStore { return newGrantFake(d) }))
	}, failsCase, failsWith)
}

// browserVariant runs the browser-session suite against a fake carrying d.
func browserVariant(name string, d browserDefect, failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: "browser-" + name,
		Run: inBackend(func(t *testing.T) {
			storetest.BrowserSessionSuite(t, func(*testing.T) oidcprovider.BrowserSessionStore { return newBrowserFake(d) })
		}),
		FailsCase: failsCase,
	}
}

// assertionVariant runs the assertion-identifier suite against a fake carrying d.
func assertionVariant(name string, d assertionDefect, failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: "assertion-" + name,
		Run: inBackend(func(t *testing.T) {
			storetest.AssertionIDSuite(t, func(*testing.T) oidcprovider.AssertionIDStore { return newAssertionFake(d) })
		}),
		FailsCase: failsCase,
	}
}

// accessVariant runs the access-token suite against a store carrying d.
func accessVariant(name string, d accessDefect, failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: "access-" + name,
		Run: inBackend(func(t *testing.T) {
			storetest.AccessTokenSuite(t, func(*testing.T) oidcprovider.AccessTokenStore { return newBrokenAccess(d) })
		}),
		FailsCase: failsCase,
	}
}

// issuerBlind remembers the issuers each upstream session has been seen under, so a store
// over it can answer a selector for one issuer's session with every issuer's.
type issuerBlind struct {
	mu      sync.Mutex
	issuers map[string][]string
}

func (b *issuerBlind) saw(issuer, session string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.issuers == nil {
		b.issuers = make(map[string][]string)
	}
	if !slices.Contains(b.issuers[session], issuer) {
		b.issuers[session] = append(b.issuers[session], issuer)
	}
}

// widened returns the selectors sel really means to this store: its session under every
// issuer seen, or sel itself when it does not name an upstream session.
func (b *issuerBlind) widened(sel oidcprovider.SignInSelector) []oidcprovider.SignInSelector {
	if sel.ExternalSessionID == "" {
		return []oidcprovider.SignInSelector{sel}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	var out []oidcprovider.SignInSelector
	for _, issuer := range b.issuers[sel.ExternalSessionID] {
		out = append(out, oidcprovider.SignInSelector{ExternalIssuer: issuer, ExternalSessionID: sel.ExternalSessionID})
	}

	return out
}

// issuerBlindCodes lists an upstream session's codes by the session alone, so one
// issuer's logout reaches another issuer's sign-in.
type issuerBlindCodes struct {
	*oidcprovider.MemoryCodeStore

	blind issuerBlind
}

func (s *issuerBlindCodes) Create(ctx context.Context, r *oidcprovider.CodeRecord) error {
	s.blind.saw(r.SignIn.ExternalIssuer, r.SignIn.ExternalSessionID)

	return s.MemoryCodeStore.Create(ctx, r)
}

func (s *issuerBlindCodes) UnspentBySignIn(ctx context.Context, sel oidcprovider.SignInSelector, includeOffline bool) ([]id.ID, error) {
	if err := sel.Validate(); err != nil {
		return nil, err
	}

	var out []id.ID
	for _, widened := range s.blind.widened(sel) {
		families, err := s.MemoryCodeStore.UnspentBySignIn(ctx, widened, includeOffline)
		if err != nil {
			return nil, err
		}
		out = append(out, families...)
	}

	return out, nil
}

// issuerBlindGrants ends an upstream session by the session alone.
type issuerBlindGrants struct {
	*oidcprovider.MemoryGrantStore

	blind issuerBlind
}

func (s *issuerBlindGrants) Create(ctx context.Context, g *oidcprovider.Grant) error {
	s.blind.saw(g.ExternalIssuer, g.ExternalSessionID)

	return s.MemoryGrantStore.Create(ctx, g)
}

func (s *issuerBlindGrants) EndSignIns(ctx context.Context, sel oidcprovider.SignInSelector, at time.Time) ([]oidcprovider.Grant, error) {
	if err := sel.Validate(); err != nil {
		return nil, err
	}

	var out []oidcprovider.Grant
	for _, widened := range s.blind.widened(sel) {
		ended, err := s.MemoryGrantStore.EndSignIns(ctx, widened, at)
		if err != nil {
			return nil, err
		}
		out = append(out, ended...)
	}

	return out, nil
}

// The in-memory defaults, sweeping as though the caller's time could only be believed so
// far as the wall clock agrees.
type (
	wallPending struct {
		*oidcprovider.MemoryPendingRequestStore
	}
	wallCodes struct {
		*oidcprovider.MemoryCodeStore
	}
	wallGrants struct {
		*oidcprovider.MemoryGrantStore
	}
)

func (s wallPending) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	return s.MemoryPendingRequestStore.DeleteExpired(ctx, laterOfWallClock(before))
}

func (s wallCodes) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	return s.MemoryCodeStore.DeleteExpired(ctx, laterOfWallClock(before))
}

func (s wallGrants) DeleteExpired(ctx context.Context, now time.Time, keepRevoked time.Duration) (int, error) {
	return s.MemoryGrantStore.DeleteExpired(ctx, laterOfWallClock(now), keepRevoked)
}

// assertionJoinedKey is a conforming store but for holding each pair under one string,
// joined by sep.
type assertionJoinedKey struct {
	*assertionFake

	sep string
}

func (f assertionJoinedKey) Record(ctx context.Context, clientID, jti string, until time.Time) (bool, error) {
	return f.assertionFake.Record(ctx, "", clientID+f.sep+jti, until)
}

// assertionJoinVariant runs the assertion-identifier suite against a store joining its
// key with sep.
func assertionJoinVariant(name, sep string) storefix.BrokenVariant {
	return reviewVariant(name, func(t *testing.T) {
		storetest.AssertionIDSuite(t, func(*testing.T) oidcprovider.AssertionIDStore {
			return assertionJoinedKey{assertionFake: newAssertionFake(assertionConforming), sep: sep}
		})
	}, assertionClientCase)
}

// reviewVariant is a variant of a whole suite, run by run, that fails at failsCase.
func reviewVariant(name string, run func(t *testing.T), failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{Name: "review-" + name, Run: inBackend(run), FailsCase: failsCase}
}

const (
	assertionClientCase = "an identifier belongs to its client alone, whatever the text of either"
	assertionForgetCase = "delete expired forgets what is strictly before the time given, and that alone"
	browserTouchAbsCase = "touch never moves the idle deadline past the absolute one"
	browserLoadCase     = "a load is judged at the caller's time, against both deadlines"
	accessDeleteCase    = "delete expired removes what is strictly before the time given, revoked or not, by that time alone"

	pastTimeCase  = "delete expired keeps what has not expired at the time given, however long ago that time is"
	wallClockCase = "delete expired judges by the caller's time, never the wall clock"

	issuerOnlyShape = "upstream issuer and session, under another issuer"
)

// providerVariants are the defects the provider's suites and races must each catch, at
// the case guarding it.
var providerVariants = []storefix.BrokenVariant{
	providerRaceVariant("advance-read-then-write", func(t *testing.T) {
		storetest.RunAdvanceRace(t, providerHarness(func() oidcprovider.PendingRequestStore { return newPendingFake(true) }))
	}, storetest.AdvanceRaceName, "more than one successful advance"),
	providerRaceVariant("code-spend-read-then-write", func(t *testing.T) {
		storetest.RunCodeSpendRace(t, providerHarness(func() onetime.Store {
			return &consumeReadsThenWrites{Store: must.Must(onetime.NewMemoryStore())}
		}))
	}, storetest.CodeSpendRaceName, "more than one successful spend"),
	providerRaceVariant("assertion-read-then-write", func(t *testing.T) {
		storetest.RunAssertionRecordRace(t, providerHarness(func() oidcprovider.AssertionIDStore {
			return newAssertionFake(assertionReadThenWrite)
		}))
	}, storetest.AssertionRecordRaceName, "more than one successful record"),

	grantRaceVariant("create-read-then-write", grantCreateReadThenWrite,
		storetest.RevocationCreateRaceName, "a revocation raced its create and was lost"),
	grantRaceVariant("revoke-overwrites", grantRevokeOverwrites,
		storetest.RevocationCreateRaceName, "the grant's own fields were lost"),
	grantRaceVariant("end-read-then-write", grantEndReadThenWrite,
		storetest.EndReportedOnceRaceName, "more than one successful report"),
	grantRaceVariant("end-create-read-then-write", grantCreateReadThenWrite,
		storetest.EndCreateRaceName, "the grant was left live"),
	grantRaceVariant("end-skips-codes", grantEndSkipsCodes,
		storetest.EndCreateRaceName, "the grant was left live"),
	grantRaceVariant("create-drops-the-mark", grantCreateDropsMark,
		storetest.EndCreateRaceName, "a second report of the end returned"),

	{
		Name: "grant-clears-a-revocation",
		Run: inBackend(func(t *testing.T) {
			storetest.GrantSuite(t, func(*testing.T) oidcprovider.GrantStore { return newClearsRevocation() })
		}),
		FailsCase: "a revocation recorded first loads revoked, before and after create (H2)",
	},

	assertionVariant("ignores-the-client", assertionIgnoresClient, assertionClientCase),
	assertionVariant("runs-the-key-together", assertionJoinsKey, assertionClientCase),
	assertionVariant("keeps-the-last-expiry", assertionKeepsLastExpiry, "a refused record keeps a later first expiry, and is not shortened"),
	assertionVariant("extends-the-expiry", assertionKeepsLatestExpiry, "a refused record does not extend the first expiry"),
	assertionVariant("deletes-by-the-wall-clock", assertionDeletesByWallClock, assertionForgetCase),

	accessVariant("revokes-the-whole-grant", accessRevokesAll, "revoking a token marks it, and no other of its grant"),
	accessVariant("revoking-a-missing-token-succeeds", accessRevokeInserts,
		"a missing token is not found, for a load and for a revocation, which inserts nothing"),
	accessVariant("rewrites-the-digest", accessRewritesDigest, "a record holds only the digest it was given, unchanged"),
	accessVariant("hides-a-revoked-token", accessHidesRevoked,
		"an expired or revoked token is still returned, because the provider judges it"),
	accessVariant("deletes-at-the-deadline", accessDeleteInclusive, accessDeleteCase),

	browserVariant("touch-past-absolute", browserTouchPastAbsolute, browserTouchAbsCase),
	browserVariant("touch-shortens", browserTouchShortens,
		"touch never shortens the idle deadline, so a slower request cannot undo a later one"),
	browserVariant("touch-inserts", browserTouchInserts, "touching what is not held is not found, and inserts nothing"),
	browserVariant("load-ignores-idle", browserLoadIgnoresIdle, browserLoadCase),
	browserVariant("load-by-the-wall-clock", browserLoadByWallClock,
		"a load never reads a clock of its own: a session the wall clock has long passed is live at a time before its end"),
	browserVariant("load-accepts-a-zero-time", browserLoadAcceptsZero, "a zero time is refused, as it would keep every session alive"),
	browserVariant("put-replaces", browserPutReplaces,
		"a digest already held is refused, the session stays, and the error carries no digest"),
	browserVariant("put-keeps-a-long-idle", browserPutKeepsLongIdle,
		"a session put with an idle deadline past its absolute one holds the absolute one"),
	browserVariant("put-accepts-an-empty-digest", browserPutAcceptsEmpty, "an empty digest is neither stored nor found"),
	browserVariant("put-accepts-a-zero-deadline", browserPutAcceptsZero,
		"a session with a zero deadline is refused, as no load could judge it"),
	browserVariant("shares-records", browserSharesRecords, "a session stored or loaded is the caller's own copy"),
	browserVariant("delete-ignores-the-exception", browserDeleteIgnoresExcept,
		"delete by sign-in by user except a family removes what it selects, and nothing else"),
	browserVariant("delete-accepts-any-shape", browserDeleteAcceptsAnyShape,
		"delete by sign-in refuses a selector of no valid shape: empty"),
	browserVariant("delete-leaves-the-user", browserDeleteIgnoresUser,
		"delete by sign-in by user and upstream issuer stays within that user"),
	browserVariant("expired-at-the-deadline", browserExpiredInclusive,
		"delete expired removes what is past either deadline, by the time given alone"),

	reviewVariant("browser-session-selector-ignores-issuer", func(t *testing.T) {
		storetest.BrowserSessionSuite(t, func(*testing.T) oidcprovider.BrowserSessionStore {
			return newBrowserFake(browserSelectorIgnoresIssuer)
		})
	}, "delete by sign-in by "+issuerOnlyShape+" removes what it selects, and nothing else"),
	reviewVariant("code-listing-ignores-issuer", func(t *testing.T) {
		storetest.CodeRecordSuite(t, func(*testing.T) oidcprovider.CodeStore {
			return &issuerBlindCodes{MemoryCodeStore: must.Must(oidcprovider.NewMemoryCodeStore())}
		})
	}, "by "+issuerOnlyShape+": lists the selected, and offline only when asked"),
	reviewVariant("grant-end-ignores-issuer", func(t *testing.T) {
		storetest.GrantSuite(t, func(*testing.T) oidcprovider.GrantStore {
			return &issuerBlindGrants{MemoryGrantStore: must.Must(oidcprovider.NewMemoryGrantStore())}
		})
	}, "end by "+issuerOnlyShape+": revokes the online, marks both, returns both, then none"),

	reviewVariant("browser-delete-expired-by-wall-clock-too", func(t *testing.T) {
		storetest.BrowserSessionSuite(t, func(*testing.T) oidcprovider.BrowserSessionStore {
			return newBrowserFake(browserExpiredByLaterOfWallClock)
		})
	}, pastTimeCase),
	reviewVariant("assertion-delete-expired-by-wall-clock-too", func(t *testing.T) {
		storetest.AssertionIDSuite(t, func(*testing.T) oidcprovider.AssertionIDStore {
			return newAssertionFake(assertionDeletesByLaterOfWallClock)
		})
	}, pastTimeCase),
	reviewVariant("access-delete-expired-by-wall-clock-too", func(t *testing.T) {
		storetest.AccessTokenSuite(t, func(*testing.T) oidcprovider.AccessTokenStore {
			return newBrokenAccess(accessDeletesByLaterOfWallClock)
		})
	}, pastTimeCase),
	reviewVariant("pending-delete-expired-by-wall-clock-too", func(t *testing.T) {
		storetest.PendingRequestSuite(t, func(*testing.T) oidcprovider.PendingRequestStore {
			return wallPending{must.Must(oidcprovider.NewMemoryPendingRequestStore())}
		})
	}, wallClockCase),
	reviewVariant("code-delete-expired-by-wall-clock-too", func(t *testing.T) {
		storetest.CodeRecordSuite(t, func(*testing.T) oidcprovider.CodeStore {
			return wallCodes{must.Must(oidcprovider.NewMemoryCodeStore())}
		})
	}, wallClockCase),
	reviewVariant("grant-delete-expired-by-wall-clock-too", func(t *testing.T) {
		storetest.GrantSuite(t, func(*testing.T) oidcprovider.GrantStore {
			return wallGrants{must.Must(oidcprovider.NewMemoryGrantStore())}
		})
	}, wallClockCase),

	reviewVariant("assertion-joins-with-a-pipe", func(t *testing.T) {
		storetest.AssertionIDSuite(t, func(*testing.T) oidcprovider.AssertionIDStore {
			return newAssertionFake(assertionJoinsWithPipe)
		})
	}, assertionClientCase),
	reviewVariant("assertion-folds-case-and-padding", func(t *testing.T) {
		storetest.AssertionIDSuite(t, func(*testing.T) oidcprovider.AssertionIDStore {
			return newAssertionFake(assertionFoldsCaseAndPadding)
		})
	}, assertionClientCase),

	// A key joined by any separator lets two clients' identifiers collide.
	assertionJoinVariant("assertion-joins-with-a-slash", "/"),
	assertionJoinVariant("assertion-joins-with-a-dot", "."),
	assertionJoinVariant("assertion-joins-with-a-hash", "#"),
	assertionJoinVariant("assertion-joins-with-nothing", ""),

	// An adapter running the suite alone, and no race of its own.
	{
		Name: "suite-alone-touch-reads-then-writes",
		Run: inBackend(func(t *testing.T) {
			storetest.BrowserSessionSuite(t, func(*testing.T) oidcprovider.BrowserSessionStore {
				return newBrowserFake(browserTouchReadsThenWrites)
			})
		}),
		FailsCase: storetest.TouchRaceName,
	},

	reviewVariant("browser-touch-reads-then-writes", func(t *testing.T) {
		storetest.RunTouchRace(t, providerHarness(func() oidcprovider.BrowserSessionStore {
			return newBrowserFake(browserTouchReadsThenWrites)
		}))
	}, storetest.TouchRaceName),
}

// providerBrokenVar names the variant TestBrokenProviderConformance runs.
const providerBrokenVar = "STORETEST_BROKEN_PROVIDER"

// TestBrokenProviderConformance is the child half of TestBrokenProviderStoresAreCaught.
func TestBrokenProviderConformance(t *testing.T) {
	storefix.RunBrokenChild(t, providerBrokenVar, "TestBrokenProviderStoresAreCaught", providerVariants)
}

// TestBrokenProviderStoresAreCaught checks that each provider suite and race fails
// against every store carrying the defect it guards, at the case guarding it.
func TestBrokenProviderStoresAreCaught(t *testing.T) {
	t.Parallel()

	storefix.CatchBrokenVariants(t, providerBrokenVar, "TestBrokenProviderConformance", providerBackend, providerVariants)
}

// TestBrokenProviderFakesConform runs the suites and races against the fakes with no
// defect, which must pass: the broken forms differ from them by their defect alone.
func TestBrokenProviderFakesConform(t *testing.T) {
	t.Parallel()

	t.Run("advance race", func(t *testing.T) {
		storetest.RunAdvanceRace(t, providerHarness(func() oidcprovider.PendingRequestStore { return newPendingFake(false) }))
	})
	t.Run("assertion race", func(t *testing.T) {
		storetest.RunAssertionRecordRace(t, providerHarness(func() oidcprovider.AssertionIDStore {
			return newAssertionFake(assertionConforming)
		}))
	})
	t.Run("assertion suite", func(t *testing.T) {
		storetest.AssertionIDSuite(t, func(*testing.T) oidcprovider.AssertionIDStore {
			return newAssertionFake(assertionConforming)
		})
	})
	t.Run("touch race", func(t *testing.T) {
		storetest.RunTouchRace(t, providerHarness(func() oidcprovider.BrowserSessionStore {
			return newBrowserFake(browserConforming)
		}))
	})
	t.Run("browser suite", func(t *testing.T) {
		storetest.BrowserSessionSuite(t, func(*testing.T) oidcprovider.BrowserSessionStore {
			return newBrowserFake(browserConforming)
		})
	})
	t.Run("grant races", func(t *testing.T) {
		storetest.RunGrantRaces(t, providerHarness(func() oidcprovider.GrantStore { return newGrantFake(grantConforming) }))
	})
}
