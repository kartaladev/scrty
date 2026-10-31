package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/pkg/logsample"
)

// HandoffTTL is how long a handoff code stays redeemable after it is issued. A
// code is refused at and after its expiry, and accepted only strictly before.
//
// It is fixed, not an option. The code travels in a URL, where browser
// history and intermediaries can record it until it expires or is spent, and a
// code whose redemption was refused stays live for the rest of its lifetime.
// Widening the window is therefore a security decision rather than a tuning
// knob, and the library does not offer it.
const HandoffTTL = 60 * time.Second

// The sizes of a code's two halves, in random bytes before encoding.
const (
	handoffTokenIDBytes = 16
	handoffSecretBytes  = 32
)

// The lengths of a code's two halves once base64url-encoded without padding.
var (
	handoffTokenIDLen = base64.RawURLEncoding.EncodedLen(handoffTokenIDBytes)
	handoffSecretLen  = base64.RawURLEncoding.EncodedLen(handoffSecretBytes)
)

// handoffLogInterval bounds repeated refusal records to one per reason per
// interval.
const handoffLogInterval = time.Minute

// Handoff conveys a completed OIDC login to the session that will be
// created for it, through a short-lived, single-use code.
//
// The callback calls Issue and hands the code to the browser; the browser
// posts it back, and the redemption endpoint calls Redeem. A code is
// <tokenID>.<secret>: 16 and 32 random bytes, each base64url-encoded without
// padding. The store holds the token id and SHA-256 of the secret, never the
// secret itself.
//
// Build one with NewHandoff. A Handoff is safe for concurrent use
// as far as the store and user loader it was given are.
type Handoff struct {
	store   HandoffStore
	users   identity.UserLoader
	random  io.Reader
	clock   clock.Clock
	ids     id.Generator
	log     *slog.Logger
	sampler *logsample.Sampler
}

// NewHandoff returns a manager that keeps codes in store and resolves
// the user a code was issued for through users.
//
// Both are required, and neither is defaulted here: a nil store or loader,
// including a nil pointer inside a non-nil interface, is refused as a missing
// port (identity.MissingPort) wrapped in ErrConfig. A consumer with no shared
// store passes NewMemoryHandoffStore(), which holds codes for one process only:
//
//	handoffs, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), users)
//
// With no options it draws codes from crypto/rand.Reader (WithHandoffRandom),
// reads time from clock.System() (WithHandoffClock), names records with
// id.NewV7Generator() (WithHandoffIDGenerator) and logs to slog.Default()
// (WithHandoffLogger). Every error it returns wraps ErrConfig.
//
// A record of a redemption the store or users failed carries a fixed reason
// and the error's Go type, never the dependency's own text; a consumer who
// wants that detail logs it inside their own implementation of the store or
// the loader.
func NewHandoff(store HandoffStore, users identity.UserLoader, opts ...HandoffOption) (*Handoff, error) {
	if nilcheck.IsNil(store) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("handoff store"))
	}
	if nilcheck.IsNil(users) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("user loader"))
	}

	h := &Handoff{store: store, users: users}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(h); err != nil {
			return nil, err
		}
	}

	if h.random == nil {
		h.random = rand.Reader
	}
	if h.clock == nil {
		h.clock = clock.System()
	}
	if h.ids == nil {
		h.ids = id.NewV7Generator()
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	h.sampler = logsample.New(handoffLogInterval, logsample.WithReporter(h.reportSuppressed))

	return h, nil
}

// Issue stores a handoff for a completed callback and returns its code, which
// expires HandoffTTL after now.
//
// The record carries the principal's user reference, the provider, the
// verified issuer, the provider session id, the raw ID token, the requested
// destination and the asserted amr and acr, all as res holds them; the amr is
// copied, so changing res afterwards changes nothing stored. A result with no
// principal or no user reference, a cancelled context, and a failure of the
// random source, the ID generator or the store each return an error and no
// code; nothing is stored then, except that a store write whose failure was
// reported may still have landed, which leaves an unknown code that simply
// expires.
//
// The code is the caller's to hand to the browser and nowhere else: the
// library never logs it.
func (h *Handoff) Issue(ctx context.Context, res CallbackResult) (string, error) {
	if res.Principal == nil || res.Principal.ID == "" {
		return "", errors.New("oidc: a handoff needs the principal's user reference")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	var raw [handoffTokenIDBytes + handoffSecretBytes]byte
	if _, err := io.ReadFull(h.random, raw[:]); err != nil {
		return "", fmt.Errorf("oidc: drawing a handoff code: %w", err)
	}
	tokenID := base64.RawURLEncoding.EncodeToString(raw[:handoffTokenIDBytes])
	secret := base64.RawURLEncoding.EncodeToString(raw[handoffTokenIDBytes:])

	recID, err := h.ids.NewID()
	if err != nil {
		return "", fmt.Errorf("oidc: naming a handoff record: %w", err)
	}

	now := h.clock.Now()
	rec := HandoffRecord{
		ID:         recID,
		TokenID:    tokenID,
		SecretHash: handoffDigest(secret),
		UserID:     res.Principal.ID,
		Provider:   res.Provider,
		Issuer:     res.Issuer,
		SessionID:  res.SessionID,
		IDToken:    res.IDToken,
		Next:       res.Next,
		AMR:        slices.Clone(res.AMR),
		ACR:        res.ACR,
		CreatedAt:  now,
		ExpiresAt:  now.Add(HandoffTTL),
	}
	if err := h.store.Insert(ctx, rec); err != nil {
		return "", diag.Wrap(err, "oidc: storing a handoff code")
	}

	return tokenID + "." + secret, nil
}

// handoffDigest is what the store holds in place of a code's secret: SHA-256
// of its encoded form.
func handoffDigest(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// reportSuppressed writes the count of refusal records the sampler held back.
func (h *Handoff) reportSuppressed(reason string, suppressed int) {
	h.log.LogAttrs(context.Background(), slog.LevelInfo, "oidc handoff refusals suppressed",
		slog.String("reason", reason),
		slog.Int("suppressed", suppressed))
}

// RedeemCandidate is what a redemption check decides on: the user a handoff
// code was issued for, loaded afresh by the recorded reference, and the login
// the record conveys.
//
// Provider, Issuer, AMR and ACR are the record's, as the library wrote them
// at the callback from the verified ID token: never a value presented with
// the redemption. AMR is a copy each check owns; writing to it changes nothing
// another check, the result or the store sees.
type RedeemCandidate struct {
	Principal         identity.Principal
	PasswordChangedAt time.Time
	Provider, Issuer  string
	AMR               []string
	ACR               string
}

// RedeemCheck is a refusal check run against the redemption candidate before
// a handoff code is spent.
//
// A check must have no side effects. Several racing redemptions of one code
// can each run every check, and only one goes on to consume it. That includes
// any consumer policy the chain's shipped check evaluates. A check that wrote
// something would write it once per attempt rather than once per sign-in.
//
// A redeemer runs the checks against the user it will return and that user's
// password-change time. The login completion step reuses the
// post-authentication decision the chain's shipped check made before the code
// was spent, rather than evaluating the policies again after it is spent, and
// refuses a redemption that returns a user with a different reference, or a
// password-change time that is not the same instant, than the checks were
// handed.
//
// The first check that returns an error stops the redemption, later checks do
// not run, the error is returned unchanged, and the code stays redeemable.
type RedeemCheck func(ctx context.Context, c RedeemCandidate) error

// HandoffResult is a redeemed handoff: the user it authenticates, loaded
// afresh by the recorded reference, and the provider session it came from.
//
// IDToken is kept for RP-initiated logout and must never be logged. Next is
// the destination recorded when the login started, still untrusted: the
// caller resolves it through its allowlist before redirecting to it. AMR and
// ACR are the assurance the record carries, the same values the checks were
// handed; AMR is the caller's own copy.
type HandoffResult struct {
	Principal                            identity.Principal
	PasswordChangedAt                    time.Time
	Provider, Issuer, SessionID, IDToken string
	Next                                 string
	AMR                                  []string
	ACR                                  string
}

// Redeem spends a handoff code and reports whom it authenticates.
//
// It checks everything before it spends anything, in this order: the code is
// parsed; its record is found; the secret is compared in constant time; expiry
// is checked (a code is refused at and after its expiry); a record already
// consumed is refused without loading anyone, as a shortcut for replays; the
// user is loaded by the recorded reference and refused when missing, disabled,
// or loaded with a different reference; the checks run in order; and only then
// is the record consumed, atomically, by the store. Single use rests on that
// consume alone, so of several racing redemptions of one code exactly one
// succeeds with a store that honours HandoffStore's contract.
//
// Every failure except a check's own error is ErrInvalidHandoff, itself and
// unwrapped: a malformed, unknown, wrong-secret, expired or spent code, a
// missing, disabled or mismatched user, a cancelled request, and a failure of
// the store or the loader, including of the consume. A caller cannot tell them
// apart; the cause is logged, at DEBUG for traffic that is simply wrong and at
// ERROR for an outage, as a fixed reason (handoff-store or user-loader) and
// the error's Go type, never the store's or loader's own text. Any failure
// before the consume leaves the code redeemable until it expires. No error and no log record carries the code or
// the ID token.
func (h *Handoff) Redeem(ctx context.Context, code string, checks ...RedeemCheck) (HandoffResult, error) {
	tokenID, secret, ok := parseHandoffCode(code)
	if !ok {
		return HandoffResult{}, h.refuse(ctx, slog.LevelDebug, "malformed")
	}

	rec, err := h.store.FindByTokenID(ctx, tokenID)
	switch {
	case errors.Is(err, ErrHandoffNotFound):
		return HandoffResult{}, h.refuse(ctx, slog.LevelDebug, "unknown")
	case err != nil:
		return HandoffResult{}, h.refuseFailure(ctx, "handoff-store", "find", err)
	case rec == nil:
		return HandoffResult{}, h.refuse(ctx, slog.LevelError, "store_returned_nil")
	}

	if subtle.ConstantTimeCompare(handoffDigest(secret), rec.SecretHash) != 1 {
		return HandoffResult{}, h.refuse(ctx, slog.LevelDebug, "secret_mismatch")
	}
	now := h.clock.Now()
	if !now.Before(rec.ExpiresAt) {
		return HandoffResult{}, h.refuse(ctx, slog.LevelDebug, "expired")
	}
	// Not what guarantees single use, which is the consume below; it only
	// spares a replayed code the user load and the checks.
	if rec.ConsumedAt != nil {
		return HandoffResult{}, h.refuse(ctx, slog.LevelDebug, "consumed")
	}

	details, err := h.users.LoadByUserID(ctx, rec.UserID)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		return HandoffResult{}, h.refuse(ctx, slog.LevelDebug, "user_not_found")
	case err != nil:
		return HandoffResult{}, h.refuseFailure(ctx, "user-loader", "", err)
	case details == nil:
		return HandoffResult{}, h.refuse(ctx, slog.LevelDebug, "user_not_found")
	case !details.Active:
		return HandoffResult{}, h.refuse(ctx, slog.LevelDebug, "user_inactive")
	case details.ID != rec.UserID:
		return HandoffResult{}, h.refuse(ctx, slog.LevelDebug, "user_mismatch")
	}

	principal := *identity.PrincipalFromDetails(details)
	for _, check := range checks {
		if check == nil {
			continue
		}
		candidate := RedeemCandidate{
			Principal:         principal,
			PasswordChangedAt: details.PasswordChangedAt,
			Provider:          rec.Provider,
			Issuer:            rec.Issuer,
			AMR:               slices.Clone(rec.AMR),
			ACR:               rec.ACR,
		}
		if err := check(ctx, candidate); err != nil {
			return HandoffResult{}, err
		}
	}

	// A request nobody will read the answer to must not spend the code.
	if ctx.Err() != nil {
		return HandoffResult{}, h.refuse(ctx, slog.LevelDebug, "request_cancelled")
	}
	err = h.store.Consume(ctx, rec.TokenID, now)
	switch {
	case errors.Is(err, ErrHandoffNotFound):
		return HandoffResult{}, h.refuse(ctx, slog.LevelDebug, "consume_lost")
	case err != nil:
		return HandoffResult{}, h.refuseFailure(ctx, "handoff-store", "consume", err)
	}

	return HandoffResult{
		Principal:         principal,
		PasswordChangedAt: details.PasswordChangedAt,
		Provider:          rec.Provider,
		Issuer:            rec.Issuer,
		SessionID:         rec.SessionID,
		IDToken:           rec.IDToken,
		Next:              rec.Next,
		AMR:               slices.Clone(rec.AMR),
		ACR:               rec.ACR,
	}, nil
}

// parseHandoffCode splits a code into its token id and secret, and reports
// whether both halves have the length and alphabet Issue produces.
func parseHandoffCode(code string) (tokenID, secret string, ok bool) {
	tokenID, secret, found := strings.Cut(code, ".")
	if !found || len(tokenID) != handoffTokenIDLen || len(secret) != handoffSecretLen {
		return "", "", false
	}
	strict := base64.RawURLEncoding.Strict()
	if _, err := strict.DecodeString(tokenID); err != nil {
		return "", "", false
	}
	if _, err := strict.DecodeString(secret); err != nil {
		return "", "", false
	}
	return tokenID, secret, true
}

// refuse logs why a redemption failed, through the sampler, and returns
// ErrInvalidHandoff. The record names the reason; never the code, the secret
// or the ID token.
func (h *Handoff) refuse(ctx context.Context, level slog.Level, reason string) error {
	return h.record(ctx, level, reason, slog.String("reason", reason))
}

// refuseFailure is refuse for a redemption stopped by a consumer-supplied
// dependency's failure: the store or the user loader. op names which call
// failed, for a reason more than one call site shares — "find" or "consume",
// for handoff-store — so a recurring failure of one does not suppress a
// record of the other under one sampling key; it is empty for a reason with
// only one call site, and then the record carries no op attribute. The
// record otherwise carries diag.Failure's reason, error_type and, for a
// cancellation, cancelled=true, never the dependency's own text. A consumer
// who wants that text logs it inside their own implementation of the store
// or the loader.
func (h *Handoff) refuseFailure(ctx context.Context, reason, op string, err error) error {
	attrs := diag.Failure(reason, err)
	key := reason
	if op != "" {
		attrs = append([]slog.Attr{slog.String("op", op)}, attrs...)
		key = reason + ":" + op
	}
	return h.record(ctx, slog.LevelError, key, attrs...)
}

// record writes one refusal record through the sampler, keyed by key, and
// returns ErrInvalidHandoff. attrs carry the reason attribute themselves, so
// it is written exactly once whichever caller built them; key distinguishes
// the sampling window from the reason attribute where a reason has more than
// one call site (refuseFailure's op), and is otherwise the reason itself.
func (h *Handoff) record(ctx context.Context, level slog.Level, key string, attrs ...slog.Attr) error {
	write, suppressed := h.sampler.Allow("oidc.handoff."+key, h.clock.Now())
	if write {
		h.log.LogAttrs(ctx, level, "oidc handoff redemption refused",
			append(attrs, slog.Int("suppressed", suppressed))...)
	}
	return ErrInvalidHandoff
}

// FlushRefusalLogs reports every refusal record the handoff manager's sampler
// has suppressed but not yet counted, then forgets every key, so the next
// redemption refused for a reason already reported is written again rather
// than held back. It always returns nil; the signature is logsample.Flusher's, the
// optional interface every refusal-log flusher shares.
//
// It is safe to call at shutdown, including while redemptions are still in
// flight, and safe to call more than once: a second flush with nothing new
// pending reports nothing. Call it directly, or let
// httpsec.Chain.FlushRefusalLogs reach it through the OIDC login manager it
// was given (oidc.RelyingParty.FlushRefusalLogs).
func (h *Handoff) FlushRefusalLogs() error {
	h.sampler.Flush()

	return nil
}

// PurgeExpired deletes the handoff records that expired before the manager's
// own now, read from its clock (WithHandoffClock), and returns how many the
// store removed. A redeemed record expires like any other, so spent codes go
// once their lifetime has passed.
//
// The cutoff is the manager's and is not configurable: nothing counts expired
// handoffs, so there is no window to wait out, and a code that has not yet
// expired is never deleted. A store error is returned with whatever count the
// store reported. HandoffExpiryTask wraps it as a task.
func (h *Handoff) PurgeExpired(ctx context.Context) (int, error) {
	return h.store.DeleteExpired(ctx, h.clock.Now())
}

// HandoffOption customises a Handoff at construction.
//
// Every option replaces a default that already works. An option given nil
// fails construction with ErrConfig rather than silently keeping the default:
// a consumer who passed one meant to replace it. A nil option is ignored.
//
// There is deliberately no option for the code's lifetime; see HandoffTTL.
type HandoffOption func(*Handoff) error

// WithHandoffRandom replaces the source the token id and the secret of every
// code are drawn from. The default is crypto/rand.Reader. A nil reader,
// including a nil pointer inside a non-nil interface, is refused.
//
// It exists so a test can fix or fail the source; production code has no
// reason to replace it, and a source that is not cryptographically secure
// makes every code guessable.
func WithHandoffRandom(r io.Reader) HandoffOption {
	return func(h *Handoff) error {
		if nilcheck.IsNil(r) {
			return fmt.Errorf("%w: WithHandoffRandom was given nil", ErrConfig)
		}
		h.random = r
		return nil
	}
}

// WithHandoffClock replaces the clock issuance stamps and redemption judges
// expiry and consumption by. The default is clock.System(). A nil clock, typed
// nil included, is a configuration error.
func WithHandoffClock(clk clock.Clock) HandoffOption {
	return func(h *Handoff) error {
		if nilcheck.IsNil(clk) {
			return fmt.Errorf("%w: WithHandoffClock was given nil", ErrConfig)
		}
		h.clock = clk
		return nil
	}
}

// WithHandoffIDGenerator replaces the generator of each handoff record's ID.
// The default is id.NewV7Generator(). A nil generator, including a nil pointer
// inside a non-nil interface, is refused.
//
// The record ID names the record for the store; it is not part of the code,
// which carries its own random token id.
func WithHandoffIDGenerator(g id.Generator) HandoffOption {
	return func(h *Handoff) error {
		if nilcheck.IsNil(g) {
			return fmt.Errorf("%w: WithHandoffIDGenerator was given nil", ErrConfig)
		}
		h.ids = g
		return nil
	}
}

// WithHandoffLogger replaces the logger every refused and failed redemption
// is reported to. The default is slog.Default(). A nil logger is refused.
//
// Redemption returns one error whatever went wrong, so this log is the only
// place the cause appears: a miss, an inactive user or a reference mismatch at
// DEBUG, a store or loader failure at ERROR. No record carries the code, its
// secret, the ID token or a claim value.
func WithHandoffLogger(l *slog.Logger) HandoffOption {
	return func(h *Handoff) error {
		if l == nil {
			return fmt.Errorf("%w: WithHandoffLogger was given nil", ErrConfig)
		}
		h.log = l
		return nil
	}
}

// errHandoffTokenIDTaken is returned by MemoryHandoffStore.Insert for a token
// id it already holds.
var errHandoffTokenIDTaken = errors.New("oidc: a handoff record with this token id is already stored")

// MemoryHandoffStore keeps handoff codes in process memory. It is the store a
// consumer passes to NewHandoff when it has no shared one, and it is
// safe for concurrent use.
//
// It is not durable and not shared: a code issued by one process cannot be
// redeemed by another, and a restart forgets every code. A deployment of
// several instances, where the callback and the redemption may land on
// different ones, supplies a shared HandoffStore instead.
//
// Nothing purges it on a timer. Expired records stay until DeleteExpired is
// called; an expired record that is still held is never honoured, because
// Handoff judges expiry at every redemption.
type MemoryHandoffStore struct {
	mu      sync.Mutex
	records map[string]HandoffRecord
}

// NewMemoryHandoffStore returns an empty in-memory handoff store.
//
// DeleteExpired judges expiry against the cutoff it is given, never against a
// clock of its own, matching HandoffStore's contract, so the store has no
// clock to configure.
func NewMemoryHandoffStore() *MemoryHandoffStore {
	return &MemoryHandoffStore{records: make(map[string]HandoffRecord)}
}

// copyHandoffRecord returns a record that shares no memory with rec, so
// neither a caller wiping the buffer it inserted nor one writing to what it
// read back can change what the store holds.
func copyHandoffRecord(rec HandoffRecord) HandoffRecord {
	rec.SecretHash = slices.Clone(rec.SecretHash)
	rec.AMR = slices.Clone(rec.AMR)
	if rec.ConsumedAt != nil {
		at := *rec.ConsumedAt
		rec.ConsumedAt = &at
	}

	return rec
}

// Insert stores rec. A token id the store already holds is refused rather than
// overwritten: replacing a record would invalidate a code already in a
// holder's hands.
func (s *MemoryHandoffStore) Insert(_ context.Context, rec HandoffRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, taken := s.records[rec.TokenID]; taken {
		return errHandoffTokenIDTaken
	}
	s.records[rec.TokenID] = copyHandoffRecord(rec)

	return nil
}

// FindByTokenID returns a copy of the record, or ErrHandoffNotFound.
func (s *MemoryHandoffStore) FindByTokenID(_ context.Context, tokenID string) (*HandoffRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[tokenID]
	if !found {
		return nil, ErrHandoffNotFound
	}
	out := copyHandoffRecord(rec)

	return &out, nil
}

// Consume marks the record consumed at the given time, and succeeds only while
// it is unconsumed.
//
// The test and the write happen under one lock, so of several callers racing
// on one code exactly one succeeds. A missing record and a consumed one are the
// same ErrHandoffNotFound.
func (s *MemoryHandoffStore) Consume(_ context.Context, tokenID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[tokenID]
	if !found || rec.ConsumedAt != nil {
		return ErrHandoffNotFound
	}
	rec.ConsumedAt = &at
	s.records[tokenID] = rec

	return nil
}

// DeleteExpired removes the records whose expiry is before the cutoff, and
// returns how many it removed. It judges expiry against the given cutoff
// alone, never the store's own clock, matching HandoffStore's contract.
//
// A zero cutoff is refused with ErrRetainSinceRequired and nothing is removed:
// the zero time is what a caller who forgot to compute a cutoff passes.
func (s *MemoryHandoffStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	if before.IsZero() {
		return 0, ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var removed int
	for key, rec := range s.records {
		if !rec.ExpiresAt.Before(before) {
			continue
		}
		delete(s.records, key)
		removed++
	}

	return removed, nil
}

var _ HandoffStore = (*MemoryHandoffStore)(nil)

// HandoffExpiryTask returns the task that deletes h's expired handoff records,
// spent or not, through h.PurgeExpired.
//
// The task is named "oidc-handoffs"; a consumer renames
// it by setting Name on the returned value. It sets no Interval, because only
// the deployment knows its cadence, and it accepts no cutoff: the manager uses
// its own clock's now. It never deletes a code that has not expired, and it
// never touches OIDC links, sessions or identity records.
func HandoffExpiryTask(h *Handoff) expiry.Task {
	return expiry.Task{Name: "oidc-handoffs", Run: h.PurgeExpired}
}
