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
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
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

// HandoffManager conveys a completed OIDC login to the session that will be
// created for it, through a short-lived, single-use code.
//
// The callback calls Issue and hands the code to the browser; the browser
// posts it back, and the redemption endpoint calls Redeem. A code is
// <tokenID>.<secret>: 16 and 32 random bytes, each base64url-encoded without
// padding. The store holds the token id and SHA-256 of the secret, never the
// secret itself.
//
// Build one with NewHandoffManager. A HandoffManager is safe for concurrent use
// as far as the store and user loader it was given are.
type HandoffManager struct {
	store   HandoffStore
	users   identity.UserLoader
	random  io.Reader
	now     func() time.Time
	ids     id.Generator
	log     *slog.Logger
	sampler *logsample.Sampler
}

// NewHandoffManager returns a manager that keeps codes in store and resolves
// the user a code was issued for through users.
//
// Both are required, and neither is defaulted here: a nil store or loader,
// including a nil pointer inside a non-nil interface, is refused as a missing
// port (identity.MissingPort) wrapped in ErrConfig. A consumer with no shared
// store passes NewMemoryHandoffStore(), which holds codes for one process only:
//
//	handoffs, err := oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), users)
//
// With no options it draws codes from crypto/rand.Reader (WithHandoffRandom),
// reads time from time.Now (WithHandoffClock), names records with
// id.NewV7Generator() (WithHandoffIDGenerator) and logs to slog.Default()
// (WithHandoffLogger). Every error it returns wraps ErrConfig.
//
// A record of a redemption the store or users failed carries a fixed reason
// and the error's Go type, never the dependency's own text; a consumer who
// wants that detail logs it inside their own implementation of the store or
// the loader.
func NewHandoffManager(store HandoffStore, users identity.UserLoader, opts ...HandoffOption) (*HandoffManager, error) {
	if nilcheck.IsNil(store) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("handoff store"))
	}
	if nilcheck.IsNil(users) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("user loader"))
	}

	h := &HandoffManager{store: store, users: users}
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
	if h.now == nil {
		h.now = time.Now
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
// verified issuer, the provider session id, the raw ID token and the requested
// destination, all as res holds them. A result with no principal or no user
// reference, a cancelled context, and a failure of the random source, the ID
// generator or the store each return an error and no code; nothing is stored
// then, except that a store write whose failure was reported may still have
// landed, which leaves an unknown code that simply expires.
//
// The code is the caller's to hand to the browser and nowhere else: the
// library never logs it.
func (h *HandoffManager) Issue(ctx context.Context, res CallbackResult) (string, error) {
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

	now := h.now()
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
func (h *HandoffManager) reportSuppressed(reason string, suppressed int) {
	h.log.LogAttrs(context.Background(), slog.LevelInfo, "oidc handoff refusals suppressed",
		slog.String("reason", reason),
		slog.Int("suppressed", suppressed))
}

// RedeemCheck is a refusal check run against the resolved principal before a
// handoff code is spent. It has magiclink.Check's shape, so one policy check
// builder serves both.
//
// A check must have no side effects. Several racing redemptions of one code
// can each run every check, and only one goes on to consume it; and the login
// completion step evaluates the post-authentication policy again after a
// successful redemption. That includes any consumer policy the chain's
// shipped check evaluates. A check that wrote something would write it once
// per attempt rather than once per sign-in.
//
// The first check that returns an error stops the redemption, later checks do
// not run, the error is returned unchanged, and the code stays redeemable.
type RedeemCheck func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error

// HandoffResult is a redeemed handoff: the user it authenticates, loaded
// afresh by the recorded reference, and the provider session it came from.
//
// IDToken is kept for RP-initiated logout and must never be logged. Next is
// the destination recorded when the login started, still untrusted: the
// caller resolves it through its allowlist before redirecting to it.
type HandoffResult struct {
	Principal                            identity.Principal
	PasswordChangedAt                    time.Time
	Provider, Issuer, SessionID, IDToken string
	Next                                 string
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
func (h *HandoffManager) Redeem(ctx context.Context, code string, checks ...RedeemCheck) (HandoffResult, error) {
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
	now := h.now()
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
		if err := check(ctx, principal, details.PasswordChangedAt); err != nil {
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
func (h *HandoffManager) refuse(ctx context.Context, level slog.Level, reason string) error {
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
func (h *HandoffManager) refuseFailure(ctx context.Context, reason, op string, err error) error {
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
func (h *HandoffManager) record(ctx context.Context, level slog.Level, key string, attrs ...slog.Attr) error {
	write, suppressed := h.sampler.Allow("oidc.handoff."+key, h.now())
	if write {
		h.log.LogAttrs(ctx, level, "oidc handoff redemption refused",
			append(attrs, slog.Int("suppressed", suppressed))...)
	}
	return ErrInvalidHandoff
}
