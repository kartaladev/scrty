package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
)

// LoginFacts is what a consumer's login check is given about a verified
// assertion, before anything is written.
type LoginFacts struct {
	// User is the credential's user.
	User identity.UserID
	// Credential is the credential's library identifier.
	Credential id.ID
	// AAGUID identifies the authenticator model: 16 bytes, or nil.
	AAGUID []byte
	// BackupEligible and BackupState are the assertion's backup flags.
	BackupEligible bool
	BackupState    bool
	// UserVerified reports whether the authenticator verified the user.
	UserVerified bool
}

// LoginResult is an accepted passwordless login.
type LoginResult struct {
	// User is the credential's user. The caller loads it and refuses an
	// unknown or disabled one.
	User identity.UserID
	// Credential is the credential's library identifier.
	Credential id.ID
	// Proof holds when the assertion was user-verified and
	// WithoutSecondFactorAtLogin is not set: the login met its second factor.
	Proof policy.SecondFactorProof
}

// The passwordless login challenge: its one-time purpose, and the constant
// subject every login token is issued for, since begin runs before anyone is
// known.
const (
	loginPurpose = "passkey-login"
	loginSubject = "passkey-login"
)

// WithLoginCheck adds a consumer check that runs on every verified assertion,
// at a passwordless login and as a second factor, after verification and
// before anything is written. There is none by default. An error it returns
// refuses the login or verification and is returned unchanged, and the
// credential's counter, flags and last use are left as they were. A consumer
// can use it to refuse device-bound passkeys for some users only. A nil check
// is a configuration error.
func WithLoginCheck(fn func(ctx context.Context, f LoginFacts) error) Option {
	return func(m *Manager) {
		m.loginCheck = fn
		m.loginCheckSet = true
	}
}

// WithoutSecondFactorAtLogin stops a passwordless login from proving the
// second factor. By default a user-verified passkey login hands the login
// completion a proof that its second factor was met, so the MFA challenge is
// never raised for it. With this option no proof is minted, and a user the
// policies require to use MFA must then complete a second factor on another
// channel, as after any other non-exempt login.
func WithoutSecondFactorAtLogin() Option {
	return func(m *Manager) { m.noProofAtLogin = true }
}

// errLoginBinding refuses a passwordless begin without a ceremony binding: a
// token issued unbound could be answered from any browser.
var errLoginBinding = fmt.Errorf("%w: a passwordless login needs a ceremony binding", ErrConfig)

// BeginLogin starts a passwordless login and returns the request options for
// the browser, as the verifier renders them.
//
// It issues a one-time token of the purpose "passkey-login", for the subject
// "passkey-login" and bound to binding — the ceremony cookie's value, which
// the finish must present again — and its string is the challenge the options
// carry. The options list no credentials, so the client offers the user's
// discoverable passkeys; they ask for the configured user verification, and
// their timeout is the challenge lifetime. An empty binding is refused with
// an error wrapping ErrConfig, and nothing is issued.
//
// At most once per challenge lifetime, a begin also removes expired login
// challenges from the store. A failed removal is logged and does not refuse
// the begin.
func (m *Manager) BeginLogin(ctx context.Context, binding string) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if binding == "" {
		return nil, errLoginBinding
	}

	challenge, _, err := m.login.Issue(ctx, loginSubject, onetime.WithBinding(binding))
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not issue a login challenge")
	}

	m.purgeLogin(ctx)

	return m.verifier.RequestOptions(ctx, RequestInput{Challenge: challenge, Timeout: m.ttl, UV: m.uv})
}

// purgeLogin removes expired login challenges when no begin of this manager
// has in the last challenge lifetime. A failure is logged by a fixed reason.
func (m *Manager) purgeLogin(ctx context.Context) {
	now := m.clock.Now()

	m.purgeMu.Lock()
	due := m.lastPurge.IsZero() || now.Sub(m.lastPurge) >= m.ttl || now.Before(m.lastPurge)
	if due {
		m.lastPurge = now
	}
	m.purgeMu.Unlock()

	if !due {
		return
	}

	if _, err := m.login.PurgeExpired(ctx); err != nil {
		m.sampled(ctx, slog.LevelError, "purge", msgPurgeFailed, diag.Failure("purge", err)...)
	}
}

// Authenticate finishes a passwordless login, in this order:
//
//  1. Read the assertion. One the verifier cannot read is
//     ErrMalformedResponse, and nothing is spent.
//  2. Spend the challenge it answers: it must be a passwordless login
//     challenge this manager issued, bound to binding, unexpired and unspent.
//     It is spent before anything else is looked at, whatever happens next.
//     A challenge of any other purpose, a registration's included, is refused
//     before any credential is looked up.
//  3. Find the credential by its ID.
//  4. Require the response's user handle to be the one mapped to the
//     credential's user.
//  5. Verify the assertion against the stored public key and the challenge,
//     with the configured user verification, and refuse one whose
//     backup-eligible flag differs from the stored one.
//  6. Only then refuse a pending credential with ErrPending and a suspended
//     one with ErrSuspended, so the state is shown only to a holder of the
//     key. Nothing is written for either.
//  7. Run the consumer's login check; its error is returned unchanged.
//  8. Record the counter, the backup state and the time of last use, under
//     the clone rule.
//
// An unknown credential, a handle mismatch, a bad signature, a missing or
// wrong binding and every other refusal of the ceremony are the one error
// authenticate.ErrAuthenticationFailed, so a client without the private key
// learns nothing about which credentials exist.
//
// The result's proof holds when the assertion was user-verified and
// WithoutSecondFactorAtLogin is not set. Loading the user, and refusing an
// unknown or disabled one, is the caller's.
func (m *Manager) Authenticate(ctx context.Context, body []byte, binding string) (*LoginResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	parsed, err := m.verifier.ParseAssertion(body)
	if err != nil || nilcheck.IsNil(parsed) {
		_ = m.refused(ctx, "malformed", id.Nil)

		if err == nil {
			return nil, ErrMalformedResponse
		}

		return nil, diag.Wrap(err, "passkey: unreadable assertion response", ErrMalformedResponse)
	}

	challenge, err := m.spendLogin(ctx, parsed.Challenge(), binding)
	if err != nil {
		return nil, err
	}

	c, err := m.credentials.FindByCredentialID(ctx, parsed.CredentialID())

	switch {
	case errors.Is(err, ErrNotFound):
		return nil, m.refused(ctx, "unknown-credential", id.Nil)
	case err != nil:
		return nil, diag.Wrap(err, "passkey: could not look up the credential")
	case c == nil:
		return nil, m.refused(ctx, "unknown-credential", id.Nil)
	}

	if err := m.matchHandle(ctx, c, parsed.UserHandle()); err != nil {
		return nil, err
	}

	res, err := m.checkAssertion(ctx, parsed, c, AssertionExpectation{Challenge: challenge, UV: m.uv})
	if err != nil {
		return nil, err
	}

	// The state is revealed only to a holder of the key: an assertion its
	// key did not make is refused as for an unknown credential.
	switch c.State {
	case StateActive:
	case StatePending:
		_ = m.refused(ctx, "pending", c.ID)
		return nil, ErrPending
	case StateSuspended:
		_ = m.refused(ctx, "suspended", c.ID)
		return nil, ErrSuspended
	default:
		return nil, m.refused(ctx, "state", c.ID)
	}

	if err := m.acceptAssertion(ctx, c, res); err != nil {
		return nil, err
	}

	out := &LoginResult{User: c.User, Credential: c.ID}
	if res.UserVerified && !m.noProofAtLogin {
		out.Proof = assurance.New(factor.Passkey, m.clock.Now())
	}

	return out, nil
}

// spendLogin checks and spends the passwordless challenge presented, as
// clientDataJSON carries it, against binding, and returns its token string.
// Every refusal is authenticate.ErrAuthenticationFailed.
func (m *Manager) spendLogin(ctx context.Context, presented, binding string) (string, error) {
	if binding == "" {
		return "", m.refused(ctx, "binding", id.Nil)
	}

	challenge, err := DecodeChallenge(presented)
	if err != nil {
		return "", m.refused(ctx, "challenge", id.Nil)
	}

	checked, err := m.login.Check(ctx, challenge, binding)
	if err != nil {
		return "", m.refused(ctx, "challenge", id.Nil)
	}

	if err := m.login.Consume(ctx, checked); err != nil {
		return "", m.refused(ctx, "challenge", id.Nil)
	}

	if checked.Token().Subject != loginSubject {
		return "", m.refused(ctx, "challenge", id.Nil)
	}

	return challenge, nil
}

// matchHandle requires handle to be the one mapped to c's user. A missing,
// unknown or other user's handle is authenticate.ErrAuthenticationFailed.
func (m *Manager) matchHandle(ctx context.Context, c *Credential, handle []byte) error {
	if len(handle) == 0 {
		return m.refused(ctx, "handle", c.ID)
	}

	user, ok, err := m.handles.UserFor(ctx, handle)
	if err != nil {
		return diag.Wrap(err, "passkey: could not look up the user handle")
	}

	if !ok || user != c.User {
		return m.refused(ctx, "handle", c.ID)
	}

	return nil
}

// verifyAssertion verifies p against c and exp, then runs the consumer's
// login check and records the use. It is the second factor's path; c must
// already be known to be active and the caller's. The passwordless login
// runs its two halves, checkAssertion and acceptAssertion, with the state
// refusal between them.
//
// A verifier error that is not a context error, a missing user verification under UVRequired and a
// backup-eligible flag that differs from the stored one are
// authenticate.ErrAuthenticationFailed. The login check's error is returned
// unchanged. A verifier error matching context.Canceled or
// context.DeadlineExceeded is returned wrapped, still matchable with
// errors.Is, and is not a refusal. Nothing is written on any refusal.
func (m *Manager) verifyAssertion(
	ctx context.Context, p ParsedAssertion, c *Credential, exp AssertionExpectation,
) (*AssertionResult, error) {
	res, err := m.checkAssertion(ctx, p, c, exp)
	if err != nil {
		return nil, err
	}

	if err := m.acceptAssertion(ctx, c, res); err != nil {
		return nil, err
	}

	return res, nil
}

// checkAssertion verifies p against c and exp, with the user verification and
// backup-eligibility rules, and writes nothing. Its refusals are those of
// verifyAssertion.
func (m *Manager) checkAssertion(
	ctx context.Context, p ParsedAssertion, c *Credential, exp AssertionExpectation,
) (*AssertionResult, error) {
	res, err := m.verifier.VerifyAssertion(ctx, p, c, exp)

	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// An interrupted check says nothing about the assertion.
		return nil, diag.Wrap(err, "passkey: verification interrupted")
	case err != nil:
		_ = m.refused(ctx, "verify", c.ID, diag.Failure("verify", err)...)
		return nil, authenticate.ErrAuthenticationFailed
	case res == nil:
		return nil, m.refused(ctx, "verify", c.ID)
	case exp.UV == UVRequired && !res.UserVerified:
		return nil, m.refused(ctx, "user-verification", c.ID)
	case res.BackupEligible != c.BackupEligible:
		return nil, m.refused(ctx, "backup-eligibility", c.ID)
	}

	return res, nil
}

// acceptAssertion runs the consumer's login check on a verified res, then
// records the use. The login check's error is returned unchanged.
func (m *Manager) acceptAssertion(ctx context.Context, c *Credential, res *AssertionResult) error {
	if m.loginCheck != nil {
		if err := m.loginCheck(ctx, LoginFacts{
			User:           c.User,
			Credential:     c.ID,
			AAGUID:         c.AAGUID,
			BackupEligible: res.BackupEligible,
			BackupState:    res.BackupState,
			UserVerified:   res.UserVerified,
		}); err != nil {
			return err
		}
	}

	return m.recordUse(ctx, c, res)
}

// recordUse records res's counter, backup state and the time on c. A write
// the store refuses is handled by the clone rule (see CloneResponse).
func (m *Manager) recordUse(ctx context.Context, c *Credential, res *AssertionResult) error {
	recorded, err := m.credentials.RecordAssertion(ctx, c.ID, res.SignCount, res.BackupState, m.clock.Now())
	if err != nil {
		return diag.Wrap(err, "passkey: could not record the assertion")
	}

	if !recorded {
		return m.onCounterRefused(ctx, c, res)
	}

	return nil
}
