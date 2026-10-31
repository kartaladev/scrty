package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// errRecoveryCheck is what the consumer's refusal check refuses with.
var errRecoveryCheck = errors.New("recovery test: the consumer refused")

// recoveryDocument is the default success body, as a client reads it.
type recoveryDocument struct {
	AccessToken   string    `json:"access_token"`
	ExpiresAt     time.Time `json:"expires_at"`
	RecoveryCodes []string  `json:"recovery_codes"`
	Remaining     int       `json:"remaining"`
	Low           bool      `json:"low"`
}

// recoveryStored reloads the session a completed recovery's credential names.
func recoveryStored(t *testing.T, h *recoveryHarness, credential string) *session.Session {
	t.Helper()

	handle, ok := strings.CutPrefix(credential, mfaTokenPrefix)
	require.True(t, ok, "the credential is not one the harness's generator issued")

	s, err := h.sessions.Load(t.Context(), handle)
	require.NoError(t, err)

	return s
}

// recovered asserts out is a completed recovery answered by the default
// responder, and returns its document.
func recovered(t *testing.T, h *recoveryHarness, out served) recoveryDocument {
	t.Helper()

	require.NoError(t, out.err)
	require.False(t, out.handlerRan, "the complete endpoint passed the request on")
	require.Equal(t, http.StatusOK, out.rec.Code)
	assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

	var doc recoveryDocument
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.AccessToken)

	s := recoveryStored(t, h, doc.AccessToken)
	assert.Equal(t, session.MFARecoveryPending, s.MFA)
	assert.Equal(t, factor.Recovery, s.FirstFactor)
	assert.Equal(t, e2eUser, s.UserID)
	assert.True(t, doc.ExpiresAt.Equal(s.IdleExpiresAt))

	return doc
}

// recoveryForm is a complete request's form.
func recoveryForm(pairs ...string) url.Values {
	v := url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}
	for i := 0; i+1 < len(pairs); i += 2 {
		v.Add(pairs[i], pairs[i+1])
	}

	return v
}

// countingLimiter is a consumer limiter that admits every source and expects
// exactly records failures to be recorded.
func countingLimiter(t *testing.T, records int) *MockLimiter {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).Times(records)

	return l
}

// TestRecoveryComplete_HTTP pins, through HTTP, spec account-recovery "A
// recovery needs two proofs of different kinds", "Every proof is checked
// before any is spent" and "A recovery produces a confined session, never a
// full one", and spec http-security-chain "Recovery endpoints plug into the
// chain", for the complete endpoint.
func TestRecoveryComplete_HTTP(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// arrange changes the harness before the chain is built.
		arrange func(t *testing.T, h *recoveryHarness)

		// act runs the requests against the built chain.
		act func(t *testing.T, h *recoveryHarness) served

		assert func(t *testing.T, h *recoveryHarness, out served)
	}

	cases := []testCase{
		{
			name: "a saved code and an issued code",
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				doc := recovered(t, h, out)
				assert.Len(t, doc.RecoveryCodes, 10, "a spent saved code reissues the set")
			},
		},
		{
			name: "a saved code and the password",
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
			},
		},
		{
			name: "an issued code and a TOTP code",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.enrolTOTP(t)
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoveryIssuedCodeParam, h.issued(t),
					httpsec.RecoveryMFAMethodParam, "totp",
					httpsec.RecoveryMFACodeParam, h.totpCode(t)))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				doc := recovered(t, h, out)
				assert.Nil(t, doc.RecoveryCodes, "no saved code was spent, so none is reissued")
				assert.Equal(t, 0, doc.Remaining)
				assert.True(t, doc.Low)
				assert.Contains(t, out.rec.Body.String(), `"recovery_codes":null`)
			},
		},
		{
			name: "an emailed code alone is malformed",
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrMalformed)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "the password and a TOTP code, with no recovery code, is malformed",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.enrolTOTP(t)
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoveryPasswordParam, e2ePassword,
					httpsec.RecoveryMFAMethodParam, "totp",
					httpsec.RecoveryMFACodeParam, h.totpCode(t)))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrMalformed)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "a locked account is refused as a wrong password, after one decoy and no password check",
			arrange: func(t *testing.T, h *recoveryHarness) {
				lockRecovery(t, h)
				h.authn = lockDecoyAuthenticator(t, 1)
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrRefused, "as an unknown user or a wrong code is")
				require.ErrorIs(t, out.err, lockout.ErrAccountLocked,
					"the consumer's own handler can still tell it is a lock")
				assert.Equal(t, recovery.ErrRefused.Error(), out.err.Error())
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "a locked account, with locks disclosed, is refused with the lock alone and no decoy",
			arrange: func(t *testing.T, h *recoveryHarness) {
				lockRecovery(t, h)
				h.chainOpts = append(h.chainOpts, httpsec.WithLockDisclosure())
				h.authn = lockDecoyAuthenticator(t, 0)
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, lockout.ErrAccountLocked)
				assert.NotErrorIs(t, out.err, recovery.ErrRefused)
				assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "a wrong password is recorded as a failed attempt, as login records it",
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, "not the password"))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrRefused)

				n, err := h.attempts.FailureCount(t.Context(), e2eAddress, time.Now().Add(-time.Hour))
				require.NoError(t, err)
				assert.Equal(t, 1, n)
			},
		},
		{
			name: "an unavailable user store during the password proof is answered 401 and charged to its source only",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.authn = unavailableAuthenticator(t)
				h.recOpts = []httpsec.RecoveryOption{
					httpsec.WithRecoveryLimiter(countingLimiter(t, 1)),
					httpsec.WithRecoveryUserLimiter(countingLimiter(t, 0)),
				}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, authenticate.ErrUnavailable)
				assert.NotErrorIs(t, out.err, recovery.ErrRefused, "an outage read as a refused proof")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err),
					"the outage was not answered as a refused proof is")

				n, err := h.attempts.FailureCount(t.Context(), e2eAddress, time.Now().Add(-time.Hour))
				require.NoError(t, err)
				assert.Zero(t, n, "the outage was recorded as a failed attempt against the account")

				left, err := h.codes.Remaining(t.Context(), e2eUser)
				require.NoError(t, err)
				assert.Equal(t, 10, left.N, "the saved code is not spent")
			},
		},
		{
			name: "a caller that hangs up during the password proof is refused and charged to its source only",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.authn = hangUpAuthenticator(t)
				h.recOpts = []httpsec.RecoveryOption{
					httpsec.WithRecoveryLimiter(countingLimiter(t, 1)),
					httpsec.WithRecoveryUserLimiter(countingLimiter(t, 0)),
				}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				hungUp, cancel := context.WithCancel(t.Context())
				cancel()

				return serveIn(hungUp, t, h.chain, postValues(hungUp, httpsec.DefaultRecoveryCompletePath, e2eSource,
					recoveryForm(
						httpsec.RecoverySavedCodeParam, h.saved(t),
						httpsec.RecoveryPasswordParam, e2ePassword)))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrRefused,
					"a hang-up during the proof was read as an outage")
				assert.ErrorIs(t, out.err, context.Canceled,
					"the refusal does not say the caller's context ended the proof's load")
				assert.NotErrorIs(t, out.err, authenticate.ErrUnavailable)
				assert.True(t, recovery.RefusedAfterValidCode(out.err),
					"the hang-up was not marked as a refusal after a valid code")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))

				n, err := h.attempts.FailureCount(t.Context(), e2eAddress, time.Now().Add(-time.Hour))
				require.NoError(t, err)
				assert.Zero(t, n,
					"the hang-up was recorded as a failed attempt, though no password was compared")
			},
		},
		{
			name: "an unknown username and a wrong saved code look alike",
			act: func(t *testing.T, h *recoveryHarness) served {
				h.saved(t)
				issued := h.issued(t)

				unknown := h.through(postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource,
					url.Values{
						httpsec.RecoveryUsernameParam:   {"nobody@example.com"},
						httpsec.RecoverySavedCodeParam:  {"0000-0000-0000-0000-0000-0000-00"},
						httpsec.RecoveryIssuedCodeParam: {issued},
					}))
				wrong := h.through(postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource,
					recoveryForm(
						httpsec.RecoverySavedCodeParam, "0000-0000-0000-0000-0000-0000-00",
						httpsec.RecoveryIssuedCodeParam, issued)))

				assert.Equal(t, http.StatusUnauthorized, unknown.Code)
				assert.Equal(t, unknown.Code, wrong.Code)
				assert.Empty(t, unknown.Body.Bytes())
				assert.Empty(t, wrong.Body.Bytes())

				return served{rec: wrong}
			},
			assert: func(*testing.T, *recoveryHarness, served) {},
		},
		{
			name: "neither an unknown username nor a wrong saved code reaches the password authenticator",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.authn = &countingAuthenticator{Authenticator: h.authn}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				h.saved(t)
				calls := h.authn.(*countingAuthenticator)

				unknown := h.complete(t, url.Values{
					httpsec.RecoveryUsernameParam:  {"nobody@example.com"},
					httpsec.RecoverySavedCodeParam: {"0000-0000-0000-0000-0000-0000-00"},
					httpsec.RecoveryPasswordParam:  {e2ePassword},
				})
				require.ErrorIs(t, unknown.err, recovery.ErrRefused)
				assert.Zero(t, calls.calls.Load(), "the unknown username paid for a password hash")

				wrong := h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, "0000-0000-0000-0000-0000-0000-00",
					httpsec.RecoveryPasswordParam, e2ePassword))
				require.ErrorIs(t, wrong.err, recovery.ErrRefused)
				assert.Zero(t, calls.calls.Load(), "the known user's wrong code paid for a password hash")

				return wrong
			},
			assert: func(*testing.T, *recoveryHarness, served) {},
		},
		{
			name: "a user store that fails after the recovery still answers with the new codes",
			arrange: func(t *testing.T, h *recoveryHarness) {
				details := &identity.Details{ID: e2eUser, Name: "Grace Hopper", Username: e2eAddress, Active: true}

				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUsername(gomock.Any(), e2eAddress).Return(details, nil).AnyTimes()
				users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).Return(nil, errRecoveryLookup).AnyTimes()
				h.users = users
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				doc := recovered(t, h, out)
				require.Len(t, doc.RecoveryCodes, 10, "the new codes reach the caller")

				left, err := h.codes.Remaining(t.Context(), e2eUser)
				require.NoError(t, err)
				assert.Equal(t, 10, left.N)
			},
		},
		{
			name: "remaining and low count the reissued set by the manager's threshold",
			arrange: func(t *testing.T, h *recoveryHarness) {
				var err error
				h.codes, err = recovery.NewCodes(recovery.WithCodesSetSize(2))
				require.NoError(t, err)
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				doc := recovered(t, h, out)
				assert.Len(t, doc.RecoveryCodes, 2)
				assert.Equal(t, 2, doc.Remaining)
				assert.True(t, doc.Low, "two codes, at the default threshold of two, is low")
			},
		},
		{
			name: "a consumer responder that sets no header still answers with no-store",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryResponder(
					func(ex *httpsec.Exchange, _ httpsec.RecoveryResult) error {
						ex.Writer.WriteHeader(http.StatusOK)

						return nil
					})}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name: "a consumer responder may override the no-store header",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryResponder(
					func(ex *httpsec.Exchange, _ httpsec.RecoveryResult) error {
						ex.Writer.SetHeader("Cache-Control", "private, no-store, max-age=0")
						ex.Writer.WriteHeader(http.StatusOK)

						return nil
					})}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, "private, no-store, max-age=0", out.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name: "a consumer hold responder that sets no header still answers with no-store",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.coreOpts = append(h.coreOpts,
					recovery.WithHoldDelay(time.Hour), recovery.WithCancelLink("https://app.example.com/cancel"))
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryHoldResponder(
					func(ex *httpsec.Exchange, _ recovery.Hold) error {
						ex.Writer.WriteHeader(http.StatusAccepted)

						return nil
					})}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name: "a wrong password keeps the codes: the same saved code then succeeds",
			act: func(t *testing.T, h *recoveryHarness) served {
				saved := h.saved(t)

				wrong := h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, saved,
					httpsec.RecoveryPasswordParam, "not the password"))
				require.ErrorIs(t, wrong.err, recovery.ErrRefused)

				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, saved,
					httpsec.RecoveryPasswordParam, e2ePassword))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
			},
		},
		{
			name: "a consumer refusal keeps the codes: the same codes then succeed",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				var allow atomic.Bool
				h.allow = &allow
				h.coreOpts = append(h.coreOpts, recovery.WithChecks(
					func(context.Context, identity.UserID, []recovery.ProofKind) error {
						if allow.Load() {
							return nil
						}

						return errRecoveryCheck
					}))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				values := recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t))

				refused := h.complete(t, values)
				require.ErrorIs(t, refused.err, errRecoveryCheck)

				h.allow.Store(true)

				return h.complete(t, values)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
			},
		},
		{
			name: "of racing recoveries with the same codes, exactly one succeeds",
			act: func(t *testing.T, h *recoveryHarness) served {
				const racers = 16

				values := recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t))

				var (
					wg       sync.WaitGroup
					barrier  = make(chan struct{})
					outcomes = make([]served, racers)
				)

				for n := range racers {
					wg.Go(func() {
						<-barrier
						outcomes[n] = h.complete(t, values)
					})
				}

				close(barrier)
				wg.Wait()

				var won []served
				for _, out := range outcomes {
					if out.err == nil && out.rec.Code == http.StatusOK {
						won = append(won, out)
						continue
					}

					assert.Error(t, out.err, "a racer neither won nor was refused")
				}

				require.Len(t, won, 1, "exactly one racing recovery succeeds")

				return won[0]
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
			},
		},
		{
			name: "the recovery session is refused once its 15 minutes are over",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.chainOpts = append(h.chainOpts, httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: h.tokens, Sessions: h.sessions, Users: h.users,
				}))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				doc := recovered(t, h, h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t))))

				protected := func() served {
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil)
					req.Header.Set("Authorization", "Bearer "+doc.AccessToken)

					return serve(t, h.chain, req)
				}

				h.clock.Advance(14 * time.Minute)

				confined := protected()
				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, confined.err, &challenge, "a live recovery session is confined, not refused")
				assert.Equal(t, policy.ChallengeAccountRecovery, challenge.Kind)

				h.clock.Advance(2 * time.Minute)

				return protected()
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired, "the expired session is gone")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
			},
		},
		{
			name: "an issued code is sent to the user's address",
			act: func(t *testing.T, h *recoveryHarness) served {
				h.issued(t)

				return served{rec: httptest.NewRecorder()}
			},
			assert: func(t *testing.T, h *recoveryHarness, _ served) {
				assert.Equal(t, e2eAddress, h.sender.last(t).To)
			},
		},
		{
			name: "a consumer contact resolver chooses where the issued code goes",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.coreOpts = append(h.coreOpts, recovery.WithContactResolver(
					func(context.Context, *identity.Details) (string, error) { return "grace.home@example.com", nil }))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				h.issued(t)

				return served{rec: httptest.NewRecorder()}
			},
			assert: func(t *testing.T, h *recoveryHarness, _ served) {
				assert.Equal(t, "grace.home@example.com", h.sender.last(t).To)
			},
		},
		{
			name: "an issued code is refused 16 minutes after it was sent",
			act: func(t *testing.T, h *recoveryHarness) served {
				saved, issued := h.saved(t), h.issued(t)

				h.clock.Advance(16 * time.Minute)

				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, saved,
					httpsec.RecoveryIssuedCodeParam, issued))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrRefused)

				left, err := h.codes.Remaining(t.Context(), e2eUser)
				require.NoError(t, err)
				assert.Equal(t, 10, left.N, "the saved code is not spent")
			},
		},
		{
			name: "a password check passed through the core is replaced by the chain's own",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				var calls atomic.Int32
				h.coreCheckCalls = &calls
				h.coreOpts = append(h.coreOpts, recovery.WithPasswordCheck(
					func(context.Context, string, []byte) error {
						calls.Add(1)

						return nil
					}))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				saved := h.saved(t)

				wrong := h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, saved,
					httpsec.RecoveryPasswordParam, "not the password"))
				require.ErrorIs(t, wrong.err, recovery.ErrRefused, "the consumer's accept-all check was used")

				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, saved,
					httpsec.RecoveryPasswordParam, e2ePassword))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
				assert.Zero(t, h.coreCheckCalls.Load(), "the core-supplied password check was called")
			},
		},
		{
			name: "the body is read and a conflicting query field ignored",
			act: func(t *testing.T, h *recoveryHarness) served {
				body := recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t))
				query := url.Values{httpsec.RecoveryUsernameParam: {"nobody@example.com"}}

				return serve(t, h.chain, postValues(t.Context(),
					httpsec.DefaultRecoveryCompletePath+"?"+query.Encode(), e2eSource, body))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
			},
		},
		{
			name: "a body of exactly 16 KiB is read",
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, paddedTo(t, 16<<10, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t))))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
			},
		},
		{
			name: "a body of 16 KiB and one byte is too large",
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, paddedTo(t, 16<<10+1, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t))))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, http.StatusRequestEntityTooLarge, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "a form content type in odd case and with parameters is read",
			act: func(t *testing.T, h *recoveryHarness) served {
				body := recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t))

				req := postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource, body)
				req.Header.Set("Content-Type", "Application/X-WWW-Form-URLEncoded; charset=UTF-8")

				return serve(t, h.chain, req)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
			},
		},
		{
			name: "the consumer's complete path",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryCompletePath("/account/recover")}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				values := recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t))

				moved := serve(t, h.chain,
					postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource, values))
				require.NoError(t, moved.err)
				require.True(t, moved.handlerRan, "the default path is still answered")

				return serve(t, h.chain, postValues(t.Context(), "/account/recover", e2eSource, values))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
			},
		},
		{
			name: "an unattributable source is refused and the recovery never runs",
			arrange: func(t *testing.T, h *recoveryHarness) {
				// A strict double: a recovery that ran would resolve the user.
				h.users = NewMockUserLoader(gomock.NewController(t))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, "0.0.0.0",
					recoveryForm(
						httpsec.RecoverySavedCodeParam, "0000-0000-0000-0000-0000-0000-00",
						httpsec.RecoveryPasswordParam, e2ePassword)))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
			},
		},
		{
			name: "a refusal after a valid code counts against the source",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.coreOpts = append(h.coreOpts, recovery.WithChecks(
					func(context.Context, identity.UserID, []recovery.ProofKind) error { return errRecoveryCheck }))
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryLimiter(countingLimiter(t, 1))}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, errRecoveryCheck)
			},
		},
		{
			name: "with refusal counting off, a refusal after a valid code does not count",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.coreOpts = append(h.coreOpts, recovery.WithChecks(
					func(context.Context, identity.UserID, []recovery.ProofKind) error { return errRecoveryCheck }))
				h.recOpts = []httpsec.RecoveryOption{
					httpsec.WithRecoveryLimiter(countingLimiter(t, 0)),
					httpsec.WithRecoveryCountRefusals(false),
				}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, errRecoveryCheck)
			},
		},
		{
			name: "with refusal counting off, a wrong code still counts",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{
					httpsec.WithRecoveryLimiter(countingLimiter(t, 1)),
					httpsec.WithRecoveryCountRefusals(false),
				}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				h.saved(t)

				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, "0000-0000-0000-0000-0000-0000-00",
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrRefused)
			},
		},
		{
			name: "a saved code given twice is malformed, and nothing is checked or spent",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryLimiter(countingLimiter(t, 0))}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				set, err := h.codes.Generate(t.Context(), e2eUser)
				require.NoError(t, err)

				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, set[0],
					httpsec.RecoverySavedCodeParam, set[1],
					httpsec.RecoveryPasswordParam, e2ePassword))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrMalformed)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))

				left, err := h.codes.Remaining(t.Context(), e2eUser)
				require.NoError(t, err)
				assert.Equal(t, 10, left.N)
			},
		},
		{
			name: "the query is never read",
			act: func(t *testing.T, h *recoveryHarness) served {
				q := recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t))

				return serve(t, h.chain, postValues(t.Context(),
					httpsec.DefaultRecoveryCompletePath+"?"+q.Encode(), e2eSource, url.Values{}))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrMalformed)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "a body over 16 KiB is too large",
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, strings.Repeat("A", 16<<10),
					httpsec.RecoveryPasswordParam, e2ePassword))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, http.StatusRequestEntityTooLarge, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "the default document carries exactly its five members",
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
				assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))

				var members map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &members))

				keys := make([]string, 0, len(members))
				for k := range members {
					keys = append(keys, k)
				}
				assert.ElementsMatch(t,
					[]string{"access_token", "expires_at", "recovery_codes", "remaining", "low"}, keys)
			},
		},
		{
			name: "a consumer responder replaces the default",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryResponder(
					func(ex *httpsec.Exchange, res httpsec.RecoveryResult) error {
						if res.Token == "" || res.Recovery == nil || res.Recovery.Session == nil ||
							len(res.Recovery.Codes) != 10 {
							return errors.New("recovery test: the responder was handed an incomplete result")
						}

						ex.Writer.WriteHeader(http.StatusCreated)

						return nil
					})}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusCreated, out.rec.Code)
				assert.Empty(t, out.rec.Body.Bytes())
			},
		},
		{
			name: "a held recovery is answered by the default hold responder",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.coreOpts = append(h.coreOpts,
					recovery.WithHoldDelay(time.Hour), recovery.WithCancelLink("https://app.example.com/cancel"))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusAccepted, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

				var doc struct {
					CompletionToken string    `json:"completion_token"`
					CompletableAt   time.Time `json:"completable_at"`
				}
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				assert.NotEmpty(t, doc.CompletionToken)
				assert.True(t, doc.CompletableAt.Equal(h.clock.Now().Add(time.Hour)),
					"completable at %s, want %s", doc.CompletableAt, h.clock.Now().Add(time.Hour))
				assert.NotContains(t, out.rec.Body.String(), "access_token")
			},
		},
		{
			name: "a consumer hold responder replaces the default",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.coreOpts = append(h.coreOpts,
					recovery.WithHoldDelay(time.Hour), recovery.WithCancelLink("https://app.example.com/cancel"))
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryHoldResponder(
					func(ex *httpsec.Exchange, hold recovery.Hold) error {
						if hold.CompletionToken == "" {
							return errors.New("recovery test: the hold carries no token")
						}

						ex.Writer.WriteHeader(http.StatusSeeOther)

						return nil
					})}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusSeeOther, out.rec.Code)
			},
		},
		{
			name: "the chain's flush reaches the recovery samplers",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.chainOpts = append(h.chainOpts, httpsec.WithLogger(slog.New(&capturingHandler{})))
				h.recOpts = []httpsec.RecoveryOption{
					httpsec.WithRecoveryLimiter(exceededLimiter(t)),
					httpsec.WithRecoveryStartLimiter(exceededLimiter(t)),
					httpsec.WithRecoveryLogInterval(time.Hour),
				}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				for range 3 {
					out := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCompletePath,
						flushSource, recoveryForm(httpsec.RecoverySavedCodeParam, "x")))
					require.Error(t, out.err)

					started := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryStartPath,
						flushSource, recoveryForm()))
					require.NoError(t, started.err)

					unattributed := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCompletePath,
						"0.0.0.0", recoveryForm(httpsec.RecoverySavedCodeParam, "x")))
					require.Error(t, unattributed.err)
				}

				return served{rec: httptest.NewRecorder()}
			},
			assert: func(t *testing.T, h *recoveryHarness, _ served) {
				logs := recoveryLogs(t, h)
				before := len(logs.records())

				h.chain.FlushRefusalLogs()

				flushed := logs.records()[before:]
				assert.Equal(t, []int64{2}, guardSummaries(t, flushed, "account-recovery"))
				assert.Equal(t, []int64{2}, guardSummaries(t, flushed, "account-recovery-start"))
				assert.NotEmpty(t, summaries(t, flushed, "httpsec: recovery logs suppressed", "", ""),
					"the recovery endpoints' own sampler was not flushed")
			},
		},
		{
			name: "the recovery guards follow the recovery interval, not the chain's refusal interval",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.chainOpts = append(h.chainOpts,
					httpsec.WithLogger(slog.New(&capturingHandler{})),
					httpsec.WithRefusalLogInterval(0))
				h.recOpts = []httpsec.RecoveryOption{
					httpsec.WithRecoveryLimiter(exceededLimiter(t)),
					httpsec.WithRecoveryStartLimiter(exceededLimiter(t)),
					httpsec.WithRecoveryLogInterval(time.Hour),
				}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				for range 3 {
					out := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCompletePath,
						flushSource, recoveryForm(httpsec.RecoverySavedCodeParam, "x")))
					require.Error(t, out.err)

					started := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryStartPath,
						flushSource, recoveryForm()))
					require.NoError(t, started.err)
				}

				return served{rec: httptest.NewRecorder()}
			},
			assert: func(t *testing.T, h *recoveryHarness, _ served) {
				// A chain interval of zero would write all three records of each
				// guard; the recovery window of an hour writes one and holds two.
				written := throttledRecords(recoveryLogs(t, h).records())
				assert.Len(t, written, 2, "one record per recovery guard: the window is the recovery interval")

				h.chain.FlushRefusalLogs()

				flushed := recoveryLogs(t, h).records()
				assert.Equal(t, []int64{2}, guardSummaries(t, flushed, "account-recovery"))
				assert.Equal(t, []int64{2}, guardSummaries(t, flushed, "account-recovery-start"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)
			if tc.arrange != nil {
				tc.arrange(t, h)
			}

			h.build(t)

			tc.assert(t, h, tc.act(t, h))
		})
	}
}

// lockRecovery locks the recovering user: a lockout of one failure, with that
// failure already recorded.
func lockRecovery(t *testing.T, h *recoveryHarness) {
	t.Helper()

	lockoutPolicy, err := lockout.New(
		lockout.WithAttemptStore(h.attempts), lockout.WithSliding(1, time.Hour))
	require.NoError(t, err)

	h.chainOpts = append(h.chainOpts, httpsec.WithPolicyEngine(engineOf(t, lockoutPolicy)))
	require.NoError(t, h.attempts.RecordFailure(t.Context(), e2eAddress, time.Now()))
}

// lockDecoyAuthenticator is a manager over the password provider whose user
// loader and encoder are strict doubles: loading the user, which checking the
// account's own password would need, fails the row, and the presented password
// must be matched against the reference hash exactly decoys times.
func lockDecoyAuthenticator(t *testing.T, decoys int) authenticate.Authenticator {
	t.Helper()

	ctrl := gomock.NewController(t)
	enc := NewMockEncoder(ctrl)
	enc.EXPECT().Encode(gomock.Any()).Return(lockReferenceHash, nil).Times(1)
	enc.EXPECT().Match(e2ePassword, lockReferenceHash).Return(false).Times(decoys)

	provider, err := authenticate.NewUsernamePasswordAuthenticator(NewMockUserLoader(ctrl),
		authenticate.WithPasswordEncoder(enc),
		authenticate.WithPasswordLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	m, err := authenticate.NewFirstOf(provider)
	require.NoError(t, err)

	return m
}

// unavailableAuthenticator is form login's password provider over a user store
// that cannot answer: every load fails with a connection error, so every
// password check returns authenticate.ErrUnavailable.
func unavailableAuthenticator(t *testing.T) authenticate.Authenticator {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
		Return(nil, errors.New("dial tcp 10.0.0.5:5432: connection refused")).AnyTimes()

	provider, err := authenticate.NewUsernamePasswordAuthenticator(users,
		authenticate.WithPasswordLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	return provider
}

// hangUpAuthenticator is form login's password provider over a user store that
// fails with the caller's own context error, as a driver does once the client
// has hung up: the load is ended by the caller, not by the store.
func hangUpAuthenticator(t *testing.T) authenticate.Authenticator {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ string) (*identity.Details, error) {
			return nil, fmt.Errorf("load user: %w", ctx.Err())
		}).AnyTimes()

	provider, err := authenticate.NewUsernamePasswordAuthenticator(users,
		authenticate.WithPasswordLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	return provider
}

// recoveryLogs is the capturing handler the row's WithLogger installed.
func recoveryLogs(t *testing.T, h *recoveryHarness) *capturingHandler {
	t.Helper()

	logger := httpsec.Settings(h.chain).Logger
	require.NotNil(t, logger)

	logs, ok := logger.Handler().(*capturingHandler)
	require.True(t, ok, "the row did not install a capturing logger")

	return logs
}

// countingAuthenticator counts the credentials its authenticator is asked to
// judge, so a case can show a password was never hashed.
type countingAuthenticator struct {
	authenticate.Authenticator

	calls atomic.Int32
}

func (a *countingAuthenticator) Authenticate(ctx context.Context, c identity.Credentials) (*authenticate.Authentication, error) {
	a.calls.Add(1)

	return a.Authenticator.Authenticate(ctx, c)
}

// paddedTo adds a padding field to values so the encoded body is exactly size
// bytes long.
func paddedTo(t *testing.T, size int, values url.Values) url.Values {
	t.Helper()

	const field = "pad"

	base := len(values.Encode()) + len("&"+field+"=")
	require.Less(t, base, size)

	padded := url.Values{}
	for k, v := range values {
		padded[k] = v
	}
	padded.Set(field, strings.Repeat("A", size-base))
	require.Len(t, padded.Encode(), size)

	return padded
}

// TestRecoveryComplete_MalformedBodies pins that the complete endpoint reads a
// URL-encoded body only: any other body is recovery.ErrMalformed (400), and
// is recorded against the source nowhere.
//
// Its own table: its rows vary only the body and its content type, under one
// fixed limiter, where TestRecoveryComplete_HTTP's rows arrange and act each
// their own way.
func TestRecoveryComplete_MalformedBodies(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		contentType string
		body        string
		assert      func(t *testing.T, out served)
	}

	malformed := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, recovery.ErrMalformed)
		assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
	}

	cases := []testCase{
		{
			name:        "a JSON body",
			contentType: "application/json",
			body:        `{"username":"` + e2eAddress + `","saved_code":"x","password":"y"}`,
			assert:      malformed,
		},
		{
			name:        "form-encoded text declared as JSON",
			contentType: "application/json",
			body: url.Values{
				httpsec.RecoveryUsernameParam:  {e2eAddress},
				httpsec.RecoverySavedCodeParam: {"0000-0000-0000-0000-0000-0000-00"},
				httpsec.RecoveryPasswordParam:  {e2ePassword},
			}.Encode(),
			assert: malformed,
		},
		{
			name:        "a multipart body",
			contentType: "multipart/form-data; boundary=xyz",
			body: "--xyz\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n" + e2eAddress +
				"\r\n--xyz--\r\n",
			assert: malformed,
		},
		{
			name:        "a body with no content type",
			contentType: "",
			body: url.Values{
				httpsec.RecoveryUsernameParam:  {e2eAddress},
				httpsec.RecoverySavedCodeParam: {"0000-0000-0000-0000-0000-0000-00"},
				httpsec.RecoveryPasswordParam:  {e2ePassword},
			}.Encode(),
			assert: malformed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)
			h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryLimiter(countingLimiter(t, 0))}
			h.build(t)

			req := postBody(t.Context(), httpsec.DefaultRecoveryCompletePath, tc.contentType,
				strings.NewReader(tc.body))
			req.RemoteAddr = e2eSource + ":51000"
			if tc.contentType == "" {
				req.Header.Del("Content-Type")
			}

			tc.assert(t, serve(t, h.chain, req))
		})
	}
}

var (
	errRecoveryLookup = errors.New("recovery test: the user store is down")
	errRecoveryTokens = errors.New("recovery test: the token store is down")
	errRecoverySend   = errors.New("recovery test: the sender refused")
)

// TestRecoveryStart pins spec account-recovery "Starting a recovery reveals
// nothing about the account": every cause the start can meet is answered with
// the first row's status, headers and empty body, and never a cookie. Each row
// also shows its cause was the one met, so a row cannot pass by never reaching
// it.
//
// The rows run in order, not in parallel: every row compares its response to
// the first row's.
func TestRecoveryStart(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// arrange changes the harness before the chain is built.
		arrange func(t *testing.T, h *recoveryHarness)

		// request is the start request, made once the chain is built.
		request func(t *testing.T, h *recoveryHarness) *http.Request

		// assert checks the cause was met, given how many messages the
		// sender held before the request.
		assert func(t *testing.T, h *recoveryHarness, sentBefore int)
	}

	form := func(username string) func(t *testing.T, h *recoveryHarness) *http.Request {
		return func(t *testing.T, _ *recoveryHarness) *http.Request {
			return postValues(t.Context(), httpsec.DefaultRecoveryStartPath, e2eSource,
				url.Values{httpsec.RecoveryUsernameParam: {username}})
		}
	}

	nothingSent := func(t *testing.T, h *recoveryHarness, before int) {
		assert.Equal(t, before, h.sender.count(), "a message was sent")
	}

	// usersAnswering replaces the user store with one answering every
	// lookup with d and err.
	usersAnswering := func(t *testing.T, h *recoveryHarness, d *identity.Details, err error) {
		users := NewMockUserLoader(gomock.NewController(t))
		users.EXPECT().LoadByUsername(gomock.Any(), e2eAddress).Return(d, err).Times(1)
		h.users = users
	}

	cases := []testCase{
		{
			name: "a code is sent, and the start is counted",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryStartLimiter(countingLimiter(t, 1))}
			},
			request: form(e2eAddress),
			assert: func(t *testing.T, h *recoveryHarness, before int) {
				assert.Equal(t, before+1, h.sender.count(), "no code was sent")
			},
		},
		{
			name: "a code is sent, asked for as JSON",
			request: func(t *testing.T, _ *recoveryHarness) *http.Request {
				req := postBody(t.Context(), httpsec.DefaultRecoveryStartPath, "application/json",
					strings.NewReader(`{"username":"`+e2eAddress+`"}`))
				req.RemoteAddr = e2eSource + ":51000"

				return req
			},
			assert: func(t *testing.T, h *recoveryHarness, before int) {
				assert.Equal(t, before+1, h.sender.count(), "no code was sent")
			},
		},
		{
			name:    "an unknown username",
			request: form("nobody@example.com"),
			assert:  nothingSent,
		},
		{
			name: "a disabled user",
			arrange: func(t *testing.T, h *recoveryHarness) {
				usersAnswering(t, h, &identity.Details{ID: e2eUser, Username: e2eAddress, Active: false}, nil)
			},
			request: form(e2eAddress),
			assert:  nothingSent,
		},
		{
			name: "the lookup fails",
			arrange: func(t *testing.T, h *recoveryHarness) {
				usersAnswering(t, h, nil, errRecoveryLookup)
			},
			request: form(e2eAddress),
			assert:  nothingSent,
		},
		{
			name: "the issuance limit is reached",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.coreOpts = append(h.coreOpts, recovery.WithIssuedCodeLimit(1))
			},
			request: func(t *testing.T, h *recoveryHarness) *http.Request {
				h.issued(t)

				return form(e2eAddress)(t, h)
			},
			assert: nothingSent,
		},
		{
			name: "the source is throttled, and the start never runs",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryStartLimiter(exceededLimiter(t))}
				// A strict double: a start that ran would resolve the user.
				h.users = NewMockUserLoader(gomock.NewController(t))
			},
			request: form(e2eAddress),
			assert:  nothingSent,
		},
		{
			name: "the source cannot be attributed, and the start never runs",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.users = NewMockUserLoader(gomock.NewController(t))
			},
			request: func(t *testing.T, _ *recoveryHarness) *http.Request {
				return postValues(t.Context(), httpsec.DefaultRecoveryStartPath, "0.0.0.0",
					url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}})
			},
			assert: nothingSent,
		},
		{
			name: "the token store fails",
			arrange: func(t *testing.T, h *recoveryHarness) {
				store := NewMockOnetimeStore(gomock.NewController(t))
				store.EXPECT().InsertWithin(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(false, errRecoveryTokens).AnyTimes()
				h.coreOpts = append(h.coreOpts, recovery.WithIssuedCodeStore(store))
			},
			request: form(e2eAddress),
			assert:  nothingSent,
		},
		{
			name: "the sender refuses the message",
			arrange: func(t *testing.T, h *recoveryHarness) {
				sender := NewMockSender(gomock.NewController(t))
				sender.EXPECT().Send(gomock.Any(), gomock.Any()).Return(errRecoverySend).Times(1)
				h.send = queuedSender{sender}
			},
			request: form(e2eAddress),
			assert:  func(*testing.T, *recoveryHarness, int) {},
		},
		{
			name: "the body is missing",
			request: func(t *testing.T, _ *recoveryHarness) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultRecoveryStartPath, nil)
				req.RemoteAddr = e2eSource + ":51000"

				return req
			},
			assert: nothingSent,
		},
		{
			name: "the JSON is malformed, and the start is still counted",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryStartLimiter(countingLimiter(t, 1))}
			},
			request: func(t *testing.T, _ *recoveryHarness) *http.Request {
				req := postBody(t.Context(), httpsec.DefaultRecoveryStartPath, "application/json",
					strings.NewReader(`{"username":`))
				req.RemoteAddr = e2eSource + ":51000"

				return req
			},
			assert: nothingSent,
		},
	}

	var first *httptest.ResponseRecorder

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRecoveryHarness(t)
			if tc.arrange != nil {
				tc.arrange(t, h)
			}

			h.build(t)

			req := tc.request(t, h)
			before := h.sender.count()

			rec := h.through(req)
			tc.assert(t, h, before)

			assert.Equal(t, http.StatusAccepted, rec.Code)
			assert.Empty(t, rec.Body.Bytes())
			assert.Empty(t, rec.Header().Values("Set-Cookie"))

			if first == nil {
				first = rec
				return
			}

			assert.Equal(t, first.Code, rec.Code)
			assert.Equal(t, first.Header(), rec.Header())
			assert.Equal(t, first.Body.Bytes(), rec.Body.Bytes())
		})
	}
}

// recoveryStart is when the recovery-pending session in these tests is
// created and marked: 09:00, so a 12-hour absolute timeout ends it at 21:00.
var recoveryStart = time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)

// recoveryDeployment is the end-to-end deployment with the recovery gate and
// a password-change resolve endpoint, over a session manager and a TOTP method
// that share one fake clock, so a case can say at what time each step runs.
type recoveryDeployment struct {
	*e2eDeployment

	// changed records that the consumer's password-change function ran, and
	// changeErr is what it returns.
	changed    atomic.Bool
	changeErr  error
	owesChange bool
}

// recoverySetup is what a case varies about the deployment.
type recoverySetup struct {
	// required is whether the user must use a second factor.
	required bool

	// pathOpts configure the requirement policy's enrolment path.
	pathOpts []policy.EnrolmentPathOption

	// changeErr is what the consumer's password-change function returns.
	changeErr error

	// owesChange marks the recovery-pending session as also owing a password
	// change, as a recovery whose reset asks for one leaves it.
	owesChange bool

	// enrolmentPathOff builds the requirement policy with no enrolment path at
	// all, rather than one configured by pathOpts.
	enrolmentPathOff bool
}

func newRecoveryDeployment(t *testing.T, setup recoverySetup) *recoveryDeployment {
	t.Helper()

	ctrl := gomock.NewController(t)
	clk := clockwork.NewFakeClockAt(recoveryStart)

	sessions, err := session.New(session.WithClock(clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	d := &recoveryDeployment{
		e2eDeployment: &e2eDeployment{
			sessions: sessions,
			clock:    clk,
			users:    NewMockUserLoader(ctrl),
			sender:   &capturingSender{},
			tokens:   NewMockGenerator(ctrl),
			required: &requiredFlag{},
			pathOpts: setup.pathOpts,
		},
		changeErr:  setup.changeErr,
		owesChange: setup.owesChange,
	}
	d.required.on.Store(setup.required)

	d.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Payroll", mfa.WithClock(clk))
	require.NoError(t, err)

	d.wireUsers(t)
	d.wireTokens()

	lookups, err := mfa.LookupsFor(d.totp)
	require.NoError(t, err)

	challenge, err := policy.NewMFA(lookups)
	require.NoError(t, err)

	var requirementOpts []policy.MFARequirementOption
	if !setup.enrolmentPathOff {
		requirementOpts = append(requirementOpts, policy.WithMFAEnrolmentPath(d.pathOpts...))
	}

	requirement, err := policy.NewMFARequirement(d.required, lookups, requirementOpts...)
	require.NoError(t, err)

	change := func(*httpsec.Exchange) error {
		d.changed.Store(true)
		return d.changeErr
	}

	chainOpts := []httpsec.Option{
		httpsec.WithPolicyEngine(engineOf(t, challenge, requirement)),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: d.tokens, Sessions: d.sessions, Users: d.users,
		}),
		httpsec.EnableMFA([]mfa.Method{d.totp}, httpsec.WithMFATokens(d.tokens)),
	}
	// With the enrolment path off, no policy ever raises ChallengeMFAEnrolment,
	// and the enrolment interceptor refuses to be registered over one that
	// cannot.
	if !setup.enrolmentPathOff {
		chainOpts = append(chainOpts,
			httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: d.users, Sender: d.sender}))
	}
	chainOpts = append(chainOpts,
		httpsec.EnablePasswordChangeGate(d.sessions,
			httpsec.WithPasswordChangeEndpoint(passwordResolvePath, change)),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: d.sessions}),
		httpsec.EnableRecoveryGateForTest(),
	)

	d.chain, err = httpsec.New(chainOpts...)
	require.NoError(t, err)

	return d
}

// recovered is a recovery-pending session for the user, created and marked at
// recoveryStart as a completed recovery creates and marks it, and the
// credential that names it.
func (d *recoveryDeployment) recovered(t *testing.T) (*session.Session, string) {
	t.Helper()

	s, err := d.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Recovery))
	require.NoError(t, err)

	d.sessions.MarkRecoveryPending(s, recoveryLifetime, d.clock.Now())
	s.PasswordChangePending = d.owesChange
	require.NoError(t, d.sessions.Save(t.Context(), s))

	return s, mfaTokenFor(s.ID)
}

// enrolled begins a TOTP enrolment, proves the device and redeems the emailed
// code, and returns the secret the authenticator holds.
func (d *recoveryDeployment) enrolled(t *testing.T, credential string) string {
	t.Helper()

	begun := d.send(t, enrolBeginPath, credential, nil)
	require.NoError(t, begun.err)

	var doc beginBody
	require.NoError(t, json.Unmarshal(begun.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.Secret)

	proven := d.send(t, enrolConfirmPath, credential, url.Values{"code": {d.code(t, doc.Secret)}})
	require.NoError(t, proven.err)
	require.Equal(t, http.StatusNoContent, proven.rec.Code)

	redeemed := d.send(t, enrolEmailPath, credential, url.Values{"code": {d.lastEmailed(t)}})
	require.NoError(t, redeemed.err)
	require.Equal(t, http.StatusNoContent, redeemed.rec.Code)

	return doc.Secret
}

// stored reloads a session by handle.
func (d *recoveryDeployment) stored(t *testing.T, handle string) *session.Session {
	t.Helper()

	s, err := d.sessions.Load(t.Context(), handle)
	require.NoError(t, err)

	return s
}

// TestRecoveryBind pins the two ways a recovery-pending session is bound, and
// so leaves the state: an enrolment through the enrolment path followed by a
// verification, and a password change resolved at the consumer's endpoint.
func TestRecoveryBind(t *testing.T) {
	t.Parallel()

	// fullDeadline is the absolute deadline a session created at
	// recoveryStart has under the default 12-hour absolute timeout.
	fullDeadline := recoveryStart.Add(12 * time.Hour)

	type testCase struct {
		name  string
		setup recoverySetup

		// act carries the recovery-pending session s, named by credential,
		// through the steps of the case.
		act    func(t *testing.T, d *recoveryDeployment, s *session.Session, credential string)
		assert func(t *testing.T, d *recoveryDeployment, s *session.Session)
	}

	resolve := func(t *testing.T, d *recoveryDeployment, credential string) served {
		t.Helper()

		return d.send(t, passwordResolvePath, credential, url.Values{"password": {"a new one"}})
	}

	cases := []testCase{
		{
			name:  "an enrolment after recovery ends satisfied, with the deadline and the recovery time",
			setup: recoverySetup{required: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				secret := d.enrolled(t, credential)

				d.clock.Advance(9 * time.Minute)

				verified := d.send(t, testMFAVerifyPath, credential, url.Values{"code": {d.code(t, secret)}})
				require.NoError(t, verified.err)
				require.Equal(t, http.StatusOK, verified.rec.Code)

				rotated := accessTokenFrom(t, verified)
				require.NotEqual(t, credential, rotated, "the verification rotates the session")

				id, ok := strings.CutPrefix(rotated, mfaTokenPrefix)
				require.True(t, ok)

				got := d.stored(t, id)
				assert.Equal(t, session.MFASatisfied, got.MFA)
				assert.True(t, got.AbsoluteExpiresAt.Equal(fullDeadline),
					"the absolute deadline is restored to 21:00, got %s", got.AbsoluteExpiresAt)
				assert.True(t, got.RecoveredAt.Equal(recoveryStart),
					"the recovery time is kept, got %s", got.RecoveredAt)
				assert.True(t, got.EnrolmentOriginDeadline.IsZero(), "the confinement marker is cleared")

				d.reached(t, rotated)
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				_, err := d.sessions.Load(t.Context(), s.ID)
				require.Error(t, err, "the recovery-pending handle no longer loads")
			},
		},
		{
			name:  "a confirmed enrolment alone is not enough",
			setup: recoverySetup{required: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				d.enrolled(t, credential)

				challengedFor(t, d.invoices(t, credential), policy.ChallengeMFA)
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				got := d.stored(t, s.ID)
				assert.Equal(t, session.MFAPending, got.MFA, "the confirmation moves the session to MFA pending")
				assert.True(t, got.EnrolmentOriginDeadline.Equal(fullDeadline), "the confinement marker is kept")
				assert.True(t, got.AbsoluteExpiresAt.Equal(recoveryStart.Add(recoveryLifetime)),
					"the lowered deadline stays until the verification")
				assert.True(t, got.RecoveredAt.Equal(recoveryStart), "the recovery time is kept")
			},
		},
		{
			name:  "the password route restores the deadline, keeps the handle and reaches the handler",
			setup: recoverySetup{owesChange: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				d.clock.Advance(5 * time.Minute)

				out := resolve(t, d, credential)
				require.NoError(t, out.err)
				assert.True(t, d.changed.Load(), "the consumer's function runs")

				d.reached(t, credential)
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				got := d.stored(t, s.ID)
				assert.Equal(t, session.MFANone, got.MFA)
				assert.False(t, got.PasswordChangePending, "the pending password change is cleared")
				assert.True(t, got.AbsoluteExpiresAt.Equal(fullDeadline),
					"the absolute deadline is restored to 21:00, got %s", got.AbsoluteExpiresAt)
				assert.True(t, got.EnrolmentOriginDeadline.IsZero(), "the confinement marker is cleared")
				assert.True(t, got.RecoveredAt.Equal(recoveryStart), "the recovery time is kept")
			},
		},
		{
			name:  "the password route for a required user with the enrolment path on",
			setup: recoverySetup{required: true, owesChange: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				require.NoError(t, resolve(t, d, credential).err)

				challengedFor(t, d.invoices(t, credential), policy.ChallengeMFAEnrolment)
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				assert.Equal(t, session.MFAEnrolmentPending, d.stored(t, s.ID).MFA,
					"the policies decide what the bound session owes")
			},
		},
		{
			name:  "the consumer's function fails",
			setup: recoverySetup{changeErr: errChangeRefused, owesChange: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				out := resolve(t, d, credential)
				require.ErrorIs(t, out.err, errChangeRefused, "the consumer's error is the refusal")
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				got := d.stored(t, s.ID)
				assert.Equal(t, session.MFARecoveryPending, got.MFA, "the session stays recovery-pending")
				assert.True(t, got.PasswordChangePending)
				assert.True(t, got.AbsoluteExpiresAt.Equal(recoveryStart.Add(recoveryLifetime)),
					"the deadline stays lowered")
			},
		},
		{
			// The stated limit (design D8): with the enrolment path off, a
			// required user left with no usable second factor after the reset
			// has no enrolment route at all. Every request is refused as their
			// login would be, before either binding endpoint is reached.
			name:  "a required user with no usable method is refused when the enrolment path is off",
			setup: recoverySetup{required: true, enrolmentPathOff: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				out := d.invoices(t, credential)
				require.ErrorIs(t, out.err, policy.ErrMFAEnrolmentRequired)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)

				var ch *httpsec.ChallengeError
				assert.NotErrorAs(t, out.err, &ch, "no challenge, only a denial")
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				got := d.stored(t, s.ID)
				assert.Equal(t, session.MFARecoveryPending, got.MFA, "the session stays recovery-pending")
				assert.True(t, got.AbsoluteExpiresAt.Equal(recoveryStart.Add(recoveryLifetime)),
					"the deadline stays lowered")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newRecoveryDeployment(t, tc.setup)
			s, credential := d.recovered(t)

			tc.act(t, d, s, credential)
			tc.assert(t, d, s)
		})
	}
}

// TestRecoveryEnrolmentSaveFails pins that a recovery-pending session whose
// confirmed enrolment cannot be saved is left recovery-pending in memory too,
// not moved to the enrolment-only state it never held. It stands alone
// because it needs a session store that fails on demand and a session carried
// in memory, which no other case here does.
func TestRecoveryEnrolmentSaveFails(t *testing.T) {
	t.Parallel()

	h := newEnrolHarness(t)
	h.sender.EXPECT().Send(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithoutEnrolmentEmailConfirmation()}
	h.extra = []httpsec.Option{httpsec.EnableRecoveryGateForTest()}

	var failing atomic.Bool

	var err error
	h.sessions, err = session.New(session.WithStore(
		failingSaves{Store: session.NewMemoryStore(), failing: &failing}))
	require.NoError(t, err)

	s := h.recoveryPending(t)
	h.pinned = s

	c := h.chain(t, s)
	secret := h.beginDoc(t, c).Secret

	failing.Store(true)

	out := serve(t, c, post(t.Context(), enrolConfirmPath, "code="+h.codeFor(t, secret)))

	require.ErrorIs(t, out.err, errStoreLeaky)
	assert.Equal(t, session.MFARecoveryPending, s.MFA, "the session keeps the state it had, in memory too")
	assert.True(t, h.enrolled(t), "the binding stands")
}

// TestRecoveryResolveRefused pins the password-change resolve endpoint's
// refusals on a recovery-pending session, each of which leaves the session in
// memory exactly as it was. A session already past its lowered deadline is not
// revived: the request is answered as for any session that no longer loads,
// and the consumer's function is not run, so no password is changed on a
// request that is then refused. A session that cannot be saved after the
// change keeps its recovery-pending state and its lowered deadlines in memory
// too. It has its own table because each case carries a session in memory
// over a session manager built for it.
func TestRecoveryResolveRefused(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// arrange builds h's session manager and returns what to do once the
		// session exists and before the request is served.
		arrange func(t *testing.T, h *enrolHarness) func()

		assert func(t *testing.T, err error, w *gateWitnesses, before, after session.Session)
	}

	unchanged := func(t *testing.T, before, after session.Session) {
		t.Helper()

		assert.Equal(t, session.MFARecoveryPending, after.MFA, "the session is not moved out of its state")
		assert.True(t, after.AbsoluteExpiresAt.Equal(before.AbsoluteExpiresAt), "nor are its deadlines restored")
		assert.Equal(t, before, after, "the session in memory is as it was")
	}

	cases := []testCase{
		{
			name: "past its lowered deadline",
			arrange: func(t *testing.T, h *enrolHarness) func() {
				t.Helper()

				clk := clockwork.NewFakeClockAt(recoveryStart)

				var err error
				h.sessions, err = session.New(session.WithClock(clk),
					session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
				require.NoError(t, err)

				return func() { clk.Advance(recoveryLifetime + time.Minute) }
			},
			assert: func(t *testing.T, err error, w *gateWitnesses, before, after session.Session) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err))
				assert.False(t, w.change.Load(), "the consumer's function is not run")
				unchanged(t, before, after)
			},
		},
		{
			name: "the session cannot be saved",
			arrange: func(t *testing.T, h *enrolHarness) func() {
				t.Helper()

				var failing atomic.Bool

				var err error
				h.sessions, err = session.New(session.WithStore(
					failingSaves{Store: session.NewMemoryStore(), failing: &failing}))
				require.NoError(t, err)

				return func() { failing.Store(true) }
			},
			assert: func(t *testing.T, err error, w *gateWitnesses, before, after session.Session) {
				t.Helper()

				require.ErrorIs(t, err, errStoreLeaky)
				assert.True(t, w.change.Load(), "the consumer's function ran")
				unchanged(t, before, after)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			ready := tc.arrange(t, h)

			w := &gateWitnesses{}
			h.extra = append(w.options(h), httpsec.EnableRecoveryGateForTest())

			s := h.recoveryPending(t)
			h.pinned = s
			before := *s

			ready()

			out := serve(t, h.chain(t, s), post(t.Context(), passwordResolvePath, "password=new"))

			tc.assert(t, out.err, w, before, *s)
		})
	}
}

// recoveryHoldDelay is the fixed delay the hold cases configure.
const recoveryHoldDelay = time.Hour

// errRecordStoreDown is what a failing record store answers, with text a
// response must never carry.
var errRecordStoreDown = errors.New("records: connection to 10.0.0.9 refused")

// errRecoveryLoginDenied is what a consumer's policy denies a login with.
var errRecoveryLoginDenied = errors.New("recovery test: the policy denied the login")

// heldRecovery is what a held recovery handed its two parties: the client's
// completion token and the instant it can be presented, and the cancel token
// the notice's link carried.
type heldRecovery struct {
	completion    string
	completableAt time.Time
	cancel        string
}

// withHold configures the fixed delay and the cancel link a hold needs.
func (h *recoveryHarness) withHold() {
	h.coreOpts = append(h.coreOpts,
		recovery.WithHoldDelay(recoveryHoldDelay), recovery.WithCancelLink("https://app.example.com/cancel"))
}

// hold completes a recovery that the configured delay holds, and returns what
// the hold handed out.
func (h *recoveryHarness) hold(t *testing.T) heldRecovery {
	t.Helper()

	out := h.complete(t, recoveryForm(
		httpsec.RecoverySavedCodeParam, h.saved(t),
		httpsec.RecoveryIssuedCodeParam, h.issued(t)))
	require.NoError(t, out.err)
	require.Equal(t, http.StatusAccepted, out.rec.Code)

	var doc struct {
		CompletionToken string    `json:"completion_token"`
		CompletableAt   time.Time `json:"completable_at"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.CompletionToken)

	held := h.sender.last(t)
	require.Equal(t, "held", held.Subject, "the hold sent no notice")

	link, err := url.Parse(held.TextBody)
	require.NoError(t, err)

	cancel := link.Query().Get(recovery.CancelLinkParam)
	require.NotEmpty(t, cancel, "the notice's link carries no cancel token")

	return heldRecovery{completion: doc.CompletionToken, completableAt: doc.CompletableAt, cancel: cancel}
}

// finish posts a completion token to the finish endpoint.
func (h *recoveryHarness) finish(t *testing.T, completion string) served {
	t.Helper()

	return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource,
		url.Values{httpsec.RecoveryCompletionTokenParam: {completion}}))
}

// cancelHold posts a cancel token to the cancel endpoint.
func (h *recoveryHarness) cancelHold(t *testing.T, cancel string) served {
	t.Helper()

	return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCancelPath, e2eSource,
		url.Values{httpsec.RecoveryCancelTokenParam: {cancel}}))
}

// passwordLogin logs the user in with their password through form login.
func (h *recoveryHarness) passwordLogin(t *testing.T) served {
	t.Helper()

	return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	}))
}

// withMagicLink adds magic-link login for the harness's user to the chain.
func (h *recoveryHarness) withMagicLink(t *testing.T) {
	t.Helper()

	onetimes, err := onetime.New("magic-link", onetime.WithTokenTTL(magicLinkTTL))
	require.NoError(t, err)

	links, err := magiclink.New(onetimes, h.users, h.sender, "https://app.example.com")
	require.NoError(t, err)

	h.chainOpts = append(h.chainOpts, httpsec.EnableMagicLink(links,
		httpsec.WithMagicLinkSessions(h.sessions), httpsec.WithMagicLinkTokens(h.tokens)))
}

// magicLinkLogin asks for a link for the harness's user and follows it.
func (h *recoveryHarness) magicLinkLogin(t *testing.T) served {
	t.Helper()

	asked := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath, e2eSource,
		url.Values{httpsec.DefaultMagicLinkAddressParam: {e2eAddress}, httpsec.DefaultMagicLinkNextParam: {"/"}}))
	require.NoError(t, asked.err)

	cookie := cookieNamed(asked.rec, httpsec.DefaultBindingCookieName)
	require.NotNil(t, cookie)

	req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, e2eSource,
		url.Values{httpsec.DefaultMagicLinkTokenParam: {h.sender.lastToken(t)}})
	req.AddCookie(bindingCookie(cookie.Value))

	return serve(t, h.chain, req)
}

// sentWithSubject counts the messages sent with subject.
func (s *capturingSender) sentWithSubject(subject string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for _, m := range s.sent {
		if m.Subject == subject {
			n++
		}
	}

	return n
}

// activeSessions counts the user's live sessions.
func (h *recoveryHarness) activeSessions(t *testing.T) int {
	t.Helper()

	n, err := h.sessions.CountActiveByUser(t.Context(), e2eUser)
	require.NoError(t, err)

	return n
}

// cancelledNothing asserts out is the cancel endpoint's one answer: 204, an
// empty body, and the application never reached.
func cancelledNothing(t *testing.T, out served) {
	t.Helper()

	require.NoError(t, out.err)
	assert.False(t, out.handlerRan, "the cancel endpoint passed the request on")
	assert.Equal(t, http.StatusNoContent, out.rec.Code)
	assert.Empty(t, out.rec.Body.Bytes())
}

// refusedFinish asserts out refused a finish as a refused recovery.
func refusedFinish(t *testing.T, out served) {
	t.Helper()

	require.ErrorIs(t, out.err, recovery.ErrRefused)
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	assert.False(t, out.handlerRan)
}

// recordsCancelPendingFails is a record store that keeps records in memory
// and fails every CancelPending with errRecordStoreDown.
func recordsCancelPendingFails(t *testing.T) recovery.RecordStore {
	t.Helper()

	mem := recovery.NewMemoryRecordStore()
	m := NewMockRecordStore(gomock.NewController(t))

	m.EXPECT().Insert(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.Insert)
	m.EXPECT().Find(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.Find)
	m.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.Complete)
	m.EXPECT().Cancel(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.Cancel)
	m.EXPECT().LatestCompletion(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.LatestCompletion)
	m.EXPECT().CancelPending(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID, time.Time) (int, error) { return 0, errRecordStoreDown })

	return m
}

// TestRecoveryHold pins held recoveries over HTTP: the hold's answer, the
// finish endpoint before and after the hold, the cancel endpoint's one
// answer, a login's cancellation of a held recovery, and the race between a
// cancel and a finish.
func TestRecoveryHold(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		arrange func(t *testing.T, h *recoveryHarness)
		act     func(t *testing.T, h *recoveryHarness) served
		assert  func(t *testing.T, h *recoveryHarness, out served)
	}

	cases := []testCase{
		{
			name:    "a fixed delay answers 202 with the completion token and the instant, and creates no session",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusAccepted, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

				var doc map[string]any
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				assert.ElementsMatch(t, []string{"completion_token", "completable_at"}, keysOf(doc))

				at, err := time.Parse(time.RFC3339Nano, doc["completable_at"].(string))
				require.NoError(t, err)
				assert.True(t, at.Equal(h.clock.Now().Add(recoveryHoldDelay)))

				assert.Zero(t, h.activeSessions(t), "a held recovery creates no session")
				assert.Equal(t, 1, h.sender.sentWithSubject("held"), "the hold's notice is sent")
			},
		},
		{
			name:    "a finish before the hold is over is 409, and the same token finishes once it is",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay / 2)

				early := h.finish(t, held.completion)
				require.ErrorIs(t, early.err, recovery.ErrNotYetCompletable)
				assert.Equal(t, http.StatusConflict, httpsec.StatusForError(early.err))
				assert.False(t, early.handlerRan)
				assert.Zero(t, h.activeSessions(t), "an early finish creates no session")

				h.clock.Advance(recoveryHoldDelay / 2)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
			},
		},
		{
			name:    "a finish after the hold answers 200 with a recovery-pending credential and the new codes",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay + time.Minute)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				doc := recovered(t, h, out)
				assert.Len(t, doc.RecoveryCodes, 10, "the spent saved code's set is replaced at the finish")
				assert.Equal(t, 1, h.sender.sentWithSubject("recovered"))
			},
		},
		{
			name:    "a finish token spent once is refused the second time",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)
				recovered(t, h, h.finish(t, held.completion))

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { refusedFinish(t, out) },
		},
		{
			name:    "an unknown finish token is 401",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.finish(t, "not-a-token")
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { refusedFinish(t, out) },
		},
		{
			name:    "a finish with no completion token is malformed",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource,
					url.Values{}))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrMalformed)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
			},
		},
		{
			name:    "a completion token given twice is malformed, and the token still finishes",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)

				twice := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource,
					url.Values{httpsec.RecoveryCompletionTokenParam: {held.completion, "other"}}))
				require.ErrorIs(t, twice.err, recovery.ErrMalformed)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(twice.err))

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) { recovered(t, h, out) },
		},
		{
			name:    "a completion token in the query is not read",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)

				return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryFinishPath+"?"+
					url.Values{httpsec.RecoveryCompletionTokenParam: {held.completion}}.Encode(), e2eSource,
					url.Values{}))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrMalformed)
				assert.Zero(t, h.activeSessions(t))
			},
		},
		{
			name:    "a finish body over 16 KiB is 413",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource,
					url.Values{httpsec.RecoveryCompletionTokenParam: {strings.Repeat("a", 17<<10)}}))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, http.StatusRequestEntityTooLarge, httpsec.StatusForError(out.err))
			},
		},
		{
			name:    "a GET to the finish path reaches the application",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return serve(t, h.chain, getFrom(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
		{
			name: "a consumer finish path is answered there",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.withHold()
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryFinishPath("/account/recover/finish")}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)

				return serve(t, h.chain, postValues(t.Context(), "/account/recover/finish", e2eSource,
					url.Values{httpsec.RecoveryCompletionTokenParam: {held.completion}}))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) { recovered(t, h, out) },
		},
		{
			name: "a consumer responder answers the finish",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.withHold()
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryResponder(
					func(ex *httpsec.Exchange, res httpsec.RecoveryResult) error {
						if res.Token == "" || res.Recovery == nil || res.Recovery.Session == nil {
							return errors.New("recovery test: the finish carries no credential")
						}

						ex.Writer.WriteHeader(http.StatusCreated)

						return nil
					})}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusCreated, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name:    "a garbage cancel token is answered 204",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.cancelHold(t, "garbage")
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				cancelledNothing(t, out)
				assert.Zero(t, h.sender.sentWithSubject("cancelled"))
			},
		},
		{
			name:    "a cancel with no body is answered 204",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
					httpsec.DefaultRecoveryCancelPath, nil)
				req.RemoteAddr = e2eSource + ":51000"

				return serve(t, h.chain, req)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { cancelledNothing(t, out) },
		},
		{
			name:    "a cancel body that is not a form, or over 16 KiB, is answered 204",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				notForm := serve(t, h.chain, postBody(t.Context(), httpsec.DefaultRecoveryCancelPath,
					"application/json", strings.NewReader(`{"cancel_token":"x"}`)))
				cancelledNothing(t, notForm)

				return h.cancelHold(t, strings.Repeat("a", 17<<10))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { cancelledNothing(t, out) },
		},
		{
			// A valid token outside the form body — as JSON, in the query, or
			// given twice — must be read as no token at all, exactly as a
			// garbage one is: readHoldToken reads only a URL-encoded body, by
			// the same rules as the complete and finish endpoints, and never
			// the query. Each of the three must cancel nothing, so the same
			// token still finishes the recovery once the hold is over.
			name:    "a valid cancel token sent as JSON, in the query, or duplicated in the form cancels nothing",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				asJSON := serve(t, h.chain, postBody(t.Context(), httpsec.DefaultRecoveryCancelPath,
					"application/json", strings.NewReader(`{"`+httpsec.RecoveryCancelTokenParam+`":"`+held.cancel+`"}`)))
				cancelledNothing(t, asJSON)

				inQuery := serve(t, h.chain, postValues(t.Context(),
					httpsec.DefaultRecoveryCancelPath+"?"+
						url.Values{httpsec.RecoveryCancelTokenParam: {held.cancel}}.Encode(),
					e2eSource, url.Values{}))
				cancelledNothing(t, inQuery)

				duplicated := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCancelPath, e2eSource,
					url.Values{httpsec.RecoveryCancelTokenParam: {held.cancel, held.cancel}}))
				cancelledNothing(t, duplicated)

				assert.Zero(t, h.sender.sentWithSubject("cancelled"), "none of the three cancelled anything")

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) { recovered(t, h, out) },
		},
		{
			name:    "the cancel link cancels: 204, one notice, and the finish is refused after the hold",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				cancelledNothing(t, h.cancelHold(t, held.cancel))
				assert.Equal(t, 1, h.sender.sentWithSubject("cancelled"))

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				refusedFinish(t, out)
				assert.Zero(t, h.activeSessions(t))
			},
		},
		{
			name:    "a finish token posted to cancel is 204, cancels nothing, and still finishes",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				cancelledNothing(t, h.cancelHold(t, held.completion))

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
				assert.Zero(t, h.sender.sentWithSubject("cancelled"), "nothing was cancelled")
			},
		},
		{
			name: "a password login cancels a held recovery",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.withHold()
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				login := h.passwordLogin(t)
				require.NoError(t, login.err)
				require.Equal(t, http.StatusOK, login.rec.Code)
				require.Equal(t, 1, h.activeSessions(t), "the login created its session")

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { refusedFinish(t, out) },
		},
		{
			name: "a magic-link login cancels a held recovery",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.withHold()
				h.withMagicLink(t)
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				login := h.magicLinkLogin(t)
				require.NoError(t, login.err)
				require.NotNil(t, login.rec)
				require.Equal(t, 1, h.activeSessions(t), "the magic-link login created its session")

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { refusedFinish(t, out) },
		},
		{
			// Unlike form login, a magic-link redemption applies the policy
			// inside its own check, before the credential is spent: a denied
			// check never reaches the login completion step that cancels held
			// recoveries, and never consumes the token either.
			name: "a magic-link login the policy denies cancels nothing, and its token stays redeemable",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.withHold()
				h.withMagicLink(t)
				h.chainOpts = append(h.chainOpts, httpsec.WithPolicyEngine(deniesOnceThenAllows(t)))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				asked := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath, e2eSource,
					url.Values{
						httpsec.DefaultMagicLinkAddressParam: {e2eAddress},
						httpsec.DefaultMagicLinkNextParam:    {"/"},
					}))
				require.NoError(t, asked.err)

				cookie := cookieNamed(asked.rec, httpsec.DefaultBindingCookieName)
				require.NotNil(t, cookie)

				tok := h.sender.lastToken(t)
				consume := func() served {
					req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, e2eSource,
						url.Values{httpsec.DefaultMagicLinkTokenParam: {tok}})
					req.AddCookie(bindingCookie(cookie.Value))

					return serve(t, h.chain, req)
				}

				denied := consume()
				require.ErrorIs(t, denied.err, errMagicLinkDenied)
				require.Zero(t, h.activeSessions(t), "the denied redemption created no session")

				h.clock.Advance(recoveryHoldDelay)

				finished := h.finish(t, held.completion)
				require.NoError(t, finished.err, "the denied redemption cancelled nothing")
				require.Equal(t, http.StatusOK, finished.rec.Code)

				redone := consume()
				require.NoError(t, redone.err, "the token was never consumed by the denied redemption")
				assert.Equal(t, 2, h.activeSessions(t),
					"the finish's session and the retried, allowed redemption's own session")

				return finished
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) { recovered(t, h, out) },
		},
		{
			name: "a login the policy phase denies still cancels, and the finish is refused",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.withHold()
				h.chainOpts = append(h.chainOpts, httpsec.WithPolicyEngine(engineOf(t, policyAnswering(t,
					policy.Decision{Outcome: policy.Deny, Reason: errRecoveryLoginDenied}))))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				// The first factor authenticated, which is the evidence the
				// real user still has access, whatever the policy then decides.
				login := h.passwordLogin(t)
				require.ErrorIs(t, login.err, errRecoveryLoginDenied)
				require.Zero(t, h.activeSessions(t), "the denied login created no session")

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { refusedFinish(t, out) },
		},
		{
			name: "a login without a hold configured never touches the record store",
			arrange: func(t *testing.T, h *recoveryHarness) {
				// A strict double: any call fails the test.
				h.records = NewMockRecordStore(gomock.NewController(t))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.passwordLogin(t)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, 1, h.activeSessions(t))
			},
		},
		{
			name: "a record store outage at login refuses the login, and no session is created",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.withHold()
				h.records = recordsCancelPendingFails(t)
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.passwordLogin(t)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.Error(t, out.err)
				require.ErrorIs(t, out.err, errRecordStoreDown)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.NotContains(t, out.err.Error(), "10.0.0.9", "the store's text is not the library's")
				assert.False(t, out.handlerRan)
				assert.Empty(t, out.rec.Body.Bytes(), "no credential is written")
				assert.Zero(t, h.activeSessions(t), "the refused login created no session")
			},
		},
		{
			name: "a racing cancel and finish over HTTP: exactly one takes effect",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.withHold()
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)

				const each = 8

				var (
					wg       sync.WaitGroup
					mu       sync.Mutex
					finishes []served
					cancels  []served
					start    = make(chan struct{})
				)

				for range each {
					wg.Add(2)

					go func() {
						defer wg.Done()
						<-start

						out := h.finish(t, held.completion)

						mu.Lock()
						finishes = append(finishes, out)
						mu.Unlock()
					}()

					go func() {
						defer wg.Done()
						<-start

						out := h.cancelHold(t, held.cancel)

						mu.Lock()
						cancels = append(cancels, out)
						mu.Unlock()
					}()
				}

				close(start)
				wg.Wait()

				// Every cancel answers exactly as a solo one does, whatever it
				// raced against; asserted here, on the test goroutine, once
				// every goroutine above has returned.
				for _, out := range cancels {
					cancelledNothing(t, out)
				}

				won := 0
				for _, out := range finishes {
					if out.err == nil && out.rec.Code == http.StatusOK {
						won++
						continue
					}

					require.ErrorIs(t, out.err, recovery.ErrRefused)
				}

				cancelled := h.sender.sentWithSubject("cancelled")
				assert.Equal(t, 1, won+cancelled,
					"exactly one of the finishes and cancels takes effect (finishes %d, cancels %d)", won, cancelled)
				assert.LessOrEqual(t, won, 1)
				assert.LessOrEqual(t, cancelled, 1)

				return served{rec: httptest.NewRecorder()}
			},
			assert: func(*testing.T, *recoveryHarness, served) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)
			if tc.arrange != nil {
				tc.arrange(t, h)
			}

			h.build(t)

			tc.assert(t, h, tc.act(t, h))
		})
	}
}

// TestRecoveryHold_EndpointsOnlyWithAHold pins that the finish and cancel
// endpoints exist only when the core may hold a recovery: without a hold a
// POST to either path reaches the application like any other request.
//
// Its own table: its rows build the harness without a hold and are named for the
// endpoint alone, a name that means "without a hold" only under this function.
func TestRecoveryHold_EndpointsOnlyWithAHold(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		values url.Values
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name:   "finish",
			path:   httpsec.DefaultRecoveryFinishPath,
			values: url.Values{httpsec.RecoveryCompletionTokenParam: {"x"}},
			assert: func(t *testing.T, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
		{
			name:   "cancel",
			path:   httpsec.DefaultRecoveryCancelPath,
			values: url.Values{httpsec.RecoveryCancelTokenParam: {"x"}},
			assert: func(t *testing.T, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t).build(t)

			tc.assert(t, serve(t, h.chain, postValues(t.Context(), tc.path, e2eSource, tc.values)))
		})
	}
}

// keysOf lists a decoded JSON object's member names.
func keysOf(doc map[string]any) []string {
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}

	return keys
}

// TestRecoveryHold_OIDCLogin pins that a federated login cancels the user's
// held recoveries, as form login and magic link do, exactly when its own
// login succeeds. Its handoff redemption ends through the same login
// completion, so a redemption a consumer policy denies — refused by
// guardRedemption before completeLogin ever runs — never reaches that step:
// it cancels nothing, and the held recovery still completes once its delay is
// over, the same way a denied magic-link redemption leaves its own held
// recovery alone.
//
// The chain is the OIDC harness's, with account recovery held beside it; the
// held recovery is a pending record placed in the store directly, since the
// federated user has no saved set to recover with, and another user's pending
// record shows the allowed case's cancellation is the user's alone.
func TestRecoveryHold_OIDCLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		arrange func(t *testing.T, h *oidcHarness)
		assert  func(t *testing.T, h *oidcHarness, out served, records recovery.RecordStore, held, other recovery.Record)
	}

	cases := []testCase{
		{
			name: "an allowed login cancels the user's held recovery",
			assert: func(t *testing.T, h *oidcHarness, out served, records recovery.RecordStore, held, other recovery.Record) {
				require.NoError(t, out.err)
				require.Equal(t, http.StatusOK, out.rec.Code)
				require.Equal(t, 1, h.activeSessions(t), "the federated login created its session")

				got, err := records.Find(t.Context(), held.ID)
				require.NoError(t, err)
				assert.False(t, got.CancelledAt.IsZero(), "the federated login cancelled the user's held recovery")

				untouched, err := records.Find(t.Context(), other.ID)
				require.NoError(t, err)
				assert.True(t, untouched.CancelledAt.IsZero(), "another user's held recovery stands")
			},
		},
		{
			name: "a denied login cancels nothing, and the held recovery still completes",
			arrange: func(t *testing.T, h *oidcHarness) {
				h.chainOpts = append(h.chainOpts,
					httpsec.WithPolicyEngine(denyingEngine(t, errRecoveryLoginDenied)))
			},
			assert: func(t *testing.T, h *oidcHarness, out served, records recovery.RecordStore, held, other recovery.Record) {
				require.ErrorIs(t, out.err, errRecoveryLoginDenied)
				assert.Zero(t, h.activeSessions(t), "the denied login created no session")

				got, err := records.Find(t.Context(), held.ID)
				require.NoError(t, err)
				assert.True(t, got.CancelledAt.IsZero(), "the denied login cancelled nothing")

				completed, err := records.Complete(t.Context(), held.ID, held.NotBefore)
				require.NoError(t, err)
				assert.True(t, completed, "the held recovery still completes")

				untouched, err := records.Find(t.Context(), other.ID)
				require.NoError(t, err)
				assert.True(t, untouched.CancelledAt.IsZero(), "another user's held recovery stands")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			h.issueTokens()

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
				Return(&identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}, nil)

			totpMethod, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
			require.NoError(t, err)

			kind, err := recovery.MFAEnrolments(totpMethod)
			require.NoError(t, err)

			codes, err := recovery.NewCodes()
			require.NoError(t, err)

			records := recovery.NewMemoryRecordStore()
			now := time.Now()

			held := recovery.Record{
				ID: id.MustParse("01900000-0000-7000-8000-000000000001"), User: oidcTestUserID,
				StartedAt: now, NotBefore: now.Add(recoveryHoldDelay),
			}
			other := recovery.Record{
				ID: id.MustParse("01900000-0000-7000-8000-000000000002"), User: "u-other",
				StartedAt: now, NotBefore: now.Add(recoveryHoldDelay),
			}
			require.NoError(t, records.Insert(t.Context(), held))
			require.NoError(t, records.Insert(t.Context(), other))

			if tc.arrange != nil {
				tc.arrange(t, h)
			}

			h.chainOpts = append(h.chainOpts,
				httpsec.EnablePasswordChangeGate(h.sessions,
					httpsec.WithPasswordChangeEndpoint(passwordResolvePath, func(*httpsec.Exchange) error { return nil })),
				httpsec.EnableAccountRecovery(httpsec.RecoveryDeps{
					Users: users, Sessions: h.sessions, Sender: &capturingSender{}, Codes: codes, Records: records,
				},
					httpsec.WithRecoveryTokens(h.tokens),
					httpsec.WithRecoveryCore(
						recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
						recovery.WithRepudiationContact("Write to security@example.com if this was not you."),
						recovery.WithAuthenticatorKinds(kind),
						recovery.WithMessages(recoveryMessages{}),
						recovery.WithHoldDelay(recoveryHoldDelay),
						recovery.WithCancelLink("https://app.example.com/cancel"),
					)),
			)

			chain := h.chain(t)

			out := serve(t, chain, handoffRequest(t.Context(), oidcTestSource, h.issueHandoff(t, "")))
			tc.assert(t, h, out, records, held, other)
		})
	}
}
