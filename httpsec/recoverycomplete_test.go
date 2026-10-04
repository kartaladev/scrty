package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
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
				require.ErrorIs(t, out.err, policy.ErrAccountLocked,
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
				require.ErrorIs(t, out.err, policy.ErrAccountLocked)
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
				h.codes, err = recovery.NewCodes(recovery.WithSetSize(2))
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
					recovery.WithDelay(time.Hour), recovery.WithCancelLink("https://app.example.com/cancel"))
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
					recovery.WithDelay(time.Hour), recovery.WithCancelLink("https://app.example.com/cancel"))
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
					recovery.WithDelay(time.Hour), recovery.WithCancelLink("https://app.example.com/cancel"))
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

	lockout, err := policy.NewAccountLockoutPolicy(
		policy.WithAttemptStore(h.attempts), policy.WithFixedLockout(1, time.Hour))
	require.NoError(t, err)

	h.chainOpts = append(h.chainOpts, httpsec.WithPolicyEngine(engineOf(t, lockout)))
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
		authenticate.WithPasswordAuthenticatorLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	m, err := authenticate.NewManager(provider)
	require.NoError(t, err)

	return m
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
