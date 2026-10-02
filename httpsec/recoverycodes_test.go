package httpsec_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// errRecoveryCodesConsumerRefused is what a consumer's own gate refuses a
// codes request with, once the recovery gate has passed it on because the
// per-request policy phase raised a challenge of the consumer's own.
var errRecoveryCodesConsumerRefused = errors.New("recoverycodes test: the consumer's gate refused")

// withCodesEndpoint lets the harness's sessions reach the saved-code
// endpoints: a bearer token names a session, and the endpoints judge the
// regeneration window on the harness's fake clock.
func (h *recoveryHarness) withCodesEndpoint() {
	h.chainOpts = append(h.chainOpts, httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
		Verifier: h.tokens, Sessions: h.sessions, Users: h.users,
	}))
	h.recOpts = append(h.recOpts, httpsec.WithRecoveryClockForTest(h.clock.Now))
}

// fullSession is a session a password login created at the harness's current
// time, with no challenge pending.
func (h *recoveryHarness) fullSession(t *testing.T) *session.Session {
	t.Helper()

	s, err := h.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	return s
}

// save persists what a case changed on s.
func (h *recoveryHarness) save(t *testing.T, s *session.Session) {
	t.Helper()

	require.NoError(t, h.sessions.Save(t.Context(), s))
}

// elapse moves the harness's clock on by d, touching s at least every 20
// minutes so it outlives the session manager's 30-minute idle timeout: the
// window is about when the user last authenticated, not about idleness.
func (h *recoveryHarness) elapse(t *testing.T, s *session.Session, d time.Duration) {
	t.Helper()

	const step = 20 * time.Minute

	for d > 0 {
		adv := min(step, d)
		h.clock.Advance(adv)
		d -= adv

		require.NoError(t, h.sessions.Touch(t.Context(), s))
	}
}

// codes sends method to the saved-code path, carrying a bearer token for s
// when s is not nil.
func (h *recoveryHarness) codesRequest(t *testing.T, method string, s *session.Session) served {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, httpsec.DefaultRecoveryCodesPath, nil)
	if s != nil {
		req.Header.Set("Authorization", "Bearer "+mfaTokenFor(s.ID))
	}

	return serve(t, h.chain, req)
}

// setUnchanged asserts the user's saved set is still the one first opened,
// all ten codes of it.
func setUnchanged(t *testing.T, h *recoveryHarness, first string) {
	t.Helper()

	require.NoError(t, h.codes.Confirm(t.Context(), e2eUser, first), "the previous set still stands")

	n, err := h.codes.Remaining(t.Context(), e2eUser)
	require.NoError(t, err)
	assert.Equal(t, 10, n.N)
	assert.Zero(t, h.sender.sentWithSubject("regenerated"), "no regeneration notice")
}

// regenerated asserts out is the default regeneration answer, and that it
// replaced the set whose first code was first.
func regenerated(t *testing.T, h *recoveryHarness, out served, first string) []string {
	t.Helper()

	require.NoError(t, out.err)
	assert.False(t, out.handlerRan, "the endpoint answers the request itself")
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	assert.Equal(t, []string{"recovery_codes"}, keysOf(doc))

	var body struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))
	require.Len(t, body.RecoveryCodes, 10)

	require.NoError(t, h.codes.Confirm(t.Context(), e2eUser, body.RecoveryCodes[0]), "the new set is usable")
	require.ErrorIs(t, h.codes.Confirm(t.Context(), e2eUser, first), recovery.ErrRefused, "the old set is void")
	assert.Equal(t, 1, h.sender.sentWithSubject("regenerated"), "the notice is queued")

	return body.RecoveryCodes
}

// TestRecoveryCodes pins the saved-code endpoints: a POST regenerates for a
// session whose latest authentication is within the window, a GET counts for
// any full session, and neither answers a session that has a challenge
// pending, an anonymous request, or a chain whose core has no saved codes.
func TestRecoveryCodes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		arrange func(t *testing.T, h *recoveryHarness)
		// unbuilt leaves the chain to act, for the rows about construction.
		unbuilt bool
		act     func(t *testing.T, h *recoveryHarness) served
		// assert is given first, the first code of the set each row opens
		// with.
		assert func(t *testing.T, h *recoveryHarness, first string, out served)
	}

	cases := []testCase{
		{
			name: "a fresh session regenerates: 200, ten codes, no-store, the old set void, the notice queued",
			act: func(t *testing.T, h *recoveryHarness) served {
				s := h.fullSession(t)
				h.elapse(t, s, 10*time.Minute)

				return h.codesRequest(t, http.MethodPost, s)
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				codes := regenerated(t, h, out, first)

				notice := h.sender.last(t)
				assert.Equal(t, e2eAddress, notice.To, "the notice goes to the user's address")
				for _, code := range codes {
					assert.NotContains(t, notice.TextBody, code, "the notice carries no code")
				}
			},
		},
		{
			name: "a stale session is refused as reauthentication required, and the set is unchanged",
			act: func(t *testing.T, h *recoveryHarness) served {
				s := h.fullSession(t) // 09:00
				h.elapse(t, s, 20*time.Minute)

				return h.codesRequest(t, http.MethodPost, s) // 09:20
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				require.ErrorIs(t, out.err, recovery.ErrReauthenticationRequired)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
				assert.Empty(t, out.rec.Body.Bytes())
				setUnchanged(t, h, first)
			},
		},
		{
			name: "a second factor satisfied at 09:15 is fresh at 09:20",
			act: func(t *testing.T, h *recoveryHarness) served {
				s := h.fullSession(t) // 09:00
				h.elapse(t, s, 15*time.Minute)

				s.MFA = session.MFASatisfied
				s.MFASatisfiedAt = h.clock.Now() // 09:15
				h.save(t, s)

				h.elapse(t, s, 5*time.Minute)

				return h.codesRequest(t, http.MethodPost, s) // 09:20
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				regenerated(t, h, out, first)
			},
		},
		{
			name: "a consumer window of 2h regenerates at 10:30",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.recOpts = append(h.recOpts, httpsec.WithRegenerationFreshness(2*time.Hour))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				s := h.fullSession(t) // 09:00
				h.elapse(t, s, 90*time.Minute)

				return h.codesRequest(t, http.MethodPost, s) // 10:30
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				regenerated(t, h, out, first)
			},
		},
		{
			name: "a consumer window of 2h still refuses at 11:01",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.recOpts = append(h.recOpts, httpsec.WithRegenerationFreshness(2*time.Hour))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				s := h.fullSession(t)
				h.elapse(t, s, 2*time.Hour+time.Minute)

				return h.codesRequest(t, http.MethodPost, s)
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				require.ErrorIs(t, out.err, recovery.ErrReauthenticationRequired)
				setUnchanged(t, h, first)
			},
		},
		{
			name: "a GET counts, with no code and no freshness asked, and changes nothing",
			act: func(t *testing.T, h *recoveryHarness) served {
				s := h.fullSession(t)
				h.elapse(t, s, 3*time.Hour)

				return h.codesRequest(t, http.MethodGet, s)
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan)
				assert.Equal(t, http.StatusOK, out.rec.Code)

				var doc map[string]any
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				assert.Equal(t, map[string]any{"remaining": float64(10), "low": false}, doc)
				assert.NotContains(t, out.rec.Body.String(), first, "no code is returned")
				setUnchanged(t, h, first)
			},
		},
		{
			name: "a GET for a user with no set counts none, which is low",
			act: func(t *testing.T, h *recoveryHarness) served {
				_, err := h.codes.Generate(t.Context(), "someone-else")
				require.NoError(t, err)

				s, err := h.sessions.Create(t.Context(), "u-without-set", session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				return h.codesRequest(t, http.MethodGet, s)
			},
			assert: func(t *testing.T, _ *recoveryHarness, _ string, out served) {
				require.NoError(t, out.err)
				assert.JSONEq(t, `{"remaining":0,"low":true}`, out.rec.Body.String())
			},
		},
		{
			name: "an MFA-pending session is refused by the MFA gate, and no set is generated",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.chainOpts = append(h.chainOpts,
					httpsec.EnableMFA([]mfa.Method{h.totp}, httpsec.WithMFATokens(h.tokens)))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				s := h.fullSession(t)
				s.MFA = session.MFAPending
				h.save(t, s)

				return h.codesRequest(t, http.MethodPost, s)
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind, "the gate enforcing the MFA challenge refuses it")
				assert.False(t, out.handlerRan)
				setUnchanged(t, h, first)
			},
		},
		{
			name: "a recovery-pending session is refused with the account-recovery challenge, and the store is unchanged",
			act: func(t *testing.T, h *recoveryHarness) served {
				s, err := h.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Recovery))
				require.NoError(t, err)

				h.sessions.MarkRecoveryPending(s, 15*time.Minute, s.CreatedAt)
				h.save(t, s)

				return h.codesRequest(t, http.MethodPost, s)
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengeAccountRecovery, ch.Kind)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
				setUnchanged(t, h, first)
			},
		},
		{
			name: "a consumer challenge raised per request is passed on to its own gate, not answered here, and no set is generated",
			arrange: func(t *testing.T, h *recoveryHarness) {
				const consumerChallenge = policy.ChallengeKind(100)

				h.chainOpts = append(h.chainOpts,
					httpsec.WithPolicyEngine(engineOf(t, raisingDeclared{kind: consumerChallenge, phase: policy.PerRequest})),
					httpsec.WithChallengeEnforcer(consumerChallenge),
					httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
						if ex.RaisedChallenge() == consumerChallenge {
							return errRecoveryCodesConsumerRefused
						}

						return next(ex)
					}), httpsec.After(httpsec.OrderPasswordChange)))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.codesRequest(t, http.MethodPost, h.fullSession(t))
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				require.ErrorIs(t, out.err, errRecoveryCodesConsumerRefused,
					"the recovery gate passes the request on to the gate enforcing the raised challenge")
				assert.False(t, out.handlerRan)
				setUnchanged(t, h, first)
			},
		},
		{
			name: "a request with no session is 401",
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.codesRequest(t, http.MethodPost, nil)
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
				setUnchanged(t, h, first)
			},
		},
		{
			name: "a GET with no session is 401",
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.codesRequest(t, http.MethodGet, nil)
			},
			assert: func(t *testing.T, _ *recoveryHarness, _ string, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.False(t, out.handlerRan)
			},
		},
		{
			name: "another method on the path reaches the application",
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.codesRequest(t, http.MethodDelete, h.fullSession(t))
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
				setUnchanged(t, h, first)
			},
		},
		{
			name: "the consumer's responders answer, and the codes keep the endpoint's no-store",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.recOpts = append(h.recOpts,
					httpsec.WithRecoveryCodesResponder(func(ex *httpsec.Exchange, codes []string) error {
						ex.Writer.WriteHeader(http.StatusCreated)
						_, err := ex.Writer.Write([]byte(strings.Join(codes, "\n")))

						return err
					}),
					httpsec.WithRecoveryCountResponder(func(ex *httpsec.Exchange, n recovery.Count) error {
						ex.Writer.WriteHeader(http.StatusAccepted)
						_, err := ex.Writer.Write([]byte(strings.Repeat("*", n.N)))

						return err
					}))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				s := h.fullSession(t)

				count := h.codesRequest(t, http.MethodGet, s)
				require.NoError(t, count.err)
				assert.Equal(t, http.StatusAccepted, count.rec.Code)
				assert.Equal(t, strings.Repeat("*", 10), count.rec.Body.String())

				return h.codesRequest(t, http.MethodPost, s)
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusCreated, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"),
					"the endpoint set no-store; this responder left it")
				assert.Len(t, strings.Split(out.rec.Body.String(), "\n"), 10)
				require.ErrorIs(t, h.codes.Confirm(t.Context(), e2eUser, first), recovery.ErrRefused)
			},
		},
		{
			name:    "a synchronous sender without acceptance fails construction",
			unbuilt: true,
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.send = NewMockSender(gomock.NewController(t))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				_, err := httpsec.New(h.options(t)...)

				return served{err: err}
			},
			assert: func(t *testing.T, _ *recoveryHarness, _ string, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrConfig)
				require.ErrorIs(t, out.err, recovery.ErrConfig)
			},
		},
		{
			name: "saved codes not enabled: the path falls through to the application",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.proofs = []recovery.ProofKind{recovery.ProofIssued, recovery.ProofPassword}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				s := h.fullSession(t)

				get := h.codesRequest(t, http.MethodGet, s)
				require.NoError(t, get.err)
				assert.True(t, get.handlerRan, "the GET reaches the application")

				return h.codesRequest(t, http.MethodPost, s)
			},
			assert: func(t *testing.T, h *recoveryHarness, first string, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan, "the POST reaches the application")
				setUnchanged(t, h, first)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)
			h.withCodesEndpoint()

			if tc.arrange != nil {
				tc.arrange(t, h)
			}

			if !tc.unbuilt {
				h.build(t)
			}

			first := h.saved(t)

			tc.assert(t, h, first, tc.act(t, h))
		})
	}
}

// TestRecoveryCodes_Options pins the options the saved-code endpoints add: a
// window of zero or less and a nil responder are configuration errors.
func TestRecoveryCodes_Options(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opt    httpsec.RecoveryOption
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
	}

	cases := []testCase{
		{name: "a zero window", opt: httpsec.WithRegenerationFreshness(0), assert: refused},
		{name: "a negative window", opt: httpsec.WithRegenerationFreshness(-time.Minute), assert: refused},
		{name: "a nil codes responder", opt: httpsec.WithRecoveryCodesResponder(nil), assert: refused},
		{name: "a nil count responder", opt: httpsec.WithRecoveryCountResponder(nil), assert: refused},
		{
			name:   "a positive window",
			opt:    httpsec.WithRegenerationFreshness(time.Minute),
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)
			h.recOpts = append(h.recOpts, tc.opt)

			_, err := httpsec.New(h.options(t)...)
			tc.assert(t, err)
		})
	}
}
