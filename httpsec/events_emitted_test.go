package httpsec_test

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/security"
	"github.com/kartaladev/scrty/session"
)

// reportedElsewhere names the events TestSecurityEvents_Emitted has no row
// for, and where each is pinned instead.
var reportedElsewhere = map[string]string{
	security.AuthnLoginLock:    "the lockout observer's report (TestSecurityEvents_Observers)",
	security.AuthnTokenReuse:   "the session-reuse observer's report (TestSecurityEvents_Observers)",
	security.SigningKeyRotated: "token/signingkey TestSecurityEvents_SigningKeyRotated",
}

// accessToken is the access_token member of a JSON success document.
func accessToken(t *testing.T, out served) string {
	t.Helper()

	require.NoError(t, out.err)

	var doc struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.AccessToken)

	return doc.AccessToken
}

// TestSecurityEvents_Emitted pins one row per event name: each runs the flow
// that decides the outcome, and asserts the event's name, outcome, user,
// resolved client address, first factor and session digest, and that no event
// the flow reported carries any secret the flow's requests carried or were
// handed.
func TestSecurityEvents_Emitted(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T) emittedRun
		assert func(t *testing.T, run emittedRun)
	}

	// worldRun is a run in the events world: the client behind its proxy.
	worldRun := func(w *eventsWorld, user identity.UserID, kind factor.Kind, sid string, secrets ...string) emittedRun {
		return emittedRun{
			events: w.rec.all(), clientIP: eventsClient, user: user, factor: kind,
			session: sid, secrets: append(secrets, e2ePassword),
		}
	}

	signedInRun := func(t *testing.T) emittedRun {
		w := newEventsWorld(t)
		tok := w.signedIn(t)

		return worldRun(w, e2eUser, factor.Password, tok, tok)
	}

	cases := []testCase{
		{
			name:   security.AuthnLoginSuccess,
			run:    signedInRun,
			assert: emitted(security.AuthnLoginSuccess, security.OutcomeSuccess),
		},
		{
			name: security.AuthnLoginSuccessAfterFail,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				require.Error(t, w.login(t, "wrong guess").err)
				tok := w.signedIn(t)

				return worldRun(w, e2eUser, factor.Password, tok, tok, "wrong guess")
			},
			assert: emitted(security.AuthnLoginSuccessAfterFail, security.OutcomeSuccess),
		},
		{
			name: security.AuthnLoginFail,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				require.Error(t, w.login(t, "wrong guess").err)

				return worldRun(w, "", factor.Password, "", "wrong guess")
			},
			assert: emitted(security.AuthnLoginFail, security.OutcomeFailure),
		},
		{
			name: security.AuthnLoginFailMax,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				for range 10 {
					_ = w.login(t, "wrong guess")
					if len(w.rec.named(security.AuthnLoginFailMax)) > 0 {
						break
					}
				}

				return worldRun(w, "", factor.Password, "", "wrong guess")
			},
			assert: emitted(security.AuthnLoginFailMax, security.OutcomeFailure),
		},
		{
			name: security.AuthnPasswordChange,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				tok := w.signedIn(t)
				out := w.send(t, http.MethodPost, eventsChangePath, tok,
					url.Values{"current": {e2ePassword}, "new": {"a brand new passphrase"}}, nil)
				require.NoError(t, out.err)

				return worldRun(w, e2eUser, factor.Password, tok, tok, "a brand new passphrase")
			},
			assert: emitted(security.AuthnPasswordChange, security.OutcomeSuccess),
		},
		{
			name: security.AuthnPasswordChangeFail,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				tok := w.signedIn(t)
				out := w.send(t, http.MethodPost, eventsChangePath, tok,
					url.Values{"current": {e2ePassword}, "new": {eventsRejectedPassword}}, nil)
				require.Error(t, out.err)

				return worldRun(w, e2eUser, factor.Password, tok, tok, eventsRejectedPassword)
			},
			assert: emitted(security.AuthnPasswordChangeFail, security.OutcomeFailure),
		},
		{
			name:   security.AuthnTokenCreated,
			run:    signedInRun,
			assert: emitted(security.AuthnTokenCreated, security.OutcomeSuccess),
		},
		{
			name: security.AuthnTokenRevoked,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				tok := w.signedIn(t)
				require.NoError(t, w.send(t, http.MethodPost, httpsec.DefaultLogoutPath, tok, nil, nil).err)

				return worldRun(w, e2eUser, factor.Password, tok, tok)
			},
			assert: emitted(security.AuthnTokenRevoked, security.OutcomeSuccess),
		},
		{
			name:   security.SessionCreated,
			run:    signedInRun,
			assert: emitted(security.SessionCreated, security.OutcomeSuccess),
		},
		{
			name: security.SessionRenewed,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				tok := w.signedIn(t)
				successor := accessToken(t, w.send(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, tok, nil, nil))

				return worldRun(w, e2eUser, factor.Password, successor, tok, successor)
			},
			assert: emitted(security.SessionRenewed, security.OutcomeSuccess),
		},
		{
			name: security.SessionExpired,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				tok := w.signedIn(t)
				w.clk.Advance(31 * time.Minute)
				require.Error(t, w.send(t, http.MethodGet, "/api/orders", tok, nil, nil).err)

				return worldRun(w, e2eUser, factor.Password, tok, tok)
			},
			assert: emitted(security.SessionExpired, security.OutcomeFailure),
		},
		{
			name: security.SessionUseAfterExpire,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				tok := w.signedIn(t)
				w.clk.Advance(31 * 24 * time.Hour)
				require.Error(t, w.send(t, http.MethodGet, "/api/orders", tok, nil, nil).err)

				return worldRun(w, "", "", "", tok)
			},
			assert: emitted(security.SessionUseAfterExpire, security.OutcomeFailure),
		},
		{
			name: security.SessionLogout,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				tok := w.signedIn(t)
				require.NoError(t, w.send(t, http.MethodPost, httpsec.DefaultLogoutPath, tok, nil, nil).err)

				return worldRun(w, e2eUser, factor.Password, tok, tok)
			},
			assert: emitted(security.SessionLogout, security.OutcomeSuccess),
		},
		{
			name: security.AuthzFail,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				tok := w.signedIn(t)
				require.Error(t, w.send(t, http.MethodGet, "/admin/users", tok, nil, nil).err)

				return worldRun(w, e2eUser, factor.Password, tok, tok)
			},
			assert: emitted(security.AuthzFail, security.OutcomeFailure),
		},
		{
			name: security.MFAVerified,
			run: func(t *testing.T) emittedRun {
				rec := &eventRecorder{}
				d := newE2EDeployment(t)
				d.enrolOpts = append(d.enrolOpts, httpsec.WithoutEnrolmentEmailConfirmation())
				d.extra = append(d.extra, httpsec.EnableSecurityEvents(rec.sink))
				d.build(t)

				pending := enrolmentChallenged(t, d.login(t))
				rotated := d.enrolAndVerify(t, pending, false)

				return emittedRun{
					events: rec.all(), clientIP: e2eSource, user: e2eUser, factor: factor.Password,
					session: strings.TrimPrefix(rotated, mfaTokenPrefix), secrets: []string{pending, rotated, e2ePassword},
				}
			},
			assert: emitted(security.MFAVerified, security.OutcomeSuccess),
		},
		{
			name: security.MFAVerifyFail,
			run: func(t *testing.T) emittedRun {
				rec := &eventRecorder{}
				d := newE2EDeployment(t)
				d.enrolOpts = append(d.enrolOpts, httpsec.WithoutEnrolmentEmailConfirmation())
				d.extra = append(d.extra, httpsec.EnableSecurityEvents(rec.sink))
				d.build(t)

				d.enrolAndVerify(t, enrolmentChallenged(t, d.login(t)), false)

				// A later sign-in owes the factor the user now holds.
				challenged := challengedFor(t, d.login(t), policy.ChallengeMFA)
				before := len(rec.all())

				refused := d.send(t, testMFAVerifyPath, challenged, url.Values{"code": {"000000"}})
				require.ErrorIs(t, refused.err, mfa.ErrInvalidCode)

				return emittedRun{
					events: rec.all()[before:], clientIP: e2eSource, user: e2eUser, factor: factor.Password,
					session: strings.TrimPrefix(challenged, mfaTokenPrefix), secrets: []string{challenged, "000000"},
				}
			},
			assert: emitted(security.MFAVerifyFail, security.OutcomeFailure),
		},
		{
			name: security.MFAEnrolled,
			run: func(t *testing.T) emittedRun {
				rec := &eventRecorder{}
				d := newE2EDeployment(t)
				d.enrolOpts = append(d.enrolOpts, httpsec.WithoutEnrolmentEmailConfirmation())
				d.extra = append(d.extra, httpsec.EnableSecurityEvents(rec.sink))
				d.build(t)

				pending := enrolmentChallenged(t, d.login(t))
				d.enrolAndVerify(t, pending, false)

				return emittedRun{
					events: rec.all(), clientIP: e2eSource, user: e2eUser, factor: factor.Password,
					session: strings.TrimPrefix(pending, mfaTokenPrefix), secrets: []string{pending, e2ePassword},
				}
			},
			assert: emitted(security.MFAEnrolled, security.OutcomeSuccess),
		},
		{
			name: security.MFARemoved,
			run: func(t *testing.T) emittedRun {
				totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
				require.NoError(t, err)

				w := newEventsWorld(t)
				w.handler = func(ex *httpsec.Exchange) error {
					return mfa.ResetEnrolment(ex.Context(), e2eUser,
						mfa.ResetDeps{Enrolments: []mfa.EnrolmentRemover{totp}},
						mfa.WithoutResetSessionRevocation(), mfa.WithoutResetNotification())
				}
				tok := w.signedIn(t)
				require.NoError(t, w.send(t, http.MethodPost, "/admin-tools/reset", tok, nil, nil).err)

				return worldRun(w, e2eUser, "", "", tok)
			},
			assert: emitted(security.MFARemoved, security.OutcomeSuccess),
		},
		{
			name: security.PasskeyRegistered,
			run: func(t *testing.T) emittedRun {
				rec := &eventRecorder{}
				h := newPasskeyHarness(t)
				h.extra = append(h.extra, httpsec.EnableSecurityEvents(rec.sink))
				s := h.sessionIn(t, factor.Password, session.MFANone)

				require.NoError(t, h.register(t, h.build(t, s), "cred-1").err)

				return emittedRun{
					events: rec.all(), clientIP: "192.0.2.1", user: testMFAUser, factor: factor.Password,
					session: s.ID, secrets: []string{s.ID},
				}
			},
			assert: emitted(security.PasskeyRegistered, security.OutcomeSuccess),
		},
		{
			name: security.PasskeyRemoved,
			run: func(t *testing.T) emittedRun {
				rec := &eventRecorder{}
				h := newPasskeyHarness(t)
				h.extra = append(h.extra, httpsec.EnableSecurityEvents(rec.sink))
				seedPasskey(t, h, testMFAUser, "cred-own", passkey.StateActive)
				gone := seedPasskey(t, h, testMFAUser, "cred-gone", passkey.StateSuspended)
				s := h.sessionIn(t, factor.Password, session.MFANone)

				out := serve(t, h.build(t, s), managePost(t, passkeyRemovePath, url.Values{"id": {gone.ID.String()}}))
				require.NoError(t, out.err)

				return emittedRun{
					events: rec.all(), clientIP: "192.0.2.1", user: testMFAUser, factor: factor.Password,
					session: s.ID, secrets: []string{s.ID},
				}
			},
			assert: emitted(security.PasskeyRemoved, security.OutcomeSuccess),
		},
		{
			name: security.RecoveryStarted,
			run: func(t *testing.T) emittedRun {
				rec := &eventRecorder{}
				h := newRecoveryHarness(t)
				h.chainOpts = append(h.chainOpts, httpsec.EnableSecurityEvents(rec.sink))
				h.build(t)

				issued := h.issued(t)

				return emittedRun{
					events: rec.all(), clientIP: e2eSource, user: e2eUser, secrets: []string{issued},
				}
			},
			assert: emitted(security.RecoveryStarted, security.OutcomeSuccess),
		},
		{
			name: security.RecoveryCompleted,
			run: func(t *testing.T) emittedRun {
				rec := &eventRecorder{}
				h := newRecoveryHarness(t)
				h.chainOpts = append(h.chainOpts, httpsec.EnableSecurityEvents(rec.sink))
				h.build(t)

				saved := h.saved(t)
				tok := accessToken(t, h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, saved, httpsec.RecoveryPasswordParam, e2ePassword)))

				return emittedRun{
					events: rec.all(), clientIP: e2eSource, user: e2eUser, factor: factor.Recovery,
					session: strings.TrimPrefix(tok, mfaTokenPrefix), secrets: []string{saved, tok, e2ePassword},
				}
			},
			assert: emitted(security.RecoveryCompleted, security.OutcomeSuccess),
		},
		{
			name: security.Reauthenticated,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				tok := w.signedIn(t)
				rotated := accessToken(t, w.send(t, http.MethodPost, httpsec.DefaultReauthenticationPrefix+"/password",
					tok, url.Values{httpsec.DefaultLoginPasswordParam: {e2ePassword}}, nil))

				return worldRun(w, e2eUser, factor.Password, rotated, tok, rotated)
			},
			assert: emitted(security.Reauthenticated, security.OutcomeSuccess),
		},
		{
			name: security.ReauthenticationFail,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				tok := w.signedIn(t)
				require.Error(t, w.send(t, http.MethodPost, httpsec.DefaultReauthenticationPrefix+"/password",
					tok, url.Values{httpsec.DefaultLoginPasswordParam: {"wrong guess"}}, nil).err)

				return worldRun(w, e2eUser, factor.Password, tok, tok, "wrong guess")
			},
			assert: emitted(security.ReauthenticationFail, security.OutcomeFailure),
		},
		{
			name: security.SignInEnded,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				other := w.signedIn(t)
				tok := w.signedIn(t)
				require.NoError(t, w.send(t, http.MethodDelete, httpsec.DefaultSessionManagementPrefix, tok, nil, nil).err)

				return worldRun(w, e2eUser, factor.Password, tok, tok, other)
			},
			assert: emitted(security.SignInEnded, security.OutcomeSuccess),
		},
		{
			name: security.CSRFRefused,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				require.ErrorIs(t, w.send(t, http.MethodPost, "/api/orders", "", url.Values{"item": {"1"}},
					map[string]string{"Sec-Fetch-Site": "cross-site"}).err, httpsec.ErrCrossSiteRequest)

				return worldRun(w, "", "", "")
			},
			assert: emitted(security.CSRFRefused, security.OutcomeFailure),
		},
		{
			name: security.HostRefused,
			run: func(t *testing.T) emittedRun {
				w := newEventsWorld(t)
				require.ErrorIs(t, w.send(t, http.MethodGet, "/", "", nil,
					map[string]string{"X-Forwarded-Host": "evil.example"}).err, httpsec.ErrHostNotAllowed)

				return worldRun(w, "", "", "", "evil.example")
			},
			assert: emitted(security.HostRefused, security.OutcomeFailure),
		},
		{
			name: security.DPoPRefused,
			run: func(t *testing.T) emittedRun {
				rec := &eventRecorder{}
				world := newDPoPBearerWorld(t)
				sid := world.session("bound-key-thumbprint")
				tok, err := world.gen.GenerateWith(t.Context(), sid, &identity.Principal{ID: "u-1", Username: testSubject})
				require.NoError(t, err)

				chain, err := httpsec.New(httpsec.WithClock(world.clk), httpsec.WithLogger(discardLogger()),
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: world.gen, Sessions: world.sessions, Users: world.users,
					}),
					httpsec.EnableSecurityEvents(rec.sink))
				require.NoError(t, err)

				out := serve(t, chain, bearerRequest(t.Context(), "Bearer "+tok))
				require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)

				return emittedRun{events: rec.all(), clientIP: "192.0.2.1", secrets: []string{tok, sid}}
			},
			assert: emitted(security.DPoPRefused, security.OutcomeFailure),
		},
		{
			name: security.CertificateBindingRefused,
			run: func(t *testing.T) emittedRun {
				rec := &eventRecorder{}
				s := newCertServer(t, httpsec.EnableCertificateBinding(), httpsec.EnableSecurityEvents(rec.sink))
				cert := newClientCert(t, "service-c")

				got := s.login(t, []tls.Certificate{cert.tls})
				before := len(rec.all())
				require.Equal(t, http.StatusUnauthorized, s.get(t, got.token, nil))

				return emittedRun{
					events: rec.all()[before:], clientIP: "127.0.0.1", secrets: []string{got.token, cert.thumb},
				}
			},
			assert: emitted(security.CertificateBindingRefused, security.OutcomeFailure),
		},
		{
			name: security.ChallengeRefused,
			run: func(t *testing.T) emittedRun {
				rec := &eventRecorder{}
				v := NewMockChallengeVerifier(gomock.NewController(t))
				v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(httpsec.ChallengeRefuse, nil)

				run := formLoginChallengeRun(t, false,
					httpsec.EnableAutomationChallenge(v), httpsec.EnableSecurityEvents(rec.sink))
				require.ErrorIs(t, run.send(t).err, httpsec.ErrChallengeRequired)

				return emittedRun{events: rec.all(), clientIP: "192.0.2.1", secrets: []string{"wrong"}}
			},
			assert: emitted(security.ChallengeRefused, security.OutcomeFailure),
		},
		{
			name: security.RateLimitRefused,
			run: func(t *testing.T) emittedRun {
				rec := &eventRecorder{}
				h := newLoginGuardHarness(t)
				c := h.chain(t, []httpsec.LoginOption{httpsec.WithLoginLimiter(exceededLimiter(t))}, nil,
					httpsec.EnableSecurityEvents(rec.sink))

				out := formLoginFrom(t, c, loginGuardSource, "ada", "wrong")
				require.Error(t, out.err)

				return emittedRun{events: rec.all(), clientIP: loginGuardSource, secrets: []string{"wrong"}}
			},
			assert: emitted(security.RateLimitRefused, security.OutcomeFailure),
		},
	}

	covered := make([]string, 0, len(cases)+len(reportedElsewhere))
	for _, tc := range cases {
		covered = append(covered, tc.name)
	}
	for name := range reportedElsewhere {
		covered = append(covered, name)
	}
	require.ElementsMatch(t, security.Names(), covered, "one row per event name")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t))
		})
	}
}
