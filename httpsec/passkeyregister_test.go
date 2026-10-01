package httpsec_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// passkeyFinishDocument is the finish endpoint's default answer, read back the
// way a client would.
type passkeyFinishDocument struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	State            string    `json:"state"`
	Pending          []string  `json:"pending"`
	RecoveryCodes    *[]string `json:"recovery_codes"`
	BackupEligible   bool      `json:"backup_eligible"`
	NoSyncedPasskey  bool      `json:"no_synced_passkey"`
	RecoveryNotSetUp bool      `json:"recovery_not_set_up"`
}

// withSavedCodes wires saved recovery codes to the harness's manager. The
// harness's user has no password and no other authenticator, so a first
// passkey awaits the codes.
func withSavedCodes(t *testing.T, h *passkeyHarness) *recovery.Codes {
	t.Helper()

	codes, err := recovery.NewCodes()
	require.NoError(t, err)

	wayBack, err := recovery.NewWayBackCheck(recovery.WayBackDeps{Users: h.users, Codes: codes})
	require.NoError(t, err)

	h.recovery = &passkey.RecoveryDeps{Codes: codes, WayBack: wayBack}

	return codes
}

// TestPasskeyRegistration drives the registration endpoints through a chain,
// with a session carried as bearer authentication would carry it.
func TestPasskeyRegistration(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// session is the carried session's state; anonymous carries none.
		state     session.MFAState
		anonymous bool
		recovered bool

		setup  func(t *testing.T, h *passkeyHarness)
		act    func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served
		assert func(t *testing.T, h *passkeyHarness, s *session.Session, out served)
	}

	finishWith := func(body func(h *passkeyHarness, challenge string) string, contentType string) func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
		return func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
			begun := serve(t, chain, post(t.Context(), passkeyBeginPath, ""))
			require.NoError(t, begun.err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, passkeyFinishPath,
				strings.NewReader(body(h, h.verifier.lastCreation(t))))
			req.Header.Set("Content-Type", contentType)

			return serve(t, chain, req)
		}
	}

	nothingStored := func(t *testing.T, h *passkeyHarness) {
		t.Helper()

		n, err := h.creds.Count(t.Context(), testMFAUser)
		require.NoError(t, err)
		assert.Zero(t, n, "a refused finish stored a passkey")
	}

	cases := []testCase{
		{
			name:  "begin answers the creation options",
			state: session.MFANone,
			act: func(t *testing.T, _ *passkeyHarness, chain *httpsec.Chain) served {
				return serve(t, chain, post(t.Context(), passkeyBeginPath, ""))
			},
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan, "the endpoint answers the request itself")
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
				assert.Contains(t, out.rec.Header().Get("Content-Type"), "application/json")

				var doc struct {
					PublicKey struct {
						Challenge string `json:"challenge"`
					} `json:"publicKey"`
				}
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				assert.Equal(t, encodeChallenge(h.verifier.lastCreation(t)), doc.PublicKey.Challenge)
			},
		},
		{
			name:  "finish stores the passkey and answers the documented document",
			state: session.MFANone,
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				return h.register(t, chain, "cred-1")
			},
			assert: func(t *testing.T, h *passkeyHarness, s *session.Session, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

				stored := h.credential(t)
				assert.Equal(t, passkey.StateActive, stored.State)

				var doc passkeyFinishDocument
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				assert.Equal(t, stored.ID.String(), doc.ID)
				assert.Equal(t, "Laptop", doc.Name)
				assert.Equal(t, "active", doc.State)
				assert.Empty(t, doc.Pending)
				assert.Nil(t, doc.RecoveryCodes, "recovery_codes is null when none were generated")
				assert.True(t, doc.BackupEligible)
				assert.False(t, doc.NoSyncedPasskey)
				assert.False(t, doc.RecoveryNotSetUp)

				assert.Equal(t, session.MFANone, h.stored(t, s.ID).MFA,
					"a registration on a full session leaves its second-factor state alone")
			},
		},
		{
			name:  "a pending passkey answers its reasons and the codes once",
			state: session.MFANone,
			setup: func(t *testing.T, h *passkeyHarness) { withSavedCodes(t, h) },
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				return h.register(t, chain, "cred-1")
			},
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)

				var doc passkeyFinishDocument
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				assert.Equal(t, "pending", doc.State)
				assert.Equal(t, []string{"saved_codes"}, doc.Pending)
				require.NotNil(t, doc.RecoveryCodes)
				assert.NotEmpty(t, *doc.RecoveryCodes)
			},
		},
		{
			name:  "a form body is missing credentials",
			state: session.MFANone,
			act: finishWith(func(h *passkeyHarness, challenge string) string {
				return url.Values{"response": {registrationBody(challenge, "cred-1")}}.Encode()
			}, "application/x-www-form-urlencoded"),
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
				nothingStored(t, h)
			},
		},
		{
			name:  "a body the verifier cannot read is missing credentials",
			state: session.MFANone,
			act:   finishWith(func(*passkeyHarness, string) string { return `{"unrelated":true}` }, "application/json"),
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
				assert.ErrorIs(t, out.err, passkey.ErrMalformedResponse, "the core's refusal stays reachable")
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
				nothingStored(t, h)
			},
		},
		{
			name:  "an oversized body is too large and does not spend the challenge",
			state: session.MFANone,
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				begun := serve(t, chain, post(t.Context(), passkeyBeginPath, ""))
				require.NoError(t, begun.err)

				challenge := h.verifier.lastCreation(t)
				huge := `{"challenge":"` + encodeChallenge(challenge) + `","id":"cred-1","pad":"` +
					strings.Repeat("a", 70<<10) + `"}`

				tooLarge := serve(t, chain, jsonPost(t.Context(), passkeyFinishPath, huge))
				require.ErrorIs(t, tooLarge.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, http.StatusRequestEntityTooLarge, httpsec.StatusForError(tooLarge.err))
				nothingStored(t, h)

				// The same challenge still finishes: the oversized body spent
				// nothing.
				return serve(t, chain, jsonPost(t.Context(), passkeyFinishPath, registrationBody(challenge, "cred-1")))
			},
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, passkey.StateActive, h.credential(t).State)
			},
		},
		{
			name:  "a response in the query string is missing credentials",
			state: session.MFANone,
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				begun := serve(t, chain, post(t.Context(), passkeyBeginPath, ""))
				require.NoError(t, begun.err)

				q := url.Values{"response": {registrationBody(h.verifier.lastCreation(t), "cred-1")}}.Encode()

				return serve(t, chain, jsonPost(t.Context(), passkeyFinishPath+"?"+q, ""))
			},
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
				nothingStored(t, h)
			},
		},
		{
			name:  "a GET on the finish path passes through",
			state: session.MFANone,
			act: func(t *testing.T, _ *passkeyHarness, chain *httpsec.Chain) served {
				return serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet, passkeyFinishPath, nil))
			},
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
				assert.Zero(t, h.verifier.parseCalls, "nothing was read")
			},
		},
		{
			name:  "a GET on the begin path passes through and issues nothing",
			state: session.MFANone,
			act: func(t *testing.T, _ *passkeyHarness, chain *httpsec.Chain) served {
				return serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet, passkeyBeginPath, nil))
			},
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
				assert.Empty(t, h.verifier.creations)
			},
		},
		{
			name:      "a begin without a session needs authentication",
			anonymous: true,
			act: func(t *testing.T, _ *passkeyHarness, chain *httpsec.Chain) served {
				return serve(t, chain, post(t.Context(), passkeyBeginPath, ""))
			},
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
				assert.Empty(t, h.verifier.creations)
			},
		},
		{
			name:      "a confirm without a session needs authentication",
			anonymous: true,
			act: func(t *testing.T, _ *passkeyHarness, chain *httpsec.Chain) served {
				return serve(t, chain, post(t.Context(), passkeyConfirmPath, "code=x"))
			},
			assert: func(t *testing.T, _ *passkeyHarness, _ *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
			},
		},
		{
			name:  "a saved code confirms a passkey awaiting it",
			state: session.MFANone,
			setup: func(t *testing.T, h *passkeyHarness) { withSavedCodes(t, h) },
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				finished := h.register(t, chain, "cred-1")
				require.NoError(t, finished.err)

				var doc passkeyFinishDocument
				require.NoError(t, json.Unmarshal(finished.rec.Body.Bytes(), &doc))
				require.NotNil(t, doc.RecoveryCodes)

				return serve(t, chain, post(t.Context(), passkeyConfirmPath, "code="+url.QueryEscape((*doc.RecoveryCodes)[0])))
			},
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.Equal(t, passkey.StateActive, h.credential(t).State)
			},
		},
		{
			name:  "a wrong saved code is an invalid code",
			state: session.MFANone,
			setup: func(t *testing.T, h *passkeyHarness) { withSavedCodes(t, h) },
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				require.NoError(t, h.register(t, chain, "cred-1").err)

				return serve(t, chain, post(t.Context(), passkeyConfirmPath, "code=wrong-code"))
			},
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.Equal(t, passkey.StatePending, h.credential(t).State)
			},
		},
		{
			name:  "a confirm without a code is missing credentials",
			state: session.MFANone,
			act: func(t *testing.T, _ *passkeyHarness, chain *httpsec.Chain) served {
				return serve(t, chain, post(t.Context(), passkeyConfirmPath, ""))
			},
			assert: func(t *testing.T, _ *passkeyHarness, _ *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
			},
		},
		{
			name:      "an active passkey moves a recovery-pending session to MFA pending",
			state:     session.MFARecoveryPending,
			recovered: true,
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				return h.register(t, chain, "cred-1")
			},
			assert: func(t *testing.T, h *passkeyHarness, s *session.Session, out served) {
				require.NoError(t, out.err)

				saved := h.stored(t, s.ID)
				assert.Equal(t, session.MFAPending, saved.MFA)
				assert.Equal(t, s.EnrolmentOriginDeadline, saved.EnrolmentOriginDeadline,
					"the confinement marker stays until the verification restores it")
				assert.Equal(t, s.AbsoluteExpiresAt, saved.AbsoluteExpiresAt)
				assert.Equal(t, s.RecoveredAt, saved.RecoveredAt)
				assert.False(t, saved.RecoveredAt.IsZero())
			},
		},
		{
			name:      "a pending passkey leaves a recovery-pending session as it was",
			state:     session.MFARecoveryPending,
			recovered: true,
			setup:     func(t *testing.T, h *passkeyHarness) { withSavedCodes(t, h) },
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				return h.register(t, chain, "cred-1")
			},
			assert: func(t *testing.T, h *passkeyHarness, s *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, passkey.StatePending, h.credential(t).State)
				assert.Equal(t, session.MFARecoveryPending, h.stored(t, s.ID).MFA)
			},
		},
		{
			name:      "the confirmation that activates a passkey moves a recovery-pending session",
			state:     session.MFARecoveryPending,
			recovered: true,
			setup:     func(t *testing.T, h *passkeyHarness) { withSavedCodes(t, h) },
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				finished := h.register(t, chain, "cred-1")
				require.NoError(t, finished.err)

				var doc passkeyFinishDocument
				require.NoError(t, json.Unmarshal(finished.rec.Body.Bytes(), &doc))
				require.NotNil(t, doc.RecoveryCodes)

				return serve(t, chain, post(t.Context(), passkeyConfirmPath, "code="+url.QueryEscape((*doc.RecoveryCodes)[0])))
			},
			assert: func(t *testing.T, h *passkeyHarness, s *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA)
			},
		},
		{
			name:  "a consumer registration prefix",
			state: session.MFANone,
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyRegistrationPrefix("/account/passkeys"))
			},
			act: func(t *testing.T, _ *passkeyHarness, chain *httpsec.Chain) served {
				moved := serve(t, chain, post(t.Context(), passkeyBeginPath, ""))
				require.NoError(t, moved.err)
				assert.True(t, moved.handlerRan, "the default path is a route like any other")

				return serve(t, chain, post(t.Context(), "/account/passkeys/begin", ""))
			},
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Len(t, h.verifier.creations, 1)
			},
		},
		{
			name:  "consumer responders",
			state: session.MFANone,
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.passkeyOpts = append(h.passkeyOpts,
					httpsec.WithPasskeyBeginResponder(func(ex *httpsec.Exchange, options json.RawMessage) error {
						ex.Writer.WriteHeader(http.StatusAccepted)
						_, err := ex.Writer.Write(options)

						return err
					}),
					httpsec.WithPasskeyRegistrationResponder(func(ex *httpsec.Exchange, res *passkey.RegistrationResult) error {
						ex.Writer.WriteHeader(http.StatusCreated)
						_, err := ex.Writer.Write([]byte(res.Credential.Name))

						return err
					}))
			},
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				begun := serve(t, chain, post(t.Context(), passkeyBeginPath, ""))
				require.NoError(t, begun.err)
				assert.Equal(t, http.StatusAccepted, begun.rec.Code)
				assert.Contains(t, begun.rec.Body.String(), `"challenge"`)
				assert.NotContains(t, begun.rec.Body.String(), "publicKey")

				return serve(t, chain, jsonPost(t.Context(), passkeyFinishPath,
					registrationBody(h.verifier.lastCreation(t), "cred-1")))
			},
			assert: func(t *testing.T, _ *passkeyHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusCreated, out.rec.Code)
				assert.Equal(t, "Laptop", out.rec.Body.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newPasskeyHarness(t)
			if tc.setup != nil {
				tc.setup(t, h)
			}

			var s *session.Session

			switch {
			case tc.anonymous:
			case tc.recovered:
				s = h.recoveryPending(t)
			default:
				s = h.sessionIn(t, factor.Password, tc.state)
			}

			chain := h.build(t, s)

			tc.assert(t, h, s, tc.act(t, h, chain))
		})
	}
}

// TestPasskeyRegistrationConstruction pins the wiring EnablePasskeys refuses.
func TestPasskeyRegistrationConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, h *passkeyHarness)
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
	}

	cases := []testCase{
		{
			name:   "the defaults assemble",
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "a registration path under the MFA verify prefix",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyRegistrationPrefix(httpsec.DefaultMFAVerifyPrefix+"/x"))
			},
			assert: refused,
		},
		{
			name: "a registration path under the MFA begin prefix",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyRegistrationPrefix(httpsec.DefaultMFABeginPrefix))
			},
			assert: refused,
		},
		{
			name: "the logout path is a registration path",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.logoutOpts = append(h.logoutOpts, httpsec.WithLogoutRequestPath(passkeyFinishPath))
			},
			assert: refused,
		},
		{
			name: "the login path is a registration path",
			setup: func(t *testing.T, h *passkeyHarness) {
				h.extra = append(h.extra, httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: NewMockAuthenticator(gomock.NewController(t)),
					Sessions:      h.sessions,
					Tokens:        h.tokens,
					Attempts:      policy.NewMemoryAttemptStore(),
				}, httpsec.WithLoginRequestPath(passkeyBeginPath)))
			},
			assert: refused,
		},
		{
			name: "a credentials path equal to a registration path",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyCredentialsPrefix(passkeyConfirmPath))
			},
			assert: refused,
		},
		{
			name: "an empty registration prefix",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyRegistrationPrefix(""))
			},
			assert: refused,
		},
		{
			name: "a registration prefix without a leading slash",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyRegistrationPrefix("passkey"))
			},
			assert: refused,
		},
		{
			name: "a credentials prefix without a leading slash",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyCredentialsPrefix("credentials"))
			},
			assert: refused,
		},
		{
			name: "a nil begin responder",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyBeginResponder(nil))
			},
			assert: refused,
		},
		{
			name: "a nil registration responder",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyRegistrationResponder(nil))
			},
			assert: refused,
		},
		{
			name: "passkeys enabled twice",
			setup: func(t *testing.T, h *passkeyHarness) {
				m, err := passkey.New(passkey.Deps{Verifier: h.verifier.mock, Users: h.users, Sender: h.notices},
					passkey.WithRepudiationContact("help@example.com"))
				require.NoError(t, err)

				h.extra = append(h.extra, httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: m, Sessions: h.sessions}))
			},
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newPasskeyHarness(t)
			if tc.setup != nil {
				tc.setup(t, h)
			}

			_, err := httpsec.New(h.chainOptions(t, nil)...)
			tc.assert(t, err)
		})
	}
}

// TestEnablePasskeysDeps pins the dependencies EnablePasskeys requires: the
// manager that runs the ceremonies, and the session manager a confined
// session whose passkey became active is saved through.
func TestEnablePasskeysDeps(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		deps   func(m *passkey.Manager, sessions *session.Manager) httpsec.PasskeyDeps
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "both given",
			deps: func(m *passkey.Manager, sessions *session.Manager) httpsec.PasskeyDeps {
				return httpsec.PasskeyDeps{Passkeys: m, Sessions: sessions}
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "no passkey manager",
			deps: func(_ *passkey.Manager, sessions *session.Manager) httpsec.PasskeyDeps {
				return httpsec.PasskeyDeps{Sessions: sessions}
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig) },
		},
		{
			name: "no session manager",
			deps: func(m *passkey.Manager, _ *session.Manager) httpsec.PasskeyDeps {
				return httpsec.PasskeyDeps{Passkeys: m}
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newPasskeyHarness(t)
			m, err := passkey.New(passkey.Deps{Verifier: h.verifier.mock, Users: h.users, Sender: h.notices},
				passkey.WithRepudiationContact("help@example.com"))
			require.NoError(t, err)

			_, err = httpsec.New(httpsec.EnablePasskeys(tc.deps(m, h.sessions)))
			tc.assert(t, err)
		})
	}
}
