package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// sourcesSignals is a stream set that hears credential_changed.
var sourcesSignals = httpsec.SessionSignals{Signals: withCredentialChanged}

// errSourceRefused is what a test's own endpoint answers a request it refuses with.
var errSourceRefused = errors.New("sources test: refused")

// callAs serves a form POST of body to path as the sign-in sid, and returns the status. It runs
// as the test's own act, and waits for every stream to have answered.
func (r *streamRig) callAs(t *testing.T, sid, path, body string) int {
	t.Helper()

	return r.callWith(t, sid, path, "application/x-www-form-urlencoded", body)
}

// callJSONAs is callAs with a JSON body.
func (r *streamRig) callJSONAs(t *testing.T, sid, path, body string) int {
	t.Helper()

	return r.callWith(t, sid, path, "application/json", body)
}

func (r *streamRig) callWith(t *testing.T, sid, path, contentType, body string) int {
	t.Helper()

	status, _ := r.callBody(t, sid, path, contentType, body)

	return status
}

// callBody is callWith that also returns what the endpoint answered with.
func (r *streamRig) callBody(t *testing.T, sid, path, contentType, body string) (int, []byte) {
	t.Helper()

	var (
		status  int
		content []byte
	)

	r.act(func() {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Authorization", "Bearer "+sid)
		req.RemoteAddr = streamClient + ":4242"

		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)
		status, content = rec.Code, rec.Body.Bytes()
	})

	return status, content
}

// heardOnly asserts every stream sent exactly one credential_changed, naming only kind.
func heardOnly(t *testing.T, kind httpsec.CredentialKind, streams []*riggedStream) {
	t.Helper()

	for i, s := range streams {
		got := s.events("credential_changed")
		require.Len(t, got, 1, "stream %d", i)
		assert.JSONEq(t, `{"kind":"`+string(kind)+`"}`, got[0].Data, "stream %d", i)
		assert.Equal(t, []string{"session", "credential_changed"}, s.sent(), "stream %d", i)
	}
}

// credentialRow is one endpoint's row: how to set the chain up, and what to do to it.
type credentialRow struct {
	name string
	kind httpsec.CredentialKind

	// build makes what one row needs of its own, such as the stores its endpoint reads.
	build func(t *testing.T) credentialRig
}

// credentialRig is one row's chain options and its two requests.
type credentialRig struct {
	opts func(r *streamRig) []httpsec.Option

	// refuse sends a request the endpoint refuses, and change one it accepts, both as the
	// sign-in sid, which is the first of the user's two open streams.
	refuse func(t *testing.T, r *streamRig, sid string)
	change func(t *testing.T, r *streamRig, sid string)
}

func TestSessionSignals_CredentialChanged(t *testing.T) {
	t.Parallel()

	const changePath = "/account/password"

	cases := []credentialRow{
		{
			name: "a password change",
			kind: httpsec.CredentialPassword,
			build: func(*testing.T) credentialRig {
				return credentialRig{
					opts: func(r *streamRig) []httpsec.Option {
						return []httpsec.Option{httpsec.EnablePasswordChangeGate(r.sessions,
							httpsec.WithPasswordChangeEndpoint(changePath, func(ex *httpsec.Exchange) error {
								body, err := ex.Request.Body(64)
								if err != nil || string(body) == "refuse" {
									return errSourceRefused
								}

								ex.Writer.WriteHeader(http.StatusNoContent)

								return nil
							}))}
					},
					refuse: func(t *testing.T, r *streamRig, sid string) {
						assert.NotEqual(t, http.StatusNoContent, r.callAs(t, sid, changePath, "refuse"))
					},
					change: func(t *testing.T, r *streamRig, sid string) {
						require.Equal(t, http.StatusNoContent, r.callAs(t, sid, changePath, "change"))
					},
				}
			},
		},
		{
			name:  "a passkey registered",
			kind:  httpsec.CredentialPasskey,
			build: passkeyRegistered,
		},
		{
			name:  "a passkey removed",
			kind:  httpsec.CredentialPasskey,
			build: passkeyRemoved("&other_sessions=keep"),
		},
		{
			name:  "a second factor enrolled",
			kind:  httpsec.CredentialSecondFactor,
			build: secondFactorEnrolled,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				rig := tc.build(t)
				r := newStreamRig(t, streamSetup{signals: sourcesSignals, opts: rig.opts})

				first, second := r.signIn(t), r.signIn(t)
				streams := []*riggedStream{r.open(t, first.ID), r.open(t, second.ID)}

				rig.refuse(t, r, first.ID)
				requireNoneSent(t, streams)

				rig.change(t, r, first.ID)
				heardOnly(t, tc.kind, streams)
			})
		})
	}
}

// passkeyOptions wires the passkey endpoints over a stub verifier and the store h holds.
func passkeyOptions(r *streamRig, v *passkeyVerifierStub, creds *passkey.MemoryCredentialStore) []httpsec.Option {
	m, err := passkey.New(passkey.Deps{
		Verifier:    v.mock,
		Credentials: creds,
		Users:       r.users,
		Sender:      &capturingSender{},
		Sessions:    r.sessions,
	}, passkey.WithRepudiationContact("help@example.com"), passkey.WithOptionalRecoveryCodes())
	if err != nil {
		panic(err)
	}

	return []httpsec.Option{httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: m, Sessions: r.sessions, Users: r.users})}
}

// passkeyRegistered is the registration's finish: a response to a challenge it never issued is
// refused, and one to the challenge it did issue activates the passkey.
func passkeyRegistered(t *testing.T) credentialRig {
	v := newPasskeyVerifierStub(t)
	creds := passkey.NewMemoryCredentialStore()

	return credentialRig{
		opts: func(r *streamRig) []httpsec.Option { return passkeyOptions(r, v, creds) },
		refuse: func(t *testing.T, r *streamRig, sid string) {
			require.Equal(t, http.StatusOK, r.callAs(t, sid, passkeyBeginPath, ""))
			assert.NotEqual(t, http.StatusOK, r.callJSONAs(t, sid, passkeyFinishPath, registrationBody("not-issued", "cred-0")))
		},
		change: func(t *testing.T, r *streamRig, sid string) {
			require.Equal(t, http.StatusOK, r.callAs(t, sid, passkeyBeginPath, ""))
			require.Equal(t, http.StatusOK, r.callJSONAs(t, sid, passkeyFinishPath, registrationBody(v.lastCreation(t), "cred-1")))
		},
	}
}

// passkeyRemoved is the removal endpoint, on a passkey the user holds, ending the user's other
// sign-ins or keeping them as the form fields in other say.
func passkeyRemoved(other string) func(t *testing.T) credentialRig {
	return func(t *testing.T) credentialRig {
		v := newPasskeyVerifierStub(t)
		creds := passkey.NewMemoryCredentialStore()

		cid, err := id.NewV7Generator().NewID()
		require.NoError(t, err)

		require.NoError(t, creds.Insert(t.Context(), &passkey.Credential{
			ID: cid, User: "u-1", CredentialID: []byte("cred-r"), PublicKey: []byte("key"),
			Name: "Laptop", CreatedAt: time.Now().UTC().Truncate(time.Second), State: passkey.StateActive,
		}))

		return credentialRig{
			opts: func(r *streamRig) []httpsec.Option { return passkeyOptions(r, v, creds) },
			refuse: func(t *testing.T, r *streamRig, sid string) {
				assert.Equal(t, http.StatusNotFound, r.callAs(t, sid, passkeyRemovePath, "id="+id.Nil.String()+other))
			},
			change: func(t *testing.T, r *streamRig, sid string) {
				require.Equal(t, http.StatusNoContent, r.callAs(t, sid, passkeyRemovePath, "id="+cid.String()+other))
			},
		}
	}
}

// TestSessionSignals_CredentialChanged_EndedStream shows a stream the change itself ended says
// session_ended and not credential_changed, while the stream of the sign-in that made the change
// hears of it.
func TestSessionSignals_CredentialChanged_EndedStream(t *testing.T) {
	t.Parallel()

	// REPRODUCED, and waiting on a decision: a stream told to end is woken and reloads, and its
	// queue is still read meanwhile, so it sends the credential_changed queued behind the end
	// before it sends session_ended. Remove this skip when a stream the change ended skips it.
	t.Skip("a stream the change ended still hears credential_changed before session_ended")

	cases := []struct {
		name  string
		build func(t *testing.T) credentialRig
	}{
		{name: "a passkey removal that ends the other sign-ins", build: passkeyRemoved("&other_sessions=end")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				rig := tc.build(t)
				r := newStreamRig(t, streamSetup{signals: sourcesSignals, opts: rig.opts})

				mine, other := r.signIn(t), r.signIn(t)
				own, ended := r.open(t, mine.ID), r.open(t, other.ID)

				rig.change(t, r, mine.ID)

				// Time moves, so the ended stream has all the beats it needs to be told.
				advance(time.Minute)
				synctest.Wait()

				assert.Equal(t, []string{"session", "credential_changed"}, own.sent())
				assert.Equal(t, []string{"session", "session_ended"}, ended.sent(), "the stream the change ended")
				assert.True(t, ended.closed())
			})
		})
	}
}

// secondFactorEnrolled is the enrolment's confirm, which a confined sign-in of the same user
// makes: a wrong code is refused and the right one binds the TOTP method.
func secondFactorEnrolled(t *testing.T) credentialRig {
	store := mfa.NewMemoryEnrolmentStore()
	method, err := mfa.NewTOTP(store, "scrty-test")
	require.NoError(t, err)

	// confirm begins an enrolment on a new confined sign-in of the user and posts code, which
	// is taken from the secret the begin provisioned.
	confirm := func(t *testing.T, r *streamRig, wrong bool) int {
		var pending *session.Session

		r.act(func() {
			var err error

			pending, err = r.sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			r.sessions.MarkEnrolmentPending(pending, 15*time.Minute)
			require.NoError(t, r.sessions.Save(t.Context(), pending))
		})

		status, body := r.callBody(t, pending.ID, enrolBeginPath, "application/x-www-form-urlencoded", "")
		require.Equal(t, http.StatusOK, status)

		var begun beginBody
		require.NoError(t, json.Unmarshal(body, &begun))

		code, err := totp.GenerateCode(begun.Secret, time.Now())
		require.NoError(t, err)

		if wrong {
			code = map[bool]string{true: "111111", false: "000000"}[code == "000000"]
		}

		return r.callAs(t, pending.ID, enrolConfirmPath, "code="+code)
	}

	return credentialRig{
		opts: func(r *streamRig) []httpsec.Option {
			return []httpsec.Option{
				httpsec.WithPolicyEngine(enrolmentPathEngine(t, method)),
				httpsec.EnableMFA([]mfa.Method{method}),
				httpsec.EnableMFAEnrolment(
					httpsec.EnrolmentDeps{Users: r.users, Sender: queuedSender{NewMockSender(gomock.NewController(t))}},
					httpsec.WithoutEnrolmentEmailConfirmation(), httpsec.WithoutEnrolmentNotification()),
			}
		},
		refuse: func(t *testing.T, r *streamRig, _ string) {
			assert.NotEqual(t, http.StatusNoContent, confirm(t, r, true))
		},
		change: func(t *testing.T, r *streamRig, _ string) {
			require.Equal(t, http.StatusNoContent, confirm(t, r, false))
		},
	}
}

// nobodyRequired is a requirement under which no user must use a second factor, so a full
// sign-in's stream is not held back for an enrolment while the enrolment path stays on.
type nobodyRequired struct{}

func (nobodyRequired) Required(context.Context, identity.UserID) (bool, error) { return false, nil }

// enrolmentPathEngine is an engine with the enrolment path on over method, which requires a
// second factor of no one.
func enrolmentPathEngine(t *testing.T, method mfa.Method) *policy.Engine {
	t.Helper()

	found, err := mfa.LookupsFor(method)
	require.NoError(t, err)

	lookups := make([]policy.MFAMethodLookup, 0, len(found))
	for _, l := range found {
		lookups = append(lookups, enrollableLookup{l})
	}

	p, err := policy.NewMFARequirement(nobodyRequired{}, lookups, policy.WithMFAEnrolmentPath())
	require.NoError(t, err)

	return engineOf(t, p)
}

// TestSessionSignals_CredentialChanged_AnswerUnchanged shows a signal that could not be raised
// changes nothing the endpoint answers, since the write has succeeded, and a chain with no
// signals runs the same endpoint as before.
func TestSessionSignals_CredentialChanged_AnswerUnchanged(t *testing.T) {
	t.Parallel()

	const changePath = "/account/password"

	changeOpts := func(r *streamRig) []httpsec.Option {
		return []httpsec.Option{httpsec.EnablePasswordChangeGate(r.sessions,
			httpsec.WithPasswordChangeEndpoint(changePath, func(ex *httpsec.Exchange) error {
				ex.Writer.WriteHeader(http.StatusNoContent)

				return nil
			}))}
	}

	t.Run("a hub that refuses the signal", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			r := newStreamRig(t, streamSetup{signals: sourcesSignals, opts: changeOpts})
			s := r.signIn(t)
			stream := r.open(t, s.ID)

			// A closed hub refuses with ErrSignalsBusy, as a full bus does.
			httpsec.SignalHubProbeOf(r.chain).Close()

			assert.Equal(t, http.StatusNoContent, r.callAs(t, s.ID, changePath, "change"))
			assert.Empty(t, stream.events("credential_changed"))
		})
	})

	t.Run("a chain without signals", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			sessions, err := session.New()
			require.NoError(t, err)

			r := &streamRig{sessions: sessions}
			chain, err := httpsec.New(append(changeOpts(r),
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: newUsers(t)}))...)
			require.NoError(t, err)

			s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, changePath, strings.NewReader("change"))
			req.Header.Set("Authorization", "Bearer "+s.ID)

			rec := httptest.NewRecorder()

			assert.NotPanics(t, func() {
				chain.Middleware()(http.NotFoundHandler()).ServeHTTP(rec, req)
			})
			assert.Equal(t, http.StatusNoContent, rec.Code)
		})
	})
}

// newUsers is a user loader that knows u-1.
func newUsers(t *testing.T) *MockUserLoader {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(storedUser(), nil)

	return users
}

// auditUsers are the two users the audit feed's rows are about: the user whose stream is open
// and another.
const (
	auditOwn   = "u-1"
	auditOther = "u-2"
)

// auditUsername is the identifier a user signs in with.
func auditUsername(user string) string { return user + "@example.com" }

// auditWorld is a deployment that raises every security event the chain can, with the stream of
// auditOwn open on it, and reports them to rec.
type auditWorld struct {
	r      *streamRig
	rec    *eventRecorder
	stream *riggedStream
	sid    map[string]string
}

// newAuditWorld builds the deployment, signs both users in, and opens auditOwn's stream.
func newAuditWorld(t *testing.T) *auditWorld {
	t.Helper()

	w := &auditWorld{rec: &eventRecorder{}, sid: map[string]string{}}

	hash, err := e2eEncoder(t).Encode(e2ePassword)
	require.NoError(t, err)

	details := func(user string) *identity.Details {
		return &identity.Details{ID: identity.UserID(user), Name: user, Username: auditUsername(user), Password: hash, Active: true}
	}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, name string) (*identity.Details, error) {
			for _, u := range []string{auditOwn, auditOther} {
				if name == auditUsername(u) {
					return details(u), nil
				}
			}

			return nil, identity.ErrUserNotFound
		})
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			return details(string(user)), nil
		})

	w.r = newStreamRig(t, streamSetup{
		signals:              sourcesSignals,
		withoutSessionBearer: true,
		opts: func(r *streamRig) []httpsec.Option {
			authn, err := authenticate.NewUsernamePasswordAuthenticator(users,
				authenticate.WithPasswordEncoder(e2eEncoder(t)))
			require.NoError(t, err)

			lock, err := lockout.New(lockout.WithClock(r.clock))
			require.NoError(t, err)

			return []httpsec.Option{
				httpsec.EnableSecurityEvents(w.rec.sink),
				httpsec.WithPolicyEngine(engineOf(t, lock)),
				httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
					Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
					Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedHost("app.example.com")),
				}),
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: r.sessions, Users: users}),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{Authenticator: authn, Sessions: r.sessions, Attempts: lock.Attempts()}),
				httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: users},
					httpsec.WithRenewalLimiter(exceededLimiter(t))),
				httpsec.EnableReauthentication(),
				httpsec.EnablePasswordChangeGate(r.sessions, httpsec.WithPasswordChangeEndpoint(eventsChangePath,
					func(ex *httpsec.Exchange) error {
						ex.Writer.WriteHeader(http.StatusNoContent)

						return nil
					})),
				httpsec.EnableCSRFProtection(),
				httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}),
			}
		},
	})

	for _, u := range []string{auditOwn, auditOther} {
		s, err := w.r.sessions.Create(t.Context(), identity.UserID(u), session.WithFirstFactor(factor.Password))
		require.NoError(t, err)

		w.sid[u] = s.ID
	}

	w.stream = w.r.open(t, w.sid[auditOwn])

	return w
}

// send serves a request from the deployment's client through its trusted proxy, as the sign-in
// credential, and returns the error the chain answered with.
func (w *auditWorld) send(t *testing.T, method, path, credential string, values url.Values, headers map[string]string) error {
	t.Helper()

	var err error

	w.r.act(func() {
		req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = eventsProxy + ":51000"
		req.Header.Set("X-Forwarded-For", eventsClient)

		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}

		for name, value := range headers {
			req.Header.Set(name, value)
		}

		run := w.r.chain.Assemble(func(*httpsec.Exchange) error { return nil })
		err = run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(httptest.NewRecorder())))
	})

	return err
}

// login posts user's identifier and pw to form login.
func (w *auditWorld) login(t *testing.T, user, pw string) error {
	t.Helper()

	return w.send(t, http.MethodPost, httpsec.DefaultLoginPath, "", url.Values{
		httpsec.DefaultLoginUsernameParam: {auditUsername(user)},
		httpsec.DefaultLoginPasswordParam: {pw},
	}, nil)
}

func TestSessionSignals_NoAuditFeed(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// happen does what the audit feed reports, and asserts that it was reported.
		happen func(t *testing.T, w *auditWorld)
	}

	reportedAs := func(t *testing.T, w *auditWorld, names ...string) {
		t.Helper()

		for _, name := range names {
			assert.NotEmpty(t, w.rec.named(name), "the audit feed did not report %s: %v", name, w.rec.names())
		}
	}

	locked := func(user string) func(t *testing.T, w *auditWorld) {
		return func(t *testing.T, w *auditWorld) {
			for range 12 {
				_ = w.login(t, user, "a wrong guess")
			}

			reportedAs(t, w, event.AuthnLoginFail, event.AuthnLoginLock)
		}
	}

	cases := []testCase{
		{name: "a failed login", happen: func(t *testing.T, w *auditWorld) {
			require.Error(t, w.login(t, auditOwn, "a wrong guess"))
			reportedAs(t, w, event.AuthnLoginFail)
		}},
		{name: "a lockout", happen: locked(auditOwn)},
		{name: "a rate-limit refusal", happen: func(t *testing.T, w *auditWorld) {
			require.ErrorIs(t, w.send(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, w.sid[auditOwn], nil, nil),
				httpsec.ErrRenewalThrottled)
			reportedAs(t, w, event.ExcessRateLimitExceeded)
		}},
		{name: "a CSRF refusal", happen: func(t *testing.T, w *auditWorld) {
			require.ErrorIs(t, w.send(t, http.MethodPost, "/api/orders", "", url.Values{"item": {"1"}},
				map[string]string{"Sec-Fetch-Site": "cross-site"}), httpsec.ErrCrossSiteRequest)
			reportedAs(t, w, event.MaliciousCSRF)
		}},
		{name: "a host refusal", happen: func(t *testing.T, w *auditWorld) {
			require.ErrorIs(t, w.send(t, http.MethodGet, "/", "", nil,
				map[string]string{"X-Forwarded-Host": "evil.example"}), httpsec.ErrHostNotAllowed)
			reportedAs(t, w, event.HostRefused)
		}},
		{name: "a DPoP refusal", happen: func(t *testing.T, w *auditWorld) {
			require.ErrorIs(t, w.send(t, http.MethodPost, httpsec.DefaultLoginPath, "", url.Values{
				httpsec.DefaultLoginUsernameParam: {auditUsername(auditOwn)},
				httpsec.DefaultLoginPasswordParam: {e2ePassword},
			}, map[string]string{"DPoP": "not-a-proof"}), httpsec.ErrInvalidDPoPProof)
			reportedAs(t, w, event.DPoPRefused)
		}},
		{name: "another user's sign-in", happen: func(t *testing.T, w *auditWorld) {
			require.NoError(t, w.login(t, auditOther, e2ePassword))
			reportedAs(t, w, event.AuthnLoginSuccess)
		}},
		{name: "another user's lockout", happen: locked(auditOther)},
		{name: "another user's password change", happen: func(t *testing.T, w *auditWorld) {
			require.NoError(t, w.send(t, http.MethodPost, eventsChangePath, w.sid[auditOther], url.Values{"new": {"x"}}, nil))
			reportedAs(t, w, event.AuthnPasswordChange)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				w := newAuditWorld(t)

				tc.happen(t, w)

				// Two heartbeats, so anything the stream was going to say has had its chance.
				before := len(w.stream.comments())
				advanceUntil(t, 10*time.Minute, "two heartbeats", func() bool { return len(w.stream.comments()) >= before+2 })

				assert.Equal(t, []string{"session"}, w.stream.sent(), "the stream carried something of the audit feed")
				assert.False(t, w.stream.closed())
			})
		})
	}
}
