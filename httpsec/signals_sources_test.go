package httpsec_test

//go:generate mockgen -destination=authenticatorkind_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/recovery AuthenticatorKind

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
	"github.com/kartaladev/scrty/recovery"
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
		if sid != "" {
			req.Header.Set("Authorization", "Bearer "+sid)
		}

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

	// partial, when set, runs between the two: the first half of a change that takes two
	// requests, after which nothing has changed yet and no stream hears anything.
	partial func(t *testing.T, r *streamRig, sid string)
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
			name:  "a passkey pending until its saved code is confirmed",
			kind:  httpsec.CredentialPasskey,
			build: passkeyConfirmed,
		},
		{
			name:  "a second factor enrolled",
			kind:  httpsec.CredentialSecondFactor,
			build: secondFactorEnrolled(false),
		},
		{
			name:  "a second factor enrolled, proved by the code emailed to the user",
			kind:  httpsec.CredentialSecondFactor,
			build: secondFactorEnrolled(true),
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

				if rig.partial != nil {
					rig.partial(t, r, first.ID)
					requireNoneSent(t, streams)
				}

				rig.change(t, r, first.ID)
				heardOnly(t, tc.kind, streams)
			})
		})
	}
}

// passkeyOptions wires the passkey endpoints over a stub verifier and the store h holds.
func passkeyOptions(r *streamRig, v *passkeyVerifierStub, creds *passkey.MemoryCredentialStore) []httpsec.Option {
	return passkeyOptionsWith(r, v, creds, nil, passkey.WithOptionalRecoveryCodes())
}

// passkeyOptionsWith is passkeyOptions with the saved-code wiring rec and further manager options.
func passkeyOptionsWith(
	r *streamRig, v *passkeyVerifierStub, creds *passkey.MemoryCredentialStore, rec *passkey.RecoveryDeps, opts ...passkey.Option,
) []httpsec.Option {
	m, err := passkey.New(passkey.Deps{
		Verifier:    v.mock,
		Credentials: creds,
		Users:       r.users,
		Sender:      &capturingSender{},
		Sessions:    r.sessions,
		Recovery:    rec,
	}, append([]passkey.Option{passkey.WithRepudiationContact("help@example.com")}, opts...)...)
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

// passkeyConfirmed is the registration of a passkey that waits for the user to confirm a new
// set of saved codes: its finish is answered with the codes and activates nothing, and the
// confirm, given one of them, activates it.
func passkeyConfirmed(t *testing.T) credentialRig {
	v := newPasskeyVerifierStub(t)
	creds := passkey.NewMemoryCredentialStore()

	// saved is the code the finish handed out, which the confirm presents.
	var saved string

	return credentialRig{
		opts: func(r *streamRig) []httpsec.Option {
			codes, err := recovery.NewCodes()
			require.NoError(t, err)

			wayBack, err := recovery.NewWayBackCheck(recovery.WayBackDeps{Users: r.users, Codes: codes})
			require.NoError(t, err)

			return passkeyOptionsWith(r, v, creds, &passkey.RecoveryDeps{Codes: codes, WayBack: wayBack})
		},
		refuse: func(t *testing.T, r *streamRig, sid string) {
			require.Equal(t, http.StatusOK, r.callAs(t, sid, passkeyBeginPath, ""))
			assert.NotEqual(t, http.StatusOK, r.callJSONAs(t, sid, passkeyFinishPath, registrationBody("not-issued", "cred-0")))
		},
		partial: func(t *testing.T, r *streamRig, sid string) {
			require.Equal(t, http.StatusOK, r.callAs(t, sid, passkeyBeginPath, ""))

			status, body := r.callBody(t, sid, passkeyFinishPath, "application/json", registrationBody(v.lastCreation(t), "cred-1"))
			require.Equal(t, http.StatusOK, status)

			var doc struct {
				State         string   `json:"state"`
				RecoveryCodes []string `json:"recovery_codes"`
			}

			require.NoError(t, json.Unmarshal(body, &doc))
			require.Equal(t, "pending", doc.State, "the finish activated nothing")
			require.NotEmpty(t, doc.RecoveryCodes)

			saved = doc.RecoveryCodes[0]
		},
		change: func(t *testing.T, r *streamRig, sid string) {
			require.Equal(t, http.StatusNoContent, r.callAs(t, sid, passkeyConfirmPath, "code="+url.QueryEscape(saved)))
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

// TestSessionSignals_CredentialChanged_UserWideEnd pins what a stream that outlives a user-wide end
// hears of a credential change raised just after it.
func TestSessionSignals_CredentialChanged_UserWideEnd(t *testing.T) {
	t.Parallel()

	const kind = `{"kind":"passkey"}`

	change := func(r *streamRig) {
		httpsec.SignalHubProbeOf(r.chain).Deliver(httpsec.SignalEnvelope{
			User: "u-1", Name: string(httpsec.SignalCredentialChanged), Data: json.RawMessage(kind),
		})
		synctest.Wait()
	}

	runStreamCases(t, []streamCase{
		{
			name:  "the family a report kept is not woken, and hears at once, where the others end",
			setup: streamSetup{signals: sourcesSignals},
			assert: func(t *testing.T, r *streamRig) {
				mine, other := r.signIn(t), r.signIn(t)
				own, ended := r.open(t, mine.ID), r.open(t, other.ID)

				// The kept stream's read is what this holds, were it to read at all.
				held := r.holdListings(t)

				r.act(func() {
					_, err := r.sessions.EndOtherSignIns(t.Context(), "u-1", mine)
					require.NoError(t, err)
				})
				change(r)

				assert.Equal(t, []string{"session", "credential_changed"}, own.sent(), "the kept stream")
				assert.False(t, own.closed())
				assert.Equal(t, []string{"session"}, ended.sent(), "the ended stream, before its reload answers")
				assert.EqualValues(t, 1, held.entered.Load(), "only the ended stream reloads")

				held.letGo()
				synctest.Wait()

				assert.Equal(t, []string{"session", "session_ended"}, ended.sent(), "the ended stream")
				assert.True(t, ended.closed())
				assert.Equal(t, []string{"session", "credential_changed"}, own.sent(), "the kept stream")
			},
		},
		{
			name:  "a report that kept nothing holds a stream the store still holds, until its reload says alive",
			setup: streamSetup{signals: sourcesSignals},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				httpsec.SignalHubProbeOf(r.chain).Deliver(httpsec.SignalEnvelope{
					User: "u-1", Name: string(httpsec.SignalSessionEnded), Reason: "all_ended",
				})
				synctest.Wait()
				change(r)

				assert.Equal(t, []string{"session"}, stream.sent(), "a signal overtook the reload")

				held.letGo()
				synctest.Wait()

				assert.Equal(t, []string{"session", "credential_changed"}, stream.sent())
				assert.False(t, stream.closed())
			},
		},
	})
}

// secondFactorEnrolled is the enrolment's confirm, which a confined sign-in of the same user
// makes: a wrong code is refused and the right one binds the TOTP method. With emailed, the
// right code only starts the proof, by emailing the user a code, and the enrolment completes
// when that code is redeemed.
func secondFactorEnrolled(emailed bool) func(t *testing.T) credentialRig {
	return func(t *testing.T) credentialRig {
		store := mfa.NewMemoryEnrolmentStore()
		method, err := mfa.NewTOTP(store, "scrty-test")
		require.NoError(t, err)

		sender := &capturingSender{}

		// confirm begins an enrolment on a new confined sign-in of the user and posts code,
		// which is taken from the secret the begin provisioned. It returns that sign-in.
		confirm := func(t *testing.T, r *streamRig, wrong bool) (int, string) {
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

			return r.callAs(t, pending.ID, enrolConfirmPath, "code="+code), pending.ID
		}

		// pendingSID is the sign-in the partial step confirmed on, which the redeem continues.
		var pendingSID string

		enrolOpts := []httpsec.EnrolmentOption{httpsec.WithoutEnrolmentEmailConfirmation(), httpsec.WithoutEnrolmentNotification()}
		if emailed {
			enrolOpts = []httpsec.EnrolmentOption{httpsec.WithoutEnrolmentNotification()}
		}

		rig := credentialRig{
			opts: func(r *streamRig) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithPolicyEngine(enrolmentPathEngine(t, method)),
					httpsec.EnableMFA([]mfa.Method{method}),
					httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: r.users, Sender: sender}, enrolOpts...),
				}
			},
			refuse: func(t *testing.T, r *streamRig, _ string) {
				status, _ := confirm(t, r, true)
				assert.NotEqual(t, http.StatusNoContent, status)
			},
		}

		if !emailed {
			rig.change = func(t *testing.T, r *streamRig, _ string) {
				status, _ := confirm(t, r, false)
				require.Equal(t, http.StatusNoContent, status)
			}

			return rig
		}

		rig.partial = func(t *testing.T, r *streamRig, _ string) {
			status, sid := confirm(t, r, false)
			require.Equal(t, http.StatusNoContent, status, "the device is proved and the code is emailed")
			require.NotEmpty(t, sender.sent)

			pendingSID = sid
		}
		rig.change = func(t *testing.T, r *streamRig, _ string) {
			code := sixDigits.FindString(sender.sent[len(sender.sent)-1].TextBody)
			require.NotEmpty(t, code)
			require.Equal(t, http.StatusNoContent, r.callAs(t, pendingSID, enrolEmailPath, "code="+code))
		}

		return rig
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

	type testCase struct {
		name string
		// withoutSignals builds the chain without EnableSessionSignals, so there is no stream.
		withoutSignals bool
		assert         func(t *testing.T, status int, stream *riggedStream)
	}

	cases := []testCase{
		{
			// A closed hub refuses with ErrSignalsBusy, as a full bus does.
			name: "a hub that refuses the signal",
			assert: func(t *testing.T, status int, stream *riggedStream) {
				assert.Equal(t, http.StatusNoContent, status)
				assert.Empty(t, stream.events("credential_changed"))
			},
		},
		{
			name:           "a chain without signals",
			withoutSignals: true,
			assert: func(t *testing.T, status int, _ *riggedStream) {
				assert.Equal(t, http.StatusNoContent, status)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				if tc.withoutSignals {
					tc.assert(t, withoutSignalsStatus(t, changeOpts, changePath), nil)

					return
				}

				r := newStreamRig(t, streamSetup{signals: sourcesSignals, opts: changeOpts})
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				httpsec.SignalHubProbeOf(r.chain).Close()

				tc.assert(t, r.callAs(t, s.ID, changePath, "change"), stream)
			})
		})
	}
}

// withoutSignalsStatus serves one request to path, as a fresh sign-in of u-1, on a chain built
// from opts without session signals, and returns the status. It fails on a panic.
func withoutSignalsStatus(t *testing.T, opts func(r *streamRig) []httpsec.Option, path string) int {
	t.Helper()

	sessions, err := session.New()
	require.NoError(t, err)

	r := &streamRig{sessions: sessions, users: newUsers(t)}
	chain, err := httpsec.New(append(opts(r),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: r.users}))...)
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader("change"))
	req.Header.Set("Authorization", "Bearer "+s.ID)

	rec := httptest.NewRecorder()

	require.NotPanics(t, func() {
		chain.Middleware()(http.NotFoundHandler()).ServeHTTP(rec, req)
	})

	return rec.Code
}

// recoveryHolds is which authenticators the recovering user holds, each of a different kind.
type recoveryHolds struct{ secondFactor, passkey, device bool }

// everything is the user holding one of each.
var everything = recoveryHolds{secondFactor: true, passkey: true, device: true}

// recoveryWorld is the stores a recovery row's chain reads: a real MFA kind and a real passkey
// kind, and a consumer's own kind, each holding or not as the row says.
type recoveryWorld struct {
	codes  *recovery.Codes
	sender *capturingSender
	kinds  []recovery.AuthenticatorKind
}

func newRecoveryWorld(t *testing.T, holds recoveryHolds) *recoveryWorld {
	t.Helper()

	w := &recoveryWorld{sender: &capturingSender{}}

	var err error

	w.codes, err = recovery.NewCodes()
	require.NoError(t, err)

	method, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "scrty-test")
	require.NoError(t, err)

	if holds.secondFactor {
		prov, err := method.BeginEnrolment(t.Context(), "u-1", testUsername)
		require.NoError(t, err)

		code, err := totp.GenerateCode(prov.Secret, time.Now())
		require.NoError(t, err)
		require.NoError(t, method.ConfirmEnrolment(t.Context(), "u-1", code))
	}

	mfaKind, err := recovery.MFAEnrolments(method)
	require.NoError(t, err)

	creds := passkey.NewMemoryCredentialStore()

	if holds.passkey {
		cid, err := id.NewV7Generator().NewID()
		require.NoError(t, err)

		require.NoError(t, creds.Insert(t.Context(), &passkey.Credential{
			ID: cid, User: "u-1", CredentialID: []byte("cred-r"), PublicKey: []byte("key"),
			Name: "Laptop", CreatedAt: time.Now().UTC().Truncate(time.Second), State: passkey.StateActive,
		}))
	}

	device := NewMockAuthenticatorKind(gomock.NewController(t))
	device.EXPECT().Kind().Return("app-device").AnyTimes()
	device.EXPECT().Remove(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	device.EXPECT().Held(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, identity.UserID) ([]recovery.AuthenticatorRef, error) {
			if !holds.device {
				return nil, nil
			}

			return []recovery.AuthenticatorRef{{Kind: "app-device", ID: "device-1"}}, nil
		}).AnyTimes()

	w.kinds = []recovery.AuthenticatorKind{mfaKind, passkey.NewRecoveryKind(creds), device}

	return w
}

// opts are the chain options of a recovery over the world, with core as further core options.
func (w *recoveryWorld) opts(core ...recovery.Option) func(r *streamRig) []httpsec.Option {
	return func(r *streamRig) []httpsec.Option {
		r.users.EXPECT().LoadByUsername(gomock.Any(), testUsername).AnyTimes().
			DoAndReturn(func(context.Context, string) (*identity.Details, error) { return storedUser(), nil })

		// The recovered session is bound by a password change, which no row here makes.
		bind := httpsec.EnablePasswordChangeGate(r.sessions,
			httpsec.WithPasswordChangeEndpoint("/account/password", func(*httpsec.Exchange) error { return errSourceRefused }))

		return []httpsec.Option{bind, httpsec.EnableAccountRecovery(
			httpsec.RecoveryDeps{Users: r.users, Sessions: r.sessions, Sender: w.sender, Codes: w.codes},
			httpsec.WithRecoveryCore(append([]recovery.Option{
				recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
				recovery.WithRepudiationContact("Write to security@example.com if this was not you."),
				recovery.WithAuthenticatorKinds(w.kinds...),
				recovery.WithMessages(recoveryMessages{}),
			}, core...)...))}
	}
}

// form is a complete request's body, with a saved code of the user's set and the issued code a
// start sent, or a code that is neither when wrong.
func (w *recoveryWorld) form(t *testing.T, r *streamRig, wrong bool) string {
	t.Helper()

	set, err := w.codes.Generate(t.Context(), "u-1")
	require.NoError(t, err)

	require.Equal(t, http.StatusAccepted, r.callAs(t, "", httpsec.DefaultRecoveryStartPath,
		url.Values{httpsec.RecoveryUsernameParam: {testUsername}}.Encode()))
	require.NotEmpty(t, w.sender.sent)

	saved, issued := set[0], w.sender.sent[len(w.sender.sent)-1].TextBody
	if wrong {
		saved = "not-a-saved-code"
	}

	return url.Values{
		httpsec.RecoveryUsernameParam: {testUsername}, httpsec.RecoverySavedCodeParam: {saved},
		httpsec.RecoveryIssuedCodeParam: {issued},
	}.Encode()
}

// TestSessionSignals_CredentialChanged_Recovery shows a recovery tells the streams that stay
// open which kinds of credential it removed, once each and only the kinds the signal names,
// and tells them nothing when it removed nothing, was held or was refused.
func TestSessionSignals_CredentialChanged_Recovery(t *testing.T) {
	t.Parallel()

	keep := recovery.WithoutSessionRevocation()

	type testCase struct {
		name  string
		holds recoveryHolds
		core  []recovery.Option
		// wrong sends a saved code that is not the user's.
		wrong bool
		// closeHub closes the signal hub before the request, so a raise is refused.
		closeHub bool
		// withoutSignals builds the chain without EnableSessionSignals, so there is no stream.
		withoutSignals bool
		assert         func(t *testing.T, status int, streams []*riggedStream)
	}

	cases := []testCase{
		{
			name:  "a second factor and a passkey removed, on streams the recovery leaves open",
			holds: everything,
			core:  []recovery.Option{keep},
			assert: func(t *testing.T, status int, streams []*riggedStream) {
				require.Equal(t, http.StatusOK, status)

				for i, s := range streams {
					got := s.events("credential_changed")
					require.Len(t, got, 2, "stream %d", i)
					assert.JSONEq(t, `{"kind":"second_factor"}`, got[0].Data, "stream %d", i)
					assert.JSONEq(t, `{"kind":"passkey"}`, got[1].Data, "stream %d", i)
					assert.Equal(t, []string{"session", "credential_changed", "credential_changed"}, s.sent(), "stream %d", i)
				}
			},
		},
		{
			name:  "by default the other sign-ins end, and their streams hear session_ended only",
			holds: everything,
			assert: func(t *testing.T, status int, streams []*riggedStream) {
				require.Equal(t, http.StatusOK, status)

				for i, s := range streams {
					assert.Empty(t, s.events("credential_changed"), "stream %d", i)
					assert.Equal(t, []string{"session", "session_ended"}, s.sent(), "stream %d", i)
					assert.True(t, s.closed(), "stream %d", i)
				}
			},
		},
		{
			name: "a recovery that removes nothing raises nothing",
			core: []recovery.Option{keep},
			assert: func(t *testing.T, status int, streams []*riggedStream) {
				require.Equal(t, http.StatusOK, status)
				requireNoneSent(t, streams)
			},
		},
		{
			name:  "only a consumer's own kind removed raises nothing",
			holds: recoveryHolds{device: true},
			core:  []recovery.Option{keep},
			assert: func(t *testing.T, status int, streams []*riggedStream) {
				require.Equal(t, http.StatusOK, status)
				requireNoneSent(t, streams)
			},
		},
		{
			name:  "a reset policy that keeps everything raises nothing",
			holds: everything,
			core: []recovery.Option{keep, recovery.WithResetPolicy(
				func(context.Context, recovery.ResetInput) ([]recovery.AuthenticatorRef, error) { return nil, nil })},
			assert: func(t *testing.T, status int, streams []*riggedStream) {
				require.Equal(t, http.StatusOK, status)
				requireNoneSent(t, streams)
			},
		},
		{
			name:  "a held recovery raises nothing at the hold",
			holds: everything,
			core: []recovery.Option{keep, recovery.WithHoldDelay(time.Hour),
				recovery.WithCancelLink("https://app.example.com/cancel")},
			assert: func(t *testing.T, status int, streams []*riggedStream) {
				require.Equal(t, http.StatusAccepted, status)
				requireNoneSent(t, streams)
			},
		},
		{
			name:  "a refused recovery raises nothing",
			holds: everything,
			core:  []recovery.Option{keep},
			wrong: true,
			assert: func(t *testing.T, status int, streams []*riggedStream) {
				assert.NotEqual(t, http.StatusOK, status)
				requireNoneSent(t, streams)
			},
		},
		{
			name:     "a signal that cannot be raised changes no answer",
			holds:    everything,
			core:     []recovery.Option{keep},
			closeHub: true,
			assert: func(t *testing.T, status int, streams []*riggedStream) {
				assert.Equal(t, http.StatusOK, status)
				assert.Empty(t, streams[0].events("credential_changed"))
			},
		},
		{
			name:           "a chain without signals changes no answer",
			holds:          everything,
			core:           []recovery.Option{keep},
			withoutSignals: true,
			assert: func(t *testing.T, status int, _ []*riggedStream) {
				assert.Equal(t, http.StatusOK, status)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				w := newRecoveryWorld(t, tc.holds)

				if tc.withoutSignals {
					tc.assert(t, recoveryStatusWithoutSignals(t, w, tc.core), nil)

					return
				}

				r := newStreamRig(t, streamSetup{signals: sourcesSignals, opts: w.opts(tc.core...)})
				first, second := r.signIn(t), r.signIn(t)
				streams := []*riggedStream{r.open(t, first.ID), r.open(t, second.ID)}

				if tc.closeHub {
					httpsec.SignalHubProbeOf(r.chain).Close()
				}

				body := w.form(t, r, tc.wrong)

				tc.assert(t, r.callAs(t, "", httpsec.DefaultRecoveryCompletePath, body), streams)
			})
		})
	}
}

// recoveryStatusWithoutSignals serves a complete request on a recovery chain with no session
// signals, and returns its status.
func recoveryStatusWithoutSignals(t *testing.T, w *recoveryWorld, core []recovery.Option) int {
	t.Helper()

	sessions, err := session.New()
	require.NoError(t, err)

	r := &streamRig{sessions: sessions, users: newUsers(t)}
	chain, err := httpsec.New(append(w.opts(core...)(r),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: r.users}))...)
	require.NoError(t, err)

	serve := func(path string, values url.Values) (int, string) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = streamClient + ":4242"

		rec := httptest.NewRecorder()

		require.NotPanics(t, func() { chain.Middleware()(http.NotFoundHandler()).ServeHTTP(rec, req) })

		return rec.Code, rec.Body.String()
	}

	set, err := w.codes.Generate(t.Context(), "u-1")
	require.NoError(t, err)

	user := url.Values{httpsec.RecoveryUsernameParam: {testUsername}}
	status, _ := serve(httpsec.DefaultRecoveryStartPath, user)
	require.Equal(t, http.StatusAccepted, status)

	user.Set(httpsec.RecoverySavedCodeParam, set[0])
	user.Set(httpsec.RecoveryIssuedCodeParam, w.sender.sent[len(w.sender.sent)-1].TextBody)

	status, _ = serve(httpsec.DefaultRecoveryCompletePath, user)

	return status
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
