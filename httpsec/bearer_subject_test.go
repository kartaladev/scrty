package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// subjectStore is a session store that counts the activity written to it and,
// once loadErr is set, fails every load with it.
type subjectStore struct {
	session.Store

	activity atomic.Int32
	loadErr  atomic.Pointer[error]
}

func (s *subjectStore) Load(ctx context.Context, id string) (*session.Session, error) {
	if err := s.loadErr.Load(); err != nil {
		return nil, *err
	}

	return s.Store.Load(ctx, id)
}

func (s *subjectStore) RecordActivity(ctx context.Context, id string, lastAccessed, idleExpires, olderThan time.Time) error {
	s.activity.Add(1)

	return s.Store.RecordActivity(ctx, id, lastAccessed, idleExpires, olderThan)
}

// subjectWorld is a chain with signed bearer tokens and a renewal endpoint over
// a memory-store manager with unused-successor recovery, on a fake clock. Its
// user loader expects nothing until a row says so, so a reload the row does not
// expect fails the row.
type subjectWorld struct {
	t        *testing.T
	clk      *clockwork.FakeClock
	store    *subjectStore
	sessions *session.Sessions
	users    *MockUserLoader
	gen      *token.JWTGenerator
	chain    *httpsec.Chain

	// claims, when set, is what the verifier reports for any token, standing in
	// for a consumer's verifier that reports a token no generator here issues.
	claims atomic.Pointer[token.Claims]

	// signInsBefore is the user's sign-ins before a row's refused renewal.
	signInsBefore []session.SignIn

	// phaseRuns counts the per-request phase's evaluations.
	phaseRuns atomic.Int32
}

func newSubjectWorld(t *testing.T, usernames, dpop bool, extra ...httpsec.Option) *subjectWorld {
	t.Helper()

	clk := clockwork.NewFakeClockAt(dpopNow)
	store := &subjectStore{Store: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))}
	sessions := must.Must(session.New(session.WithClock(clk), session.WithUnusedSuccessorRecovery(),
		session.WithStore(store)))

	keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	require.NoError(t, err)

	genOpts := []token.Option{token.WithoutIssuer(), token.WithoutAudience(), token.WithClock(clk)}
	var bearerOpts []httpsec.BearerTokenOption
	if usernames {
		genOpts = append(genOpts, token.WithUsernameSubject())
		bearerOpts = append(bearerOpts, httpsec.WithBearerUsernameSubject())
	}

	w := &subjectWorld{
		t: t, clk: clk, store: store, sessions: sessions,
		users: NewMockUserLoader(gomock.NewController(t)),
		gen:   must.Must(token.NewGenerator(keys, genOpts...)),
	}

	verifier := NewMockVerifier(gomock.NewController(t))
	verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, presented string) (*token.Claims, error) {
			if c := w.claims.Load(); c != nil {
				return c, nil
			}

			return w.gen.Verify(ctx, presented)
		})

	phase := NewMockPolicy(gomock.NewController(t))
	phase.EXPECT().Name().Return("test: per-request counter").AnyTimes()
	phase.EXPECT().Phases().Return([]policy.Phase{policy.PerRequest}).AnyTimes()
	phase.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, *policy.Input) policy.Decision {
			w.phaseRuns.Add(1)

			return policy.Decision{Outcome: policy.Allow}
		})

	opts := []httpsec.Option{
		httpsec.WithClock(clk),
		httpsec.WithLogger(slog.New(slog.DiscardHandler)),
		httpsec.WithPolicyEngine(engineOf(t, phase)),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: verifier, Sessions: sessions, Users: w.users}, bearerOpts...),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: w.users, Tokens: w.gen}),
	}
	if dpop {
		opts = append(opts, httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}))
	}
	opts = append(opts, extra...)

	w.chain, err = httpsec.New(opts...)
	require.NoError(t, err)

	return w
}

// signIn creates a session of u-1's, with the given binding.
func (w *subjectWorld) signIn(binding session.KeyBinding) string {
	w.t.Helper()

	opts := []session.CreateOption{session.WithFirstFactor(factor.Password)}
	if !binding.IsZero() {
		opts = append(opts, session.WithKeyBinding(binding))
	}

	s, err := w.sessions.Create(w.t.Context(), "u-1", opts...)
	require.NoError(w.t, err)

	return s.ID
}

// tokenFor is a token naming the session sid with subject as its sub, whichever
// value the world's generator writes, and cnf as its confirmation.
func (w *subjectWorld) tokenFor(sid, subject string, cnf token.Confirmation) string {
	w.t.Helper()

	tok, err := w.gen.GenerateWith(w.t.Context(), sid,
		&identity.Principal{ID: identity.UserID(subject), Username: subject}, token.WithConfirmation(cnf))
	require.NoError(w.t, err)

	return tok
}

// get presents credential on an application route, under the given scheme.
func (w *subjectWorld) get(scheme, credential string, proofs ...string) served {
	w.t.Helper()

	req := dpopRequest(w.t, http.MethodGet, "http://example.com/api/orders", proofs...)
	req.Header.Set("Authorization", scheme+" "+credential)

	return serve(w.t, w.chain, req)
}

// renew posts a renewal presenting credential as a plain bearer token.
func (w *subjectWorld) renew(credential string) served {
	w.t.Helper()

	req := postValues(w.t.Context(), httpsec.DefaultSessionRenewalPath, e2eSource, nil)
	req.Header.Set("Authorization", "Bearer "+credential)

	return serve(w.t, w.chain, req)
}

// late signs in, renews once with a token whose subject is own, leaves the
// successor unused and moves past the grace window, and returns the renewed
// session: one only a late renewal may recover. It also keeps the user's
// sign-ins as they then stand, for noSuccessor.
func (w *subjectWorld) late(own string) string {
	w.t.Helper()

	sid := w.signIn(session.KeyBinding{})

	out := w.renew(w.tokenFor(sid, own, token.Confirmation{}))
	require.NoError(w.t, out.err)

	w.clk.Advance(session.DefaultRenewalGrace + time.Second)

	var err error
	w.signInsBefore, err = w.sessions.ListSignIns(w.t.Context(), "u-1", nil)
	require.NoError(w.t, err)

	return sid
}

// noSuccessor asserts the user's sign-ins are as late left them.
func (w *subjectWorld) noSuccessor() {
	w.t.Helper()

	signIns, err := w.sessions.ListSignIns(w.t.Context(), "u-1", nil)
	require.NoError(w.t, err)
	assert.Equal(w.t, w.signInsBefore, signIns, "no successor is created")
}

// stillStored asserts sid was not revoked.
func (w *subjectWorld) stillStored(sid string) {
	w.t.Helper()

	stored, err := w.sessions.Load(w.t.Context(), sid)
	require.NoError(w.t, err, "the refused session is still stored")
	assert.Equal(w.t, identity.UserID("u-1"), stored.UserID)
}

// alice is u-1's stored record, under the given username.
func alice(username string) *identity.Details {
	return &identity.Details{ID: "u-1", Username: username, Active: true}
}

// asPrincipal asserts out reached the handler as u-1, named username.
func asPrincipal(t *testing.T, out served, username string) {
	t.Helper()

	require.NoError(t, out.err)
	require.True(t, out.handlerRan)

	auth, ok := authenticate.AuthenticationFromContext(out.handled.Context())
	require.True(t, ok)
	assert.Equal(t, identity.UserID("u-1"), auth.Principal.ID)
	assert.Equal(t, username, auth.Principal.Username)
}

// TestBearer_SubjectIsTheSessionUser pins how a signed bearer reads a verified
// token's subject: by default it must be the user reference the session records
// and the user is reloaded by that reference, and under
// WithBearerUsernameSubject the user is reloaded by the username it names. A
// loader call a row does not expect fails that row.
func TestBearer_SubjectIsTheSessionUser(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	other := newDPoPKey(t, elliptic.P256())
	cert := newClientCert(t, "subject-cert")
	otherCert := newClientCert(t, "subject-other-cert")
	errStoreDown := errors.New("session store down")
	errUsersDown := errors.New("user store down")

	// subjectRefused asserts the refusal a subject earns, and that it left
	// nothing behind: the session stored, no activity, no per-request phase.
	subjectRefused := func(t *testing.T, w *subjectWorld, sid string, out served) {
		t.Helper()

		refusedBeforeHandler(t, out, "a token whose subject is refused reached the handler")
		assert.Zero(t, w.store.activity.Load(), "no activity is recorded")
		assert.Zero(t, w.phaseRuns.Load(), "the per-request phase does not run")
		w.stillStored(sid)
	}

	type testCase struct {
		name      string
		usernames bool
		dpop      bool
		extra     []httpsec.Option
		act       func(t *testing.T, w *subjectWorld) (string, served)
		assert    func(t *testing.T, w *subjectWorld, sid string, out served)
	}

	// presenting is an act presenting a plain token for a new session.
	presenting := func(subject string, expect func(w *subjectWorld)) func(*testing.T, *subjectWorld) (string, served) {
		return func(_ *testing.T, w *subjectWorld) (string, served) {
			if expect != nil {
				expect(w)
			}

			sid := w.signIn(session.KeyBinding{})

			return sid, w.get("Bearer", w.tokenFor(sid, subject, token.Confirmation{}))
		}
	}
	// noSubject is an act presenting a verified token with no subject.
	noSubject := func(_ *testing.T, w *subjectWorld) (string, served) {
		sid := w.signIn(session.KeyBinding{})
		w.claims.Store(token.NewClaims("", sid))

		return sid, w.get("Bearer", "any.verified.token")
	}
	refusedKept := func(t *testing.T, w *subjectWorld, sid string, out served) {
		t.Helper()

		refusedBeforeHandler(t, out, "the user is gone or is someone else")
		w.stillStored(sid)
	}
	// namedAway is a loader under usernames on which alice signs in, and the
	// username then answers as next does for every later load.
	namedAway := func(next func(c *MockUserLoaderLoadByUsernameCall)) func(*subjectWorld) {
		return func(w *subjectWorld) {
			first := w.users.EXPECT().LoadByUsername(gomock.Any(), "alice").Return(alice("alice"), nil).Times(1)
			later := w.users.EXPECT().LoadByUsername(gomock.Any(), "alice")
			later.Call = later.AnyTimes().After(first)
			next(later)
		}
	}
	// lateUnderUsernames is an act presenting a token with the given subject for
	// a session of alice's that only a late renewal may recover.
	lateUnderUsernames := func(subject string, expect func(w *subjectWorld)) func(*testing.T, *subjectWorld) (string, served) {
		return func(_ *testing.T, w *subjectWorld) (string, served) {
			w.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(alice("alice"), nil).AnyTimes()
			expect(w)

			sid := w.late("alice")

			return sid, w.renew(w.tokenFor(sid, subject, token.Confirmation{}))
		}
	}
	lateRefused := func(t *testing.T, w *subjectWorld, _ string, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
		w.noSuccessor()
	}
	// dependencyFailure asserts a failed username load is answered as an outage.
	dependencyFailure := func(t *testing.T, out served) {
		t.Helper()

		assert.False(t, out.handlerRan)
		require.ErrorIs(t, out.err, errUsersDown)
		assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
		assert.NotContains(t, out.err.Error(), errUsersDown.Error(), "the loader's text stays out of the error")
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
	}
	// certBound is an act presenting, over a connection holding cert, a token
	// with the given subject whose cnf is cert, for a session bound to otherCert.
	certBound := func(subject string) func(*testing.T, *subjectWorld) (string, served) {
		return func(_ *testing.T, w *subjectWorld) (string, served) {
			sid := w.signIn(session.KeyBinding{X5TS256: otherCert.thumb})

			req := dpopRequest(w.t, http.MethodGet, "http://example.com/api/orders")
			req.Header.Set("Authorization", "Bearer "+w.tokenFor(sid, subject, token.Confirmation{X5TS256: cert.thumb}))

			return sid, serve(w.t, w.chain, withConnectionCert(req, cert))
		}
	}
	// keyBound is an act presenting a token with the given subject, proved with
	// key, for a session bound to the other key.
	keyBound := func(subject string) func(*testing.T, *subjectWorld) (string, served) {
		return func(_ *testing.T, w *subjectWorld) (string, served) {
			sid := w.signIn(session.KeyBinding{JKT: other.jkt})
			tok := w.tokenFor(sid, subject, token.Confirmation{JKT: key.jkt})
			proof := key.validProof("j-binding").with(map[string]any{"ath": tokenHash(tok)}).sign(w.t)

			return sid, w.get("DPoP", tok, proof)
		}
	}
	proofRefused := func(t *testing.T, _ *subjectWorld, _ string, out served) {
		t.Helper()

		assert.False(t, out.handlerRan)
		require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof, "the wrong sender is answered as that")
		assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
	}
	certRefused := func(t *testing.T, _ *subjectWorld, _ string, out served) {
		t.Helper()

		assert.False(t, out.handlerRan)
		require.ErrorIs(t, out.err, httpsec.ErrCertificateBinding, "the wrong sender is answered as that")
		assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
	}

	cases := []testCase{
		{
			name: "Default token reloads the session's user",
			act: presenting("u-1", func(w *subjectWorld) {
				w.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(alice("alice"), nil)
			}),
			assert: func(t *testing.T, w *subjectWorld, _ string, out served) {
				t.Helper()

				asPrincipal(t, out, "alice")
				assert.Equal(t, int32(1), w.phaseRuns.Load(), "the per-request phase ran")
			},
		},
		{
			name:   "Subject is not the session's user",
			act:    presenting("u-2", nil),
			assert: subjectRefused,
		},
		{
			name:      "Consumer reads the subject as a username",
			usernames: true,
			act: presenting("alice", func(w *subjectWorld) {
				w.users.EXPECT().LoadByUsername(gomock.Any(), "alice").Return(alice("alice"), nil)
			}),
			assert: func(t *testing.T, _ *subjectWorld, _ string, out served) {
				t.Helper()

				asPrincipal(t, out, "alice")
			},
		},
		{
			name:      "Username reassigned to another user",
			usernames: true,
			act: presenting("alice", func(w *subjectWorld) {
				w.users.EXPECT().LoadByUsername(gomock.Any(), "alice").
					Return(&identity.Details{ID: "u-2", Username: "alice", Active: true}, nil)
			}),
			assert: refusedKept,
		},
		{
			name: "Session's user no longer exists",
			act: presenting("u-1", func(w *subjectWorld) {
				w.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
					Return(nil, fmt.Errorf("gone: %w", identity.ErrUserNotFound))
			}),
			assert: refusedKept,
		},
		{
			name:      "Named username no longer exists",
			usernames: true,
			act: presenting("alice", func(w *subjectWorld) {
				w.users.EXPECT().LoadByUsername(gomock.Any(), "alice").
					Return(nil, fmt.Errorf("gone: %w", identity.ErrUserNotFound))
			}),
			assert: refusedKept,
		},
		{
			name:   "Token with no subject, default",
			act:    noSubject,
			assert: subjectRefused,
		},
		{
			name:      "Token with no subject, usernames",
			usernames: true,
			act:       noSubject,
			assert:    subjectRefused,
		},
		{
			name: "Subject refusal consumes no proof",
			dpop: true,
			act: func(_ *testing.T, w *subjectWorld) (string, served) {
				sid := w.signIn(session.KeyBinding{JKT: key.jkt})
				tok := w.tokenFor(sid, "u-2", token.Confirmation{JKT: key.jkt})
				proof := key.validProof("j-subject").with(map[string]any{"ath": tokenHash(tok)}).sign(w.t)

				first := w.get("DPoP", tok, proof)
				require.ErrorIs(w.t, first.err, httpsec.ErrAuthenticationRequired)

				// A recorded proof would be refused as a replay here.
				return sid, w.get("DPoP", tok, proof)
			},
			assert: func(t *testing.T, w *subjectWorld, sid string, out served) {
				t.Helper()

				assert.NotErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof, "the first refusal recorded the proof")
				subjectRefused(t, w, sid, out)
			},
		},
		{
			name:   "Binding judged before the subject, by DPoP key",
			dpop:   true,
			act:    keyBound("u-2"),
			assert: proofRefused,
		},
		{
			name:   "Binding judged before the subject, by certificate",
			extra:  []httpsec.Option{httpsec.EnableCertificateBinding()},
			act:    certBound("u-2"),
			assert: certRefused,
		},
		{
			// No loader call is expected: a wrong sender costs no user load.
			name:      "Binding judged before the subject under usernames, by DPoP key",
			usernames: true,
			dpop:      true,
			act:       keyBound("mallory"),
			assert:    proofRefused,
		},
		{
			name:      "Binding judged before the subject under usernames, by certificate",
			usernames: true,
			extra:     []httpsec.Option{httpsec.EnableCertificateBinding()},
			act:       certBound("mallory"),
			assert:    certRefused,
		},
		{
			name: "Session load precedes the subject check",
			act: func(_ *testing.T, w *subjectWorld) (string, served) {
				sid := w.signIn(session.KeyBinding{})
				w.store.loadErr.Store(&errStoreDown)

				return sid, w.get("Bearer", w.tokenFor(sid, "u-2", token.Confirmation{}))
			},
			assert: func(t *testing.T, _ *subjectWorld, _ string, out served) {
				t.Helper()

				assert.False(t, out.handlerRan)
				require.ErrorIs(t, out.err, errStoreDown)
				assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "Subject refusal keeps the session",
			act:  presenting("u-2", nil),
			assert: func(t *testing.T, w *subjectWorld, sid string, out served) {
				t.Helper()

				subjectRefused(t, w, sid, out)

				// The session answers its own user afterwards, unharmed.
				w.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(alice("alice"), nil)
				asPrincipal(t, w.get("Bearer", w.tokenFor(sid, "u-1", token.Confirmation{})), "alice")
			},
		},
		{
			name: "Late renewal with a subject that is not the session's user",
			act: func(_ *testing.T, w *subjectWorld) (string, served) {
				w.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(alice("alice"), nil).AnyTimes()
				sid := w.late("u-1")

				return sid, w.renew(w.tokenFor(sid, "u-2", token.Confirmation{}))
			},
			assert: func(t *testing.T, w *subjectWorld, sid string, out served) {
				t.Helper()

				lateRefused(t, w, sid, out)

				// The same session's own token recovers it, so nothing was spent.
				recovered := w.renew(w.tokenFor(sid, "u-1", token.Confirmation{}))
				require.NoError(t, recovered.err, "a late renewal naming the session's own user recovers it")
				assert.Equal(t, http.StatusOK, recovered.rec.Code)
			},
		},
		{
			name:      "Late renewal under usernames with a username that is not the session's user's: renamed",
			usernames: true,
			act: lateUnderUsernames("alice", namedAway(func(c *MockUserLoaderLoadByUsernameCall) {
				c.Return(nil, fmt.Errorf("renamed: %w", identity.ErrUserNotFound))
			})),
			assert: lateRefused,
		},
		{
			name:      "Late renewal under usernames with a username that is not the session's user's: reassigned",
			usernames: true,
			act: lateUnderUsernames("alice", namedAway(func(c *MockUserLoaderLoadByUsernameCall) {
				c.Return(&identity.Details{ID: "u-2", Username: "alice", Active: true}, nil)
			})),
			assert: lateRefused,
		},
		{
			name:      "Late renewal under usernames with a username that is not the session's user's: belongs to u-2",
			usernames: true,
			act: lateUnderUsernames("mallory", func(w *subjectWorld) {
				w.users.EXPECT().LoadByUsername(gomock.Any(), "alice").Return(alice("alice"), nil).AnyTimes()
				w.users.EXPECT().LoadByUsername(gomock.Any(), "mallory").
					Return(&identity.Details{ID: "u-2", Username: "mallory", Active: true}, nil)
			}),
			assert: func(t *testing.T, w *subjectWorld, sid string, out served) {
				t.Helper()

				lateRefused(t, w, sid, out)

				// The session's own token recovers it, so nothing was spent.
				recovered := w.renew(w.tokenFor(sid, "alice", token.Confirmation{}))
				require.NoError(t, recovered.err, "a late renewal naming the session's own user recovers it")
				assert.Equal(t, http.StatusOK, recovered.rec.Code)
			},
		},
		{
			name:      "Late renewal under usernames with a loader that found no user",
			usernames: true,
			act: lateUnderUsernames("alice", namedAway(func(c *MockUserLoaderLoadByUsernameCall) {
				c.Return(nil, nil)
			})),
			assert: lateRefused,
		},
		{
			name:      "Late renewal under usernames with the session's user's own username",
			usernames: true,
			act: lateUnderUsernames("alice", func(w *subjectWorld) {
				w.users.EXPECT().LoadByUsername(gomock.Any(), "alice").Return(alice("alice"), nil).Times(2)
			}),
			assert: func(t *testing.T, _ *subjectWorld, _ string, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name:      "Late renewal under usernames when the username cannot be loaded",
			usernames: true,
			act: lateUnderUsernames("alice", namedAway(func(c *MockUserLoaderLoadByUsernameCall) {
				c.Return(nil, errUsersDown)
			})),
			assert: func(t *testing.T, w *subjectWorld, _ string, out served) {
				t.Helper()

				dependencyFailure(t, out)
				w.noSuccessor()
			},
		},
		{
			name:      "Subject refusal under usernames consumes no proof",
			usernames: true,
			dpop:      true,
			act: func(_ *testing.T, w *subjectWorld) (string, served) {
				w.users.EXPECT().LoadByUsername(gomock.Any(), "mallory").
					Return(&identity.Details{ID: "u-2", Username: "mallory", Active: true}, nil).Times(2)

				sid := w.signIn(session.KeyBinding{JKT: key.jkt})
				tok := w.tokenFor(sid, "mallory", token.Confirmation{JKT: key.jkt})
				proof := key.validProof("j-usernames").with(map[string]any{"ath": tokenHash(tok)}).sign(w.t)

				first := w.get("DPoP", tok, proof)
				require.ErrorIs(w.t, first.err, httpsec.ErrAuthenticationRequired)

				// A recorded proof would be refused as a replay here.
				return sid, w.get("DPoP", tok, proof)
			},
			assert: func(t *testing.T, w *subjectWorld, sid string, out served) {
				t.Helper()

				assert.NotErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof, "the first refusal recorded the proof")
				subjectRefused(t, w, sid, out)
			},
		},
		{
			name:      "A username that cannot be loaded consumes no proof",
			usernames: true,
			dpop:      true,
			act: func(_ *testing.T, w *subjectWorld) (string, served) {
				w.users.EXPECT().LoadByUsername(gomock.Any(), "alice").Return(nil, errUsersDown).Times(2)

				sid := w.signIn(session.KeyBinding{JKT: key.jkt})
				tok := w.tokenFor(sid, "alice", token.Confirmation{JKT: key.jkt})
				proof := key.validProof("j-usernames-down").with(map[string]any{"ath": tokenHash(tok)}).sign(w.t)

				dependencyFailure(w.t, w.get("DPoP", tok, proof))

				// A recorded proof would be refused as a replay here.
				return sid, w.get("DPoP", tok, proof)
			},
			assert: func(t *testing.T, w *subjectWorld, sid string, out served) {
				t.Helper()

				dependencyFailure(t, out)
				w.stillStored(sid)
			},
		},
		{
			name:      "A username whose load the request's own end cut short",
			usernames: true,
			act: func(_ *testing.T, w *subjectWorld) (string, served) {
				ctx, cancel := context.WithCancel(w.t.Context())
				w.t.Cleanup(cancel)

				w.users.EXPECT().LoadByUsername(gomock.Any(), "alice").
					DoAndReturn(func(context.Context, string) (*identity.Details, error) {
						cancel()

						return nil, ctx.Err()
					})

				sid := w.signIn(session.KeyBinding{})

				req := dpopRequest(w.t, http.MethodGet, "http://example.com/api/orders")
				req.Header.Set("Authorization", "Bearer "+w.tokenFor(sid, "alice", token.Confirmation{}))

				return sid, serveContext(ctx, w.t, w.chain, req.WithContext(ctx))
			},
			assert: func(t *testing.T, _ *subjectWorld, _ string, out served) {
				t.Helper()

				assert.False(t, out.handlerRan)
				require.ErrorIs(t, out.err, context.Canceled)
				assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				// A hang-up, not an outage: the loader returned the context's own
				// error, which classifyReload leaves as it is rather than word as
				// the dependency failure it would otherwise be.
				assert.NotEqual(t, textUserNotReloaded, out.err.Error())
			},
		},
		{
			name: "Rename keeps a live token working",
			act: presenting("u-1", func(w *subjectWorld) {
				w.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(alice("ana"), nil)
			}),
			assert: func(t *testing.T, _ *subjectWorld, _ string, out served) {
				t.Helper()

				asPrincipal(t, out, "ana")
			},
		},
		{
			name:      "Rename under the username subject",
			usernames: true,
			act: presenting("alice", func(w *subjectWorld) {
				w.users.EXPECT().LoadByUsername(gomock.Any(), "alice").
					Return(nil, fmt.Errorf("renamed: %w", identity.ErrUserNotFound))
			}),
			assert: refusedKept,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newSubjectWorld(t, tc.usernames, tc.dpop, tc.extra...)
			sid, out := tc.act(t, w)
			tc.assert(t, w, sid, out)
		})
	}
}

// subjectEntryPoint is one place a chain is given a token generator.
type subjectEntryPoint struct {
	name, field string

	// opts enables the entry point with g, and anything else it needs with a
	// generator in the default mode.
	opts func(t *testing.T, g, ok token.Generator) []httpsec.Option
}

// subjectEntryPoints are all eight places a chain is given a token generator.
func subjectEntryPoints() []subjectEntryPoint {
	totpLike := func(t *testing.T) mfa.Method {
		t.Helper()

		method := NewMockMethod(gomock.NewController(t))
		method.EXPECT().Name().Return("totp").AnyTimes()
		method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
		method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
		method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

		return method
	}

	return []subjectEntryPoint{
		{
			name: "form login", field: "FormLoginDeps.Tokens",
			opts: func(t *testing.T, g, _ token.Generator) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: NewMockAuthenticator(gomock.NewController(t)),
					Sessions:      dpopSessions(t, clockwork.NewFakeClockAt(dpopNow)),
					Tokens:        g,
					Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
				})}
			},
		},
		{
			name: "session renewal", field: "SessionRenewalDeps.Tokens",
			opts: func(t *testing.T, g, _ token.Generator) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{
					Users: NewMockUserLoader(gomock.NewController(t)), Tokens: g,
				})}
			},
		},
		{
			name: "magic link", field: "WithMagicLinkTokens",
			opts: func(t *testing.T, g, _ token.Generator) []httpsec.Option {
				h := newMagicLinkHarness(t)

				return []httpsec.Option{httpsec.EnableMagicLink(h.manager,
					httpsec.WithMagicLinkSessions(h.sessions), httpsec.WithMagicLinkTokens(g))}
			},
		},
		{
			name: "passkey login", field: "PasswordlessTokens",
			opts: func(t *testing.T, g, ok token.Generator) []httpsec.Option {
				h := newPasskeyHarness(t)
				h.pkOpts = append(h.pkOpts, passkey.WithOptionalRecoveryCodes())
				h.mfaOpts = append(h.mfaOpts, httpsec.WithMFATokens(ok))
				h.withoutReauth = true
				h.extra = append(h.extra, httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(ok)))
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyPasswordlessLogin(httpsec.PasswordlessTokens(g)))

				return h.chainOptions(t, nil)
			},
		},
		{
			name: "MFA", field: "WithMFATokens",
			opts: func(t *testing.T, g, _ token.Generator) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableMFA([]mfa.Method{totpLike(t)}, httpsec.WithMFATokens(g))}
			},
		},
		{
			name: "re-authentication", field: "WithReauthenticationTokens",
			opts: func(t *testing.T, g, ok token.Generator) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableMFA([]mfa.Method{totpLike(t)}, httpsec.WithMFATokens(ok)),
					httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(g)),
				}
			},
		},
		{
			name: "recovery", field: "WithRecoveryTokens",
			opts: func(t *testing.T, g, _ token.Generator) []httpsec.Option {
				h := newRecoveryHarness(t)
				h.noFormLogin = true
				h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}
				h.recOpts = append(h.recOpts, httpsec.WithRecoveryTokens(g))

				return h.options(t)
			},
		},
		{
			name: "OIDC handoff", field: "WithOIDCTokens",
			opts: func(t *testing.T, g, _ token.Generator) []httpsec.Option {
				flows, err := oidc.NewMemoryFlowStore()
				require.NoError(t, err)

				return []httpsec.Option{httpsec.EnableOIDCLogin(
					httpsec.OIDCDeps{RelyingParty: oidcManagerOver(t, flows), Handoff: newTestHandoffManager(t)},
					httpsec.WithOIDCTokens(g),
					httpsec.WithOIDCSessions(dpopSessions(t, clockwork.NewFakeClockAt(dpopNow))))}
			},
		},
	}
}

// TestChain_GeneratorSubjectModeMustMatchBearer pins that a chain with signed
// bearer tokens refuses to build when a generator it is given writes a subject
// its bearer would read differently, through every entry point and whatever the
// order of the chain's options.
func TestChain_GeneratorSubjectModeMustMatchBearer(t *testing.T) {
	t.Parallel()

	keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))

	byID := must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience()))
	byName := must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience(), token.WithUsernameSubject()))

	bearerOver := func(t *testing.T, v token.Verifier, opts ...httpsec.BearerTokenOption) httpsec.Option {
		t.Helper()

		return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: v,
			Sessions: dpopSessions(t, clockwork.NewFakeClockAt(dpopNow)),
			Users:    NewMockUserLoader(gomock.NewController(t)),
		}, opts...)
	}
	bearer := func(t *testing.T, opts ...httpsec.BearerTokenOption) httpsec.Option {
		t.Helper()

		return bearerOver(t, NewMockVerifier(gomock.NewController(t)), opts...)
	}
	login := func(t *testing.T, g token.Generator) httpsec.Option {
		t.Helper()

		return httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: NewMockAuthenticator(gomock.NewController(t)),
			Sessions:      dpopSessions(t, clockwork.NewFakeClockAt(dpopNow)),
			Tokens:        g,
			Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
		})
	}
	reporting := func(t *testing.T, mode token.SubjectMode) *MockGenerator {
		t.Helper()

		g := NewMockGenerator(gomock.NewController(t))
		g.EXPECT().SubjectMode().Return(mode).AnyTimes()

		return g
	}

	built := func(t *testing.T, chain *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, chain)
	}
	refusedNaming := func(names ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain)
			assert.Contains(t, err.Error(), "subject")
			for _, name := range names {
				assert.Contains(t, err.Error(), name)
			}
		}
	}

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			name: "Generator and bearer disagree on the subject",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{bearer(t), login(t, byName)}
			},
			assert: refusedNaming("EnableFormLogin", "FormLoginDeps.Tokens", "WithBearerUsernameSubject"),
		},
		{
			name: "Username bearer with a default generator",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{bearer(t, httpsec.WithBearerUsernameSubject()), login(t, byID)}
			},
			assert: refusedNaming("EnableFormLogin", "FormLoginDeps.Tokens", "WithBearerUsernameSubject"),
		},
		{
			name: "Generator and bearer agree on usernames",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{
					bearer(t, httpsec.WithBearerUsernameSubject()),
					login(t, byName),
					httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{
						Users: NewMockUserLoader(gomock.NewController(t)), Tokens: byName,
					}),
				}
			},
			assert: built,
		},
		{
			name: "Generator given as the bearer's verifier",
			opts: func(t *testing.T) []httpsec.Option { return []httpsec.Option{bearerOver(t, byName)} },
			assert: refusedNaming("EnableBearerToken", "BearerTokenDeps.Verifier",
				"token.WithUsernameSubject", "WithBearerUsernameSubject"),
		},
		{
			name: "Generator given as the verifier of a bearer configured to use usernames",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{bearerOver(t, byID, httpsec.WithBearerUsernameSubject())}
			},
			assert: refusedNaming("EnableBearerToken", "BearerTokenDeps.Verifier"),
		},
		{
			name:   "Generator given as the verifier of a bearer that agrees, default",
			opts:   func(t *testing.T) []httpsec.Option { return []httpsec.Option{bearerOver(t, byID)} },
			assert: built,
		},
		{
			name: "Generator given as the verifier of a bearer that agrees, usernames",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{bearerOver(t, byName, httpsec.WithBearerUsernameSubject())}
			},
			assert: built,
		},
		{
			// The stated limit: a wrapped verifier cannot be seen, so its tokens
			// are refused at request time rather than at build.
			name: "Generator wrapped in a verifier of the consumer's",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{bearerOver(t, struct{ token.Verifier }{byName})}
			},
			assert: built,
		},
		{
			name: "Two bearers that disagree, the default first",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{bearer(t), bearer(t, httpsec.WithBearerUsernameSubject())}
			},
			assert: refusedNaming("EnableBearerToken", "WithBearerUsernameSubject"),
		},
		{
			name: "Two bearers that disagree, the default last",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{bearer(t, httpsec.WithBearerUsernameSubject()), bearer(t)}
			},
			assert: refusedNaming("EnableBearerToken", "WithBearerUsernameSubject"),
		},
		{
			name: "Two bearers that disagree, under different schemes",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{
					bearer(t),
					bearer(t, httpsec.WithBearerScheme("Partner"), httpsec.WithBearerUsernameSubject()),
				}
			},
			assert: refusedNaming("EnableBearerToken", "WithBearerUsernameSubject"),
		},
		{
			name: "Two bearers that agree on the default",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{bearer(t), bearer(t, httpsec.WithBearerScheme("Partner"))}
			},
			assert: built,
		},
		{
			name: "Two bearers that agree on usernames",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{
					bearer(t, httpsec.WithBearerUsernameSubject()),
					bearer(t, httpsec.WithBearerScheme("Partner"), httpsec.WithBearerUsernameSubject()),
				}
			},
			assert: built,
		},
		{
			name:   "Verify-only chain, default",
			opts:   func(t *testing.T) []httpsec.Option { return []httpsec.Option{bearer(t)} },
			assert: built,
		},
		{
			name: "Verify-only chain, usernames",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{bearer(t, httpsec.WithBearerUsernameSubject())}
			},
			assert: built,
		},
		{
			name: "Generator reporting the zero subject mode, default bearer",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{bearer(t), login(t, reporting(t, token.SubjectMode(0)))}
			},
			assert: built,
		},
		{
			name: "Generator reporting the zero subject mode, username bearer",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{
					bearer(t, httpsec.WithBearerUsernameSubject()),
					login(t, reporting(t, token.SubjectMode(0))),
				}
			},
			assert: refusedNaming("FormLoginDeps.Tokens"),
		},
		{
			name: "Generator reporting a mode no bearer reads",
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{bearer(t), login(t, reporting(t, token.SubjectMode(99)))}
			},
			assert: refusedNaming("FormLoginDeps.Tokens"),
		},
		{
			name: "No generator with a callback success handler",
			opts: func(t *testing.T) []httpsec.Option {
				flows, err := oidc.NewMemoryFlowStore()
				require.NoError(t, err)

				return []httpsec.Option{
					bearer(t, httpsec.WithBearerUsernameSubject()),
					httpsec.EnableOIDCLogin(httpsec.OIDCDeps{RelyingParty: oidcManagerOver(t, flows)},
						httpsec.WithOIDCSessions(dpopSessions(t, clockwork.NewFakeClockAt(dpopNow))),
						httpsec.WithOIDCCallbackSuccess(func(*httpsec.Exchange, oidc.CallbackResult, string) error { return nil })),
				}
			},
			assert: built,
		},
		{
			name:   "Generators on a chain with no signed bearer",
			opts:   func(t *testing.T) []httpsec.Option { return []httpsec.Option{login(t, byName)} },
			assert: built,
		},
	}

	for _, ep := range subjectEntryPoints() {
		ordered := func(t *testing.T, reversed bool, opts ...httpsec.BearerTokenOption) func(g token.Generator) []httpsec.Option {
			return func(g token.Generator) []httpsec.Option {
				all := append([]httpsec.Option{bearer(t, opts...)}, ep.opts(t, g, byID)...)
				if reversed {
					for l, r := 0, len(all)-1; l < r; l, r = l+1, r-1 {
						all[l], all[r] = all[r], all[l]
					}
				}

				return all
			}
		}

		for _, reversed := range []bool{false, true} {
			order := "bearer first"
			if reversed {
				order = "bearer last"
			}

			cases = append(cases,
				testCase{
					name: "Every entry point is checked/" + ep.name + "/" + order,
					opts: func(t *testing.T) []httpsec.Option {
						return ordered(t, reversed)(byName)
					},
					assert: refusedNaming(ep.field),
				},
				testCase{
					name: "A matching generator builds/" + ep.name + "/" + order,
					opts: func(t *testing.T) []httpsec.Option {
						return ordered(t, reversed)(byID)
					},
					assert: built,
				},
			)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.opts(t)...)
			tc.assert(t, chain, err)
		})
	}
}

// TestChain_EveryIssuedTokenAuthenticates pins that the token each issuing
// endpoint hands out, from the library's own generator in its default mode, is
// accepted by the chain that issued it: every endpoint must name the session's
// own user, or the subject check would refuse the token it just issued.
func TestChain_EveryIssuedTokenAuthenticates(t *testing.T) {
	t.Parallel()

	reachesTheHandler := func(t *testing.T, f issuingFixture, next served) {
		t.Helper()

		require.NoError(t, next.err)
		require.True(t, next.handlerRan)

		auth, ok := authenticate.AuthenticationFromContext(next.handled.Context())
		require.True(t, ok)
		assert.Equal(t, f.user, auth.Principal.ID)
	}

	type testCase struct {
		name   string
		assert func(t *testing.T, f issuingFixture, next served)
	}

	cases := []testCase{
		{name: "login", assert: reachesTheHandler},
		{name: "MFA verify", assert: reachesTheHandler},
		{name: "passkey login", assert: reachesTheHandler},
		{name: "magic link", assert: reachesTheHandler},
		{name: "OIDC handoff", assert: reachesTheHandler},
		{name: "re-authentication", assert: reachesTheHandler},
		{name: "renewal", assert: reachesTheHandler},
		{
			// A recovered session is confined until it binds a new way in, so
			// past authentication its gate turns the route down, with a
			// challenge for that user rather than a call to authenticate.
			name: "recovery",
			assert: func(t *testing.T, f issuingFixture, next served) {
				t.Helper()

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, next.err, &challenge)
				assert.NotErrorIs(t, next.err, httpsec.ErrAuthenticationRequired)
				assert.False(t, next.handlerRan)
				assert.Equal(t, policy.ChallengeAccountRecovery, challenge.Kind)
				require.NotNil(t, challenge.Session)
				assert.Equal(t, f.user, challenge.Session.UserID, "the token authenticated the recovered user")
			},
		},
	}

	require.Len(t, cases, len(issuingEndpoints), "every issuing endpoint has a row")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			idx := slices.IndexFunc(issuingEndpoints, func(ep issuingEndpoint) bool { return ep.name == tc.name })
			require.GreaterOrEqual(t, idx, 0, "no issuing endpoint is named %q", tc.name)

			f := issuingEndpoints[idx].build(t, httpsec.DPoP{PublicURL: dpopPublicURL})
			out := f.prepare(t, "")(t, noProof)
			f.issued(t, out)

			var doc struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))

			req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders")
			req.Header.Set("Authorization", "Bearer "+doc.AccessToken)

			tc.assert(t, f, serve(t, f.chain, req))
		})
	}
}

// TestChain_TypedNilGeneratorDoesNotPanic pins that a nil pointer given as a
// token generator never reaches SubjectMode, which would dereference it: every
// entry point refuses it as a missing generator, not as a subject mismatch.
func TestChain_TypedNilGeneratorDoesNotPanic(t *testing.T) {
	t.Parallel()

	keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
	byID := must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience()))

	for _, ep := range subjectEntryPoints() {
		t.Run(ep.name, func(t *testing.T) {
			t.Parallel()

			var typedNil *token.JWTGenerator

			opts := append([]httpsec.Option{httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
				Verifier: NewMockVerifier(gomock.NewController(t)),
				Sessions: dpopSessions(t, clockwork.NewFakeClockAt(dpopNow)),
				Users:    NewMockUserLoader(gomock.NewController(t)),
			})}, ep.opts(t, typedNil, byID)...)

			assert.NotPanics(t, func() {
				chain, err := httpsec.New(opts...)

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, chain)
				assert.Contains(t, err.Error(), "needs a token generator")
			})
		})
	}
}

// TestCheckSubjectGenerator_NilGenerators pins the guard itself, which the
// options in front of it leave nothing typed-nil to reach through a chain: with a
// signed bearer on, neither nil asks a generator for its mode.
func TestCheckSubjectGenerator_NilGenerators(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		g    token.Generator
	}

	cases := []testCase{
		{name: "no generator", g: nil},
		{name: "a nil pointer", g: (*token.JWTGenerator)(nil)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := httpsec.CheckSubjectGeneratorForTest(httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
				Verifier: NewMockVerifier(gomock.NewController(t)),
				Sessions: dpopSessions(t, clockwork.NewFakeClockAt(dpopNow)),
				Users:    NewMockUserLoader(gomock.NewController(t)),
			}), tc.g)

			require.NoError(t, err)
		})
	}
}
