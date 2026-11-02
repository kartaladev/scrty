package httpsec_test

import (
	"crypto/elliptic"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// lateRenewalWorld is a chain in one bearer mode with the renewal endpoint,
// over a session manager with unused-successor recovery on a fake clock, so a
// renewed credential can be presented after its grace window.
type lateRenewalWorld struct {
	t        *testing.T
	mode     bearerMode
	clk      *clockwork.FakeClock
	sessions *session.Sessions
	gen      *token.JWTGenerator
	chain    *httpsec.Chain
}

// newLateRenewalWorld builds the world; limiter is the session-reference
// bearer's source limiter, and is used in that mode only.
func newLateRenewalWorld(t *testing.T, mode bearerMode, limiter ratelimit.Limiter) *lateRenewalWorld {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now().Truncate(time.Second))
	sessions := must.Must(session.New(session.WithClock(clk), session.WithUnusedSuccessorRecovery(),
		session.WithStore(must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))))

	u := &switchableUser{}
	u.set(userActive(true))
	users := u.loader(t)

	w := &lateRenewalWorld{t: t, mode: mode, clk: clk, sessions: sessions, gen: issuingGenerator(t)}

	opts := []httpsec.Option{httpsec.WithLogger(slog.New(slog.DiscardHandler)), httpsec.EnableDPoP(httpsec.DPoP{})}

	switch mode {
	case signedBearer:
		opts = append(opts,
			httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: w.gen, Sessions: sessions, Users: users}),
			httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: users, Tokens: w.gen}))
	case referenceBearer:
		opts = append(opts,
			httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users},
				httpsec.WithSessionBearerLimiter(limiter)),
			httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: users}))
	}

	w.chain = must.Must(httpsec.New(opts...))

	return w
}

// signIn creates a sign-in of u-1's bound to jkt and returns its credential:
// a token carrying the binding, or the session reference.
func (w *lateRenewalWorld) signIn(jkt string) string {
	w.t.Helper()

	s, err := w.sessions.Create(w.t.Context(), "u-1", session.WithFirstFactor(factor.Password),
		session.WithKeyBinding(session.KeyBinding{JKT: jkt}))
	require.NoError(w.t, err)

	if w.mode == referenceBearer {
		return s.ID
	}

	tok, err := w.gen.GenerateWith(w.t.Context(), s.ID, &identity.Principal{ID: "u-1", Username: testSubject},
		token.WithConfirmation(token.Confirmation{JKT: jkt}))
	require.NoError(w.t, err)

	return tok
}

// renew posts a renewal presenting credential under scheme, with proof as its
// DPoP header unless it is empty.
func (w *lateRenewalWorld) renew(scheme, credential, proof string) served {
	w.t.Helper()

	req := withProof(postValues(w.t.Context(), httpsec.DefaultSessionRenewalPath, e2eSource, nil), proof)
	req.Header.Set("Authorization", scheme+" "+credential)

	return serve(w.t, w.chain, req)
}

// proof is k's proof for a renewal presenting credential, issued now.
func (w *lateRenewalWorld) proof(k dpopKey, jti, credential string) string {
	w.t.Helper()

	return k.issuingProofParts(httpsec.DefaultSessionRenewalPath, jti, credential).sign(w.t)
}

// late signs in bound to k, renews once, leaves the successor unused and
// moves past the grace window, and returns the renewed credential: one the
// endpoint may only recover.
func (w *lateRenewalWorld) late(k dpopKey) string {
	w.t.Helper()

	renewed := w.signIn(k.jkt)

	out := w.renew("DPoP", renewed, w.proof(k, "j-first", renewed))
	require.NoError(w.t, out.err)

	w.clk.Advance(session.DefaultRenewalGrace + time.Second)

	return renewed
}

func TestDPoP_Rotation(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	thief := newDPoPKey(t, elliptic.P256())

	// outcome is what a case's act produced: the response, the fixture it
	// ran against and the user's live sessions before the request.
	type outcome struct {
		out    served
		f      *issuingFixture
		before int
	}

	type testCase struct {
		name   string
		act    func(t *testing.T) outcome
		assert func(t *testing.T, o outcome)
	}

	// through prepares f with a sign-in bound to bound and sends one request
	// with proof.
	through := func(t *testing.T, f issuingFixture, bound string, proof prover) outcome {
		t.Helper()

		send := f.prepare(t, bound)
		before := f.activeSessions(t)

		return outcome{out: send(t, proof), f: &f, before: before}
	}
	boundTo := func(want string) func(*testing.T, outcome) {
		return func(t *testing.T, o outcome) {
			t.Helper()

			jkt, s := o.f.issued(t, o.out)
			assert.Equal(t, want, jkt, "the successor's token")
			assert.Equal(t, session.KeyBinding{JKT: want}, s.KeyBinding, "the stored successor")
		}
	}
	refusedNothingRotated := func(t *testing.T, o outcome) {
		t.Helper()

		require.ErrorIs(t, o.out.err, httpsec.ErrInvalidDPoPProof)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(o.out.err))
		assert.Equal(t, o.before, o.f.activeSessions(t), "nothing is rotated")
	}
	// late runs a renewal after the grace window, under unused-successor
	// recovery, in mode, presenting the renewed credential as present says.
	late := func(mode bearerMode, records int, present func(t *testing.T, w *lateRenewalWorld, renewed string) served) func(t *testing.T) outcome {
		return func(t *testing.T) outcome {
			t.Helper()

			limiter := NewMockLimiter(gomock.NewController(t))
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
			limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).Times(records)

			w := newLateRenewalWorld(t, mode, limiter)

			return outcome{out: present(t, w, w.late(key))}
		}
	}
	lateRefusedAsWrongSender := func(t *testing.T, o outcome) {
		t.Helper()

		require.ErrorIs(t, o.out.err, httpsec.ErrInvalidDPoPProof)
		require.ErrorIs(t, o.out.err, httpsec.ErrAuthenticationRequired, "it reads as a missing session")
		assert.NotErrorIs(t, o.out.err, session.ErrReused, "nothing was rotated, so nothing was reused")
		assert.False(t, o.out.handlerRan)
	}

	cases := []testCase{
		{
			name: "renewal with a proof leaves an unbound session unbound",
			act: func(t *testing.T) outcome {
				return through(t, renewalEndpoint(t, httpsec.DPoP{}), "", key.validProver("j-1"))
			},
			assert: boundTo(""),
		},
		{
			name: "renewal keeps a bound session bound",
			act: func(t *testing.T) outcome {
				return through(t, renewalEndpoint(t, httpsec.DPoP{}), key.jkt, key.validProver("j-1"))
			},
			assert: boundTo(key.jkt),
		},
		{
			name: "re-authentication binds an unbound session",
			act: func(t *testing.T) outcome {
				return through(t, reauthEndpoint(t, httpsec.DPoP{}), "", key.validProver("j-1"))
			},
			assert: boundTo(key.jkt),
		},
		{
			name: "re-authentication keeps a bound session bound",
			act: func(t *testing.T) outcome {
				return through(t, reauthEndpoint(t, httpsec.DPoP{}), key.jkt, key.validProver("j-1"))
			},
			assert: boundTo(key.jkt),
		},
		{
			name: "renewal with another key is refused",
			act: func(t *testing.T) outcome {
				return through(t, renewalEndpoint(t, httpsec.DPoP{}), key.jkt, thief.validProver("j-1"))
			},
			assert: refusedNothingRotated,
		},
		{
			name: "re-authentication with another key is refused",
			act: func(t *testing.T) outcome {
				return through(t, reauthEndpoint(t, httpsec.DPoP{}), key.jkt, thief.validProver("j-1"))
			},
			assert: refusedNothingRotated,
		},
		{
			// Created at 09:00 by a manager with no family maximum, renewed at
			// 16:00 by one whose family maximum of six hours ended it at 15:00.
			name: "an ended family is refused with the bound key",
			act: func(t *testing.T) outcome {
				clk := clockwork.NewFakeClockAt(time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC))
				store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
				creator := must.Must(session.New(session.WithClock(clk), session.WithStore(store),
					session.WithIdleTimeout(12*time.Hour), session.WithAbsoluteTimeout(12*time.Hour)))
				sessions := must.Must(session.New(session.WithClock(clk), session.WithStore(store),
					session.WithIdleTimeout(6*time.Hour), session.WithAbsoluteTimeout(6*time.Hour),
					session.WithMaxFamilyLifetime(6*time.Hour)))

				f := renewalOver(t, newIssuingBaseOver(t, sessions, creator), httpsec.DPoP{})
				send := f.prepare(t, key.jkt)
				clk.Advance(7 * time.Hour)

				before := f.activeSessions(t)

				return outcome{out: send(t, key.validProver("j-1")), f: &f, before: before}
			},
			assert: func(t *testing.T, o outcome) {
				t.Helper()

				require.ErrorIs(t, o.out.err, httpsec.ErrAuthenticationRequired, "refused as expired")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(o.out.err))
				assert.LessOrEqual(t, o.f.activeSessions(t), o.before, "nothing is stored")
			},
		},
		{
			name: "a late bound reference presented as Bearer is refused and charged",
			act: late(referenceBearer, 1, func(_ *testing.T, w *lateRenewalWorld, renewed string) served {
				return w.renew("Bearer", renewed, "")
			}),
			assert: lateRefusedAsWrongSender,
		},
		{
			name: "a late bound reference with another key's proof is refused and charged",
			act: late(referenceBearer, 1, func(_ *testing.T, w *lateRenewalWorld, renewed string) served {
				return w.renew("DPoP", renewed, w.proof(thief, "j-late", renewed))
			}),
			assert: lateRefusedAsWrongSender,
		},
		{
			name: "a late bound token with another key's proof is refused",
			act: late(signedBearer, 0, func(_ *testing.T, w *lateRenewalWorld, renewed string) served {
				return w.renew("DPoP", renewed, w.proof(thief, "j-late", renewed))
			}),
			assert: func(t *testing.T, o outcome) {
				t.Helper()

				require.ErrorIs(t, o.out.err, httpsec.ErrInvalidDPoPProof)
				assert.NotErrorIs(t, o.out.err, session.ErrReused)
			},
		},
	}

	for _, mode := range []bearerMode{signedBearer, referenceBearer} {
		cases = append(cases, testCase{
			name: mode.String() + "/a late renewal's proof is recorded, and refused when presented again",
			act: late(mode, 0, func(t *testing.T, w *lateRenewalWorld, renewed string) served {
				proof := w.proof(key, "j-late", renewed)

				recovered := w.renew("DPoP", renewed, proof)
				require.NoError(t, recovered.err, "the late renewal is recovered with its own key's proof")

				return w.renew("DPoP", renewed, proof)
			}),
			assert: func(t *testing.T, o outcome) {
				t.Helper()

				require.ErrorIs(t, o.out.err, httpsec.ErrInvalidDPoPProof, "the proof was recorded")
				assert.NotErrorIs(t, o.out.err, session.ErrReused)
			},
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.act(t))
		})
	}
}
