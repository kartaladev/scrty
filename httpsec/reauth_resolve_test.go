package httpsec_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// reauthWrongPassword is the wrong password the log case submits, distinctive
// enough that finding it in a record cannot be a coincidence.
//
//nolint:gosec // G101: a test's wrong password, not a credential
const reauthWrongPassword = "wrong-pw-7f3c9a"

// elapse moves the harness's clock on by d, touching s at least every 20
// minutes so it outlives the session manager's 30-minute idle timeout: what is
// judged is when the user last authenticated, not idleness.
func (f *pwFixture) elapse(t *testing.T, s *session.Session, d time.Duration) {
	t.Helper()

	const step = 20 * time.Minute

	for d > 0 {
		adv := min(step, d)
		f.clock.Advance(adv)
		d -= adv

		require.NoError(t, f.sessions.Touch(t.Context(), s))
	}
}

// totpPost is a TOTP re-proof of the code these tests post, carrying tok.
func totpPost(ctx context.Context, tok string) *http.Request {
	return bearerRequestTo(ctx, http.MethodPost, reauthVerifyTOTP, tok, "code="+testMFACode)
}

// recent is a route behind the recency guard, judged on the harness's clock.
// It reports the status the guard let through or refused with, for the
// session the chain resolved from tok.
func (f *pwFixture) recent(t *testing.T, c *httpsec.Chain, tok string) int {
	t.Helper()

	guards, err := httpsec.NewGuards(projectDeleters{}, httpsec.WithGuardClock(f.clock))
	require.NoError(t, err)

	route := guards.RequireRecentAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	out := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/admin", tok, ""))
	require.NoError(t, out.err)
	require.True(t, out.handlerRan, "the chain lets the credential through")

	rec := httptest.NewRecorder()
	route.ServeHTTP(rec, httptest.NewRequestWithContext(out.handled.Context(), http.MethodGet, "/admin", nil))

	return rec.Code
}

// recordsText is every record the fixture captured, message and attributes,
// as one string.
func (f *pwFixture) recordsText() string {
	var b strings.Builder

	for _, r := range f.logs.records() {
		b.WriteString(r.Message)
		r.Attrs(func(a slog.Attr) bool {
			fmt.Fprintf(&b, " %s=%s", a.Key, a.Value)

			return true
		})
		b.WriteString("\n")
	}

	return b.String()
}

// TestReauthResolve pins what a successful re-proof does: the authentication
// time, and for a second factor the second factor, set from the chain's clock;
// a strict rotation, rolled back in memory when it fails; the rotated
// session's credential issued in the chain's bearer mode and answered through
// the responder; and logs that carry no secret.
//
// The chain authenticates by bearer token unless a row says otherwise, and its
// clock is the harness's controlled one, started at the session's sign-in.
func TestReauthResolve(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// fixture builds the harness; nil is newPwFixture.
		fixture func(t *testing.T) *pwFixture
		wire    func(t *testing.T, f *pwFixture)
		// state is the session's second-factor state.
		state session.MFAState
		// first is the first factor the session was signed in with; the zero
		// value is a password.
		first factor.Kind
		act   func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served
		// assert is given the session as it was signed in.
		assert func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session, out served)
	}

	totp := func(t *testing.T, _ *pwFixture, c *httpsec.Chain, s *session.Session) served {
		return serve(t, c, totpPost(t.Context(), mfaTokenFor(s.ID)))
	}

	// totpHolder is a user enrolled on TOTP whose code is accepted once.
	totpHolder := func(_ *testing.T, f *pwFixture) {
		f.totpUnenrolled = false
		f.allows().accepts().recordsNoFailure()
	}

	responded := &atomic.Pointer[httpsec.ReauthenticationResult]{}

	// secondServer is the manager the cross-server row's second chain runs
	// on, over the store the first chain's manager uses, and bearerAt is where
	// the first chain's bearer option sits in the fixture's options. The row
	// sets both.
	var (
		secondServer *session.Sessions
		bearerAt     int
	)

	cases := []testCase{
		{
			// "Second-factor re-proof", "Controlled chain time source".
			name:  "a TOTP re-proof at 09:30 refreshes both times, rotates, and the credential authenticates",
			wire:  totpHolder,
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.elapse(t, s, 30*time.Minute) // 09:00 to 09:30

				return totp(t, f, c, s)
			},
			assert: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session, out served) {
				rotated := reproved(t, f.reauthHarness, s, out)
				assert.True(t, rotated.AuthenticatedAt.Equal(s.AuthenticatedAt.Add(30*time.Minute)), "09:30")

				next := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/app", accessTokenFrom(t, out), ""))
				require.NoError(t, next.err)
				require.True(t, next.handlerRan, "the next request authenticates")
				assert.Equal(t, rotated.ID, next.handled.Session.ID)

				old := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/app", mfaTokenFor(s.ID), ""))
				require.Error(t, old.err, "the credential the caller arrived with is refused")
				assert.False(t, old.handlerRan)
			},
		},
		{
			// "A same-channel re-proof refreshes freshness only": a passkey
			// sign-in that counted as one factor, re-proved with the passkey
			// method, which travels the same channel.
			name: "a same-channel re-proof refreshes freshness only",
			wire: func(t *testing.T, f *pwFixture) {
				f.methodChannel = factor.PublicKey
				totpHolder(t, f)
			},
			first: factor.Passkey,
			state: session.MFANone,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.elapse(t, s, 30*time.Minute) // 09:00 to 09:30

				return totp(t, f, c, s)
			},
			assert: func(t *testing.T, f *pwFixture, _ *httpsec.Chain, s *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)

				issued, ok := f.issuedFor.Load().(string)
				require.True(t, ok, "a credential was issued")
				assert.Equal(t, mfaTokenFor(issued), accessTokenFrom(t, out))
				assert.NotEqual(t, s.ID, issued, "the session was rotated")

				rotated := f.stored(t, issued)
				assert.True(t, rotated.AuthenticatedAt.Equal(s.AuthenticatedAt.Add(30*time.Minute)), "09:30: %s", rotated.AuthenticatedAt)
				assert.Equal(t, session.MFANone, rotated.MFA)
				assert.True(t, rotated.MFASatisfiedAt.IsZero(), "no second factor was met: %s", rotated.MFASatisfiedAt)
			},
		},
		{
			// "Password re-proof leaves the second-factor state".
			name:  "a password re-proof refreshes the authentication time and keeps no second factor",
			wire:  func(_ *testing.T, f *pwFixture) { f.resets() },
			state: session.MFANone,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.elapse(t, s, 30*time.Minute)

				return serve(t, c, passwordOf(reauthAdaPassword)(t.Context(), t, mfaTokenFor(s.ID)))
			},
			assert: func(t *testing.T, f *pwFixture, _ *httpsec.Chain, s *session.Session, out served) {
				rotated := passwordReproved(t, f.reauthHarness, s, out)
				assert.Equal(t, session.MFANone, rotated.MFA)
				assert.True(t, rotated.MFASatisfiedAt.IsZero())
			},
		},
		{
			// "A session that met no second factor yet".
			name:  "a session that met no second factor becomes satisfied by a TOTP re-proof",
			wire:  totpHolder,
			state: session.MFANone,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.elapse(t, s, 5*time.Minute)

				return totp(t, f, c, s)
			},
			assert: func(t *testing.T, f *pwFixture, _ *httpsec.Chain, s *session.Session, out served) {
				reproved(t, f.reauthHarness, s, out)
			},
		},
		{
			// "A fresh session re-proves".
			name:  "a session authenticated one minute ago re-proves",
			wire:  totpHolder,
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(time.Minute)

				return totp(t, f, c, s)
			},
			assert: func(t *testing.T, f *pwFixture, _ *httpsec.Chain, s *session.Session, out served) {
				reproved(t, f.reauthHarness, s, out)
			},
		},
		{
			// "The guard passes afterwards".
			name:  "a stale session refused by the recency guard passes it after a re-proof",
			wire:  totpHolder,
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.elapse(t, s, 20*time.Minute)
				require.Equal(t, http.StatusForbidden, f.recent(t, c, mfaTokenFor(s.ID)), "stale before the re-proof")

				return totp(t, f, c, s)
			},
			assert: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session, out served) {
				reproved(t, f.reauthHarness, s, out)
				assert.Equal(t, http.StatusNoContent, f.recent(t, c, accessTokenFrom(t, out)))
			},
		},
		{
			// "A fresh sign-in still makes the session fresh".
			name: "under second-factor-only a new sign-in without a second factor passes the guard",
			wire: func(_ *testing.T, f *pwFixture) {
				f.password = nil
				f.reauthOpts = append(f.reauthOpts, httpsec.RequireSecondFactorForReauthentication())
				f.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(&authenticate.Authentication{
					Principal: &identity.Principal{ID: testMFAUser, Username: mfaUsername},
				}, nil)
				f.resets()
			},
			state: session.MFANone,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.elapse(t, s, 20*time.Minute)

				return serve(t, c, formRequest(t.Context(), httpsec.DefaultLoginPath, url.Values{
					httpsec.DefaultLoginUsernameParam: {mfaUsername},
					httpsec.DefaultLoginPasswordParam: {reauthAdaPassword},
				}.Encode()))
			},
			assert: func(t *testing.T, f *pwFixture, c *httpsec.Chain, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, f.recent(t, c, accessTokenFrom(t, out)))
			},
		},
		{
			// "Concurrent re-proofs": both requests hold the session before
			// either rotates it. One manager serialises the two strict
			// rotations of one handle, so the loser finds the handle already
			// moved inside the winner's in-flight window and is refused as a
			// renewal conflict (409), not as signed out; nothing is rotated
			// twice and nothing is revoked.
			name: "two concurrent re-proofs: one succeeds, the other is a renewal conflict and the winner's session stands",
			wire: func(_ *testing.T, f *pwFixture) {
				f.noCarrier = true
				f.totpUnenrolled = false
				f.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).Return(false, nil).Times(2)
				f.recordsNoFailure()

				var arrived sync.WaitGroup
				arrived.Add(2)
				f.method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Times(2).
					DoAndReturn(func(context.Context, identity.UserID, []byte) error {
						arrived.Done()
						arrived.Wait()

						return nil
					})
			},
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(time.Minute)

				var (
					wg   sync.WaitGroup
					outs [2]served
				)
				for i := range outs {
					wg.Go(func() { outs[i] = serve(t, c, totpPost(t.Context(), mfaTokenFor(s.ID))) })
				}
				wg.Wait()

				// The one that lost is the one returned.
				if outs[0].err == nil {
					require.Error(t, outs[1].err, "exactly one wins")

					return outs[1]
				}

				require.NoError(t, outs[1].err, "exactly one wins")

				return outs[0]
			},
			assert: func(t *testing.T, f *pwFixture, _ *httpsec.Chain, s *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrSessionRenewalConflict)
				require.ErrorIs(t, out.err, session.ErrRenewalConflict)
				assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired, "the loser is not signed out")
				assert.Equal(t, http.StatusConflict, httpsec.StatusForError(out.err))

				winner, ok := f.issuedFor.Load().(string)
				require.True(t, ok)
				assert.Equal(t, session.MFASatisfied, f.stored(t, winner).MFA, "the winner's session is in place")

				n, err := f.sessions.CountActiveByUser(t.Context(), s.UserID)
				require.NoError(t, err)
				assert.Equal(t, 1, n, "one session, the winner's")
			},
		},
		{
			// A renewal that rotates the session while the re-proof is being
			// verified wins: the re-proof's strict rotation finds the session
			// superseded inside the renewal's window.
			name: "a re-proof racing a renewal of its session is a renewal conflict and the renewal's session stands",
			wire: func(_ *testing.T, f *pwFixture) {
				f.totpUnenrolled = false
				f.allows().recordsNoFailure()
				f.chainOpts = append(f.chainOpts, httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{
					Users: f.users, Tokens: f.tokens,
				}))
				f.users.EXPECT().LoadByUserID(gomock.Any(), testMFAUser).AnyTimes().Return(&identity.Details{
					ID: testMFAUser, Username: mfaUsername, Active: true,
				}, nil)
			},
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(time.Minute)

				var renewed served

				f.method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).
					DoAndReturn(func(ctx context.Context, _ identity.UserID, _ []byte) error {
						renewed = serveIn(ctx, t, c, bearerRequestTo(ctx, http.MethodPost,
							httpsec.DefaultSessionRenewalPath, mfaTokenFor(s.ID), ""))

						return nil
					})

				out := serve(t, c, totpPost(t.Context(), mfaTokenFor(s.ID)))

				require.NoError(t, renewed.err, "the renewal wins")
				f.issuedFor.Store(sessionIDOf(t, accessTokenFrom(t, renewed)))

				return out
			},
			assert: func(t *testing.T, f *pwFixture, _ *httpsec.Chain, s *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrSessionRenewalConflict)
				assert.Equal(t, http.StatusConflict, httpsec.StatusForError(out.err))

				winner, _ := f.issuedFor.Load().(string)
				renewed := f.stored(t, winner)
				assert.True(t, renewed.AuthenticatedAt.Equal(s.AuthenticatedAt), "the renewal is not an authentication")
			},
		},
		{
			// The other direction of the race above: the re-proof rotates the
			// session after the renewal has loaded it and before the renewal
			// rotates it, so the renewal finds its handle already moved
			// inside the re-proof's in-flight window.
			name: "a renewal racing a re-proof of its session is a renewal conflict and the re-proof's credential authenticates",
			wire: func(_ *testing.T, f *pwFixture) {
				f.totpUnenrolled = false
				f.allows().recordsNoFailure()
				f.method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Return(nil)
				f.chainOpts = append(f.chainOpts, httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{
					Users: f.users, Tokens: f.tokens,
				}))
			},
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(time.Minute)

				// The renewal reloads the user before it rotates; the
				// re-proof runs there, once, and wins.
				var (
					once    sync.Once
					reprove served
				)
				f.users.EXPECT().LoadByUserID(gomock.Any(), testMFAUser).AnyTimes().
					DoAndReturn(func(ctx context.Context, _ identity.UserID) (*identity.Details, error) {
						//nolint:contextcheck // the request carries ctx, the renewal's own request context
						once.Do(func() { reprove = serve(t, c, totpPost(ctx, mfaTokenFor(s.ID))) })

						return &identity.Details{ID: testMFAUser, Username: mfaUsername, Active: true}, nil
					})

				out := serve(t, c, bearerRequestTo(t.Context(), http.MethodPost,
					httpsec.DefaultSessionRenewalPath, mfaTokenFor(s.ID), ""))

				require.NoError(t, reprove.err, "the re-proof wins")

				return out
			},
			assert: func(t *testing.T, f *pwFixture, c *httpsec.Chain, _ *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrSessionRenewalConflict)
				require.ErrorIs(t, out.err, session.ErrRenewalConflict)
				assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired, "the loser is not signed out")
				assert.Equal(t, http.StatusConflict, httpsec.StatusForError(out.err))

				winner, ok := f.issuedFor.Load().(string)
				require.True(t, ok, "the re-proof issued a credential")
				next := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/app", mfaTokenFor(winner), ""))
				require.NoError(t, next.err)
				require.True(t, next.handlerRan, "the winner's credential authenticates the next request")
			},
		},
		{
			// "Concurrent re-proofs" across two servers: two chains, each
			// with its own session manager, over one session store. Neither
			// manager's lock sees the other, so the store alone decides.
			name: "two concurrent re-proofs through two chains sharing a session store: one succeeds, the other is a renewal conflict",
			fixture: func(t *testing.T) *pwFixture {
				// The bearer chain reads the harness's manager when the
				// harness is built, so the shared store is wired in first.
				h := newReauthHarness(t)

				store, err := session.NewMemoryStore(session.WithMemoryStoreClock(h.clock))
				require.NoError(t, err)

				h.sessions, err = session.New(session.WithClock(h.clock), session.WithStore(store))
				require.NoError(t, err)

				secondServer, err = session.New(session.WithClock(h.clock), session.WithStore(store))
				require.NoError(t, err)

				bearerAt = len(h.chainOpts)
				h.chainOpts = append(h.chainOpts, httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: h.tokens, Sessions: h.sessions, Users: h.users,
				}))

				f := newPwFixtureOn(t, h)

				return f
			},
			wire: func(_ *testing.T, f *pwFixture) {
				f.noCarrier = true
				f.totpUnenrolled = false
				f.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).Return(false, nil).Times(2)
				f.recordsNoFailure()

				var arrived sync.WaitGroup
				arrived.Add(2)
				f.method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Times(2).
					DoAndReturn(func(context.Context, identity.UserID, []byte) error {
						arrived.Done()
						arrived.Wait()

						return nil
					})
			},
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(time.Minute)

				// The second server: a manager of its own over the first's
				// store, and a chain built on it.
				first, firstOpts := f.sessions, f.chainOpts
				f.sessions = secondServer
				f.chainOpts = slices.Clone(firstOpts)
				f.chainOpts[bearerAt] = httpsec.EnableBearerToken(
					httpsec.BearerTokenDeps{Verifier: f.tokens, Sessions: secondServer, Users: f.users})
				other, err := f.build(nil)
				require.NoError(t, err)
				f.sessions, f.chainOpts = first, firstOpts

				var (
					wg   sync.WaitGroup
					outs [2]served
				)
				for i, chain := range []*httpsec.Chain{c, other} {
					wg.Go(func() { outs[i] = serve(t, chain, totpPost(t.Context(), mfaTokenFor(s.ID))) })
				}
				wg.Wait()

				if outs[0].err == nil {
					require.Error(t, outs[1].err, "exactly one wins")

					return outs[1]
				}

				require.NoError(t, outs[1].err, "exactly one wins")

				return outs[0]
			},
			assert: func(t *testing.T, f *pwFixture, _ *httpsec.Chain, s *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrSessionRenewalConflict)
				require.ErrorIs(t, out.err, session.ErrRenewalConflict)
				assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired, "the loser is not signed out")
				assert.Equal(t, http.StatusConflict, httpsec.StatusForError(out.err))

				winner, ok := f.issuedFor.Load().(string)
				require.True(t, ok)
				assert.Equal(t, session.MFASatisfied, f.stored(t, winner).MFA, "the winner's session is in place")

				n, err := f.sessions.CountActiveByUser(t.Context(), s.UserID)
				require.NoError(t, err)
				assert.Equal(t, 1, n, "one session, the winner's")
			},
		},
		{
			// "A failure SHALL change neither the session nor its handle": the
			// fields set before the rotation are put back on the session the
			// exchange carries.
			name: "a failed rotation rolls the session's fields back",
			wire: func(_ *testing.T, f *pwFixture) {
				f.totpUnenrolled = false
				f.allows().recordsNoFailure()
			},
			state: session.MFANone,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(5 * time.Minute)

				// The session vanishes once the endpoint holds it, so the
				// rotation finds nothing to move.
				f.method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).
					DoAndReturn(func(ctx context.Context, _ identity.UserID, _ []byte) error {
						return f.sessions.Delete(ctx, s.ID)
					})

				return totp(t, f, c, s)
			},
			assert: func(t *testing.T, f *pwFixture, _ *httpsec.Chain, s *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, out.err, session.ErrNotFound)
				assert.Nil(t, f.issuedFor.Load(), "no credential was issued")

				require.NotNil(t, f.resolved)
				assert.Equal(t, s.ID, f.resolved.ID, "the exchange keeps the session it arrived with")
				assert.True(t, f.resolved.AuthenticatedAt.Equal(s.AuthenticatedAt), "authentication time rolled back")
				assert.Equal(t, session.MFANone, f.resolved.MFA, "second-factor state rolled back")
				assert.True(t, f.resolved.MFASatisfiedAt.IsZero(), "second-factor time rolled back")
			},
		},
		{
			// The session-reference bearer: the credential is the rotated
			// session's own identifier.
			name: "in the session-reference mode a new reference is returned and the old one is refused",
			fixture: func(t *testing.T) *pwFixture {
				h := newReauthHarness(t)
				h.sessionBearer = true
				h.noReauthTokens = true
				h.chainOpts = append(h.chainOpts, httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
					Sessions: h.sessions, Users: h.users,
				}))
				h.users.EXPECT().LoadByUserID(gomock.Any(), testMFAUser).AnyTimes().Return(&identity.Details{
					ID: testMFAUser, Username: mfaUsername, Active: true,
				}, nil)

				return newPwFixtureOn(t, h)
			},
			wire:  totpHolder,
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(time.Minute)

				return serve(t, c, bearerRequestTo(t.Context(), http.MethodPost, reauthVerifyTOTP, s.ID, "code="+testMFACode))
			},
			assert: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

				ref := accessTokenFrom(t, out)
				require.NotEqual(t, s.ID, ref, "a new reference")
				assert.True(t, f.stored(t, ref).AuthenticatedAt.Equal(f.clock.Now()))

				next := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/app", ref, ""))
				require.NoError(t, next.err)
				require.True(t, next.handlerRan, "the new reference authenticates")

				old := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/app", s.ID, ""))
				require.Error(t, old.err, "the old reference is refused")
				assert.False(t, old.handlerRan)
			},
		},
		{
			// The signed-token bearer: a new token naming the rotated session.
			name:  "in the signed-token mode a new token is returned whose session loads",
			wire:  totpHolder,
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(time.Minute)

				return totp(t, f, c, s)
			},
			assert: func(t *testing.T, f *pwFixture, _ *httpsec.Chain, s *session.Session, out served) {
				tok := accessTokenFrom(t, out)
				assert.NotEqual(t, mfaTokenFor(s.ID), tok)
				assert.Equal(t, s.UserID, f.stored(t, sessionIDOf(t, tok)).UserID)
			},
		},
		{
			// "Consumer responder".
			name: "a consumer responder receives the rotated session and the library writes nothing",
			wire: func(t *testing.T, f *pwFixture) {
				totpHolder(t, f)
				f.reauthOpts = append(f.reauthOpts, httpsec.WithReauthenticationResponder(
					func(ex *httpsec.Exchange, r httpsec.ReauthenticationResult) error {
						assert.Same(t, r.Session, ex.Session, "the rotated session is published on the exchange")
						responded.Store(&r)

						return nil
					}))
			},
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(time.Minute)

				return totp(t, f, c, s)
			},
			assert: func(t *testing.T, f *pwFixture, _ *httpsec.Chain, s *session.Session, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan)
				assert.Zero(t, out.rec.Body.Len(), "the library wrote no body")
				assert.Empty(t, out.rec.Header(), "the library wrote no header")

				r := responded.Load()
				require.NotNil(t, r)
				require.NotNil(t, r.Session)
				assert.NotEqual(t, s.ID, r.Session.ID)
				assert.Equal(t, mfaTokenFor(r.Session.ID), r.Token)
				assert.True(t, r.Session.AuthenticatedAt.Equal(f.clock.Now()))
				assert.Equal(t, r.Session.ID, f.stored(t, r.Session.ID).ID, "the session it received is the stored one")
			},
		},
		{
			// "Default verify response".
			name:  "the default response is the credential document, not cached",
			wire:  totpHolder,
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(time.Minute)

				return totp(t, f, c, s)
			},
			assert: func(t *testing.T, _ *pwFixture, _ *httpsec.Chain, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
				assert.Contains(t, out.rec.Header().Get("Content-Type"), "application/json")

				var doc map[string]any
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				assert.ElementsMatch(t, []string{"access_token", "refresh_token", "valid_until"}, keysOf(doc))
			},
		},
		{
			// "Refusal logs", for a wrong password.
			name: "the records a refused password writes do not carry it",
			wire: func(t *testing.T, f *pwFixture) {
				f.recordsAttempt()
				f.loginOpts = append(f.loginOpts, httpsec.WithLoginLimiter(memLimiter(t, 1, time.Hour)))
			},
			state: session.MFANone,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(time.Minute)

				out := serve(t, c, passwordOf(reauthWrongPassword)(t.Context(), t, mfaTokenFor(s.ID)))
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)

				// The source is now throttled, which the guard records.
				return serve(t, c, passwordOf(reauthWrongPassword)(t.Context(), t, mfaTokenFor(s.ID)))
			},
			assert: func(t *testing.T, f *pwFixture, c *httpsec.Chain, _ *session.Session, out served) {
				require.Error(t, out.err)
				require.NoError(t, c.FlushRefusalLogs())

				text := f.recordsText()
				require.NotEmpty(t, text, "the refusals were recorded")
				assert.NotContains(t, text, reauthWrongPassword)
			},
		},
		{
			// "Refusal logs", for a wrong code.
			name: "the records a refused code writes do not carry it",
			wire: func(_ *testing.T, f *pwFixture) {
				f.totpUnenrolled = false
				f.allows().refuses().recordsFailure()
				f.throttles()
			},
			state: session.MFASatisfied,
			act: func(t *testing.T, f *pwFixture, c *httpsec.Chain, s *session.Session) served {
				f.clock.Advance(time.Minute)

				out := totp(t, f, c, s)
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)

				// The user is now at their limit, which the throttle records.
				return totp(t, f, c, s)
			},
			assert: func(t *testing.T, f *pwFixture, c *httpsec.Chain, _ *session.Session, out served) {
				require.Error(t, out.err)
				require.NoError(t, c.FlushRefusalLogs())

				text := f.recordsText()
				require.NotEmpty(t, text, "the refusal was recorded")
				assert.NotContains(t, text, testMFACode)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fixture := newPwFixture
			if tc.fixture != nil {
				fixture = tc.fixture
			}

			f := fixture(t)
			if tc.wire != nil {
				tc.wire(t, f)
			}

			first := tc.first
			if first == "" {
				first = factor.Password
			}

			s := f.newSession(t, first, tc.state)

			c, err := f.build(nil)
			require.NoError(t, err)

			tc.assert(t, f, c, s, tc.act(t, f, c, s))
		})
	}
}
