package httpsec_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
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
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// The passwords and hashes a password re-proof is judged against. The
// session's user is ada (the bearer's principal); u-9 is another user whose
// correct password a request may name ada's session alongside.
const (
	reauthAdaPassword   = "ada-correct-password"
	reauthOtherUsername = "u-9"
	reauthOtherPassword = "u9-correct-password"
)

var (
	reauthAdaHash       = []byte("hash-of-ada")
	reauthOtherHash     = []byte("hash-of-u9")
	reauthReferenceHash = []byte("hash-of-the-reference")
)

// errReauthDenied is a pre-authentication policy's refusal.
var errReauthDenied = errors.New("reauthpassword_test: pre-authentication denies")

// errReauthUserStore is the user store's outage, whose text no refusal carries.
var errReauthUserStore = errors.New("reauthpassword_test: user store down, dsn=secret")

// pwFixture is the bearer re-authentication harness with form login judging
// passwords through the real password provider, over a user store and an
// encoder that are doubles. The encoder compares the fixed hashes above, and
// counts how often ada's own hash is compared, so a case can tell a decoy
// verification from a password check.
type pwFixture struct {
	*reauthHarness

	logs *capturingHandler

	// adaMatches counts comparisons against ada's hash.
	adaMatches atomic.Int32

	// decoyMatches counts comparisons against the reference hash a decoy
	// verification spends.
	decoyMatches atomic.Int32

	// noHash makes the store report ada with no password, and storeDown makes
	// it fail.
	noHash, storeDown bool
}

func newPwFixture(t *testing.T) *pwFixture {
	t.Helper()

	return newPwFixtureOn(t, reauthBearer(t))
}

// newPwFixtureOn is newPwFixture over the harness h, for a case that needs
// another bearer mode.
func newPwFixtureOn(t *testing.T, h *reauthHarness) *pwFixture {
	t.Helper()

	ctrl := gomock.NewController(t)

	f := &pwFixture{reauthHarness: h, logs: &capturingHandler{}}

	enc := NewMockEncoder(ctrl)
	enc.EXPECT().Encode(gomock.Any()).Return(reauthReferenceHash, nil).AnyTimes()
	enc.EXPECT().Match(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(input string, encoded []byte) bool {
			switch {
			case bytes.Equal(encoded, reauthAdaHash):
				f.adaMatches.Add(1)

				return input == reauthAdaPassword
			case bytes.Equal(encoded, reauthOtherHash):
				return input == reauthOtherPassword
			case bytes.Equal(encoded, reauthReferenceHash):
				f.decoyMatches.Add(1)

				return false
			default:
				return false
			}
		})

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, username string) (*identity.Details, error) {
			switch {
			case f.storeDown:
				return nil, errReauthUserStore
			case username == mfaUsername:
				d := &identity.Details{ID: testMFAUser, Username: mfaUsername, Password: reauthAdaHash, Active: true}
				if f.noHash {
					d.Password = nil
				}

				return d, nil
			case username == reauthOtherUsername:
				return &identity.Details{ID: "u-9", Username: reauthOtherUsername, Password: reauthOtherHash, Active: true}, nil
			default:
				return nil, identity.ErrUserNotFound
			}
		})

	authn, err := authenticate.NewUsernamePasswordAuthenticator(users,
		authenticate.WithPasswordEncoder(enc),
		authenticate.WithPasswordLogger(slog.New(f.logs)))
	require.NoError(t, err)

	f.password = authn
	f.chainOpts = append(f.chainOpts, httpsec.WithLogger(slog.New(f.logs)))

	// The user is enrolled on no second factor unless a case says so.
	f.totpUnenrolled = true

	return f
}

// resets pins that a success clears ada's recorded failures, once.
func (f *pwFixture) resets() {
	f.attempts.EXPECT().Reset(gomock.Any(), mfaUsername).Return(nil)
}

// recordsAttempt pins that exactly one failed attempt is recorded, against ada.
func (f *pwFixture) recordsAttempt() {
	f.attempts.EXPECT().RecordFailure(gomock.Any(), mfaUsername, gomock.Any()).Return(nil)
}

// passwordPost is a form re-proof with values, carrying tok.
func passwordPost(ctx context.Context, tok string, values url.Values) *http.Request {
	return bearerRequestTo(ctx, http.MethodPost, reauthPasswordPath, tok, values.Encode())
}

// passwordOf is a form re-proof of password alone.
func passwordOf(password string) func(context.Context, *testing.T, string) *http.Request {
	return func(ctx context.Context, _ *testing.T, tok string) *http.Request {
		return passwordPost(ctx, tok, url.Values{httpsec.DefaultLoginPasswordParam: {password}})
	}
}

// passwordJSON is a JSON re-proof with body, carrying tok.
func passwordJSON(ctx context.Context, tok, body string) *http.Request {
	req := jsonRequest(ctx, reauthPasswordPath, body)
	req.Header.Set("Authorization", "Bearer "+tok)

	return req
}

// passwordReproved asserts out is a successful password re-proof of s: the
// session rotated, its authentication time the chain's now, and its second
// factor state left as it was. It returns the rotated session.
func passwordReproved(t *testing.T, h *reauthHarness, s *session.Session, out served) *session.Session {
	t.Helper()

	require.NoError(t, out.err)
	assert.False(t, out.handlerRan, "the endpoint answers the request itself")
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

	issued, ok := h.issuedFor.Load().(string)
	require.True(t, ok, "a credential was issued")
	assert.NotEqual(t, s.ID, issued, "the session was rotated")
	assert.Equal(t, mfaTokenFor(issued), accessTokenFrom(t, out), "the credential names the rotated session")

	_, err := h.sessions.Load(t.Context(), s.ID)
	require.ErrorIs(t, err, session.ErrNotFound, "the handle the caller arrived with is gone")

	rotated := h.stored(t, issued)
	assert.True(t, rotated.AuthenticatedAt.Equal(h.clock.Now()), "authenticated at the chain's now: %s", rotated.AuthenticatedAt)
	assert.Equal(t, s.MFA, rotated.MFA, "a password leaves the second-factor state alone")
	assert.True(t, rotated.MFASatisfiedAt.Equal(s.MFASatisfiedAt), "a password satisfies no second factor")

	return rotated
}

// emptyUsername replaces the published caller with one that names no
// username, past every gate, as a consumer's first factor might.
func emptyUsername() httpsec.Option {
	blank := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if ex.Authentication != nil && ex.Authentication.Principal != nil {
			p := *ex.Authentication.Principal
			p.Username = ""
			ex.Authentication = &authenticate.Authentication{Principal: &p, Time: ex.Authentication.Time}
		}

		return next(ex)
	})

	return httpsec.RegisterInterceptor(blank, httpsec.After(httpsec.OrderPasswordChange))
}

// TestReauthPassword pins the password re-proof at POST <prefix>/password: the
// factor policy decided before the body is read, only the password read, and
// checked for the session's own user through form login's password path,
// under the account lockout and the password-login source guard.
//
// The chain authenticates by bearer token, and the clock has moved on since the
// session signed in, so a refreshed authentication time is observable.
func TestReauthPassword(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		wire func(t *testing.T, f *pwFixture)
		// before runs requests ahead of the one under test, with the same
		// credential.
		before  func(t *testing.T, f *pwFixture, c *httpsec.Chain, tok string)
		request func(ctx context.Context, t *testing.T, tok string) *http.Request
		assert  func(t *testing.T, f *pwFixture, s *session.Session, out served)
	}

	unread := func(ctx context.Context, t *testing.T, tok string) *http.Request {
		req := postUnread(ctx, t, reauthPasswordPath)
		req.Header.Set("Authorization", "Bearer "+tok)

		return req
	}

	// refusedWith is a refusal that wrote nothing and changed nothing.
	refusedWith := func(want error) func(*testing.T, *pwFixture, *session.Session, served) {
		return func(t *testing.T, f *pwFixture, s *session.Session, out served) {
			t.Helper()

			require.ErrorIs(t, out.err, want)
			assert.False(t, out.handlerRan)
			assert.Zero(t, out.rec.Body.Len(), "nothing was written")
			unchanged(t, f.reauthHarness, s)
		}
	}

	// unchecked is a refusal that compared no password of ada's.
	unchecked := func(want error) func(*testing.T, *pwFixture, *session.Session, served) {
		return func(t *testing.T, f *pwFixture, s *session.Session, out served) {
			t.Helper()

			refusedWith(want)(t, f, s, out)
			assert.Zero(t, f.adaMatches.Load(), "the password was not checked")
		}
	}

	errLookup := errors.New("reauthpassword_test: enrolment store unavailable for ada@example.com")

	cases := []testCase{
		{
			// "Correct password", "A user without a second factor".
			name:    "the correct password re-proves and clears the user's failures",
			wire:    func(_ *testing.T, f *pwFixture) { f.resets() },
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				passwordReproved(t, f.reauthHarness, s, out)
				assert.Equal(t, int32(1), f.adaMatches.Load())
			},
		},
		{
			// "A username in the request is ignored", as a form.
			name: "a username in the form is ignored and the failure is ada's",
			wire: func(_ *testing.T, f *pwFixture) { f.recordsAttempt() },
			request: func(ctx context.Context, _ *testing.T, tok string) *http.Request {
				return passwordPost(ctx, tok, url.Values{
					httpsec.DefaultLoginUsernameParam: {reauthOtherUsername},
					httpsec.DefaultLoginPasswordParam: {reauthOtherPassword},
				})
			},
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				refusedWith(authenticate.ErrAuthenticationFailed)(t, f, s, out)
				assert.Equal(t, int32(1), f.adaMatches.Load(), "u-9's password was compared with ada's hash")
			},
		},
		{
			// "A username in the request is ignored", as JSON.
			name: "a username in a JSON body is ignored and the failure is ada's",
			wire: func(_ *testing.T, f *pwFixture) { f.recordsAttempt() },
			request: func(ctx context.Context, _ *testing.T, tok string) *http.Request {
				return passwordJSON(ctx, tok, `{"username":"`+reauthOtherUsername+`","password":"`+reauthOtherPassword+`"}`)
			},
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				refusedWith(authenticate.ErrAuthenticationFailed)(t, f, s, out)
				assert.Equal(t, int32(1), f.adaMatches.Load())
			},
		},
		{
			name: "the correct password in a JSON body re-proves",
			wire: func(_ *testing.T, f *pwFixture) { f.resets() },
			request: func(ctx context.Context, _ *testing.T, tok string) *http.Request {
				return passwordJSON(ctx, tok, `{"password":"`+reauthAdaPassword+`"}`)
			},
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				passwordReproved(t, f.reauthHarness, s, out)
			},
		},
		{
			// "Wrong password".
			name:    "a wrong password is recorded against the user and leaves the session",
			wire:    func(_ *testing.T, f *pwFixture) { f.recordsAttempt() },
			request: passwordOf("not-the-password"),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				refusedWith(authenticate.ErrAuthenticationFailed)(t, f, s, out)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			},
		},
		{
			// "Locked account": refused as a login refuses a lock, concealed
			// behind a decoy verification by default.
			name: "a locked account is refused as a locked login and its password is not compared",
			wire: func(t *testing.T, f *pwFixture) {
				f.chainOpts = append(f.chainOpts, httpsec.WithPolicyEngine(lockingAda(t)))
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				unchecked(authenticate.ErrAuthenticationFailed)(t, f, s, out)
				require.ErrorIs(t, out.err, lockout.ErrAccountLocked, "the lock stays reachable")
				assert.Positive(t, f.decoyMatches.Load(), "the refusal was concealed behind a decoy verification")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			},
		},
		{
			// "A user with no password".
			name:    "a user with no password is refused as authentication failed",
			wire:    func(_ *testing.T, f *pwFixture) { f.noHash = true; f.recordsAttempt() },
			request: passwordOf("anything"),
			assert:  refusedWith(authenticate.ErrAuthenticationFailed),
		},
		{
			// "Missing password field".
			name: "a missing password is malformed and records nothing",
			request: func(ctx context.Context, _ *testing.T, tok string) *http.Request {
				return passwordPost(ctx, tok, url.Values{httpsec.DefaultLoginUsernameParam: {mfaUsername}})
			},
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				unchecked(httpsec.ErrCredentialsMissing)(t, f, s, out)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
			},
		},
		{
			name:    "an empty password is missing",
			request: passwordOf(""),
			assert:  unchecked(httpsec.ErrCredentialsMissing),
		},
		{
			// "Oversized body".
			name: "a body over the login limit is too large and records nothing",
			request: func(ctx context.Context, _ *testing.T, tok string) *http.Request {
				return passwordPost(ctx, tok, url.Values{
					httpsec.DefaultLoginPasswordParam: {strings.Repeat("p", int(httpsec.DefaultLoginBodyLimit))},
				})
			},
			assert: unchecked(httpsec.ErrRequestTooLarge),
		},
		{
			// "User store unavailable".
			name:    "an unavailable user store is refused as such and records nothing",
			wire:    func(_ *testing.T, f *pwFixture) { f.storeDown = true },
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				refusedWith(authenticate.ErrUnavailable)(t, f, s, out)
				assert.NotContains(t, out.err.Error(), "dsn=secret")
			},
		},
		{
			// "A TOTP holder offers a password".
			name:    "a second-factor holder is refused the password before the body is read",
			wire:    func(_ *testing.T, f *pwFixture) { f.totpUnenrolled = false },
			request: unread,
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				unchecked(httpsec.ErrReauthenticationMethodNotUsable)(t, f, s, out)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
			},
		},
		{
			// "Lookup failure does not downgrade".
			name: "an enrolment lookup failure refuses before the body is read",
			wire: func(_ *testing.T, f *pwFixture) {
				f.extra = []mfa.Method{&challengeStub{channel: testDeviceChannel, enrolledErr: errLookup}}
			},
			request: unread,
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				unchecked(errLookup)(t, f, s, out)
				assert.NotContains(t, out.err.Error(), "ada@example.com", "the store's own text stays out")
			},
		},
		{
			// "Second factor only".
			name: "under second-factor-only a user without one is refused the password",
			wire: func(_ *testing.T, f *pwFixture) {
				f.reauthOpts = append(f.reauthOpts, httpsec.RequireSecondFactorForReauthentication())
			},
			request: unread,
			assert:  unchecked(httpsec.ErrReauthenticationMethodNotUsable),
		},
		{
			// "MFA not configured".
			name:    "without the MFA slot the correct password re-proves",
			wire:    func(_ *testing.T, f *pwFixture) { f.noMFA = true; f.resets() },
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				passwordReproved(t, f.reauthHarness, s, out)
			},
		},
		{
			name:    "a caller with no username is refused as authentication failed",
			wire:    func(_ *testing.T, f *pwFixture) { f.chainOpts = append(f.chainOpts, emptyUsername()) },
			request: passwordOf(reauthAdaPassword),
			assert:  unchecked(authenticate.ErrAuthenticationFailed),
		},
		{
			// The password-login source guard: a refused password spends the
			// source's allowance, and a source past it is refused before the
			// password is checked.
			name: "a refused password is charged to the source, which is then throttled",
			wire: func(t *testing.T, f *pwFixture) {
				f.loginOpts = append(f.loginOpts, httpsec.WithLoginLimiter(memLimiter(t, 1, time.Hour)))
				f.recordsAttempt()
			},
			before: func(t *testing.T, f *pwFixture, c *httpsec.Chain, tok string) {
				out := serve(t, c, passwordOf("not-the-password")(t.Context(), t, tok))
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				f.adaMatches.Store(0)
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				unchecked(ratelimit.ErrThrottled)(t, f, s, out)
			},
		},
		{
			// Form login charges a pre-authentication refusal to the source
			// only when it is a lock.
			name: "a pre-authentication policy refusal is not charged to the source",
			wire: func(t *testing.T, f *pwFixture) {
				f.loginOpts = append(f.loginOpts, httpsec.WithLoginLimiter(memLimiter(t, 1, time.Hour)))
				f.chainOpts = append(f.chainOpts, httpsec.WithPolicyEngine(denyingIn(t, policy.PreAuthentication, errReauthDenied)))
			},
			before: func(t *testing.T, _ *pwFixture, c *httpsec.Chain, tok string) {
				out := serve(t, c, passwordOf(reauthAdaPassword)(t.Context(), t, tok))
				require.ErrorIs(t, out.err, errReauthDenied)
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				unchecked(errReauthDenied)(t, f, s, out)
				assert.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "a policy refusal spent the source's allowance")
			},
		},
		{
			// The check is the session's own user's, whatever a consumer's
			// interceptor past the gates published as the caller.
			name: "a caller who is not the session's user is refused before any password is checked",
			wire: func(_ *testing.T, f *pwFixture) {
				swap := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					if ex.Authentication != nil && ex.Authentication.Principal != nil {
						p := *ex.Authentication.Principal
						p.ID = identity.UserID("u-9")
						p.Username = reauthOtherUsername
						ex.Authentication = &authenticate.Authentication{Principal: &p, Time: ex.Authentication.Time}
					}

					return next(ex)
				})
				f.chainOpts = append(f.chainOpts, httpsec.RegisterInterceptor(swap, httpsec.After(httpsec.OrderPasswordChange)))
			},
			request: passwordOf(reauthOtherPassword),
			assert:  unchecked(authenticate.ErrAuthenticationFailed),
		},
		{
			// A rewrite of the username alone still names another account;
			// the password it proves is that account's, not the session's.
			name: "a caller whose username names another user is refused",
			wire: func(_ *testing.T, f *pwFixture) {
				swap := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					if ex.Authentication != nil && ex.Authentication.Principal != nil {
						p := *ex.Authentication.Principal
						p.Username = reauthOtherUsername
						ex.Authentication = &authenticate.Authentication{Principal: &p, Time: ex.Authentication.Time}
					}

					return next(ex)
				})
				f.chainOpts = append(f.chainOpts, httpsec.RegisterInterceptor(swap, httpsec.After(httpsec.OrderPasswordChange)))
			},
			request: passwordOf(reauthOtherPassword),
			assert:  unchecked(authenticate.ErrAuthenticationFailed),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newPwFixture(t)
			if tc.wire != nil {
				tc.wire(t, f)
			}

			s := f.newSession(t, factor.Password, session.MFANone)

			// Time has passed since the sign-in, so a refreshed
			// authentication time differs from the one the session holds.
			f.clock.Advance(10 * time.Minute)

			c, err := f.build(nil)
			require.NoError(t, err)

			tok := mfaTokenFor(s.ID)
			if tc.before != nil {
				tc.before(t, f, c, tok)
			}

			tc.assert(t, f, s, serve(t, c, tc.request(t.Context(), t, tok)))
		})
	}
}
