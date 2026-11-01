package httpsec_test

//go:generate mockgen -destination=challengemethod_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authenticate/mfa ChallengeMethod

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
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
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

// errReauthPostDenied is a post-authentication policy's refusal.
var errReauthPostDenied = errors.New("reauthpassword_test: post-authentication denies")

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

	// lookups counts the enrolment lookups the methods built by
	// countedMethods receive.
	lookups atomic.Int32

	// adaMatches counts comparisons against ada's hash.
	adaMatches atomic.Int32

	// decoyMatches counts comparisons against the reference hash a decoy
	// verification spends.
	decoyMatches atomic.Int32

	// noHash makes the store report ada with no password, and storeDown makes
	// it fail.
	noHash, storeDown bool

	// changedAt is when the store reports ada last changed her password; the
	// zero time reports it unknown.
	changedAt time.Time

	// records is the recovery record store a case enabled account recovery
	// over (withRecovery), and held is ada's recovery it holds.
	records recovery.RecordStore
	held    recovery.Record

	// holdTokens is the store the held recovery's finish and cancel tokens
	// live in, and built the chain a case runs its request on.
	holdTokens onetime.Store
	built      *httpsec.Chain

	// capture, when a case sets it, collects every post-authentication input.
	capture *[]policy.Input

	// loginIssued is the last credential issued before the request under
	// test, by a login a case ran first.
	loginIssued any
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
				d := &identity.Details{
					ID: testMFAUser, Username: mfaUsername, Password: reauthAdaHash, Active: true,
					PasswordChangedAt: f.changedAt,
				}
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

// reauthOtherHeldID names a recovery held for another user, which no re-proof
// of ada's may cancel.
var reauthOtherHeldID = id.MustParse("01900000-0000-7000-8000-0000000000b2")

// withRecovery enables account recovery with a hold over records, which then
// holds a recovery of ada's and one of another user's. A hold is what makes
// a first factor cancel the user's held recoveries.
func (f *pwFixture) withRecovery(t *testing.T, records recovery.RecordStore) {
	t.Helper()

	totpMethod, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
	require.NoError(t, err)

	kind, err := recovery.MFAEnrolments(totpMethod)
	require.NoError(t, err)

	codes, err := recovery.NewCodes()
	require.NoError(t, err)

	now := f.clock.Now()
	f.held = recovery.Record{
		ID: id.MustParse("01900000-0000-7000-8000-0000000000b1"), User: testMFAUser,
		StartedAt: now, NotBefore: now.Add(recoveryHoldDelay),
	}
	other := recovery.Record{
		ID: reauthOtherHeldID, User: "u-9",
		StartedAt: now, NotBefore: now.Add(recoveryHoldDelay),
	}
	require.NoError(t, records.Insert(t.Context(), f.held))
	require.NoError(t, records.Insert(t.Context(), other))

	f.records = records

	holdTokens, err := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(f.clock))
	require.NoError(t, err)

	f.holdTokens = holdTokens
	f.chainOpts = append(f.chainOpts,
		// A recovered session needs a way to become a full one.
		httpsec.EnablePasswordChangeGate(f.sessions,
			httpsec.WithPasswordChangeEndpoint(passwordResolvePath, func(*httpsec.Exchange) error { return nil })),
		httpsec.EnableAccountRecovery(httpsec.RecoveryDeps{
			Users: f.users, Sessions: f.sessions, Sender: &capturingSender{}, Codes: codes, Records: records,
		},
			httpsec.WithRecoveryTokens(f.tokens),
			httpsec.WithRecoveryCore(
				recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
				recovery.WithRepudiationContact("Write to security@example.com if this was not you."),
				recovery.WithAuthenticatorKinds(kind),
				recovery.WithMessages(recoveryMessages{}),
				recovery.WithHoldDelay(recoveryHoldDelay),
				recovery.WithHoldTokenStore(holdTokens),
				recovery.WithCancelLink("https://app.example.com/cancel"),
			)))
}

// finishHeld is the request that finishes ada's held recovery: a POST to the
// finish endpoint carrying a completion token issued for it, which the hold
// accepts for as long as the recovery is pending.
func (f *pwFixture) finishHeld(t *testing.T) *http.Request {
	t.Helper()

	tokens, err := onetime.New(recovery.FinishTokenPurpose,
		onetime.WithStore(f.holdTokens), onetime.WithTokenTTL(24*time.Hour), onetime.WithClock(f.clock))
	require.NoError(t, err)

	token, _, err := tokens.Issue(t.Context(), f.held.ID.String())
	require.NoError(t, err)

	return postValues(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource,
		url.Values{httpsec.RecoveryCompletionTokenParam: {token}})
}

// heldStands asserts whether ada's held recovery still stands, and that the
// other user's always does.
func (f *pwFixture) heldStands(t *testing.T, stands bool) {
	t.Helper()

	got, err := f.records.Find(t.Context(), f.held.ID)
	require.NoError(t, err)
	assert.Equal(t, stands, got.CancelledAt.IsZero(), "ada's held recovery cancelled: %s", got.CancelledAt)

	other, err := f.records.Find(t.Context(), reauthOtherHeldID)
	require.NoError(t, err)
	assert.True(t, other.CancelledAt.IsZero(), "another user's held recovery stands")
}

// capturingInputs is a post-authentication policy that allows and records
// every input it is given.
func capturingInputs(t *testing.T, seen *[]policy.Input) *policy.Engine {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("test: capture").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, in *policy.Input) policy.Decision {
			*seen = append(*seen, *in)

			return policy.Decision{Outcome: policy.Allow}
		})

	return engineOf(t, p)
}

// adaLogin is a form login by ada with her correct password.
func adaLogin(t *testing.T, c *httpsec.Chain) served {
	t.Helper()

	return serve(t, c, formRequest(t.Context(), httpsec.DefaultLoginPath, url.Values{
		httpsec.DefaultLoginUsernameParam: {mfaUsername},
		httpsec.DefaultLoginPasswordParam: {reauthAdaPassword},
	}.Encode()))
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

// countedMethods are methods named a, b and c, in that order, whose lookups
// all add to counter. enrolled says which of them the user is enrolled on, and
// errs which of them fail the lookup.
func countedMethods(t *testing.T, counter *atomic.Int32, enrolled [3]bool, errs [3]error) []mfa.Method {
	names := [3]string{"a", "b", "c"}
	methods := make([]mfa.Method, 0, len(names))

	ctrl := gomock.NewController(t)

	for i, name := range names {
		stub := &challengeStub{
			name: name, channel: testDeviceChannel, enrolled: enrolled[i], enrolledErr: errs[i],
		}

		// The mock stands in for the method and delegates to the scripted
		// stub, counting only the enrolment lookups.
		m := NewMockChallengeMethod(ctrl)
		m.EXPECT().Name().DoAndReturn(stub.Name).AnyTimes()
		m.EXPECT().Channel().DoAndReturn(stub.Channel).AnyTimes()
		m.EXPECT().Response().DoAndReturn(stub.Response).AnyTimes()
		m.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(stub.Verify).AnyTimes()
		m.EXPECT().BeginChallenge(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(stub.BeginChallenge).AnyTimes()
		m.EXPECT().PresentedChallenge(gomock.Any()).DoAndReturn(stub.PresentedChallenge).AnyTimes()
		m.EXPECT().Enrolled(gomock.Any(), gomock.Any()).AnyTimes().
			DoAndReturn(func(ctx context.Context, user identity.UserID) (bool, error) {
				counter.Add(1)

				return stub.Enrolled(ctx, user)
			})

		methods = append(methods, m)
	}

	return methods
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
			// "The password endpoint settles at the first enrolled method".
			name: "the first enrolled method settles the refusal without asking the others",
			wire: func(t *testing.T, f *pwFixture) {
				f.extra = countedMethods(t, &f.lookups, [3]bool{true, true, true}, [3]error{})
			},
			request: unread,
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				unchecked(httpsec.ErrReauthenticationMethodNotUsable)(t, f, s, out)
				assert.Equal(t, int32(1), f.lookups.Load(), "only the first method was asked")
			},
		},
		{
			name: "a method after the first enrolled one that would fail is never asked",
			wire: func(t *testing.T, f *pwFixture) {
				f.extra = countedMethods(t, &f.lookups, [3]bool{true}, [3]error{1: errLookup})
			},
			request: unread,
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				unchecked(httpsec.ErrReauthenticationMethodNotUsable)(t, f, s, out)
				assert.NotErrorIs(t, out.err, errLookup)
				assert.Equal(t, int32(1), f.lookups.Load())
			},
		},
		{
			name: "a lookup that fails before one is enrolled refuses as a failed lookup",
			wire: func(t *testing.T, f *pwFixture) {
				f.extra = countedMethods(t, &f.lookups, [3]bool{2: true}, [3]error{1: errLookup})
			},
			request: unread,
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				unchecked(errLookup)(t, f, s, out)
				assert.Equal(t, int32(2), f.lookups.Load(), "the methods after the failure were not asked")
			},
		},
		{
			name: "with none enrolled every method is asked and the password re-proves",
			wire: func(t *testing.T, f *pwFixture) {
				f.extra = countedMethods(t, &f.lookups, [3]bool{}, [3]error{})
				f.resets()
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				passwordReproved(t, f.reauthHarness, s, out)
				assert.Equal(t, int32(3), f.lookups.Load())
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
			// A source hammering a locked account spends its own allowance,
			// as at form login, so the lock is charged and the next attempt
			// is throttled rather than refused as locked again.
			name: "a locked account is charged to the source, which is then throttled",
			wire: func(t *testing.T, f *pwFixture) {
				f.loginOpts = append(f.loginOpts, httpsec.WithLoginLimiter(memLimiter(t, 1, time.Hour)))
				f.chainOpts = append(f.chainOpts, httpsec.WithPolicyEngine(lockingAda(t)))
			},
			before: func(t *testing.T, _ *pwFixture, c *httpsec.Chain, tok string) {
				out := serve(t, c, passwordOf(reauthAdaPassword)(t.Context(), t, tok))
				require.ErrorIs(t, out.err, lockout.ErrAccountLocked)
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				unchecked(ratelimit.ErrThrottled)(t, f, s, out)
				assert.NotErrorIs(t, out.err, lockout.ErrAccountLocked, "the lock did not spend the source's allowance")
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
			// "Post-authentication deny": refused as ada's login is refused,
			// with nothing reset, rotated or refreshed.
			name: "a post-authentication deny refuses with the policy's reason and resets nothing",
			wire: func(t *testing.T, f *pwFixture) {
				f.chainOpts = append(f.chainOpts,
					httpsec.WithPolicyEngine(denyingIn(t, policy.PostAuthentication, errReauthPostDenied)))
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				refusedWith(errReauthPostDenied)(t, f, s, out)
				assert.Equal(t, int32(1), f.adaMatches.Load(), "the password was proved first")
			},
		},
		{
			// Form login charges the source nothing for a policy's refusal
			// after the password, so neither does a re-proof.
			name: "a post-authentication deny is not charged to the source",
			wire: func(t *testing.T, f *pwFixture) {
				f.loginOpts = append(f.loginOpts, httpsec.WithLoginLimiter(memLimiter(t, 1, time.Hour)))
				f.chainOpts = append(f.chainOpts,
					httpsec.WithPolicyEngine(denyingIn(t, policy.PostAuthentication, errReauthPostDenied)))
			},
			before: func(t *testing.T, _ *pwFixture, c *httpsec.Chain, tok string) {
				out := serve(t, c, passwordOf(reauthAdaPassword)(t.Context(), t, tok))
				require.ErrorIs(t, out.err, errReauthPostDenied)
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				refusedWith(errReauthPostDenied)(t, f, s, out)
				assert.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "a policy refusal spent the source's allowance")
			},
		},
		{
			// "Post-authentication challenge": refused with the challenge,
			// carrying no session, and nothing marked pending.
			name: "a post-authentication password-change challenge refuses with no session and marks nothing",
			wire: func(t *testing.T, f *pwFixture) {
				f.chainOpts = append(f.chainOpts,
					httpsec.EnableGateForTest(policy.ChallengePasswordChange),
					httpsec.WithPolicyEngine(challengingIn(t, policy.PostAuthentication, policy.ChallengePasswordChange)))
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				var ce *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ce)
				assert.Equal(t, policy.ChallengePasswordChange, ce.Kind)
				assert.Nil(t, ce.Session, "a re-proof establishes no pending session")
				assert.Empty(t, ce.Token, "a re-proof issues no credential for a challenge")
				assert.False(t, out.handlerRan)
				assert.Zero(t, out.rec.Body.Len(), "nothing was written")
				unchanged(t, f.reauthHarness, s)
				assert.False(t, f.stored(t, s.ID).PasswordChangePending, "no pending mark was stored")
			},
		},
		{
			// A challenge nothing on the chain enforces is the wiring
			// mistake a login refuses it as, before anything is marked.
			name: "an unenforced post-authentication challenge is a configuration error",
			wire: func(t *testing.T, f *pwFixture) {
				f.chainOpts = append(f.chainOpts,
					httpsec.WithPolicyEngine(challengingIn(t, policy.PostAuthentication, policy.ChallengeMFAEnrolment)))
			},
			request: passwordOf(reauthAdaPassword),
			assert:  refusedWith(httpsec.ErrConfig),
		},
		{
			// An allowing policy leaves the re-proof as it was.
			name: "an allowing post-authentication policy re-proves",
			wire: func(t *testing.T, f *pwFixture) {
				f.chainOpts = append(f.chainOpts, httpsec.WithPolicyEngine(allowingEngine(t)))
				f.resets()
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				passwordReproved(t, f.reauthHarness, s, out)
			},
		},
		{
			// "A user at the session cap re-proves": the re-proved session is
			// the user's only one, under a cap of one.
			name: "a user at the session cap re-proves the session already counted",
			wire: func(t *testing.T, f *pwFixture) {
				capPolicy, err := policy.NewConcurrentSessions(f.sessions, 1)
				require.NoError(t, err)
				f.chainOpts = append(f.chainOpts, httpsec.WithPolicyEngine(engineOf(t, capPolicy)))
				f.resets()
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				passwordReproved(t, f.reauthHarness, s, out)
			},
		},
		{
			// "Consumer policy sees a re-proof": the phase is told it judges a
			// re-authentication, and a login through the same chain is not.
			name: "the post-authentication phase is told the re-proof re-authenticates and a login is not",
			wire: func(t *testing.T, f *pwFixture) {
				f.capture = new([]policy.Input)
				f.chainOpts = append(f.chainOpts, httpsec.WithPolicyEngine(capturingInputs(t, f.capture)))
				f.attempts.EXPECT().Reset(gomock.Any(), mfaUsername).Return(nil).Times(2)
			},
			before: func(t *testing.T, f *pwFixture, c *httpsec.Chain, _ string) {
				out := adaLogin(t, c)
				require.NoError(t, out.err)
				require.Len(t, *f.capture, 1, "the login ran the phase once")
				assert.False(t, (*f.capture)[0].Reauthenticating, "a login is not a re-authentication")
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				passwordReproved(t, f.reauthHarness, s, out)
				require.Len(t, *f.capture, 2, "the re-proof ran the phase once")

				in := (*f.capture)[1]
				assert.True(t, in.Reauthenticating, "the phase was not told it judges a re-proof")
				assert.Equal(t, testMFAUser, in.User)
				assert.Equal(t, mfaUsername, in.Username)
				assert.Equal(t, factor.Password, in.FirstFactor)
			},
		},
		{
			// The phase receives login's input: a gate keyed on the user's
			// password-change time refuses the re-proof as it challenges
			// ada's login through the same chain.
			name: "a password-age gate refuses the re-proof as it challenges the login",
			wire: func(t *testing.T, f *pwFixture) {
				f.changedAt = f.clock.Now().Add(-2 * maxPasswordAge)
				f.chainOpts = append(f.chainOpts,
					httpsec.EnableGateForTest(policy.ChallengePasswordChange),
					httpsec.WithPolicyEngine(engineOf(t, passwordAgeGate(t))))
				// Login clears failures before its phase; the refused
				// re-proof clears nothing.
				f.resets()
			},
			before: func(t *testing.T, f *pwFixture, c *httpsec.Chain, _ string) {
				var ce *httpsec.ChallengeError
				require.ErrorAs(t, adaLogin(t, c).err, &ce, "the gate let ada's stale login through")
				require.Equal(t, policy.ChallengePasswordChange, ce.Kind)
				f.loginIssued = f.issuedFor.Load()
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				var ce *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ce, "the gate let a stale password re-prove")
				assert.Equal(t, policy.ChallengePasswordChange, ce.Kind)
				assert.Nil(t, ce.Session)
				assert.Zero(t, out.rec.Body.Len(), "nothing was written")

				stored := f.stored(t, s.ID)
				assert.True(t, stored.AuthenticatedAt.Equal(s.AuthenticatedAt), "the authentication time is unchanged")
				assert.False(t, stored.PasswordChangePending, "no pending mark was stored")
				assert.Equal(t, f.loginIssued, f.issuedFor.Load(), "the re-proof issued a credential")
			},
		},
		{
			// "A held recovery is cancelled": a proved password shows the user
			// holds the account, so the held recovery can no longer finish.
			name: "a successful re-proof cancels the user's held recovery",
			wire: func(t *testing.T, f *pwFixture) {
				f.withRecovery(t, recovery.NewMemoryRecordStore())
				f.resets()
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				passwordReproved(t, f.reauthHarness, s, out)
				f.heldStands(t, false)

				// The hold's delay has run out, so only the cancellation
				// stands between the recovery and its completion.
				finish := f.finishHeld(t)
				f.clock.Advance(recoveryHoldDelay)

				finished := serve(t, f.built, finish)
				require.ErrorIs(t, finished.err, recovery.ErrRefused, "the held recovery still finishes after the re-proof")
			},
		},
		{
			// As at login, the cancel runs before the phase, so a re-proof the
			// phase refuses has still cancelled.
			name: "a re-proof the phase denies still cancels the user's held recovery",
			wire: func(t *testing.T, f *pwFixture) {
				f.withRecovery(t, recovery.NewMemoryRecordStore())
				f.chainOpts = append(f.chainOpts,
					httpsec.WithPolicyEngine(denyingIn(t, policy.PostAuthentication, errReauthPostDenied)))
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				refusedWith(errReauthPostDenied)(t, f, s, out)
				f.heldStands(t, false)
			},
		},
		{
			// A wrong password proves nothing, so nothing is cancelled.
			name: "a wrong password cancels nothing",
			wire: func(t *testing.T, f *pwFixture) {
				f.withRecovery(t, recovery.NewMemoryRecordStore())
				f.recordsAttempt()
			},
			request: passwordOf("not-the-password"),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				refusedWith(authenticate.ErrAuthenticationFailed)(t, f, s, out)
				f.heldStands(t, true)
			},
		},
		{
			// A cancellation the store cannot record refuses, as at login,
			// before the phase runs and with nothing reset or rotated.
			name: "a cancellation the record store cannot record refuses and leaves the session",
			wire: func(t *testing.T, f *pwFixture) {
				f.capture = new([]policy.Input)
				f.chainOpts = append(f.chainOpts, httpsec.WithPolicyEngine(capturingInputs(t, f.capture)))
				f.withRecovery(t, recordsCancelPendingFails(t))
			},
			request: passwordOf(reauthAdaPassword),
			assert: func(t *testing.T, f *pwFixture, s *session.Session, out served) {
				refusedWith(errRecordStoreDown)(t, f, s, out)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.NotContains(t, out.err.Error(), "10.0.0.9", "the store's text is not the library's")
				assert.Empty(t, *f.capture, "the phase ran although the cancel failed")
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

			f.built = c

			tok := mfaTokenFor(s.ID)
			if tc.before != nil {
				tc.before(t, f, c, tok)
			}

			tc.assert(t, f, s, serve(t, c, tc.request(t.Context(), t, tok)))
		})
	}
}
