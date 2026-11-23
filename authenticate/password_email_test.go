package authenticate_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/eventsink"
)

// emailUserLoader is a user loader that also loads by email, built from the
// two generated mocks, as a consumer's store implementing both ports is.
type emailUserLoader struct {
	*MockUserLoader
	*MockEmailLoader
}

// emailVerifiedAt is when the verified emails below were verified.
var emailVerifiedAt = time.Date(2024, time.May, 2, 10, 0, 0, 0, time.UTC)

// identifierConflictEvent is the event name the conflict refusal reports.
const identifierConflictEvent = "scrty_identifier_conflict"

// emailFixture is one case's world: the mocks, the encoder that counts the
// password work, the users the mocks hand out, and the events reported.
type emailFixture struct {
	users  *MockUserLoader
	emails *MockEmailLoader
	enc    *recordingEncoder

	// ada is an active user whose verified email is Ada@Example.com.
	ada *identity.Details
	// unverified is ada with her email not verified.
	unverified *identity.Details
	// emailNamed is an active user whose username is x@example.com.
	emailNamed *identity.Details
	// owner is a different active user whose verified email is x@example.com.
	owner *identity.Details

	// logs is where the provider's records are written.
	logs *bytes.Buffer

	mu     sync.Mutex
	events []event.Event
}

func newEmailFixture(t *testing.T) *emailFixture {
	t.Helper()

	ctrl := gomock.NewController(t)
	inner := cheapEncoder(t)

	ada := storedUser(t, inner, true)
	ada.Email = "Ada@Example.com"
	ada.EmailVerifiedAt = emailVerifiedAt

	unverified := *ada
	unverified.EmailVerifiedAt = time.Time{}

	emailNamed := storedUser(t, inner, true)
	emailNamed.ID = "u-x"
	emailNamed.Username = "x@example.com"

	owner := storedUser(t, inner, true)
	owner.ID = "u-owner"
	owner.Username = "owner"
	owner.Email = "x@example.com"
	owner.EmailVerifiedAt = emailVerifiedAt

	return &emailFixture{
		users:      NewMockUserLoader(ctrl),
		emails:     NewMockEmailLoader(ctrl),
		enc:        newRecordingEncoder(t, ctrl, inner),
		ada:        ada,
		unverified: &unverified,
		emailNamed: emailNamed,
		owner:      owner,
		logs:       &bytes.Buffer{},
	}
}

// loader is the fixture's loader implementing both ports.
func (f *emailFixture) loader() identity.UserLoader {
	return emailUserLoader{MockUserLoader: f.users, MockEmailLoader: f.emails}
}

// watch returns ctx carrying an emitter that records every event reported on it.
func (f *emailFixture) watch(ctx context.Context) context.Context {
	return eventsink.With(ctx, func(_ context.Context, e event.Event) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.events = append(f.events, e)
	})
}

func (f *emailFixture) reported() []event.Event {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]event.Event(nil), f.events...)
}

// build constructs the provider over loader with the fixture's encoder.
func (f *emailFixture) build(loader identity.UserLoader, opts ...authenticate.PasswordOption) (*authenticate.UsernamePasswordAuthenticator, error) {
	return authenticate.NewUsernamePasswordAuthenticator(loader,
		append([]authenticate.PasswordOption{
			authenticate.WithPasswordEncoder(f.enc),
			authenticate.WithPasswordLogger(debugLogger(f.logs)),
		}, opts...)...)
}

// oneReferenceVerification asserts the attempt cost exactly what an unknown
// username costs: one verification, against the reference hash.
func (f *emailFixture) oneReferenceVerification(t *testing.T) {
	t.Helper()

	matches, matchedTo := f.enc.calls()
	require.Equal(t, 1, matches, "the attempt must cost one verification, as an unknown username does")
	assert.Equal(t, f.enc.reference(t), matchedTo[0], "the one verification was not against the reference hash")
}

// conflictEvents counts the identifier-conflict events reported.
func (f *emailFixture) conflictEvents() int {
	n := 0
	for _, e := range f.reported() {
		if e.Name == identifierConflictEvent {
			n++
		}
	}

	return n
}

// assertNoIdentifierInError asserts the error text quotes none of the
// identifiers involved.
func assertNoIdentifierInError(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	for _, s := range []string{"example.com", "Example.com", "ada", "owner"} {
		assert.NotContains(t, err.Error(), s)
	}
}

func TestPassword_EmailLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		emailLogin bool
		// usernameOnly builds over a loader without the email port.
		usernameOnly bool
		identifier   string
		ctx          func(ctx context.Context) context.Context
		expect       func(f *emailFixture)
		assert       func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error)
	}

	cases := []testCase{
		{
			name:       "off by default: a verified email is not a username",
			identifier: "ada@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), gomock.Any()).Times(0)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
				f.oneReferenceVerification(t)
			},
		},
		{
			name:         "a loader without the email port fails construction",
			emailLogin:   true,
			usernameOnly: true,
			identifier:   "ada@example.com",
			assert: func(t *testing.T, _ *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				require.ErrorIs(t, err, authenticate.ErrConfig)
			},
		},
		{
			name:       "email login succeeds, ignoring case",
			emailLogin: true,
			identifier: "ADA@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ADA@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ADA@example.com").Return(f.ada, nil).Times(1)
			},
			assert: func(t *testing.T, _ *emailFixture, result *authenticate.Authentication, err error) {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, "ada", result.Principal.Username)
				assert.Equal(t, identity.UserID("u1"), result.Principal.ID)
			},
		},
		{
			name:       "a username without @ keeps the username-only path",
			emailLogin: true,
			identifier: "ada",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(f.ada, nil).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), gomock.Any()).Times(0)
			},
			assert: func(t *testing.T, _ *emailFixture, result *authenticate.Authentication, err error) {
				require.NoError(t, err)
				assert.Equal(t, "ada", result.Principal.Username)
			},
		},
		{
			name:       "an unverified email gives the uniform failure",
			emailLogin: true,
			identifier: "ada@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
				f.oneReferenceVerification(t)
			},
		},
		{
			name:       "an email loader that returns an unverified user is refused",
			emailLogin: true,
			identifier: "ada@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(f.unverified, nil).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
				f.oneReferenceVerification(t)
			},
		},
		{
			name:       "an email loader that returns a user with another email is refused",
			emailLogin: true,
			identifier: "eve@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "eve@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "eve@example.com").Return(f.ada, nil).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
				f.oneReferenceVerification(t)
			},
		},
		{
			name:       "an identifier naming two users is refused with decoy work and an event",
			emailLogin: true,
			identifier: "x@example.com",
			ctx:        nil,
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "x@example.com").Return(f.emailNamed, nil).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "x@example.com").Return(f.owner, nil).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
				f.oneReferenceVerification(t)
				require.Equal(t, 1, f.conflictEvents(), "the conflict must be reported once")
				for _, e := range f.reported() {
					assert.Equal(t, event.OutcomeFailure, e.Outcome)
					assert.Empty(t, e.User, "a refused login names no user")
				}
			},
		},
		{
			name:       "a username equal to the same user's own email is no conflict",
			emailLogin: true,
			identifier: "x@example.com",
			expect: func(f *emailFixture) {
				self := *f.emailNamed
				self.Email = "x@example.com"
				self.EmailVerifiedAt = emailVerifiedAt
				f.users.EXPECT().LoadByUsername(gomock.Any(), "x@example.com").Return(&self, nil).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "x@example.com").Return(&self, nil).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				require.NoError(t, err)
				assert.Equal(t, "x@example.com", result.Principal.Username)
				assert.Zero(t, f.conflictEvents())
			},
		},
		{
			name:       "conflict check: an unverified other user is no conflict",
			emailLogin: true,
			identifier: "x@example.com",
			expect: func(f *emailFixture) {
				other := *f.owner
				other.EmailVerifiedAt = time.Time{}
				f.users.EXPECT().LoadByUsername(gomock.Any(), "x@example.com").Return(f.emailNamed, nil).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "x@example.com").Return(&other, nil).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				require.NoError(t, err)
				assert.Equal(t, "x@example.com", result.Principal.Username)
				assert.Zero(t, f.conflictEvents())
				assert.Empty(t, refusalRecords(t, f.logs), "an answer that names no second account writes no refusal record")
			},
		},
		{
			name:       "conflict check: an other user with another email is no conflict",
			emailLogin: true,
			identifier: "x@example.com",
			expect: func(f *emailFixture) {
				other := *f.owner
				other.Email = "y@example.com"
				f.users.EXPECT().LoadByUsername(gomock.Any(), "x@example.com").Return(f.emailNamed, nil).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "x@example.com").Return(&other, nil).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				require.NoError(t, err)
				assert.Equal(t, "x@example.com", result.Principal.Username)
				assert.Zero(t, f.conflictEvents())
				assert.Empty(t, refusalRecords(t, f.logs), "an answer that names no second account writes no refusal record")
			},
		},
		{
			name:       "conflict check: an other user returned with not-found is no conflict",
			emailLogin: true,
			identifier: "x@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "x@example.com").Return(f.emailNamed, nil).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "x@example.com").Return(f.owner, identity.ErrUserNotFound).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				require.NoError(t, err)
				assert.Equal(t, "x@example.com", result.Principal.Username)
				assert.Zero(t, f.conflictEvents())
				assert.Empty(t, refusalRecords(t, f.logs), "an answer that names no second account writes no refusal record")
			},
		},
		{
			name:       "conflict check the caller's cancellation ended is the uniform failure, no event",
			emailLogin: true,
			identifier: "x@example.com",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "x@example.com").Return(f.emailNamed, nil).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "x@example.com").
					DoAndReturn(func(ctx context.Context, _ string) (*identity.Details, error) { return nil, ctx.Err() }).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, authenticate.ErrUnavailable)
				f.oneReferenceVerification(t)
				assert.Empty(t, f.reported())
			},
		},
		{
			name:       "an email loader answering nothing and no error is the uniform failure",
			emailLogin: true,
			identifier: "ada@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(nil, nil).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
				f.oneReferenceVerification(t)
				assert.Empty(t, f.reported())
			},
		},
		{
			name:       "an email loader answering a user with not-found is the uniform failure",
			emailLogin: true,
			identifier: "ada@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(f.ada, identity.ErrUserNotFound).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
				f.oneReferenceVerification(t)
				assert.Empty(t, f.reported())
			},
		},
		{
			name:       "an email loader answering a user with an outage is unavailable",
			emailLogin: true,
			identifier: "ada@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(f.ada, errBackendDown).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrUnavailable, err)
				assertNoIdentifierInError(t, err)
				f.oneReferenceVerification(t)
				assert.Empty(t, f.reported())
			},
		},
		{
			name:       "an email lookup outage gives the unavailable error after the same work",
			emailLogin: true,
			identifier: "ada@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(nil, errBackendDown).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrUnavailable, err)
				assertNoIdentifierInError(t, err)
				f.oneReferenceVerification(t)
			},
		},
		{
			name:       "a conflict-check outage gives the unavailable error after the same work",
			emailLogin: true,
			identifier: "x@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "x@example.com").Return(f.emailNamed, nil).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "x@example.com").Return(nil, errBackendDown).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrUnavailable, err)
				f.oneReferenceVerification(t)
				assert.Zero(t, f.conflictEvents())
			},
		},
		{
			name:       "an email lookup the caller's cancellation ended is the uniform failure",
			emailLogin: true,
			identifier: "ada@example.com",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").
					DoAndReturn(func(ctx context.Context, _ string) (*identity.Details, error) { return nil, ctx.Err() }).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, result *authenticate.Authentication, err error) {
				assert.Nil(t, result)
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, authenticate.ErrUnavailable)
				f.oneReferenceVerification(t)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailFixture(t)
			if tc.expect != nil {
				tc.expect(f)
			}

			ctx := f.watch(t.Context())
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			loader := f.loader()
			if tc.usernameOnly {
				loader = f.users
			}

			var opts []authenticate.PasswordOption
			if tc.emailLogin {
				opts = append(opts, authenticate.WithEmailLogin())
			}

			auth, err := f.build(loader, opts...)
			if err != nil {
				tc.assert(t, f, nil, err)

				return
			}

			result, err := auth.Authenticate(ctx, identity.NewUsernamePassword(tc.identifier, []byte(storedPassword)))
			tc.assert(t, f, result, err)
		})
	}
}

// TestPassword_ResolveIdentifier pins the resolution step the chain runs before
// its pre-authentication phase, and the carrier that hands its result to the
// provider without a second load.
func TestPassword_ResolveIdentifier(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		identifier string
		// presented is the username of the credentials authenticated after
		// resolving; empty means the identifier.
		presented string
		expect    func(f *emailFixture)
		// carrier turns the resolution into what is put on the context.
		carrier func(t *testing.T, f *emailFixture, r authenticate.ResolvedIdentifier) authenticate.ResolvedIdentifier
		assert  func(t *testing.T, f *emailFixture, r authenticate.ResolvedIdentifier, resolveErr error, result *authenticate.Authentication, err error)
	}

	cases := []testCase{
		{
			name:       "found by email: keyed on the username, loaded once",
			identifier: "ada@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(f.ada, nil).Times(1)
			},
			assert: func(t *testing.T, _ *emailFixture, r authenticate.ResolvedIdentifier, resolveErr error, result *authenticate.Authentication, err error) {
				require.NoError(t, resolveErr)
				assert.Equal(t, "ada", r.Key)
				require.NotNil(t, r.Details)
				assert.Equal(t, identity.UserID("u1"), r.Details.ID)
				assert.Empty(t, r.Details.Password, "the resolution must not hand the hash outward")
				require.NoError(t, err)
				assert.Equal(t, "ada", result.Principal.Username)
			},
		},
		{
			name:       "found by username: keyed on the username, loaded once",
			identifier: "ada",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(f.ada, nil).Times(1)
			},
			assert: func(t *testing.T, _ *emailFixture, r authenticate.ResolvedIdentifier, resolveErr error, result *authenticate.Authentication, err error) {
				require.NoError(t, resolveErr)
				assert.Equal(t, "ada", r.Key)
				require.NoError(t, err)
				assert.Equal(t, "ada", result.Principal.Username)
			},
		},
		{
			name:       "not found: keyed on the identifier as typed, refused without a second load",
			identifier: "Nobody@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "Nobody@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "Nobody@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, r authenticate.ResolvedIdentifier, resolveErr error, _ *authenticate.Authentication, err error) {
				require.NoError(t, resolveErr)
				assert.Equal(t, "Nobody@example.com", r.Key)
				assert.Nil(t, r.Details)
				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
				f.oneReferenceVerification(t)
			},
		},
		{
			name:       "conflict: keyed on the identifier, reported once, refused with decoy work",
			identifier: "x@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "x@example.com").Return(f.emailNamed, nil).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "x@example.com").Return(f.owner, nil).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, r authenticate.ResolvedIdentifier, resolveErr error, _ *authenticate.Authentication, err error) {
				require.NoError(t, resolveErr)
				assert.Equal(t, "x@example.com", r.Key)
				assert.Nil(t, r.Details)
				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
				f.oneReferenceVerification(t)
				assert.Equal(t, 1, f.conflictEvents())
			},
		},
		{
			name:       "outage: resolution and authentication both unavailable, one lookup each",
			identifier: "ada@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(nil, errBackendDown).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, r authenticate.ResolvedIdentifier, resolveErr error, _ *authenticate.Authentication, err error) {
				assert.Equal(t, authenticate.ErrUnavailable, resolveErr)
				assert.Equal(t, "ada@example.com", r.Key)
				assert.Equal(t, authenticate.ErrUnavailable, err)
				f.oneReferenceVerification(t)
			},
		},
		{
			name:       "a carrier for other credentials is refused, not reloaded",
			identifier: "ada@example.com",
			presented:  "mallory",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(f.ada, nil).Times(1)
			},
			assert: func(t *testing.T, f *emailFixture, _ authenticate.ResolvedIdentifier, resolveErr error, result *authenticate.Authentication, err error) {
				require.NoError(t, resolveErr)
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
				f.oneReferenceVerification(t)
			},
		},
		{
			name:       "a carrier whose Key was rewritten is refused for credentials naming the new Key",
			identifier: "ada@example.com",
			presented:  "mallory",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(f.ada, nil).Times(1)
			},
			carrier: func(_ *testing.T, _ *emailFixture, r authenticate.ResolvedIdentifier) authenticate.ResolvedIdentifier {
				r.Key = "mallory"

				return r
			},
			assert: func(t *testing.T, f *emailFixture, _ authenticate.ResolvedIdentifier, resolveErr error, result *authenticate.Authentication, err error) {
				require.NoError(t, resolveErr)
				assert.Nil(t, result)
				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
				f.oneReferenceVerification(t)
			},
		},
		{
			name:       "a carrier built by hand is ignored and the user loaded",
			identifier: "ada",
			expect: func(f *emailFixture) {
				// Once by the resolution the test discards, once by the
				// provider ignoring the forged carrier.
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(f.ada, nil).Times(2)
			},
			carrier: func(t *testing.T, _ *emailFixture, r authenticate.ResolvedIdentifier) authenticate.ResolvedIdentifier {
				t.Helper()

				forged := *r.Details
				hash, err := cheapEncoder(t).Encode("attacker")
				require.NoError(t, err)
				forged.Password = hash

				return authenticate.ResolvedIdentifier{Key: r.Key, Details: &forged}
			},
			presented: "ada",
			assert: func(t *testing.T, _ *emailFixture, _ authenticate.ResolvedIdentifier, resolveErr error, result *authenticate.Authentication, err error) {
				require.NoError(t, resolveErr)
				// The credentials present storedPassword, which the forged
				// hash does not match: success shows the real record decided.
				require.NoError(t, err)
				assert.Equal(t, "ada", result.Principal.Username)
			},
		},
		{
			name:       "mutating the returned details does not reach the provider",
			identifier: "ada",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(f.ada, nil).Times(1)
			},
			carrier: func(_ *testing.T, _ *emailFixture, r authenticate.ResolvedIdentifier) authenticate.ResolvedIdentifier {
				r.Details.Active = false
				r.Details.Username = "mallory"

				return r
			},
			assert: func(t *testing.T, _ *emailFixture, _ authenticate.ResolvedIdentifier, resolveErr error, result *authenticate.Authentication, err error) {
				require.NoError(t, resolveErr)
				require.NoError(t, err)
				assert.Equal(t, "ada", result.Principal.Username)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailFixture(t)
			tc.expect(f)

			auth, err := f.build(f.loader(), authenticate.WithEmailLogin())
			require.NoError(t, err)

			ctx := f.watch(t.Context())
			r, resolveErr := auth.ResolveIdentifier(ctx, tc.identifier)

			carried := r
			if tc.carrier != nil {
				carried = tc.carrier(t, f, r)
			}

			presented := tc.presented
			if presented == "" {
				presented = tc.identifier
			}

			result, err := auth.Authenticate(authenticate.WithResolved(ctx, carried),
				identity.NewUsernamePassword(presented, []byte(storedPassword)))
			tc.assert(t, f, r, resolveErr, result, err)
		})
	}
}

// TestPassword_ResolveIdentifierFromAnotherProvider pins that a carrier one
// provider resolved is not honoured by another, which loads for itself.
func TestPassword_ResolveIdentifierFromAnotherProvider(t *testing.T) {
	t.Parallel()

	f := newEmailFixture(t)
	f.users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(f.ada, nil).Times(2)

	first, err := f.build(f.loader(), authenticate.WithEmailLogin())
	require.NoError(t, err)
	second, err := f.build(f.loader(), authenticate.WithEmailLogin())
	require.NoError(t, err)

	r, err := first.ResolveIdentifier(t.Context(), "ada")
	require.NoError(t, err)

	result, err := second.Authenticate(authenticate.WithResolved(t.Context(), r),
		identity.NewUsernamePassword("ada", []byte(storedPassword)))
	require.NoError(t, err)
	assert.Equal(t, "ada", result.Principal.Username)
}

// TestPassword_EmailTimingParity covers task 11.3: every refusal that compared
// no stored password costs one verification against the reference hash.
func TestPassword_EmailTimingParity(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		emailLogin bool
		identifier string
		expect     func(f *emailFixture)
	}

	cases := []testCase{
		{
			name:       "unknown username, username-only provider",
			identifier: "nobody",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "nobody").Return(nil, identity.ErrUserNotFound)
			},
		},
		{
			name:       "unknown username, email login on",
			emailLogin: true,
			identifier: "nobody",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "nobody").Return(nil, identity.ErrUserNotFound)
			},
		},
		{
			name:       "unknown email",
			emailLogin: true,
			identifier: "nobody@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "nobody@example.com").Return(nil, identity.ErrUserNotFound)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "nobody@example.com").Return(nil, identity.ErrUserNotFound)
			},
		},
		{
			name:       "unverified email",
			emailLogin: true,
			identifier: "ada@example.com",
			expect: func(f *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(f.unverified, nil)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailFixture(t)
			tc.expect(f)

			var opts []authenticate.PasswordOption
			if tc.emailLogin {
				opts = append(opts, authenticate.WithEmailLogin())
			}
			auth, err := f.build(f.loader(), opts...)
			require.NoError(t, err)

			_, err = auth.Authenticate(t.Context(), identity.NewUsernamePassword(tc.identifier, []byte(storedPassword)))

			// Invariant: the uniform failure, after exactly one verification
			// against the reference hash.
			assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
			f.oneReferenceVerification(t)
		})
	}
}

// TestPassword_ResolveRefusesAccountWithoutUsername pins that a loader answer
// naming an account with no username is a contract violation, refused as an
// unknown identifier is: a resolution keyed on the typed text would give every
// case variant of one email its own lockout budget.
func TestPassword_ResolveRefusesAccountWithoutUsername(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		emailLogin bool
		// identifier is distinct per row, so the log assertion cannot be
		// satisfied by another row's text.
		identifier string
		expect     func(f *emailFixture, nameless *identity.Details)
		assert     func(t *testing.T, f *emailFixture, identifier string, result *authenticate.Authentication, err error)
	}

	// The refusal is the uniform failure after the decoy work, no account is
	// authenticated, and the contract breach is logged without the identifier.
	refused := func(t *testing.T, f *emailFixture, identifier string, result *authenticate.Authentication, err error) {
		t.Helper()

		assert.Nil(t, result)
		assert.Equal(t, authenticate.ErrAuthenticationFailed, err)
		f.oneReferenceVerification(t)

		assert.Contains(t, f.logs.String(), "user-without-username")
		assert.NotContains(t, f.logs.String(), identifier)
	}

	cases := []testCase{
		{
			name:       "email path",
			emailLogin: true,
			identifier: "ADA@example.com",
			expect: func(f *emailFixture, nameless *identity.Details) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ADA@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ADA@example.com").Return(nameless, nil).Times(1)
			},
			assert: refused,
		},
		{
			name:       "username path with email login on",
			emailLogin: true,
			identifier: "nameless-user@host.test",
			expect: func(f *emailFixture, nameless *identity.Details) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "nameless-user@host.test").Return(nameless, nil).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "nameless-user@host.test").Return(nil, identity.ErrUserNotFound).Times(1)
			},
			assert: refused,
		},
		{
			name:       "username path with email login off",
			identifier: "nameless-off",
			expect: func(f *emailFixture, nameless *identity.Details) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "nameless-off").Return(nameless, nil).Times(1)
			},
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			f := newEmailFixture(t)
			nameless := *f.ada
			nameless.Username = ""
			tc.expect(f, &nameless)

			var opts []authenticate.PasswordOption
			if tc.emailLogin {
				opts = append(opts, authenticate.WithEmailLogin())
			}
			auth, err := f.build(f.loader(), opts...)
			require.NoError(t, err)

			// Resolution names no account.
			r, err := auth.ResolveIdentifier(ctx, tc.identifier)
			require.NoError(t, err)
			assert.Nil(t, r.Details)
			assert.Equal(t, tc.identifier, r.Key)

			result, err := auth.Authenticate(authenticate.WithResolved(ctx, r),
				identity.NewUsernamePassword(tc.identifier, []byte(storedPassword)))
			tc.assert(t, f, tc.identifier, result, err)
		})
	}
}
