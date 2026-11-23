package identitytest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// emailVerifiedAt is the verification time the suite seeds on an email. It is
// whole seconds in UTC for the reason passwordChangedAt is.
var emailVerifiedAt = time.Date(2030, 2, 1, 0, 0, 0, 0, time.UTC)

// effectiveScopes returns p with each scope read as its effective scope, so a
// store that returns an unscoped grant as "all" and one that returns it empty
// compare alike: both mean every record.
func effectiveScopes(p []identity.Privilege) []identity.Privilege {
	out := make([]identity.Privilege, len(p))
	for i, e := range p {
		out[i] = e
		out[i].Scope = e.EffectiveScope()
	}

	return out
}

// uniqueEmail returns an email address unique to the case, the run and i, in
// lower case.
func uniqueEmail(t *testing.T, prefix string, i int) string {
	t.Helper()

	return uniqueName(t, prefix, i) + "@example.com"
}

// runDeletedUserCases checks that a soft-deleted user is unknown to every port
// that names a user, while its username stays held.
func runDeletedUserCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		// act is the port call made after the user is deleted.
		act    func(ctx context.Context, f Fixture, d *identity.Details) (*identity.Details, error)
		assert func(t *testing.T, got *identity.Details, err error)
	}

	notFound := func(t *testing.T, got *identity.Details, err error) {
		t.Helper()

		require.ErrorIs(t, err, identity.ErrUserNotFound,
			"a deleted user keeps its record, so a store that does not filter it hands a "+
				"deleted account back to authentication and to every live session it had")
		assert.Nil(t, got)
	}

	cases := []testCase{
		{
			name: "by username",
			act: func(ctx context.Context, f Fixture, d *identity.Details) (*identity.Details, error) {
				return f.LoadByUsername(ctx, d.Username)
			},
			assert: notFound,
		},
		{
			name: "by reference",
			act: func(ctx context.Context, f Fixture, d *identity.Details) (*identity.Details, error) {
				return f.LoadByUserID(ctx, d.ID)
			},
			assert: notFound,
		},
		{
			name: "an update finds no user",
			act: func(ctx context.Context, f Fixture, d *identity.Details) (*identity.Details, error) {
				return f.Update(ctx, d.Username, identity.WithUserName("revived"))
			},
			assert: notFound,
		},
		{
			name: "the username stays held",
			act: func(ctx context.Context, f Fixture, d *identity.Details) (*identity.Details, error) {
				return f.Provision(ctx, d.Username)
			},
			assert: func(t *testing.T, got *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserExists,
					"a deleted username is never reused: a new user under it would inherit "+
						"the deleted one's audit trail and any grant still naming it")
				assert.Nil(t, got)
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			user := uniqueName(t, "deleted", i)

			d := mustProvision(ctx, t, f, user, identity.WithUserRoles("viewer"))
			require.NoError(t, f.SoftDelete(ctx, user))

			got, err := tc.act(ctx, f, d)
			tc.assert(t, got, err)
		})
	}
}

// runEmailFieldsCases checks that a loaded user carries its email and the time
// it was verified, as stored.
func runEmailFieldsCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		seed   func(t *testing.T, ctx context.Context, f Fixture, user, email string)
		assert func(t *testing.T, email string, d *identity.Details)
	}

	cases := []testCase{
		{
			name: "a verified email loads with its verification time",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user, email string) {
				t.Helper()
				require.NoError(t, f.SeedEmail(ctx, user, email, emailVerifiedAt))
			},
			assert: func(t *testing.T, email string, d *identity.Details) {
				assert.Equal(t, email, d.Email)
				assert.True(t, emailVerifiedAt.Equal(d.EmailVerifiedAt),
					"the verification time is returned as stored, got %v", d.EmailVerifiedAt)
				assert.True(t, d.EmailVerified())
			},
		},
		{
			name: "an unverified email loads with no verification time",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user, email string) {
				t.Helper()
				require.NoError(t, f.SeedEmail(ctx, user, email, time.Time{}))
			},
			assert: func(t *testing.T, email string, d *identity.Details) {
				assert.Equal(t, email, d.Email)
				assert.True(t, d.EmailVerifiedAt.IsZero(),
					"an address nobody proved they control must not read as verified")
				assert.False(t, d.EmailVerified())
			},
		},
		{
			name: "a user with no email loads with none",
			assert: func(t *testing.T, _ string, d *identity.Details) {
				assert.Empty(t, d.Email)
				assert.True(t, d.EmailVerifiedAt.IsZero())
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			user := uniqueName(t, "email", i)
			email := uniqueEmail(t, "fields", i)

			d := mustProvision(ctx, t, f, user)
			if tc.seed != nil {
				tc.seed(t, ctx, f, user, email)
			}

			byName, err := f.LoadByUsername(ctx, user)
			require.NoError(t, err)
			tc.assert(t, email, byName)

			byID, err := f.LoadByUserID(ctx, d.ID)
			require.NoError(t, err)
			tc.assert(t, email, byID)
		})
	}
}

// runStoredScopeCase checks that a grant's scope is returned as stored.
func runStoredScopeCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	role := uniqueName(t, "sales", 0)

	require.NoError(t, f.SeedRole(ctx, role, []*identity.ResourcePrivileges{{
		Group:    "crm",
		Resource: "lead",
		Privileges: []identity.Privilege{
			{Name: "update", Granted: true, Scope: identity.ScopeOwn},
			{Name: "read", Granted: true, Scope: identity.ScopeAll},
		},
	}}))

	got, err := f.LoadPrivileges(ctx, role)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.ElementsMatch(t, []identity.Privilege{
		{Name: "update", Granted: true, Scope: identity.ScopeOwn},
		{Name: "read", Granted: true, Scope: identity.ScopeAll},
	}, got[0].Privileges,
		"a store that drops the scope widens an own-only grant to every record of the resource")
}

// runLegacyScopeCase checks that a grant recorded with no scope, as every grant
// written before scopes existed was, loads as reaching every record.
func runLegacyScopeCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	role := uniqueName(t, "legacy", 0)

	require.NoError(t, f.SeedRole(ctx, role, []*identity.ResourcePrivileges{{
		Group:      "crm",
		Resource:   "lead",
		Privileges: []identity.Privilege{{Name: "read", Granted: true}},
	}}))

	got, err := f.LoadPrivileges(ctx, role)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Len(t, got[0].Privileges, 1)
	assert.Equal(t, identity.ScopeAll, got[0].Privileges[0].Scope,
		"a grant from before scopes existed loads carrying the scope all, which authorized "+
			"every record; loading it narrower or unset would take access away on upgrade")
}

// runUsernameIsAnotherEmailCases checks that provisioning refuses a username
// equal to another live user's email, ignoring case, and writes nothing.
func runUsernameIsAnotherEmailCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		// seed gives the holder its email, and returns the username to provision.
		seed   func(t *testing.T, ctx context.Context, f Fixture, holder, email string) string
		assert func(t *testing.T, ctx context.Context, f Fixture, username string, d *identity.Details, err error)
	}

	refused := func(t *testing.T, ctx context.Context, f Fixture, username string, d *identity.Details, err error) {
		t.Helper()

		require.ErrorIs(t, err, identity.ErrUserExists,
			"a federated username equal to a local user's email would make one address name "+
				"two accounts, and a login by email could reach the wrong one")
		assert.Nil(t, d)
		assert.NotContains(t, err.Error(), username, "the refusal must not quote the address")
		assert.NotContains(t, strings.ToLower(err.Error()), strings.ToLower(username),
			"the refusal must not quote the address in any case")

		_, loadErr := f.LoadByUsername(ctx, username)
		require.ErrorIs(t, loadErr, identity.ErrUserNotFound, "a refused provision writes nothing")
	}

	cases := []testCase{
		{
			name: "a verified email",
			seed: func(t *testing.T, ctx context.Context, f Fixture, holder, email string) string {
				t.Helper()
				require.NoError(t, f.SeedEmail(ctx, holder, email, emailVerifiedAt))

				return email
			},
			assert: refused,
		},
		{
			name: "an unverified email",
			seed: func(t *testing.T, ctx context.Context, f Fixture, holder, email string) string {
				t.Helper()
				require.NoError(t, f.SeedEmail(ctx, holder, email, time.Time{}))

				return email
			},
			assert: refused,
		},
		{
			name: "an email in another case",
			seed: func(t *testing.T, ctx context.Context, f Fixture, holder, email string) string {
				t.Helper()
				require.NoError(t, f.SeedEmail(ctx, holder, email, emailVerifiedAt))

				return strings.ToUpper(email[:1]) + email[1:len(email)-len("example.com")] + "EXAMPLE.com"
			},
			assert: refused,
		},
		{
			name: "the email of a deleted user is free",
			seed: func(t *testing.T, ctx context.Context, f Fixture, holder, email string) string {
				t.Helper()
				require.NoError(t, f.SeedEmail(ctx, holder, email, emailVerifiedAt))
				require.NoError(t, f.SoftDelete(ctx, holder))

				return email
			},
			assert: func(t *testing.T, _ context.Context, _ Fixture, username string, d *identity.Details, err error) {
				require.NoError(t, err, "deletion releases the email, so it no longer blocks a username")
				require.NotNil(t, d)
				assert.Equal(t, username, d.Username)
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			holder := uniqueName(t, "holder", i)
			mustProvision(ctx, t, f, holder)

			username := tc.seed(t, ctx, f, holder, uniqueEmail(t, "carol", i))

			d, err := f.Provision(ctx, username)
			tc.assert(t, ctx, f, username, d, err)
		})
	}
}

// runEmailNotStoredCases checks that the identity ports discard an email they
// are given: only the consumer's administration sets one.
func runEmailNotStoredCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name  string
		write func(ctx context.Context, f Fixture, user, email string) (*identity.Details, error)
	}

	cases := []testCase{
		{
			name: "provision",
			write: func(ctx context.Context, f Fixture, user, email string) (*identity.Details, error) {
				return f.Provision(ctx, user, identity.WithUserEmail(email))
			},
		},
		{
			name: "update",
			write: func(ctx context.Context, f Fixture, user, email string) (*identity.Details, error) {
				if _, err := f.Provision(ctx, user); err != nil {
					return nil, err
				}

				return f.Update(ctx, user, identity.WithUserEmail(email))
			},
		},
	}

	// The same for both verbs: the write succeeds, and neither the record it
	// returns nor a later load carries the address.
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			user := uniqueName(t, "nomail", i)
			email := uniqueEmail(t, "ada", i)

			d, err := tc.write(ctx, f, user, email)
			require.NoError(t, err)
			require.NotNil(t, d)
			assert.Empty(t, d.Email,
				"a provider's email stored on every just-in-time login would make a federated "+
					"first login fail on any collision")

			got := mustLoad(ctx, t, f, user)
			assert.Empty(t, got.Email)
			assert.True(t, got.EmailVerifiedAt.IsZero())

			if l, ok := f.(identity.EmailLoader); ok {
				_, err := l.LoadByEmail(ctx, email)
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			}
		})
	}
}

// raceRounds is how many contested addresses the username-and-email race
// runs, and raceWriters how many writers contend for each. One round's window
// is a few statements wide, so a store that checks without serialising passes
// a single round more often than not; over 32 rounds it was caught on every
// run tried.
const (
	raceRounds  = 32
	raceWriters = 8
)

// runUsernameEmailRaceCase checks that a username and another user's email
// cannot race to coincide: writers alternately provision the address as a
// username and set it as the email of users of their own, all released at
// once, and exactly one of them may succeed.
func runUsernameEmailRaceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	for round := range raceRounds {
		contested := uniqueEmail(t, "x", round)

		holders := make([]string, raceWriters)
		for i := range holders {
			if i%2 == 1 {
				holders[i] = uniqueName(t, "racer", round*raceWriters+i)
				mustProvision(ctx, t, f, holders[i])
			}
		}

		var (
			start sync.WaitGroup
			done  sync.WaitGroup
			errs  = make([]error, raceWriters)
		)
		start.Add(1)
		for i := range raceWriters {
			done.Go(func() {
				start.Wait()
				if i%2 == 0 {
					_, errs[i] = f.Provision(ctx, contested)
				} else {
					errs[i] = f.SeedEmail(ctx, holders[i], contested, emailVerifiedAt)
				}
			})
		}
		start.Done()
		done.Wait()

		won := 0
		for i, err := range errs {
			if err == nil {
				won++
				continue
			}
			require.ErrorIs(t, err, identity.ErrUserExists,
				"round %d writer %d: a lost race is a refusal, never a storage error", round, i)
		}
		require.Equal(t, 1, won,
			"round %d: exactly one writer may claim the address, as a username or as an email", round)

		_, err := f.LoadByUsername(ctx, contested)
		provisioned := err == nil
		if !provisioned {
			require.ErrorIs(t, err, identity.ErrUserNotFound)
		}

		holding := 0
		for _, h := range holders {
			if h == "" {
				continue
			}
			if d := mustLoad(ctx, t, f, h); strings.EqualFold(d.Email, contested) {
				holding++
			}
		}

		assert.False(t, provisioned && holding > 0,
			"round %d: the address is one user's username and another's email", round)
		assert.LessOrEqual(t, holding, 1, "round %d: two live users hold one email", round)
	}
}

// RunEmailLoaderSuite checks the optional email loader contract. The fixture
// must implement identity.EmailLoader. Like RunConformanceSuite, it fails
// before any case when a hook is missing.
func RunEmailLoaderSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	requireUsableFixture(t, newFixture)

	_, ok := newFixture(t).(identity.EmailLoader)
	require.True(t, ok, "identitytest: the fixture does not implement identity.EmailLoader")

	runEmailLoaderCases(t, newFixture)
}

// runEmailLoaderSuite runs the email loader cases when the fixture implements
// the optional identity.EmailLoader, and says so in the log when it does not.
func runEmailLoaderSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	if _, ok := newFixture(t).(identity.EmailLoader); !ok {
		t.Log("identitytest: the fixture does not implement the optional identity.EmailLoader; " +
			"its cases did not run. Use RunEmailLoaderSuite to require it.")

		return
	}

	runEmailLoaderCases(t, newFixture)
}

func runEmailLoaderCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		// seed arranges the user and returns the address to look up.
		seed   func(t *testing.T, ctx context.Context, f Fixture, user, email string) string
		assert func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error)
	}

	verified := func(t *testing.T, ctx context.Context, f Fixture, user, email string) {
		t.Helper()
		require.NoError(t, f.SeedEmail(ctx, user, email, emailVerifiedAt))
	}

	notFound := func(t *testing.T, _ context.Context, _ Fixture, _ string, d *identity.Details, err error) {
		t.Helper()

		require.ErrorIs(t, err, identity.ErrUserNotFound)
		assert.Nil(t, d)
	}

	cases := []testCase{
		{
			name: "CaseInsensitive",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user, email string) string {
				t.Helper()
				mixed := strings.ToUpper(email[:1]) + email[1:len(email)-len("example.com")] + "Example.com"
				verified(t, ctx, f, user, mixed)

				return strings.ToLower(email[:len(email)-len(".com")]) + ".COM"
			},
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error) {
				require.NoError(t, err, "an address is matched ignoring case")
				require.NotNil(t, d)
				assert.Equal(t, atUTC(mustLoad(ctx, t, f, user)), atUTC(d),
					"the email loader returns the complete record, as loading by username does")
			},
		},
		{
			name: "UnverifiedNotFound",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user, email string) string {
				t.Helper()
				require.NoError(t, f.SeedEmail(ctx, user, email, time.Time{}))

				return email
			},
			assert: notFound,
		},
		{
			name: "DeletedNotFound",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user, email string) string {
				t.Helper()
				verified(t, ctx, f, user, email)
				require.NoError(t, f.SoftDelete(ctx, user))

				return email
			},
			assert: notFound,
		},
		{
			name: "Unrepresentable",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user, email string) string {
				t.Helper()
				verified(t, ctx, f, user, email)

				return email + "\x00"
			},
			assert: notFound,
		},
		{
			name: "InvalidUTF8",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user, email string) string {
				t.Helper()
				verified(t, ctx, f, user, email)

				return email + "\xff"
			},
			assert: notFound,
		},
		{
			// An empty address names no user, so it is answered before the
			// backend is asked: an outage is not reported for it.
			name: "Empty",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user, email string) string {
				t.Helper()
				verified(t, ctx, f, user, email)
				f.FailUserLoads(errBackendUnreachable)

				return ""
			},
			assert: notFound,
		},
		{
			name: "Miss",
			seed: func(t *testing.T, _ context.Context, _ Fixture, _, email string) string {
				t.Helper()

				return email
			},
			assert: notFound,
		},
		{
			name: "FailureIsNotNotFound",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user, email string) string {
				t.Helper()
				verified(t, ctx, f, user, email)
				f.FailUserLoads(errBackendUnreachable)

				return email
			},
			assert: func(t *testing.T, _ context.Context, _ Fixture, _ string, d *identity.Details, err error) {
				require.Error(t, err)
				assert.False(t, errors.Is(err, identity.ErrUserNotFound),
					"an outage read as an unknown address counts against nobody and tells the "+
						"caller the account does not exist")
				assert.Nil(t, d)
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			user := uniqueName(t, "bymail", i)
			mustProvision(ctx, t, f, user, identity.WithUserRoles("viewer"))

			lookup := tc.seed(t, ctx, f, user, uniqueEmail(t, "ada", i))

			l, ok := f.(identity.EmailLoader)
			require.True(t, ok, "every fixture of one factory implements the email loader alike")

			d, err := l.LoadByEmail(ctx, lookup)
			tc.assert(t, ctx, f, user, d, err)
		})
	}
}
