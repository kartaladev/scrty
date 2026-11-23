package authenticate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
)

// TestResolverOf pins which authenticators expose the identifier resolution a
// chain runs before its pre-authentication phase.
func TestResolverOf(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		authn  func(t *testing.T, f *emailFixture) authenticate.Authenticator
		assert func(t *testing.T, authn authenticate.Authenticator, r authenticate.IdentifierResolver, ok bool)
	}

	cases := []testCase{
		{
			name: "a password provider with email login on is its own resolver",
			authn: func(t *testing.T, f *emailFixture) authenticate.Authenticator {
				t.Helper()
				p, err := f.build(f.loader(), authenticate.WithEmailLogin())
				require.NoError(t, err)

				return p
			},
			assert: func(t *testing.T, authn authenticate.Authenticator, r authenticate.IdentifierResolver, ok bool) {
				require.True(t, ok)
				assert.Same(t, authn, r)
				assert.True(t, r.EmailLogin())
			},
		},
		{
			name: "a password provider with email login off needs no resolution",
			authn: func(t *testing.T, f *emailFixture) authenticate.Authenticator {
				t.Helper()
				p, err := f.build(f.loader())
				require.NoError(t, err)

				return p
			},
			assert: func(t *testing.T, authn authenticate.Authenticator, r authenticate.IdentifierResolver, ok bool) {
				assert.False(t, ok)
				assert.Nil(t, r)
				assert.False(t, authn.(authenticate.IdentifierResolver).EmailLogin())
			},
		},
		{
			name: "an authenticator that resolves nothing exposes no resolver",
			authn: func(*testing.T, *emailFixture) authenticate.Authenticator {
				return plainDelegate{}
			},
			assert: func(t *testing.T, _ authenticate.Authenticator, r authenticate.IdentifierResolver, ok bool) {
				assert.False(t, ok)
				assert.Nil(t, r)
			},
		},
		{
			name: "a FirstOf with one email-login member exposes it, however deep",
			authn: func(t *testing.T, f *emailFixture) authenticate.Authenticator {
				t.Helper()
				p, err := f.build(f.loader(), authenticate.WithEmailLogin())
				require.NoError(t, err)
				inner, err := authenticate.NewFirstOf(plainDelegate{}, p)
				require.NoError(t, err)
				outer, err := authenticate.NewFirstOf(plainDelegate{}, inner)
				require.NoError(t, err)

				return outer
			},
			assert: func(t *testing.T, authn authenticate.Authenticator, r authenticate.IdentifierResolver, ok bool) {
				require.True(t, ok)
				assert.Same(t, authn, r, "a FirstOf forwards the resolution itself")
				assert.True(t, r.EmailLogin())
			},
		},
		{
			name: "a FirstOf with no email-login member exposes no resolver",
			authn: func(t *testing.T, f *emailFixture) authenticate.Authenticator {
				t.Helper()
				p, err := f.build(f.loader())
				require.NoError(t, err)
				m, err := authenticate.NewFirstOf(plainDelegate{}, p)
				require.NoError(t, err)

				return m
			},
			assert: func(t *testing.T, authn authenticate.Authenticator, r authenticate.IdentifierResolver, ok bool) {
				assert.False(t, ok)
				assert.Nil(t, r)
				assert.False(t, authn.(authenticate.IdentifierResolver).EmailLogin())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailFixture(t)
			authn := tc.authn(t, f)
			r, ok := authenticate.ResolverOf(authn)
			tc.assert(t, authn, r, ok)
		})
	}
}

// TestNewFirstOf_EmailLoginMembers pins that a FirstOf has at most one member
// that logs in by email, counted through nested FirstOfs, since the chain can
// run only one resolution before its pre-authentication phase.
func TestNewFirstOf_EmailLoginMembers(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		delegates func(t *testing.T, f *emailFixture) []authenticate.Authenticator
		assert    func(t *testing.T, m *authenticate.FirstOf, err error)
	}

	provider := func(t *testing.T, f *emailFixture, emailLogin bool) authenticate.Authenticator {
		t.Helper()
		var opts []authenticate.PasswordOption
		if emailLogin {
			opts = append(opts, authenticate.WithEmailLogin())
		}
		p, err := f.build(f.loader(), opts...)
		require.NoError(t, err)

		return p
	}

	cases := []testCase{
		{
			name: "two username-only password providers are allowed",
			delegates: func(t *testing.T, f *emailFixture) []authenticate.Authenticator {
				return []authenticate.Authenticator{provider(t, f, false), provider(t, f, false)}
			},
			assert: func(t *testing.T, m *authenticate.FirstOf, err error) {
				require.NoError(t, err)
				assert.False(t, m.EmailLogin())
			},
		},
		{
			name: "a username-only password provider after the email-login member is allowed",
			delegates: func(t *testing.T, f *emailFixture) []authenticate.Authenticator {
				return []authenticate.Authenticator{provider(t, f, true), provider(t, f, false)}
			},
			assert: func(t *testing.T, m *authenticate.FirstOf, err error) {
				require.NoError(t, err)
				assert.True(t, m.EmailLogin())
			},
		},
		{
			name: "a username-only password provider before the email-login member is a configuration error",
			delegates: func(t *testing.T, f *emailFixture) []authenticate.Authenticator {
				return []authenticate.Authenticator{provider(t, f, false), provider(t, f, true)}
			},
			assert: func(t *testing.T, m *authenticate.FirstOf, err error) {
				assert.Nil(t, m)
				require.ErrorIs(t, err, authenticate.ErrConfig)
			},
		},
		{
			name: "a nested username-only password provider before the email-login member is a configuration error",
			delegates: func(t *testing.T, f *emailFixture) []authenticate.Authenticator {
				inner, err := authenticate.NewFirstOf(plainDelegate{}, provider(t, f, false))
				require.NoError(t, err)

				return []authenticate.Authenticator{inner, provider(t, f, true)}
			},
			assert: func(t *testing.T, m *authenticate.FirstOf, err error) {
				assert.Nil(t, m)
				require.ErrorIs(t, err, authenticate.ErrConfig)
			},
		},
		{
			name: "a username-only password provider before a nested email-login member is a configuration error",
			delegates: func(t *testing.T, f *emailFixture) []authenticate.Authenticator {
				inner, err := authenticate.NewFirstOf(plainDelegate{}, provider(t, f, true))
				require.NoError(t, err)

				return []authenticate.Authenticator{provider(t, f, false), inner}
			},
			assert: func(t *testing.T, m *authenticate.FirstOf, err error) {
				assert.Nil(t, m)
				require.ErrorIs(t, err, authenticate.ErrConfig)
			},
		},
		{
			name: "a username-only password provider after a nested email-login member is allowed",
			delegates: func(t *testing.T, f *emailFixture) []authenticate.Authenticator {
				inner, err := authenticate.NewFirstOf(provider(t, f, true), provider(t, f, false))
				require.NoError(t, err)

				return []authenticate.Authenticator{plainDelegate{}, inner, provider(t, f, false)}
			},
			assert: func(t *testing.T, m *authenticate.FirstOf, err error) {
				require.NoError(t, err)
				assert.True(t, m.EmailLogin())
			},
		},
		{
			name: "a consumer's own authenticator before the email-login member is its own responsibility",
			delegates: func(t *testing.T, f *emailFixture) []authenticate.Authenticator {
				return []authenticate.Authenticator{plainDelegate{}, provider(t, f, true)}
			},
			assert: func(t *testing.T, m *authenticate.FirstOf, err error) {
				require.NoError(t, err)
				assert.True(t, m.EmailLogin())
			},
		},
		{
			name: "two email-login providers are a configuration error",
			delegates: func(t *testing.T, f *emailFixture) []authenticate.Authenticator {
				return []authenticate.Authenticator{provider(t, f, true), provider(t, f, true)}
			},
			assert: func(t *testing.T, m *authenticate.FirstOf, err error) {
				assert.Nil(t, m)
				require.ErrorIs(t, err, authenticate.ErrConfig)
			},
		},
		{
			name: "two email-login providers across a nested FirstOf are a configuration error",
			delegates: func(t *testing.T, f *emailFixture) []authenticate.Authenticator {
				inner, err := authenticate.NewFirstOf(plainDelegate{}, provider(t, f, true))
				require.NoError(t, err)

				return []authenticate.Authenticator{inner, provider(t, f, true)}
			},
			assert: func(t *testing.T, m *authenticate.FirstOf, err error) {
				assert.Nil(t, m)
				require.ErrorIs(t, err, authenticate.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailFixture(t)
			m, err := authenticate.NewFirstOf(tc.delegates(t, f)...)
			tc.assert(t, m, err)
		})
	}
}

// TestFirstOf_ResolveIdentifier pins the forwarded resolution: the carrier the
// resolving member made reaches that member through the FirstOf and is
// ignored by the others.
func TestFirstOf_ResolveIdentifier(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		identifier string
		// manager builds what resolves and what authenticates from the
		// fixture's provider with email login on, and a second, username-only
		// provider with a store of its own.
		manager func(t *testing.T, resolving authenticate.Authenticator, other authenticate.Authenticator) (*authenticate.FirstOf, authenticate.Authenticator)
		expect  func(f, g *emailFixture)
		assert  func(t *testing.T, r authenticate.ResolvedIdentifier, resolveErr error, result *authenticate.Authentication, err error)
	}

	cases := []testCase{
		{
			name:       "the resolving member honours its carrier through the FirstOf",
			identifier: "ada@example.com",
			manager: func(t *testing.T, resolving, _ authenticate.Authenticator) (*authenticate.FirstOf, authenticate.Authenticator) {
				t.Helper()
				inner, err := authenticate.NewFirstOf(resolving)
				require.NoError(t, err)
				m, err := authenticate.NewFirstOf(inner)
				require.NoError(t, err)

				return m, m
			},
			expect: func(f, _ *emailFixture) {
				// Loaded once, by the resolution; the authentication reuses it.
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(f.ada, nil).Times(1)
			},
			assert: func(t *testing.T, r authenticate.ResolvedIdentifier, resolveErr error, result *authenticate.Authentication, err error) {
				require.NoError(t, resolveErr)
				assert.Equal(t, "ada", r.Key)
				require.NoError(t, err)
				assert.Equal(t, "ada", result.Principal.Username)
			},
		},
		{
			// NewFirstOf refuses a username-only password provider ahead of
			// the email-login member, so the carrier is presented to the other
			// provider directly: what it would see if a consumer's wiring
			// handed it the FirstOf's resolution.
			name:       "a provider that did not resolve ignores the carrier and loads for itself",
			identifier: "ada@example.com",
			manager: func(t *testing.T, resolving, other authenticate.Authenticator) (*authenticate.FirstOf, authenticate.Authenticator) {
				t.Helper()
				m, err := authenticate.NewFirstOf(resolving)
				require.NoError(t, err)

				return m, other
			},
			expect: func(f, g *emailFixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				f.emails.EXPECT().LoadByEmail(gomock.Any(), "ada@example.com").Return(f.ada, nil).Times(1)
				// The username-only provider ignores the carrier and loads
				// the identifier as typed from its own store.
				own := *g.emailNamed
				own.Username = "ada@example.com"
				g.users.EXPECT().LoadByUsername(gomock.Any(), "ada@example.com").Return(&own, nil).Times(1)
			},
			assert: func(t *testing.T, _ authenticate.ResolvedIdentifier, resolveErr error, result *authenticate.Authentication, err error) {
				require.NoError(t, resolveErr)
				require.NoError(t, err)
				assert.Equal(t, "ada@example.com", result.Principal.Username, "the other provider decided on its own record")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailFixture(t)
			g := newEmailFixture(t)
			tc.expect(f, g)

			resolving, err := f.build(f.loader(), authenticate.WithEmailLogin())
			require.NoError(t, err)
			other, err := g.build(g.users)
			require.NoError(t, err)

			m, authn := tc.manager(t, resolving, other)
			r, ok := authenticate.ResolverOf(m)
			require.True(t, ok)

			ctx := t.Context()
			resolved, resolveErr := r.ResolveIdentifier(ctx, tc.identifier)
			result, err := authn.Authenticate(authenticate.WithResolved(ctx, resolved),
				identity.NewUsernamePassword(tc.identifier, []byte(storedPassword)))
			tc.assert(t, resolved, resolveErr, result, err)
		})
	}
}

// TestFirstOf_ResolveIdentifierWithoutResolver pins what a FirstOf with no
// email-login member resolves to: the identifier as typed, with nothing
// loaded, which every member ignores.
func TestFirstOf_ResolveIdentifierWithoutResolver(t *testing.T) {
	t.Parallel()

	m, err := authenticate.NewFirstOf(plainDelegate{})
	require.NoError(t, err)

	r, err := m.ResolveIdentifier(t.Context(), "ada@example.com")
	require.NoError(t, err)
	assert.Equal(t, "ada@example.com", r.Key)
	assert.Nil(t, r.Details)
}
