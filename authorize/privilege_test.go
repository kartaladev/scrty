// The privilege authorizer is exercised through several tables rather than one:
// each varies a different axis of the same Authorize call — the shape of the
// attributes, the subject's role, the privilege names, the loader's failures —
// and each axis needs its own setup, which a single table would have to carry
// for every row.
package authorize_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// grantOn builds the one resource-privileges entry a role loader returns for
// billing/invoice, with each named privilege granted or refused as given.
func grantOn(group, resource string, privileges map[string]bool) []*identity.ResourcePrivileges {
	entry := &identity.ResourcePrivileges{Group: group, Resource: resource}
	for name, granted := range privileges {
		entry.Privileges = append(entry.Privileges, identity.Privilege{Name: name, Granted: granted})
	}

	return []*identity.ResourcePrivileges{entry}
}

// withRole returns a context carrying a principal whose active role is named
// role, which is the only thing the privilege authorizer reads about a caller.
func withRole(ctx context.Context, role string) context.Context {
	assigned := &identity.AssignedRole{ID: "r-1", Name: role, Primary: true}

	return identity.WithPrincipal(ctx, &identity.Principal{
		ID:         "u-1",
		Username:   "ada",
		Roles:      []*identity.AssignedRole{assigned},
		ActiveRole: assigned,
	})
}

func TestNewPrivilegeAuthorizer(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		roles  func(ctrl *gomock.Controller) identity.RoleLoader
		opts   []authorize.PrivilegeOption
		assert func(t *testing.T, authorizer *authorize.PrivilegeAuthorizer, err error)
	}

	cases := []testCase{
		{
			name:  "a loader is all it needs",
			roles: func(ctrl *gomock.Controller) identity.RoleLoader { return NewMockRoleLoader(ctrl) },
			assert: func(t *testing.T, authorizer *authorize.PrivilegeAuthorizer, err error) {
				require.NoError(t, err)
				assert.NotNil(t, authorizer)
			},
		},
		{
			name:  "no role loader is a configuration error",
			roles: func(_ *gomock.Controller) identity.RoleLoader { return nil },
			assert: func(t *testing.T, authorizer *authorize.PrivilegeAuthorizer, err error) {
				require.ErrorIs(t, err, authorize.ErrConfig)
				assert.ErrorIs(t, err, identity.ErrMissingPort,
					"a missing port was not reported as one")
				assert.Nil(t, authorizer)
			},
		},
		{
			name: "a typed nil role loader is a configuration error",
			roles: func(_ *gomock.Controller) identity.RoleLoader {
				var absent *MockRoleLoader

				return absent
			},
			assert: func(t *testing.T, authorizer *authorize.PrivilegeAuthorizer, err error) {
				require.ErrorIs(t, err, authorize.ErrConfig)
				assert.Nil(t, authorizer)
			},
		},
		{
			name:  "a nil name comparer is a configuration error, not a silent default",
			roles: func(ctrl *gomock.Controller) identity.RoleLoader { return NewMockRoleLoader(ctrl) },
			opts:  []authorize.PrivilegeOption{authorize.WithPrivilegeNameComparer(nil)},
			assert: func(t *testing.T, authorizer *authorize.PrivilegeAuthorizer, err error) {
				require.ErrorIs(t, err, authorize.ErrConfig)
				assert.Nil(t, authorizer)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			authorizer, err := authorize.NewPrivilegeAuthorizer(tc.roles(ctrl), tc.opts...)
			tc.assert(t, authorizer, err)
		})
	}
}

func TestPrivilegeAuthorizerAttributes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		attrs  authorize.Attributes
		assert func(t *testing.T, err error)
	}

	unsupported := func(t *testing.T, err error) {
		require.ErrorIs(t, err, authorize.ErrUnsupportedAttributes)
		assert.NotErrorIs(t, err, authorize.ErrInvalidAttributes,
			"attributes for another authorizer were refused instead of declined")
		assert.NotErrorIs(t, err, authorize.ErrAccessDenied,
			"declining to judge was reported as a decision about the caller")
	}
	invalid := func(t *testing.T, err error) {
		require.ErrorIs(t, err, authorize.ErrInvalidAttributes)
		assert.NotErrorIs(t, err, authorize.ErrUnsupportedAttributes,
			"malformed attributes were declined, so they would fall through to another authorizer")
		assert.NotErrorIs(t, err, authorize.ErrAccessDenied,
			"a wiring mistake was reported as a decision about the caller")
	}

	cases := []testCase{
		{
			name:   "attributes of a shape this authorizer does not handle are a skip",
			attrs:  authorize.OwnershipAttributes{Group: "billing", Resource: "invoice"},
			assert: unsupported,
		},
		{
			name:   "attributes of no recognised shape at all are a skip",
			attrs:  "billing/invoice:read",
			assert: unsupported,
		},
		{
			name:   "an absent pointer to privilege attributes is a refusal, not a panic",
			attrs:  (*authorize.PrivilegeAttributes)(nil),
			assert: invalid,
		},
		{
			name:   "a blank group is a refusal",
			attrs:  authorize.PrivilegeAttributes{Resource: "invoice", Required: []string{"read"}},
			assert: invalid,
		},
		{
			name:   "a group of nothing but whitespace is a refusal",
			attrs:  authorize.PrivilegeAttributes{Group: "   ", Resource: "invoice", Required: []string{"read"}},
			assert: invalid,
		},
		{
			name:   "a blank resource is a refusal",
			attrs:  authorize.PrivilegeAttributes{Group: "billing", Required: []string{"read"}},
			assert: invalid,
		},
		{
			name:   "requiring no privileges at all is a refusal",
			attrs:  authorize.PrivilegeAttributes{Group: "billing", Resource: "invoice"},
			assert: invalid,
		},
		{
			name: "requiring a blank privilege name is a refusal",
			attrs: authorize.PrivilegeAttributes{
				Group: "billing", Resource: "invoice", Required: []string{"read", " "},
			},
			assert: invalid,
		},
		{
			name: "a matching mode this package does not define is a refusal",
			attrs: authorize.PrivilegeAttributes{
				Group: "billing", Resource: "invoice", Required: []string{"read"},
				Mode: authorize.MatchMode(42),
			},
			assert: invalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			// No EXPECT: attributes that are declined or refused must be
			// answered before the loader is asked anything.
			authorizer, err := authorize.NewPrivilegeAuthorizer(NewMockRoleLoader(ctrl))
			require.NoError(t, err)

			tc.assert(t, authorizer.Authorize(withRole(t.Context(), "clerk"), tc.attrs))
		})
	}
}

func TestPrivilegeAuthorizerSubject(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, err error)
	}

	denied := func(t *testing.T, err error) {
		require.ErrorIs(t, err, authorize.ErrAccessDenied)
	}

	cases := []testCase{
		{
			name:   "a request with no subject denies without consulting the role loader",
			assert: denied,
		},
		{
			name: "a subject carried as nil denies without consulting the role loader",
			ctx: func(ctx context.Context) context.Context {
				return identity.WithPrincipal(ctx, nil)
			},
			assert: denied,
		},
		{
			name: "a subject with no active role denies without consulting the role loader",
			ctx: func(ctx context.Context) context.Context {
				return identity.WithPrincipal(ctx, &identity.Principal{ID: "u-1", Username: "ada"})
			},
			assert: denied,
		},
		{
			name: "an active role with a blank name denies without consulting the role loader",
			ctx: func(ctx context.Context) context.Context {
				return withRole(ctx, "  ")
			},
			assert: denied,
		},
		{
			name: "a super role allows without consulting the role loader",
			ctx: func(ctx context.Context) context.Context {
				super := &identity.AssignedRole{ID: "r-0", Name: "root", SuperRole: true}

				return identity.WithPrincipal(ctx, &identity.Principal{
					ID:         "u-0",
					Roles:      []*identity.AssignedRole{super},
					ActiveRole: super,
				})
			},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			// No EXPECT: the controller fails the test if the loader is asked
			// anything, which is what proves the decision was reached without
			// it — and, for the super role, that the bypass happens before
			// matching rather than after.
			authorizer, err := authorize.NewPrivilegeAuthorizer(NewMockRoleLoader(ctrl))
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			tc.assert(t, authorizer.Authorize(ctx, authorize.PrivilegeAttributes{
				Group:    "billing",
				Resource: "invoice",
				Required: []string{"read"},
				Mode:     authorize.MatchAnyOf,
			}))
		})
	}
}

func TestPrivilegeAuthorizerMatching(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		group    string
		resource string
		granted  map[string]bool
		required []string
		mode     authorize.MatchMode
		comparer func(a, b string) bool // nil means the library's default
		assert   func(t *testing.T, err error)
	}

	allowed := func(t *testing.T, err error) { require.NoError(t, err) }
	denied := func(t *testing.T, err error) { require.ErrorIs(t, err, authorize.ErrAccessDenied) }

	cases := []testCase{
		{
			name: "any-of matches one", granted: map[string]bool{"read": true, "write": true},
			required: []string{"write"}, mode: authorize.MatchAnyOf, assert: allowed,
		},
		{
			name: "any-of with none granted denies", granted: map[string]bool{"read": true},
			required: []string{"write"}, mode: authorize.MatchAnyOf, assert: denied,
		},
		{
			name: "all-of needs every one", granted: map[string]bool{"read": true},
			required: []string{"read", "write"}, mode: authorize.MatchAllOf, assert: denied,
		},
		{
			name: "all-of allows when every one is granted", granted: map[string]bool{"read": true, "write": true},
			required: []string{"read", "write"}, mode: authorize.MatchAllOf, assert: allowed,
		},
		{
			name: "the zero mode demands every privilege", granted: map[string]bool{"read": true},
			required: []string{"read", "write"}, assert: denied,
		},
		{
			name:     "a privilege present but not granted never counts",
			granted:  map[string]bool{"write": false},
			required: []string{"write"}, mode: authorize.MatchAnyOf, assert: denied,
		},
		{
			name: "a privilege the role never mentions denies", granted: map[string]bool{"read": true},
			required: []string{"approve"}, mode: authorize.MatchAnyOf, assert: denied,
		},
		{
			name: "names match case-insensitively by default", granted: map[string]bool{"Write": true},
			required: []string{"write"}, mode: authorize.MatchAnyOf, assert: allowed,
		},
		{
			name: "names match after trimming by default", granted: map[string]bool{"  write  ": true},
			required: []string{"write"}, mode: authorize.MatchAnyOf, assert: allowed,
		},
		{
			name:  "group and resource match case-insensitively by default",
			group: "Billing", resource: "Invoice", granted: map[string]bool{"READ": true},
			required: []string{"read"}, mode: authorize.MatchAnyOf, assert: allowed,
		},
		{
			name:  "another resource's privileges never count",
			group: "billing", resource: "receipt", granted: map[string]bool{"read": true},
			required: []string{"read"}, mode: authorize.MatchAnyOf, assert: denied,
		},
		{
			// The default row above and this one are the same request: the only
			// difference is the comparer the consumer supplied.
			name:     "a consumer comparer replaces the default without changing it",
			comparer: func(a, b string) bool { return a == b }, // exact, case-sensitive
			granted:  map[string]bool{"Write": true},
			required: []string{"write"}, mode: authorize.MatchAnyOf, assert: denied,
		},
		{
			name:     "a consumer comparer still allows what it does match",
			comparer: func(a, b string) bool { return a == b },
			granted:  map[string]bool{"write": true},
			required: []string{"write"}, mode: authorize.MatchAnyOf, assert: allowed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			group, resource := tc.group, tc.resource
			if group == "" {
				group = "billing"
			}

			if resource == "" {
				resource = "invoice"
			}

			roles := NewMockRoleLoader(ctrl)
			roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").
				Return(grantOn(group, resource, tc.granted), nil)

			var opts []authorize.PrivilegeOption
			if tc.comparer != nil {
				opts = append(opts, authorize.WithPrivilegeNameComparer(tc.comparer))
			}

			authorizer, err := authorize.NewPrivilegeAuthorizer(roles, opts...)
			require.NoError(t, err)

			tc.assert(t, authorizer.Authorize(withRole(t.Context(), "clerk"), authorize.PrivilegeAttributes{
				Group:    "billing",
				Resource: "invoice",
				Required: tc.required,
				Mode:     tc.mode,
			}))
		})
	}
}

func TestPrivilegeAuthorizerLoaderFailures(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		privileges []*identity.ResourcePrivileges
		loadErr    error
		assert     func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:    "privileges not found denies",
			loadErr: identity.ErrPrivilegesNotFound,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied)
			},
		},
		{
			name:    "any other loader error stays matchable",
			loadErr: errBackendDown,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errBackendDown, "the cause was collapsed into a denial")
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied,
					"an outage was reported as a decision about this caller")
			},
		},
		{
			name:       "a role holding no entries at all denies",
			privileges: nil,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied)
			},
		},
		{
			name:       "an absent entry among the privileges is skipped, not dereferenced",
			privileges: []*identity.ResourcePrivileges{nil},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			roles := NewMockRoleLoader(ctrl)
			roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(tc.privileges, tc.loadErr)

			authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
			require.NoError(t, err)

			tc.assert(t, authorizer.Authorize(withRole(t.Context(), "clerk"), authorize.PrivilegeAttributes{
				Group:    "billing",
				Resource: "invoice",
				Required: []string{"read"},
				Mode:     authorize.MatchAnyOf,
			}))
		})
	}
}
