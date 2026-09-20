package authorize_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// errUnparsableID stands in for a resolver that cannot make sense of the
// request it was given, which is an outage on the authorization path rather
// than a decision about the caller.
var errUnparsableID = errors.New("unparsable resource identifier")

func TestOwnershipAuthorizerAuthorize(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		attrs  func(t *testing.T, calls *ownershipCalls) authorize.Attributes
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, calls *ownershipCalls, err error)
	}

	// owns builds attributes whose resolver yields id and whose check answers
	// owned, recording what each was asked.
	owns := func(id string, owned bool) func(*testing.T, *ownershipCalls) authorize.Attributes {
		return func(_ *testing.T, calls *ownershipCalls) authorize.Attributes {
			return authorize.OwnershipAttributes{
				Group:    "billing",
				Resource: "invoice",
				ResolveID: func(context.Context) (string, error) {
					calls.resolved++

					return id, nil
				},
				OwnedBy: func(_ context.Context, subject *identity.Principal, got string) (bool, error) {
					calls.checked++
					calls.id = got
					calls.subject = subject

					return owned, nil
				},
			}
		}
	}

	denied := func(t *testing.T, _ *ownershipCalls, err error) {
		require.ErrorIs(t, err, authorize.ErrAccessDenied)
	}
	invalid := func(t *testing.T, calls *ownershipCalls, err error) {
		require.ErrorIs(t, err, authorize.ErrInvalidAttributes)
		assert.Zero(t, calls.resolved, "malformed attributes still ran the consumer's resolver")
		assert.Zero(t, calls.checked, "malformed attributes still ran the consumer's check")
	}

	cases := []testCase{
		{
			name:  "the owner is allowed",
			attrs: owns("o-9", true),
			assert: func(t *testing.T, calls *ownershipCalls, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, calls.resolved)
				assert.Equal(t, 1, calls.checked)
			},
		},
		{
			name:   "someone who is not the owner is denied",
			attrs:  owns("o-9", false),
			assert: denied,
		},
		{
			name:  "the identifier reaches the check exactly as the resolver produced it",
			attrs: owns("  \u00d8/9 ?#\u00a0", true),
			assert: func(t *testing.T, calls *ownershipCalls, err error) {
				require.NoError(t, err)
				assert.Equal(t, "  \u00d8/9 ?#\u00a0", calls.id,
					"the identifier was interpreted on its way to the consumer's check")
			},
		},
		{
			name:  "the check is given the subject the request carries",
			attrs: owns("o-9", true),
			assert: func(t *testing.T, calls *ownershipCalls, err error) {
				require.NoError(t, err)
				require.NotNil(t, calls.subject)
				assert.Equal(t, identity.UserID("u-1"), calls.subject.ID)
			},
		},
		{
			name: "a resolver failure stays matchable and is not a denial",
			attrs: func(_ *testing.T, calls *ownershipCalls) authorize.Attributes {
				return authorize.OwnershipAttributes{
					Group:    "billing",
					Resource: "invoice",
					ResolveID: func(context.Context) (string, error) {
						calls.resolved++

						return "", errUnparsableID
					},
					OwnedBy: func(context.Context, *identity.Principal, string) (bool, error) {
						calls.checked++

						return true, nil
					},
				}
			},
			assert: func(t *testing.T, calls *ownershipCalls, err error) {
				require.ErrorIs(t, err, errUnparsableID, "the cause was collapsed")
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied,
					"a failure to identify the record was reported as a decision about the caller")
				assert.Zero(t, calls.checked, "ownership was checked for a record that was never identified")
			},
		},
		{
			name: "a check failure stays matchable and is not a denial",
			attrs: func(_ *testing.T, calls *ownershipCalls) authorize.Attributes {
				return authorize.OwnershipAttributes{
					Group:    "billing",
					Resource: "invoice",
					ResolveID: func(context.Context) (string, error) {
						calls.resolved++

						return "o-9", nil
					},
					OwnedBy: func(context.Context, *identity.Principal, string) (bool, error) {
						calls.checked++

						return true, errBackendDown
					},
				}
			},
			// The check reports ownership and fails at the same time, so a
			// caller that read its bool anyway would allow on an outage.
			assert: func(t *testing.T, _ *ownershipCalls, err error) {
				require.ErrorIs(t, err, errBackendDown)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied,
					"an outage was reported as a decision about this caller")
			},
		},
		{
			name:  "a request with no subject is denied without running the consumer's functions",
			attrs: owns("o-9", true),
			ctx: func(ctx context.Context) context.Context {
				return ctx
			},
			assert: func(t *testing.T, calls *ownershipCalls, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied)
				assert.Zero(t, calls.resolved, "a record was identified for a caller who is not there")
				assert.Zero(t, calls.checked, "ownership was checked for a caller who is not there")
			},
		},
		{
			name: "privilege attributes are declined so another authorizer may judge them",
			attrs: func(_ *testing.T, _ *ownershipCalls) authorize.Attributes {
				return authorize.PrivilegeAttributes{
					Group: "billing", Resource: "invoice", Required: []string{"read"},
				}
			},
			assert: func(t *testing.T, _ *ownershipCalls, err error) {
				require.ErrorIs(t, err, authorize.ErrUnsupportedAttributes)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied)
			},
		},
		{
			name: "an absent pointer to ownership attributes is refused, not a panic",
			attrs: func(_ *testing.T, _ *ownershipCalls) authorize.Attributes {
				return (*authorize.OwnershipAttributes)(nil)
			},
			assert: invalid,
		},
		{
			name: "a blank group is refused",
			attrs: func(_ *testing.T, calls *ownershipCalls) authorize.Attributes {
				attrs, _ := owns("o-9", true)(nil, calls).(authorize.OwnershipAttributes)
				attrs.Group = " "

				return attrs
			},
			assert: invalid,
		},
		{
			name: "a blank resource is refused",
			attrs: func(_ *testing.T, calls *ownershipCalls) authorize.Attributes {
				attrs, _ := owns("o-9", true)(nil, calls).(authorize.OwnershipAttributes)
				attrs.Resource = ""

				return attrs
			},
			assert: invalid,
		},
		{
			name: "attributes with no resolver are refused",
			attrs: func(_ *testing.T, calls *ownershipCalls) authorize.Attributes {
				attrs, _ := owns("o-9", true)(nil, calls).(authorize.OwnershipAttributes)
				attrs.ResolveID = nil

				return attrs
			},
			assert: invalid,
		},
		{
			name: "attributes with no ownership check are refused",
			attrs: func(_ *testing.T, calls *ownershipCalls) authorize.Attributes {
				attrs, _ := owns("o-9", true)(nil, calls).(authorize.OwnershipAttributes)
				attrs.OwnedBy = nil

				return attrs
			},
			assert: invalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			calls := &ownershipCalls{}
			authorizer := authorize.NewOwnershipAuthorizer()

			ctx := withRole(t.Context(), "clerk")
			if tc.ctx != nil {
				ctx = tc.ctx(t.Context())
			}

			tc.assert(t, calls, authorizer.Authorize(ctx, tc.attrs(t, calls)))
		})
	}
}

// ownershipCalls records what the consumer's own functions were asked, so a
// case can assert that they ran, that they did not, and what reached them.
type ownershipCalls struct {
	resolved int
	checked  int
	id       string
	subject  *identity.Principal
}
