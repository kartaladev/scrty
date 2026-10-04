package authenticate_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
)

func TestPasswordAuthenticator_VerifyDecoy(t *testing.T) {
	t.Parallel()

	reference := []byte("reference-hash")

	type testCase struct {
		name   string
		creds  identity.Credentials
		expect func(enc *MockEncoder)
		assert func(t *testing.T, handled bool)
	}

	cases := []testCase{
		{
			name:  "username and password is verified against the reference hash once",
			creds: identity.NewUsernamePassword("ada", []byte("guess")),
			expect: func(enc *MockEncoder) {
				enc.EXPECT().Match("guess", reference).Return(false).Times(1)
			},
			assert: func(t *testing.T, handled bool) {
				assert.True(t, handled)
			},
		},
		{
			name:  "other credentials are declined without hashing",
			creds: authenticate.NewBearerToken("x"),
			assert: func(t *testing.T, handled bool) {
				assert.False(t, handled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			enc := NewMockEncoder(ctrl)
			enc.EXPECT().Encode(gomock.Any()).Return(reference, nil).Times(1)
			if tc.expect != nil {
				tc.expect(enc)
			}
			// No expectations: any call to the loader fails the test.
			users := NewMockUserLoader(ctrl)

			a, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(enc))
			require.NoError(t, err)

			v, ok := a.(authenticate.DecoyVerifier)
			require.True(t, ok, "the password provider must implement DecoyVerifier")

			tc.assert(t, v.VerifyDecoy(t.Context(), tc.creds))
		})
	}
}

// decoyDelegate is a delegate that can spend a decoy. It handles only
// credentials of the kind it is told to, and counts the offers it received.
// Authenticate is never expected: the walk must not authenticate.
type decoyDelegate struct {
	handlesPassword bool
	handlesBearer   bool
	offered         int
	handled         int
}

func (d *decoyDelegate) Authenticate(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
	panic("VerifyDecoy must not authenticate")
}

func (d *decoyDelegate) VerifyDecoy(_ context.Context, c identity.Credentials) bool {
	d.offered++
	var ok bool
	switch c.(type) {
	case *identity.UsernamePassword:
		ok = d.handlesPassword
	case *authenticate.BearerToken:
		ok = d.handlesBearer
	}
	if ok {
		d.handled++
	}

	return ok
}

// plainDelegate implements Authenticator only.
type plainDelegate struct{}

func (plainDelegate) Authenticate(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
	panic("VerifyDecoy must not authenticate")
}

func TestManager_VerifyDecoy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func() ([]authenticate.Authenticator, []*decoyDelegate)
		assert func(t *testing.T, handled bool, decoys []*decoyDelegate)
	}

	cases := []testCase{
		{
			name: "manager delegates to the first that handles, skipping decliners",
			build: func() ([]authenticate.Authenticator, []*decoyDelegate) {
				a := &decoyDelegate{handlesBearer: true}
				b := &decoyDelegate{handlesPassword: true}
				return []authenticate.Authenticator{plainDelegate{}, a, b}, []*decoyDelegate{a, b}
			},
			assert: func(t *testing.T, handled bool, d []*decoyDelegate) {
				assert.True(t, handled)
				assert.Equal(t, 1, d[0].offered, "decoyA offered")
				assert.Equal(t, 0, d[0].handled, "decoyA declined")
				assert.Equal(t, 1, d[1].handled, "decoyB called once")
			},
		},
		{
			name: "first handler wins and later delegates are not offered",
			build: func() ([]authenticate.Authenticator, []*decoyDelegate) {
				a := &decoyDelegate{handlesPassword: true}
				b := &decoyDelegate{handlesPassword: true}
				return []authenticate.Authenticator{a, b}, []*decoyDelegate{a, b}
			},
			assert: func(t *testing.T, handled bool, d []*decoyDelegate) {
				assert.True(t, handled)
				assert.Equal(t, 1, d[0].handled)
				assert.Equal(t, 0, d[1].offered)
			},
		},
		{
			name: "no delegate offers a decoy",
			build: func() ([]authenticate.Authenticator, []*decoyDelegate) {
				return []authenticate.Authenticator{plainDelegate{}, plainDelegate{}}, nil
			},
			assert: func(t *testing.T, handled bool, _ []*decoyDelegate) {
				assert.False(t, handled)
			},
		},
		{
			name: "no delegate handles the credentials",
			build: func() ([]authenticate.Authenticator, []*decoyDelegate) {
				a := &decoyDelegate{handlesBearer: true}
				return []authenticate.Authenticator{a}, []*decoyDelegate{a}
			},
			assert: func(t *testing.T, handled bool, d []*decoyDelegate) {
				assert.False(t, handled)
				assert.Equal(t, 1, d[0].offered)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			delegates, decoys := tc.build()
			m, err := authenticate.NewManager(delegates...)
			require.NoError(t, err)

			v, ok := any(m).(authenticate.DecoyVerifier)
			require.True(t, ok)

			tc.assert(t, v.VerifyDecoy(t.Context(), identity.NewUsernamePassword("ada", []byte("guess"))), decoys)
		})
	}
}

func TestManager_OffersDecoy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		delegates func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator
		assert    func(t *testing.T, offers bool)
	}

	passwordProvider := func(t *testing.T, ctrl *gomock.Controller) authenticate.Authenticator {
		t.Helper()

		enc := NewMockEncoder(ctrl)
		enc.EXPECT().Encode(gomock.Any()).Return([]byte("reference"), nil).Times(1)

		a, err := authenticate.NewUsernamePasswordAuthenticator(NewMockUserLoader(ctrl),
			authenticate.WithPasswordEncoder(enc))
		require.NoError(t, err)

		return a
	}
	manager := func(t *testing.T, delegates ...authenticate.Authenticator) authenticate.Authenticator {
		t.Helper()

		m, err := authenticate.NewManager(delegates...)
		require.NoError(t, err)

		return m
	}

	cases := []testCase{
		{
			name: "over the password provider",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				return []authenticate.Authenticator{passwordProvider(t, ctrl)}
			},
			assert: func(t *testing.T, offers bool) { assert.True(t, offers) },
		},
		{
			name: "over a delegate offering no decoy",
			delegates: func(_ *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				return []authenticate.Authenticator{NewMockAuthenticator(ctrl)}
			},
			assert: func(t *testing.T, offers bool) { assert.False(t, offers) },
		},
		{
			name: "a decoy delegate after one offering none",
			delegates: func(_ *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				return []authenticate.Authenticator{NewMockAuthenticator(ctrl), &decoyDelegate{handlesPassword: true}}
			},
			assert: func(t *testing.T, offers bool) { assert.True(t, offers) },
		},
		{
			name: "over a nested manager whose only delegate offers no decoy",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				return []authenticate.Authenticator{manager(t, NewMockAuthenticator(ctrl))}
			},
			assert: func(t *testing.T, offers bool) {
				assert.False(t, offers, "a nested manager is a DecoyVerifier, but answers for its delegates")
			},
		},
		{
			name: "over a nested manager over the password provider",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				return []authenticate.Authenticator{manager(t, passwordProvider(t, ctrl))}
			},
			assert: func(t *testing.T, offers bool) { assert.True(t, offers) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			m, err := authenticate.NewManager(tc.delegates(t, ctrl)...)
			require.NoError(t, err)

			tc.assert(t, m.OffersDecoy())
		})
	}
}
