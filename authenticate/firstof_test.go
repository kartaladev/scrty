package authenticate_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/logsample"
)

func TestManagerAuthenticate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		delegates func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator
		assert    func(t *testing.T, got *authenticate.Authentication, err error)
	}

	cases := []testCase{
		{
			name: "the first delegate that answers decides, and later ones are never asked",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				first := NewMockAuthenticator(ctrl)
				first.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(&authenticate.Authentication{Principal: principal(t)}, nil)

				// No EXPECT: asking it at all is the failure.
				second := NewMockAuthenticator(ctrl)

				return []authenticate.Authenticator{first, second}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, "ada", got.Principal.Username)
			},
		},
		{
			name: "ErrUnsupportedCredentials skips to the next delegate",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				first := NewMockAuthenticator(ctrl)
				first.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(nil, authenticate.ErrUnsupportedCredentials)
				second := NewMockAuthenticator(ctrl)
				second.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(&authenticate.Authentication{Principal: principal(t)}, nil)

				return []authenticate.Authenticator{first, second}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, got)
			},
		},
		{
			name: "any other error is returned unchanged, and stops the manager",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				first := NewMockAuthenticator(ctrl)
				first.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(nil, errBackendDown)

				// No EXPECT: a failure must not be retried by a later delegate.
				second := NewMockAuthenticator(ctrl)

				return []authenticate.Authenticator{first, second}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, errBackendDown)
				assert.Nil(t, got)
			},
		},
		{
			name: "every delegate skipping is reported as such",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				first := NewMockAuthenticator(ctrl)
				first.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(nil, authenticate.ErrUnsupportedCredentials)
				second := NewMockAuthenticator(ctrl)
				second.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(nil, authenticate.ErrUnsupportedCredentials)

				return []authenticate.Authenticator{first, second}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrNoEligibleAuthenticator)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"skipped credentials were reported as a judged refusal")
				assert.Nil(t, got)
			},
		},
		{
			name: "a nil result becomes a failure, not a nil-principal success",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				only := NewMockAuthenticator(ctrl)
				only.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(nil, nil)

				return []authenticate.Authenticator{only}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, got)
			},
		},
		{
			name: "a result with a nil principal becomes a failure",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				only := NewMockAuthenticator(ctrl)
				only.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(&authenticate.Authentication{Principal: nil}, nil)

				return []authenticate.Authenticator{only}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, got,
					"a caller reading Principal after a nil error would dereference nothing")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			m, err := authenticate.NewFirstOf(tc.delegates(t, ctrl)...)
			require.NoError(t, err)

			got, err := m.Authenticate(t.Context(), credentials(t))
			tc.assert(t, got, err)
		})
	}
}

// credentials returns credentials to present to a manager. The manager itself
// never reads them, so any kind will do.
func credentials(t *testing.T) identity.Credentials {
	t.Helper()

	return identity.NewUsernamePassword("ada", []byte("correct-horse"))
}

func TestNewManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		delegates func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator
		assert    func(t *testing.T, m *authenticate.FirstOf, err error)
	}

	configError := func(t *testing.T, m *authenticate.FirstOf, err error) {
		t.Helper()

		require.ErrorIs(t, err, authenticate.ErrConfig)
		assert.Nil(t, m, "a refused configuration still produced a manager")
	}

	cases := []testCase{
		{
			name: "one live delegate constructs",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				return []authenticate.Authenticator{NewMockAuthenticator(ctrl)}
			},
			assert: func(t *testing.T, m *authenticate.FirstOf, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "no delegates is refused, because such a manager authenticates nobody",
			delegates: func(t *testing.T, _ *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				return nil
			},
			assert: configError,
		},
		{
			name: "an absent delegate is refused rather than skipped",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				return []authenticate.Authenticator{NewMockAuthenticator(ctrl), nil}
			},
			assert: configError,
		},
		{
			name: "a non-nil interface holding a nil pointer is refused too",
			delegates: func(t *testing.T, _ *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				// What an unchecked constructor error hands over: `d == nil` is
				// false, so an unchecked manager panics on the first request.
				var unchecked *authenticate.FirstOf

				return []authenticate.Authenticator{unchecked}
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			m, err := authenticate.NewFirstOf(tc.delegates(t, ctrl)...)
			tc.assert(t, m, err)
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
			m, err := authenticate.NewFirstOf(delegates...)
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

		m, err := authenticate.NewFirstOf(delegates...)
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

			m, err := authenticate.NewFirstOf(tc.delegates(t, ctrl)...)
			require.NoError(t, err)

			tc.assert(t, m.OffersDecoy())
		})
	}
}

// Standalone: already a table over Authenticate; inside TestManagerAuthenticate its cases would sit a level deeper.
func TestManager_NestedManagerThatSkipsLetsOuterTryNextDelegate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator
		assert func(t *testing.T, got *authenticate.Authentication, err error)
	}

	// skipping returns a manager whose only provider skips every credential, so
	// its own answer is ErrNoEligibleAuthenticator.
	skipping := func(t *testing.T, ctrl *gomock.Controller) *authenticate.FirstOf {
		t.Helper()

		inner := NewMockAuthenticator(ctrl)
		inner.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(nil, authenticate.ErrUnsupportedCredentials)

		nested, err := authenticate.NewFirstOf(inner)
		require.NoError(t, err)

		return nested
	}

	cases := []testCase{
		{
			name: "the next delegate authenticates what the nested manager skipped",
			build: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				next := NewMockAuthenticator(ctrl)
				next.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(&authenticate.Authentication{Principal: principal(t)}, nil)

				return []authenticate.Authenticator{skipping(t, ctrl), next}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err, "a nested manager that skipped is a skip, not an answer")
				require.NotNil(t, got)
				assert.Equal(t, "ada", got.Principal.Username)
			},
		},
		{
			name: "every delegate being a skipping manager is still no eligible authenticator",
			build: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				return []authenticate.Authenticator{skipping(t, ctrl), skipping(t, ctrl)}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrNoEligibleAuthenticator)
				assert.Nil(t, got)
			},
		},
		{
			name: "an outage inside a nested manager still stops the walk",
			build: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				inner := NewMockAuthenticator(ctrl)
				inner.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(nil, errBackendDown)

				nested, err := authenticate.NewFirstOf(inner)
				require.NoError(t, err)

				// No EXPECT: an outage must not be retried by a later delegate.
				return []authenticate.Authenticator{nested, NewMockAuthenticator(ctrl)}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, errBackendDown)
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			outer, err := authenticate.NewFirstOf(tc.build(t, ctrl)...)
			require.NoError(t, err)

			got, err := outer.Authenticate(t.Context(), credentials(t))
			tc.assert(t, got, err)
		})
	}
}

var (
	errFlushFirst = errors.New("firstof_test: first delegate flush failed")
	errFlushLast  = errors.New("firstof_test: last delegate flush failed")
)

// flushDelegate is a delegate that records its refusal-log flush into a
// sequence shared with its siblings, and fails the flush with err.
type flushDelegate struct {
	plainDelegate
	name string
	seq  *[]string
	err  error
}

func (d *flushDelegate) FlushRefusalLogs() error {
	*d.seq = append(*d.seq, d.name)

	return d.err
}

var _ logsample.Flusher = (*flushDelegate)(nil)

func TestFirstOf_FlushRefusalLogs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// build returns the FirstOf under test and the sequence its flushing
		// delegates append their names to.
		build  func(t *testing.T) (*authenticate.FirstOf, *[]string)
		assert func(t *testing.T, err error, calls []string)
	}

	mustFirstOf := func(t *testing.T, delegates ...authenticate.Authenticator) *authenticate.FirstOf {
		t.Helper()

		m, err := authenticate.NewFirstOf(delegates...)
		require.NoError(t, err)

		return m
	}

	cases := []testCase{
		{
			name: "flushes in delegate order and joins every failure in that order",
			build: func(t *testing.T) (*authenticate.FirstOf, *[]string) {
				t.Helper()

				seq := &[]string{}
				first := &flushDelegate{name: "first", seq: seq, err: errFlushFirst}
				middle := &flushDelegate{name: "middle", seq: seq}
				last := &flushDelegate{name: "last", seq: seq, err: errFlushLast}

				return mustFirstOf(t, first, plainDelegate{}, middle, last), seq
			},
			assert: func(t *testing.T, err error, calls []string) {
				t.Helper()

				require.ErrorIs(t, err, errFlushFirst)
				require.ErrorIs(t, err, errFlushLast)
				assert.Equal(t, errFlushFirst.Error()+"\n"+errFlushLast.Error(), err.Error())
				assert.Equal(t, []string{"first", "middle", "last"}, calls)
			},
		},
		{
			name: "a failing delegate does not stop the later ones",
			build: func(t *testing.T) (*authenticate.FirstOf, *[]string) {
				t.Helper()

				seq := &[]string{}
				first := &flushDelegate{name: "first", seq: seq, err: errFlushFirst}
				last := &flushDelegate{name: "last", seq: seq}

				return mustFirstOf(t, first, last), seq
			},
			assert: func(t *testing.T, err error, calls []string) {
				t.Helper()

				require.ErrorIs(t, err, errFlushFirst)
				assert.Equal(t, []string{"first", "last"}, calls)
			},
		},
		{
			name: "nested FirstOf is reached",
			build: func(t *testing.T) (*authenticate.FirstOf, *[]string) {
				t.Helper()

				seq := &[]string{}
				leaf := &flushDelegate{name: "leaf", seq: seq}
				inner := mustFirstOf(t, leaf)

				return mustFirstOf(t, inner), seq
			},
			assert: func(t *testing.T, err error, calls []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"leaf"}, calls)
			},
		},
		{
			name: "no flusher",
			build: func(t *testing.T) (*authenticate.FirstOf, *[]string) {
				t.Helper()

				return mustFirstOf(t, plainDelegate{}), &[]string{}
			},
			assert: func(t *testing.T, err error, calls []string) {
				t.Helper()

				assert.NoError(t, err)
				assert.Empty(t, calls)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, seq := tc.build(t)

			tc.assert(t, m.FlushRefusalLogs(), *seq)
		})
	}
}
