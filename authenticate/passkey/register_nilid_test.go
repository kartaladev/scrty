package passkey_test

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/pkg/id"
)

// armedIDs answers from inner until armed, then answers the fixed pair. It is
// hand-written because BeginRegistration's one-time store mints an unknown
// number of ids from the same generator; only the finish is armed.
type armedIDs struct {
	inner id.Generator
	armed *atomic.Bool
	id    id.ID
	err   error
}

func (g armedIDs) NewID() (id.ID, error) {
	if g.armed.Load() {
		return g.id, g.err
	}

	return g.inner.NewID()
}

func requireIDMintRefusal(t *testing.T, err error) {
	t.Helper()

	assert.ErrorContains(t, err, "could not mint a credential identifier")
	assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
	assert.NotErrorIs(t, err, passkey.ErrPerUserLimitReached)
}

func TestFinishRegistration_CredentialIdentifier(t *testing.T) {
	t.Parallel()

	good, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	outage := errors.New("generator down")

	type testCase struct {
		name   string
		id     id.ID
		err    error
		assert func(t *testing.T, held int, err error)
	}

	cases := []testCase{
		{
			name: "generator outage stores nothing",
			err:  outage,
			assert: func(t *testing.T, held int, err error) {
				t.Helper()
				require.ErrorIs(t, err, outage)
				requireIDMintRefusal(t, err)
				assert.Zero(t, held)
			},
		},
		{
			name: "nil identifier is refused like an outage and stores nothing",
			id:   id.Nil,
			assert: func(t *testing.T, held int, err error) {
				t.Helper()
				require.Error(t, err)
				requireIDMintRefusal(t, err)
				assert.Zero(t, held, "a credential must not be stored under the nil identifier")
			},
		},
		{
			name: "good identifier registers",
			id:   good,
			assert: func(t *testing.T, held int, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, 1, held)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			armed := &atomic.Bool{}
			m := f.manager(t, passkey.WithIDGenerator(armedIDs{
				inner: id.NewV7Generator(), armed: armed, id: tc.id, err: tc.err,
			}))
			s := enrolmentSession("sess-a", "u-1")

			challenge := f.begin(t, m, s)

			armed.Store(true)

			_, err := m.FinishRegistration(t.Context(), s, regBody(challenge, "cred-a", ""), passkey.RegistrationContext{})

			held, lerr := f.creds.List(t.Context(), "u-1")
			require.NoError(t, lerr)

			tc.assert(t, len(held), err)
		})
	}
}

type nilGen struct{}

func (*nilGen) NewID() (id.ID, error) { return id.ID{}, nil }

func TestNew_IDGeneratorOptionRefusal(t *testing.T) {
	t.Parallel()

	var typedNil *nilGen

	cases := []struct {
		name string
		gen  id.Generator
	}{
		{name: "nil", gen: nil},
		{name: "typed nil", gen: typedNil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			m, err := passkey.New(f.deps, passkey.WithClock(f.clock),
				passkey.WithRepudiationContact("help@example.com"), passkey.WithIDGenerator(tc.gen))
			require.ErrorIs(t, err, passkey.ErrConfig)
			assert.Nil(t, m)
			assert.Contains(t, err.Error(), "identifier generator")
		})
	}
}
