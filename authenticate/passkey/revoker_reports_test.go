package passkey_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/session"
)

// TestSessionRevoker_TakesNoRawStore pins that a session store cannot be wired as the
// revoker: it ends sessions with no report, so an observer relying on being told, such
// as an OpenID Provider ending grants, would not be, and could not find that out.
func TestSessionRevoker_TakesNoRawStore(t *testing.T) {
	t.Parallel()

	revoker := reflect.TypeFor[passkey.SessionRevoker]()

	assert.False(t, reflect.TypeFor[session.Store]().Implements(revoker), "a store reports nothing")
	assert.True(t, reflect.TypeFor[*session.Sessions]().Implements(revoker), "the manager reports its ends")
}

// endWatcher is an observer a manager can be asked about.
type endWatcher struct{}

func (*endWatcher) SignInsEnded(context.Context, session.EndReport) {}

// TestPasskeys_ReportsEndsTo pins what a component relying on end reports is told of
// the sessions this manager ends.
func TestPasskeys_ReportsEndsTo(t *testing.T) {
	t.Parallel()

	watcher := &endWatcher{}

	type testCase struct {
		name   string
		wire   func(t *testing.T, deps *passkey.Deps) []passkey.Option
		assert func(t *testing.T, reports bool)
	}

	cases := []testCase{
		{
			name: "a revoker reporting to the observer",
			wire: func(t *testing.T, deps *passkey.Deps) []passkey.Option {
				t.Helper()

				sessions, err := session.New(session.WithEndObserver(watcher))
				require.NoError(t, err)

				deps.Sessions = sessions

				return nil
			},
			assert: func(t *testing.T, reports bool) {
				t.Helper()

				assert.True(t, reports)
			},
		},
		{
			name: "a revoker that does not",
			wire: func(*testing.T, *passkey.Deps) []passkey.Option { return nil },
			assert: func(t *testing.T, reports bool) {
				t.Helper()

				assert.False(t, reports)
			},
		},
		{
			name: "no revoker, so no session is ended",
			wire: func(_ *testing.T, deps *passkey.Deps) []passkey.Option {
				deps.Sessions = nil

				return []passkey.Option{passkey.WithoutSessionRevocationOnRemoval(), passkey.WithoutSessionRevocationOnClone()}
			},
			assert: func(t *testing.T, reports bool) {
				t.Helper()

				assert.True(t, reports)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			opts := tc.wire(t, &f.deps)

			m, err := passkey.New(f.deps, append(opts, passkey.WithRepudiationContact("help@example.com"))...)
			require.NoError(t, err)

			tc.assert(t, m.ReportsEndsTo(watcher))
		})
	}
}
