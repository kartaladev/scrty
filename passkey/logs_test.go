package passkey_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/passkey"
)

func TestPasskeyLogs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []passkey.Option
		assert func(t *testing.T, e *loginEnv)
	}

	// refuseUnknown runs n begins, each answered from a credential nobody
	// holds.
	refuseUnknown := func(t *testing.T, e *loginEnv, n int) {
		t.Helper()

		for range n {
			_, err := e.m.Authenticate(t.Context(),
				assertion(e.begin(t), func(b *assertionBody) { b.ID = "nobody's key" }), e.binding)
			require.Error(t, err)
		}
	}

	cases := []testCase{
		{
			name: "refusals within one window are written once and the rest reported",
			assert: func(t *testing.T, e *loginEnv) {
				t.Helper()

				refuseUnknown(t, e, 200)
				assert.Equal(t, 1, countRecords(e.logs, "passkey: assertion refused"))

				require.NoError(t, e.m.FlushRefusalLogs())

				var reported []string
				for _, r := range e.logs.records() {
					if strings.Contains(r, `"msg":"passkey: records suppressed"`) {
						reported = append(reported, r)
					}
				}

				require.Len(t, reported, 1)
				assert.Contains(t, reported[0], `"key":"refused|unknown-credential"`)
				assert.Contains(t, reported[0], `"suppressed":199`)
			},
		},
		{
			name: "a log interval of zero writes every record",
			opts: []passkey.Option{passkey.WithLogInterval(0)},
			assert: func(t *testing.T, e *loginEnv) {
				t.Helper()

				refuseUnknown(t, e, 20)
				assert.Equal(t, 20, countRecords(e.logs, "passkey: assertion refused"))
			},
		},
		{
			name: "a log interval replaces the window",
			opts: []passkey.Option{passkey.WithLogInterval(10 * time.Second)},
			assert: func(t *testing.T, e *loginEnv) {
				t.Helper()

				refuseUnknown(t, e, 5)
				e.f.clock.Advance(11 * time.Second)
				refuseUnknown(t, e, 5)
				assert.Equal(t, 2, countRecords(e.logs, "passkey: assertion refused"))
			},
		},
		{
			name: "no record carries a challenge, a key, a handle, a credential ID or an address",
			opts: []passkey.Option{passkey.WithLogInterval(0)},
			assert: func(t *testing.T, e *loginEnv) {
				t.Helper()

				var challenges [][]byte

				// A bad signature.
				c := e.begin(t)
				challenges = append(challenges, []byte(c))
				_, err := e.m.Authenticate(t.Context(), assertion(c, func(b *assertionBody) { b.Sig = "forged" }), e.binding)
				require.Error(t, err)

				// Another user's handle.
				c = e.begin(t)
				challenges = append(challenges, []byte(c))
				_, err = e.m.Authenticate(t.Context(), assertion(c, func(b *assertionBody) { b.Handle = handleU2 }), e.binding)
				require.Error(t, err)

				// A suspected clone, whose notice the queue refuses.
				e.f.mu.Lock()
				e.f.sendErr = errors.New("queue full for ana@example.com")
				e.f.mu.Unlock()

				c = e.begin(t)
				challenges = append(challenges, []byte(c))
				_, err = e.m.Authenticate(t.Context(), assertion(c, func(b *assertionBody) { b.Count = 41 }), e.binding)
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)

				// A wrong binding.
				c = e.begin(t)
				challenges = append(challenges, []byte(c))
				_, err = e.m.Authenticate(t.Context(), assertion(c, nil), "another-browser")
				require.Error(t, err)

				out := e.logs.String()
				require.NotEmpty(t, out)
				assert.Contains(t, out, e.cred.ID.String(), "credentials are named by their library identifier")
				assert.NotContains(t, out, "ana@example.com")
				assert.NotContains(t, out, "queue full")
				assert.NotContains(t, out, e.binding)
				assertNoSecrets(t, out, append(challenges,
					e.cred.PublicKey, e.cred.CredentialID, handleU1, handleU2)...)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, nil)
			e.manager(t, tc.opts...)
			tc.assert(t, e)
		})
	}
}
