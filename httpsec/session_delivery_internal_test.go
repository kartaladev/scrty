package httpsec

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// TestDetachedCopy pins that the exchange a consumer's session delivery is
// handed shares no per-request mutable state with the real one: not the
// per-request phase, not the stack of runs, and not the session.
func TestDetachedCopy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ex     func(ctx context.Context) *Exchange
		assert func(t *testing.T, orig, port *Exchange, staged *stagedWriter)
	}

	cases := []testCase{
		{
			name: "the copy has no per-request phase, no shared run stack and its own session",
			ex: func(ctx context.Context) *Exchange {
				ex := NewExchange(ctx, nil, nil)
				ex.perRequest = &perRequestPhase{}
				ex.Session = &session.Session{ID: "real"}
				ex.extra = make([]runTerminal, 1, 4)

				return ex
			},
			assert: func(t *testing.T, orig, port *Exchange, staged *stagedWriter) {
				t.Helper()

				assert.Nil(t, port.perRequest, "the per-request phase is not shared")
				assert.NotNil(t, orig.perRequest, "the real exchange keeps its phase")
				assert.True(t, port.detached)
				assert.False(t, orig.detached)
				assert.Same(t, staged, port.Writer)
				assert.NotSame(t, orig.Session, port.Session)

				port.extra = append(port.extra, runTerminal{chain: &Chain{}})
				assert.Len(t, orig.extra, 1)
				assert.Nil(t, orig.extra[:cap(orig.extra)][1].chain,
					"an append on the copy does not write into the real run stack")
			},
		},
		{
			name: "the copy has its own authentication result",
			ex: func(ctx context.Context) *Exchange {
				ex := NewExchange(ctx, nil, nil)
				ex.Authentication = &authenticate.Authentication{
					Principal: &identity.Principal{ID: "u-1"},
					Time:      time.Unix(1, 0),
				}

				return ex
			},
			assert: func(t *testing.T, orig, port *Exchange, _ *stagedWriter) {
				t.Helper()

				require.NotNil(t, port.Authentication)
				assert.NotSame(t, orig.Authentication, port.Authentication)
				assert.Equal(t, *orig.Authentication, *port.Authentication, "the copy reads what the real one holds")

				port.Authentication.Principal = &identity.Principal{ID: "someone-else"}
				port.Authentication.Time = time.Unix(2, 0)

				assert.Equal(t, identity.UserID("u-1"), orig.Authentication.Principal.ID,
					"changing the copy's result leaves the real one's caller")
				assert.True(t, orig.Authentication.Time.Equal(time.Unix(1, 0)))
			},
		},
		{
			name: "a copy of an exchange with no runs in progress",
			ex:   func(ctx context.Context) *Exchange { return NewExchange(ctx, nil, nil) },
			assert: func(t *testing.T, orig, port *Exchange, _ *stagedWriter) {
				t.Helper()
				require.NotNil(t, port)
				assert.Nil(t, port.extra)
				assert.Nil(t, orig.extra)
				assert.Nil(t, port.Authentication, "no result stays no result")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			orig := tc.ex(t.Context())
			staged := &stagedWriter{}

			tc.assert(t, orig, detachedCopy(orig, staged), staged)
		})
	}
}
