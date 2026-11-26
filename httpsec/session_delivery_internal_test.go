package httpsec

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			name: "a copy of an exchange with no runs in progress",
			ex:   func(ctx context.Context) *Exchange { return NewExchange(ctx, nil, nil) },
			assert: func(t *testing.T, orig, port *Exchange, _ *stagedWriter) {
				t.Helper()
				require.NotNil(t, port)
				assert.Nil(t, port.extra)
				assert.Nil(t, orig.extra)
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
