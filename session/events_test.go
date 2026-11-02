package session_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/internal/secevent"
	"github.com/kartaladev/scrty/security"
	"github.com/kartaladev/scrty/session"
)

// eventLog is a security-event sink that keeps what it receives.
type eventLog struct {
	mu     sync.Mutex
	events []security.Event
}

func (l *eventLog) sink(_ context.Context, e security.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.events = append(l.events, e)
}

func (l *eventLog) all() []security.Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]security.Event(nil), l.events...)
}

// TestSecurityEvents_Reuse pins that a detected reuse is reported as
// authn_token_reuse where the manager decides it: to the chain's delivery on a
// chain's request and to the manager's own sink otherwise, naming the user and
// the presented session by its digest, while a configured reuse observer is
// still called.
func TestSecurityEvents_Reuse(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// ownSink gives the manager a sink of its own; observe a reuse
		// observer.
		ownSink, observe bool

		// onChain presents the reused session on a chain's request.
		onChain bool

		assert func(t *testing.T, f *graceFixture, own, chain []security.Event, observed int)
	}

	reuseOf := func(f *graceFixture) []security.Event {
		sum := sha256.Sum256([]byte(f.o.ID))

		return []security.Event{{
			Name:    security.AuthnTokenReuse,
			At:      createdAt.Add(5 * time.Minute),
			Outcome: security.OutcomeFailure,
			User:    testUser,
			Session: hex.EncodeToString(sum[:]),
		}}
	}

	cases := []testCase{
		{
			name:    "a reuse reports authn_token_reuse to the manager's own sink",
			ownSink: true,
			assert: func(t *testing.T, f *graceFixture, own, chain []security.Event, _ int) {
				assert.Equal(t, reuseOf(f), own)
				assert.Empty(t, chain)
			},
		},
		{
			name:    "a configured reuse observer is still called beside the sink",
			ownSink: true,
			observe: true,
			assert: func(t *testing.T, f *graceFixture, own, _ []security.Event, observed int) {
				assert.Equal(t, reuseOf(f), own)
				assert.Equal(t, 1, observed)
			},
		},
		{
			name:    "without a sink the observer alone is called",
			observe: true,
			assert: func(t *testing.T, _ *graceFixture, own, chain []security.Event, observed int) {
				assert.Empty(t, own)
				assert.Empty(t, chain)
				assert.Equal(t, 1, observed)
			},
		},
		{
			name:    "on a chain's request the reuse reports through the chain, not the manager's own sink",
			ownSink: true,
			onChain: true,
			assert: func(t *testing.T, f *graceFixture, own, chain []security.Event, _ int) {
				assert.Empty(t, own, "one reuse is reported once")
				assert.Equal(t, reuseOf(f), chain)
			},
		},
		{
			name:    "on a chain's request a manager with no sink of its own reports through the chain",
			onChain: true,
			assert: func(t *testing.T, f *graceFixture, _, chain []security.Event, _ int) {
				assert.Equal(t, reuseOf(f), chain)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				own, chain eventLog
				mu         sync.Mutex
				observed   int
			)

			var opts []session.Option
			if tc.ownSink {
				opts = append(opts, session.WithSecurityEvents(own.sink))
			}
			if tc.observe {
				opts = append(opts, session.WithReuseObserver(func(context.Context, session.ReuseReport) {
					mu.Lock()
					defer mu.Unlock()

					observed++
				}))
			}

			f := newGraceFixture(t, opts...)
			f.renew(t.Context(), t, f.o, 30*time.Second)
			f.clk.Advance(5 * time.Minute)

			ctx := t.Context()
			if tc.onChain {
				ctx = secevent.With(ctx, chain.sink)
			}

			_, err := f.m.Load(ctx, f.o.ID)
			require.ErrorIs(t, err, session.ErrReused)

			mu.Lock()
			defer mu.Unlock()

			tc.assert(t, f, own.all(), chain.all(), observed)
		})
	}
}

// TestSecurityEvents_SessionsConfig pins that the manager's own sink is one
// sink: none given is the default, and a nil sink or the option twice is a
// configuration error.
func TestSecurityEvents_SessionsConfig(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.Option
		assert func(t *testing.T, m *session.Sessions, err error)
	}

	sink := func(context.Context, security.Event) {}

	cases := []testCase{
		{
			name: "no sink is the default",
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "one sink",
			opts: []session.Option{session.WithSecurityEvents(sink)},
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "a nil sink is a configuration error",
			opts: []session.Option{session.WithSecurityEvents(nil)},
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name: "the option twice is a configuration error",
			opts: []session.Option{session.WithSecurityEvents(sink), session.WithSecurityEvents(sink)},
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, m)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := session.New(append(tc.opts, session.WithStore(must.Must(session.NewMemoryStore())))...)
			tc.assert(t, m, err)
		})
	}
}
