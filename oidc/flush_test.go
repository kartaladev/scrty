package oidc_test

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidc"
)

// flushSummaries returns, in the order written, the suppressed count of every
// record in logs whose message is msg. It is how these tests read what a
// flush reported without depending on the sampling key's own text.
func flushSummaries(t *testing.T, logs, msg string) []int {
	t.Helper()

	var counts []int
	for _, line := range strings.Split(logs, "\n") {
		if line == "" || !strings.Contains(line, `msg="`+msg+`"`) {
			continue
		}

		idx := strings.Index(line, "suppressed=")
		require.GreaterOrEqual(t, idx, 0, "a summary record carried no suppressed attribute: %s", line)

		rest := line[idx+len("suppressed="):]
		if end := strings.IndexByte(rest, ' '); end >= 0 {
			rest = rest[:end]
		}
		n, err := strconv.Atoi(rest)
		require.NoError(t, err)
		counts = append(counts, n)
	}
	return counts
}

// flushFixedClock is a clock that never advances, so every refusal a test
// drives falls in the sampler's very first window.
func flushFixedClock() *clockwork.FakeClock {
	return clockwork.NewFakeClockAt(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
}

// TestHandoffManagerFlushRefusalLogs pins spec oidc-login "OIDC components
// flush their refusal logs": FlushRefusalLogs reports what the handoff
// manager's sampler is holding back, reports nothing when there is nothing
// pending, and leaves the manager usable afterward.
func TestHandoffManagerFlushRefusalLogs(t *testing.T) {
	t.Parallel()

	// buildHandoff issues one code and returns the manager under test, the
	// issued code, and a sink of every record it writes. Every case shares a
	// clock that never advances, so repeated refusals of one reason land in
	// the same sampling window.
	buildHandoff := func(t *testing.T) (m *oidc.HandoffManager, code string, logs *handoffLogSink) {
		t.Helper()

		logs = &handoffLogSink{}
		m, err := oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)),
			oidc.WithHandoffClock(flushFixedClock()), oidc.WithHandoffLogger(logs.Logger()))
		require.NoError(t, err)

		code, err = m.Issue(t.Context(), handoffCallback())
		require.NoError(t, err)

		return m, code, logs
	}

	// wrongSecretFor returns a well-formed secret half that is not code's
	// own, so FindByTokenID still finds the record and the secret mismatch is
	// what refuses the redemption, every time, under one sampling key.
	wrongSecretFor := func(t *testing.T, code string) string {
		t.Helper()

		tokenID, _ := splitHandoffCode(t, code)
		return tokenID + "." + strings.Repeat("A", 43)
	}

	type testCase struct {
		name string
		act  func(t *testing.T, m *oidc.HandoffManager, code string)

		// afterFlush runs after FlushRefusalLogs, only for the row proving the
		// manager still works afterward; nil for every other row.
		afterFlush func(t *testing.T, m *oidc.HandoffManager, code string)

		assert func(t *testing.T, err error, logs string)
	}

	redeemWrongThrice := func(t *testing.T, m *oidc.HandoffManager, code string) {
		t.Helper()

		wrong := wrongSecretFor(t, code)
		for range 3 {
			_, err := m.Redeem(t.Context(), wrong)
			require.ErrorIs(t, err, oidc.ErrInvalidHandoff)
		}
	}

	cases := []testCase{
		{
			name: "records suppressed within a window are reported by the flush with their count",
			act:  redeemWrongThrice,
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc handoff refusals suppressed")
				require.Len(t, sums, 1, "three refusals of one reason must flush to exactly one summary record")
				assert.Equal(t, 2, sums[0], "the first refusal was already written; the flush owes the other two")
			},
		},
		{
			name: "a flush with nothing pending reports nothing",
			act:  func(*testing.T, *oidc.HandoffManager, string) {},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)
				assert.Empty(t, flushSummaries(t, logs, "oidc handoff refusals suppressed"))
			},
		},
		{
			name: "the component still works after a flush",
			act:  redeemWrongThrice,
			afterFlush: func(t *testing.T, m *oidc.HandoffManager, code string) {
				t.Helper()

				// One more refusal of the same reason, after the flush, must
				// be written again rather than counted as still suppressed.
				wrong := wrongSecretFor(t, code)
				_, err := m.Redeem(t.Context(), wrong)
				require.ErrorIs(t, err, oidc.ErrInvalidHandoff)
			},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				// The flush forgot the key, so the redemption afterFlush
				// drove is written again, unsampled, rather than counted as
				// still suppressed.
				sums := flushSummaries(t, logs, "oidc handoff refusals suppressed")
				require.Len(t, sums, 1)
				assert.Equal(t, 2, sums[0])

				assert.Equal(t, 2, strings.Count(logs, `msg="oidc handoff redemption refused"`),
					"the refusal after the flush must be written again, not suppressed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, code, logs := buildHandoff(t)
			tc.act(t, m, code)
			err := m.FlushRefusalLogs()

			if tc.afterFlush != nil {
				tc.afterFlush(t, m, code)
			}

			tc.assert(t, err, logs.String())
		})
	}
}

// TestBrokerFlushRefusalLogs pins spec oidc-login "OIDC components flush
// their refusal logs" for the identity broker: FlushRefusalLogs reports what
// its sampler is holding back, reports nothing when there is nothing
// pending, and leaves the broker usable afterward.
func TestBrokerFlushRefusalLogs(t *testing.T) {
	t.Parallel()

	// buildBroker returns a broker with no links seeded and no provisioning
	// enabled, so every Broker call for corpIdentity refuses with the same
	// reason, and the identity itself, under one sampling key. The clock
	// never advances, so repeated refusals land in the same window.
	buildBroker := func(t *testing.T) (b *oidc.Broker, ext oidc.ExternalIdentity, logs *bytes.Buffer) {
		t.Helper()

		logs = &bytes.Buffer{}
		b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(gomock.NewController(t)),
			oidc.WithBrokerClock(flushFixedClock()), oidc.WithBrokerLogger(testTextLogger(logs)))
		require.NoError(t, err)

		return b, brokerCorpIdentity(), logs
	}

	refuse := func(t *testing.T, b *oidc.Broker, ext oidc.ExternalIdentity) {
		t.Helper()

		_, err := b.Broker(t.Context(), ext)
		require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
	}

	refuseThrice := func(t *testing.T, b *oidc.Broker, ext oidc.ExternalIdentity) {
		t.Helper()
		for range 3 {
			refuse(t, b, ext)
		}
	}

	type testCase struct {
		name string
		act  func(t *testing.T, b *oidc.Broker, ext oidc.ExternalIdentity)

		// afterFlush runs after FlushRefusalLogs, only for the row proving the
		// broker still works afterward; nil for every other row.
		afterFlush func(t *testing.T, b *oidc.Broker, ext oidc.ExternalIdentity)

		assert func(t *testing.T, err error, logs string)
	}

	cases := []testCase{
		{
			name: "records suppressed within a window are reported by the flush with their count",
			act:  refuseThrice,
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc broker refusals suppressed")
				require.Len(t, sums, 1, "three refusals of one reason must flush to exactly one summary record")
				assert.Equal(t, 2, sums[0], "the first refusal was already written; the flush owes the other two")
			},
		},
		{
			name: "a flush with nothing pending reports nothing",
			act:  func(*testing.T, *oidc.Broker, oidc.ExternalIdentity) {},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)
				assert.Empty(t, flushSummaries(t, logs, "oidc broker refusals suppressed"))
			},
		},
		{
			name: "the component still works after a flush",
			act:  refuseThrice,
			afterFlush: func(t *testing.T, b *oidc.Broker, ext oidc.ExternalIdentity) {
				t.Helper()

				// The flush forgot the key, so a refusal for the same reason
				// afterward is written again, not held back.
				refuse(t, b, ext)
			},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc broker refusals suppressed")
				require.Len(t, sums, 1)
				assert.Equal(t, 2, sums[0])

				assert.Equal(t, 2, strings.Count(logs, `msg="oidc: no link for the external identity"`),
					"the refusal after the flush must be written again, not suppressed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b, ext, logs := buildBroker(t)
			tc.act(t, b, ext)
			err := b.FlushRefusalLogs()

			if tc.afterFlush != nil {
				tc.afterFlush(t, b, ext)
			}

			tc.assert(t, err, logs.String())
		})
	}
}

// flushProvider is a minimal, statically valid provider: nothing in these
// tests ever reaches discovery or the network.
func flushProvider() oidc.Provider {
	return oidc.Provider{
		Name: "corp", Issuer: "https://idp.example",
		ClientID: "client-corp", ClientSecret: "secret-corp",
		RedirectURL: "https://app.example/callback",
	}
}

// TestManagerFlushRefusalLogs pins spec oidc-login scenario "Manager flushes
// its broker": flushing the manager reports its own pending count and, when
// its broker can flush, the broker's; a broker that cannot flush is skipped
// without error.
func TestManagerFlushRefusalLogs(t *testing.T) {
	t.Parallel()

	// flowFault is a flow-store failure the manager's own sampler records
	// (logCallbackFailure), unlike ErrInvalidState, which is never logged.
	flowFault := errors.New("oidc_test: flow store fault fixture")

	type testCase struct {
		name  string
		build func(t *testing.T) (m *oidc.Manager, logs *bytes.Buffer)

		// afterFlush runs after FlushRefusalLogs, only for the row proving the
		// manager still works afterward; nil for every other row.
		afterFlush func(t *testing.T, m *oidc.Manager)

		assert func(t *testing.T, err error, logs string)
	}

	cases := []testCase{
		{
			name: "the manager's own pending count is reported",
			build: func(t *testing.T) (*oidc.Manager, *bytes.Buffer) {
				t.Helper()

				logs := &bytes.Buffer{}
				reg, err := oidc.NewRegistry(flushProvider())
				require.NoError(t, err)

				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidc.Flow{}, flowFault).Times(3)

				m, err := oidc.NewManager(reg, NewMockIdentityBroker(gomock.NewController(t)),
					oidc.WithFlowStore(flows), oidc.WithClock(flushFixedClock()), oidc.WithLogger(testTextLogger(logs)))
				require.NoError(t, err)

				for range 3 {
					_, err := m.Callback(t.Context(), "corp", "the-code", "the-state", "the-handle")
					require.Error(t, err)
				}

				return m, logs
			},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc refusals suppressed")
				require.Len(t, sums, 1, "three refusals of one reason must flush to exactly one summary record")
				assert.Equal(t, 2, sums[0], "the first refusal was already written; the flush owes the other two")
			},
		},
		{
			name: "a broker's pending count is reached through the manager",
			build: func(t *testing.T) (*oidc.Manager, *bytes.Buffer) {
				t.Helper()

				brokerLogs := &bytes.Buffer{}
				broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(gomock.NewController(t)),
					oidc.WithBrokerClock(flushFixedClock()), oidc.WithBrokerLogger(testTextLogger(brokerLogs)))
				require.NoError(t, err)

				ext := brokerCorpIdentity()
				for range 3 {
					_, err := broker.Broker(t.Context(), ext)
					require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				}

				reg, err := oidc.NewRegistry(flushProvider())
				require.NoError(t, err)
				m, err := oidc.NewManager(reg, broker)
				require.NoError(t, err)

				return m, brokerLogs
			},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc broker refusals suppressed")
				require.Len(t, sums, 1, "the manager must reach its broker's flush")
				assert.Equal(t, 2, sums[0])
			},
		},
		{
			name: "a consumer broker without a flush is skipped without error",
			build: func(t *testing.T) (*oidc.Manager, *bytes.Buffer) {
				t.Helper()

				reg, err := oidc.NewRegistry(flushProvider())
				require.NoError(t, err)

				m, err := oidc.NewManager(reg, NewMockIdentityBroker(gomock.NewController(t)))
				require.NoError(t, err)

				return m, &bytes.Buffer{}
			},
			assert: func(t *testing.T, err error, _ string) {
				require.NoError(t, err, "a broker with no flush of its own must not turn the manager's flush into an error")
			},
		},
		{
			name: "the manager still works after a flush",
			build: func(t *testing.T) (*oidc.Manager, *bytes.Buffer) {
				t.Helper()

				logs := &bytes.Buffer{}
				reg, err := oidc.NewRegistry(flushProvider())
				require.NoError(t, err)

				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidc.Flow{}, flowFault).Times(4)

				m, err := oidc.NewManager(reg, NewMockIdentityBroker(gomock.NewController(t)),
					oidc.WithFlowStore(flows), oidc.WithClock(flushFixedClock()), oidc.WithLogger(testTextLogger(logs)))
				require.NoError(t, err)

				for range 3 {
					_, err := m.Callback(t.Context(), "corp", "the-code", "the-state", "the-handle")
					require.Error(t, err)
				}

				return m, logs
			},
			afterFlush: func(t *testing.T, m *oidc.Manager) {
				t.Helper()

				// One more callback failure of the same reason, after the
				// flush, must be written again rather than counted as still
				// suppressed.
				_, err := m.Callback(t.Context(), "corp", "the-code", "the-state", "the-handle")
				require.Error(t, err)
			},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc refusals suppressed")
				require.Len(t, sums, 1)
				assert.Equal(t, 2, sums[0])

				assert.Equal(t, 2, strings.Count(logs, `msg="oidc callback failed"`),
					"the refusal after the flush must be written again, not suppressed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, logs := tc.build(t)
			err := m.FlushRefusalLogs()

			if tc.afterFlush != nil {
				tc.afterFlush(t, m)
			}

			tc.assert(t, err, logs.String())
		})
	}
}
