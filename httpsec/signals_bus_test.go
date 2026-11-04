package httpsec_test

// The rows of TestSessionSignals_BusOutage differ in their whole setup (a real logout, a fake
// clock, a synctest bubble), so each row runs its own scenario.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/session"
)

// busHealthyAfter is how long a subscription stays up for its backoff to start over.
const busHealthyAfter = 30 * time.Second

// busLogs is a log sink a test can read while the hub's goroutines write to it.
type busLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *busLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.buf.Write(p)
}

func (l *busLogs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.buf.String()
}

func (l *busLogs) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// busHub is a hub under test, closed when the test ends.
type busHub struct {
	*httpsec.SignalHubProbe

	clk  *clockwork.FakeClock
	logs *busLogs
}

// newBusHub builds a hub on a fake clock, with a sampler of one record a minute. setup's
// clock, log and sampler are filled when not set, and a queue or timeout of zero means 8
// and a minute.
func newBusHub(t *testing.T, setup httpsec.SignalHubSetup) *busHub {
	t.Helper()

	h := &busHub{clk: clockwork.NewFakeClockAt(endedAt), logs: &busLogs{}}

	if setup.Clock == nil {
		setup.Clock = h.clk
	}

	if setup.Log == nil {
		setup.Log = h.logs.logger()
	}

	if setup.Sampler == nil {
		setup.Sampler = logsample.New(time.Minute)
	}

	if setup.Queue == 0 {
		setup.Queue = 8
	}

	if setup.Timeout == 0 {
		setup.Timeout = time.Minute
	}

	h.SignalHubProbe = httpsec.NewSignalHubProbe(setup)
	t.Cleanup(h.Close)

	return h
}

// admit registers a stream and releases it when the test ends.
func (h *busHub) admit(t *testing.T, spec httpsec.RegistryStream) *httpsec.SignalStreamProbe {
	t.Helper()

	stream := httpsec.NewRegistryStream(spec)
	release, err := h.Registry().Admit(stream)
	require.NoError(t, err)
	t.Cleanup(release)

	return stream
}

// waitBus waits for a value on ch, and fails the test if none comes.
func waitBus[T any](t *testing.T, ch <-chan T) T {
	t.Helper()

	select {
	case v := <-ch:
		return v
	case <-time.After(signalsTestBound):
		require.FailNow(t, "what the bus should have done did not happen")

		panic("unreachable")
	}
}

// subscribeBlocks makes bus's subscription stay up until its context ends.
func subscribeBlocks(bus *MockSignalBus) {
	bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ func(httpsec.SignalEnvelope)) error {
			<-ctx.Done()

			return ctx.Err()
		}).AnyTimes()
}

// endEnvelope is what a report raises.
func endEnvelope(t *testing.T, r session.EndReport) httpsec.SignalEnvelope {
	t.Helper()

	e, ok := httpsec.EnvelopeForEnd(r)
	require.True(t, ok)

	return e
}

// loopBus makes bus hand what is published back to the subscription, as a shared bus hands
// it to every replica, and tell delivered once it has.
func loopBus(bus *MockSignalBus, delivered chan<- struct{}) {
	subscribed := make(chan func(httpsec.SignalEnvelope), 1)

	bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, deliver func(httpsec.SignalEnvelope)) error {
			subscribed <- deliver
			<-ctx.Done()

			return ctx.Err()
		}).AnyTimes()

	var deliver func(httpsec.SignalEnvelope)

	bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, e httpsec.SignalEnvelope) error {
			if deliver == nil {
				select {
				case deliver = <-subscribed:
				case <-ctx.Done():
					return ctx.Err()
				}
			}

			deliver(e)
			delivered <- struct{}{}

			return nil
		}).AnyTimes()
}

func TestSessionSignals_BusRouting(t *testing.T) {
	t.Parallel()

	const (
		issuer   = "https://issuer.example"
		sid      = "raw-upstream-session"
		appData  = `{"unchanged":  true}`
		credData = `{"kind":"password"}`
	)

	familyNoStream := id.MustParse("01963b5e-0000-7000-8000-00000000f00d")
	digest := httpsec.UpstreamDigest(issuer, sid)
	library := []httpsec.Signal{httpsec.SignalCredentialChanged}

	streams := map[string]httpsec.RegistryStream{
		"one-a": {User: "u-1", Family: familyOne, Upstream: digest, Library: library},
		"one-b": {User: "u-1", Family: familyOne, Library: library},
		"two":   {User: "u-1", Family: familyTwo, Library: library},
		"other": {User: "u-2", Family: familyThree, Library: library},
	}

	// got is what one envelope left on the streams, by the stream's name.
	type got struct {
		woken     []string
		notices   map[string]string
		reuses    map[string]string
		noticedAt map[string]time.Time
		queued    map[string][]httpsec.QueuedSignalView
	}

	type testCase struct {
		name   string
		env    httpsec.SignalEnvelope
		assert func(t *testing.T, g got)
	}

	sameReason := func(t *testing.T, g got, reason string, names ...string) {
		t.Helper()

		assert.ElementsMatch(t, names, g.woken)
		assert.Empty(t, g.queued, "session_ended must never reach a stream's queue")

		for _, name := range names {
			assert.Equal(t, reason, g.notices[name], name)
			assert.Equal(t, endedAt, g.noticedAt[name], "a notice is stamped with this replica's receipt")
		}
	}

	cases := []testCase{
		{
			name: "a logout names user and family, and reaches that family's streams only",
			env:  endEnvelope(t, session.EndReport{Cause: session.EndLogout, User: "u-1", Family: familyOne}),
			assert: func(t *testing.T, g got) {
				sameReason(t, g, "logout", "one-a", "one-b")
			},
		},
		{
			name: "a family-only report reaches its family",
			env:  endEnvelope(t, session.EndReport{Cause: session.EndFamilyRevoked, Family: familyTwo}),
			assert: func(t *testing.T, g got) {
				sameReason(t, g, "ended", "two")
			},
		},
		{
			name: "a user and a family with no stream reach no other stream of the user",
			env:  endEnvelope(t, session.EndReport{Cause: session.EndLogout, User: "u-1", Family: familyNoStream}),
			assert: func(t *testing.T, g got) {
				assert.Empty(t, g.woken)
			},
		},
		{
			name: "a user-wide report with no kept family wakes all the user's streams",
			env:  endEnvelope(t, session.EndReport{Cause: session.EndUserSessions, User: "u-1"}),
			assert: func(t *testing.T, g got) {
				sameReason(t, g, "all_ended", "one-a", "one-b", "two")
			},
		},
		{
			name: "a user-wide report spares its kept family",
			env: endEnvelope(t, session.EndReport{
				Cause: session.EndUserSessionsExcept, User: "u-1", KeptFamily: familyTwo,
			}),
			assert: func(t *testing.T, g got) {
				sameReason(t, g, "all_ended", "one-a", "one-b")
			},
		},
		{
			name: "an upstream session's report reaches the streams holding its digest",
			env: endEnvelope(t, session.EndReport{
				Cause: session.EndExternalSession, ExternalIssuer: issuer, ExternalSessionID: sid,
			}),
			assert: func(t *testing.T, g got) {
				sameReason(t, g, "provider_logout", "one-a")
			},
		},
		{
			name: "an issuer's report for a user names no digest, and reaches the user",
			env: endEnvelope(t, session.EndReport{
				Cause: session.EndUserExternalIssuer, User: "u-2", ExternalIssuer: issuer,
			}),
			assert: func(t *testing.T, g got) {
				sameReason(t, g, "provider_logout", "other")
			},
		},
		{
			name: "a family outranks a digest that came with it",
			env: httpsec.SignalEnvelope{
				Name: string(httpsec.SignalSessionEnded), Family: familyTwo, Upstream: digest, Reason: "ended",
			},
			assert: func(t *testing.T, g got) {
				sameReason(t, g, "ended", "two")
			},
		},
		{
			name: "reuse is kept apart from every other reason",
			env:  endEnvelope(t, session.EndReport{Cause: session.EndReuse, User: "u-1", Family: familyTwo}),
			assert: func(t *testing.T, g got) {
				assert.Equal(t, []string{"two"}, g.woken)
				assert.Equal(t, "reuse", g.reuses["two"])
				assert.Empty(t, g.notices["two"])
			},
		},
		{
			name: "an end naming no one reaches no stream",
			env:  httpsec.SignalEnvelope{Name: string(httpsec.SignalSessionEnded), Reason: "logout"},
			assert: func(t *testing.T, g got) {
				assert.Empty(t, g.woken)
				assert.Empty(t, g.queued)
			},
		},
		{
			name: "a credential change reaches only its user's streams, unchanged",
			env: httpsec.SignalEnvelope{
				User: "u-1", Name: string(httpsec.SignalCredentialChanged), Data: json.RawMessage(credData),
			},
			assert: func(t *testing.T, g got) {
				assert.Empty(t, g.woken)

				want := []httpsec.QueuedSignalView{{Name: string(httpsec.SignalCredentialChanged), Data: credData}}
				assert.Equal(t, map[string][]httpsec.QueuedSignalView{"one-a": want, "one-b": want, "two": want}, g.queued)
			},
		},
		{
			name: "a consumer's signal reaches only its user's streams, unchanged",
			env:  httpsec.SignalEnvelope{User: "u-2", Name: "app.billing", Data: json.RawMessage(appData)},
			assert: func(t *testing.T, g got) {
				assert.Empty(t, g.woken)
				assert.Equal(t, map[string][]httpsec.QueuedSignalView{
					"other": {{Name: "app.billing", Data: appData}},
				}, g.queued)
			},
		},
		{
			name: "a consumer's signal to no user reaches no stream",
			env:  httpsec.SignalEnvelope{Name: "app.billing", Data: json.RawMessage(appData)},
			assert: func(t *testing.T, g got) {
				assert.Empty(t, g.queued)
			},
		},
	}

	// send is one way an envelope gets to the registry, each with a hub of its own.
	type send struct {
		name string
		hub  func(t *testing.T) (*busHub, func(t *testing.T, h *busHub, e httpsec.SignalEnvelope))
	}

	sends := []send{
		{
			name: "deliver",
			hub: func(t *testing.T) (*busHub, func(*testing.T, *busHub, httpsec.SignalEnvelope)) {
				return newBusHub(t, httpsec.SignalHubSetup{}),
					func(_ *testing.T, h *busHub, e httpsec.SignalEnvelope) { h.Deliver(e) }
			},
		},
		{
			name: "the default bus",
			hub: func(t *testing.T) (*busHub, func(*testing.T, *busHub, httpsec.SignalEnvelope)) {
				return newBusHub(t, httpsec.SignalHubSetup{}),
					func(t *testing.T, h *busHub, e httpsec.SignalEnvelope) { require.NoError(t, h.Raise(e)) }
			},
		},
		{
			name: "a consumer's bus",
			hub: func(t *testing.T) (*busHub, func(*testing.T, *busHub, httpsec.SignalEnvelope)) {
				bus := NewMockSignalBus(gomock.NewController(t))
				delivered := make(chan struct{}, 1)
				loopBus(bus, delivered)

				return newBusHub(t, httpsec.SignalHubSetup{Bus: bus}),
					func(t *testing.T, h *busHub, e httpsec.SignalEnvelope) {
						require.NoError(t, h.Raise(e))
						waitBus(t, delivered)
					}
			},
		},
	}

	for _, via := range sends {
		for _, tc := range cases {
			t.Run(via.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				h, raise := via.hub(t)

				probes := map[string]*httpsec.SignalStreamProbe{}
				for name, spec := range streams {
					probes[name] = h.admit(t, spec)
				}

				raise(t, h, tc.env)

				g := got{
					notices:   map[string]string{},
					reuses:    map[string]string{},
					noticedAt: map[string]time.Time{},
					queued:    map[string][]httpsec.QueuedSignalView{},
				}

				for name, probe := range probes {
					if probe.Woken() {
						g.woken = append(g.woken, name)
					}

					reason, at := probe.Notice()
					g.notices[name], g.noticedAt[name] = reason, at

					reused, _ := probe.Reuse()
					g.reuses[name] = reused

					if queued := probe.TakeQueued(); len(queued) > 0 {
						g.queued[name] = queued
					}
				}

				assert.NotContains(t, fmt.Sprintf("%+v", tc.env), sid, "an envelope carries no raw upstream session")
				tc.assert(t, g)
			})
		}
	}
}

func TestSessionSignals_BusUntrusted(t *testing.T) {
	t.Parallel()

	const (
		user   = "u-untrusted-identifier"
		marker = "marker-in-the-data"
	)

	name := string(httpsec.SignalCredentialChanged)
	oversized := func(fill int, wrap string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(wrap, strings.Repeat("x", fill)))
	}

	type testCase struct {
		name   string
		env    httpsec.SignalEnvelope
		assert func(t *testing.T, stream *httpsec.SignalStreamProbe, logs string, stats httpsec.SignalHubStats)
	}

	dropped := func(t *testing.T, stream *httpsec.SignalStreamProbe, logs string, stats httpsec.SignalHubStats) {
		t.Helper()

		assert.False(t, stream.Woken(), "a dropped envelope wakes nothing")
		assert.Empty(t, stream.TakeQueued(), "a dropped envelope queues nothing")
		assert.Contains(t, logs, "dropped", "a dropped envelope is logged")
		assert.NotContains(t, logs, user, "a drop's record holds no identifier")
		assert.NotContains(t, logs, marker, "a drop's record holds no data")
		assert.NotContains(t, logs, familyOne.String(), "a drop's record holds no identifier")
		assert.Zero(t, stats.Dropped, "only a signal lost to a full queue counts as a drop")
	}

	delivered := func(data string) func(*testing.T, *httpsec.SignalStreamProbe, string, httpsec.SignalHubStats) {
		return func(t *testing.T, stream *httpsec.SignalStreamProbe, logs string, _ httpsec.SignalHubStats) {
			t.Helper()

			queued := stream.TakeQueued()
			require.Len(t, queued, 1)
			assert.Equal(t, data, queued[0].Data)
			assert.Empty(t, logs)
		}
	}

	endWithReason := func(reason string) func(*testing.T, *httpsec.SignalStreamProbe, string, httpsec.SignalHubStats) {
		return func(t *testing.T, stream *httpsec.SignalStreamProbe, _ string, _ httpsec.SignalHubStats) {
			t.Helper()

			assert.True(t, stream.Woken(), "whatever its reason says, an end still wakes the stream")
			assert.Empty(t, stream.TakeQueued())

			kept, _ := stream.Notice()
			if reused, _ := stream.Reuse(); reused != "" {
				kept = reused
			}

			assert.Equal(t, reason, kept)
		}
	}

	cases := []testCase{
		{
			name:   "an unknown library name",
			env:    httpsec.SignalEnvelope{User: user, Name: "password_stolen", Data: json.RawMessage(`{"m":"` + marker + `"}`)},
			assert: dropped,
		},
		{
			name:   "no name at all",
			env:    httpsec.SignalEnvelope{User: user},
			assert: dropped,
		},
		{
			name:   "session_expiring, which only a stream's own timer raises",
			env:    httpsec.SignalEnvelope{User: user, Name: string(httpsec.SignalSessionExpiring), Data: json.RawMessage(`{"deadline":"idle"}`)},
			assert: dropped,
		},
		{
			name:   "assurance_lapsed, which only a stream's own timer raises",
			env:    httpsec.SignalEnvelope{User: user, Name: string(httpsec.SignalAssuranceLapsed), Data: json.RawMessage(`{}`)},
			assert: dropped,
		},
		{
			name:   "session, which only a stream sends",
			env:    httpsec.SignalEnvelope{User: user, Name: "session", Data: json.RawMessage(`{}`)},
			assert: dropped,
		},
		{
			name:   "a credential change with malformed data",
			env:    httpsec.SignalEnvelope{User: user, Name: name, Data: json.RawMessage(`{"kind":"password"`)},
			assert: dropped,
		},
		{
			name:   "a credential change with no data",
			env:    httpsec.SignalEnvelope{User: user, Name: name},
			assert: dropped,
		},
		{
			name:   "a credential change of an unknown kind",
			env:    httpsec.SignalEnvelope{User: user, Name: name, Data: json.RawMessage(`{"kind":"` + marker + `"}`)},
			assert: dropped,
		},
		{
			name:   "a credential change naming no kind",
			env:    httpsec.SignalEnvelope{User: user, Name: name, Data: json.RawMessage(`null`)},
			assert: dropped,
		},
		{
			name:   "a credential change of the wrong shape",
			env:    httpsec.SignalEnvelope{User: user, Name: name, Data: json.RawMessage(`{"kind":7}`)},
			assert: dropped,
		},
		{
			name:   "a credential change of 9 KiB",
			env:    httpsec.SignalEnvelope{User: user, Name: name, Data: oversized(9<<10, `{"kind":"password","pad":"%s"}`)},
			assert: dropped,
		},
		{
			name:   "a consumer's signal of 9 KiB",
			env:    httpsec.SignalEnvelope{User: user, Name: "app.big", Data: oversized(9<<10, `{"pad":"%s"}`)},
			assert: dropped,
		},
		{
			name:   "app.X, an upper-case consumer name",
			env:    httpsec.SignalEnvelope{User: user, Name: "app.X", Data: json.RawMessage(`{"m":"` + marker + `"}`)},
			assert: dropped,
		},
		{
			name:   "a consumer's name holding a line break",
			env:    httpsec.SignalEnvelope{User: user, Name: "app.x\ndata: forged", Data: json.RawMessage(`{}`)},
			assert: dropped,
		},
		{
			name:   "a consumer's signal with raw newlines between its tokens",
			env:    httpsec.SignalEnvelope{User: user, Name: "app.lines", Data: json.RawMessage("{\n\"m\": \"" + marker + "\"\n}")},
			assert: dropped,
		},
		{
			name:   "a consumer's signal with malformed data",
			env:    httpsec.SignalEnvelope{User: user, Name: "app.bad", Data: json.RawMessage(`{"m":`)},
			assert: dropped,
		},
		{
			name:   "a consumer's signal with no data",
			env:    httpsec.SignalEnvelope{User: user, Name: "app.none"},
			assert: dropped,
		},
		{
			name:   "a consumer's signal of exactly 8 KiB",
			env:    httpsec.SignalEnvelope{User: user, Name: "app.big", Data: oversized(8<<10-len(`""`), `"%s"`)},
			assert: delivered(`"` + strings.Repeat("x", 8<<10-len(`""`)) + `"`),
		},
		{
			name:   "a credential change keeps only its kind",
			env:    httpsec.SignalEnvelope{User: user, Name: name, Data: json.RawMessage(`{"kind":"passkey","injected":"` + marker + `"}`)},
			assert: delivered(`{"kind":"passkey"}`),
		},
		{
			name:   "second_factor is a known kind",
			env:    httpsec.SignalEnvelope{User: user, Name: name, Data: json.RawMessage(`{"kind":"second_factor"}`)},
			assert: delivered(`{"kind":"second_factor"}`),
		},
		{
			name:   "a forged reason is not kept, and the end still wakes",
			env:    httpsec.SignalEnvelope{Family: familyOne, Name: string(httpsec.SignalSessionEnded), Reason: "your account was " + marker},
			assert: endWithReason(""),
		},
		{
			name:   "expired is not kept, since a stream decides that locally",
			env:    httpsec.SignalEnvelope{Family: familyOne, Name: string(httpsec.SignalSessionEnded), Reason: "expired"},
			assert: endWithReason(""),
		},
		{
			name: "an end's data is ignored",
			env: httpsec.SignalEnvelope{
				Family: familyOne, Name: string(httpsec.SignalSessionEnded), Reason: "logout", Data: json.RawMessage(`{"m":"` + marker + `"}`),
			},
			assert: endWithReason("logout"),
		},
	}

	for _, reason := range []string{"logout", "ended", "reuse", "all_ended", "provider_logout"} {
		cases = append(cases, testCase{
			name:   "the known reason " + reason + " is kept",
			env:    httpsec.SignalEnvelope{Family: familyOne, Name: string(httpsec.SignalSessionEnded), Reason: reason},
			assert: endWithReason(reason),
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newBusHub(t, httpsec.SignalHubSetup{})
			stream := h.admit(t, httpsec.RegistryStream{
				User: user, Family: familyOne,
				Library: []httpsec.Signal{
					httpsec.SignalCredentialChanged, httpsec.SignalSessionExpiring, httpsec.SignalAssuranceLapsed,
				},
			})

			h.Deliver(tc.env)

			tc.assert(t, stream, h.logs.String(), h.Stats())
		})
	}

	t.Run("what is queued does not share a bus's buffer", func(t *testing.T) {
		t.Parallel()

		h := newBusHub(t, httpsec.SignalHubSetup{})
		stream := h.admit(t, httpsec.RegistryStream{User: user})

		buffer := []byte(`{"seen":"before"}`)
		h.Deliver(httpsec.SignalEnvelope{User: user, Name: "app.buffer", Data: buffer})
		copy(buffer, `{"seen":"AFTER!"}`)

		data := stream.TakeQueuedData()
		require.Len(t, data, 1)
		assert.JSONEq(t, `{"seen":"before"}`, string(data[0]))
	})

	t.Run("an unknown reason does not erase a kept one", func(t *testing.T) {
		t.Parallel()

		h := newBusHub(t, httpsec.SignalHubSetup{})
		stream := h.admit(t, httpsec.RegistryStream{User: user, Family: familyOne})
		name := string(httpsec.SignalSessionEnded)

		h.Deliver(httpsec.SignalEnvelope{Family: familyOne, Name: name, Reason: "logout"})
		h.Deliver(httpsec.SignalEnvelope{Family: familyOne, Name: name, Reason: "garbage"})

		reason, _ := stream.Notice()
		assert.Equal(t, "logout", reason)
		assert.True(t, stream.TakeWake())
	})

	t.Run("a stream's full queue is counted and logged with sampling", func(t *testing.T) {
		t.Parallel()

		h := newBusHub(t, httpsec.SignalHubSetup{})
		stream := h.admit(t, httpsec.RegistryStream{User: user})

		for range httpsec.StreamQueueSize + 3 {
			h.Deliver(httpsec.SignalEnvelope{User: user, Name: "app.full", Data: json.RawMessage(`{"m":"` + marker + `"}`)})
		}

		assert.Equal(t, httpsec.StreamQueueSize, stream.Queued())
		assert.Equal(t, uint64(3), h.Stats().StreamDropped)
		assert.Zero(t, h.Stats().Dropped, "a stream's own drop is no bus drop, and the default bus has no queue to overflow")

		logs := h.logs.String()
		assert.Equal(t, 1, strings.Count(logs, "\n"), "three drops within a window leave one record: %s", logs)
		assert.NotContains(t, logs, user)
		assert.NotContains(t, logs, marker)
	})
}

// busSecretPanic is what a bus panics with: its value must never reach a log.
type busSecretPanic struct{ Token string }

const busSecret = "s3cret-of-the-bus"

// panickyHandler is a consumer's slog handler that panics on every record.
type panickyHandler struct{ slog.Handler }

func (panickyHandler) Enabled(context.Context, slog.Level) bool { return true }

func (panickyHandler) Handle(context.Context, slog.Record) error { panic("the logger panicked") }

// panickyClock is a consumer's clock whose waits panic.
type panickyClock struct{ clock.Timed }

func (panickyClock) After(time.Duration) <-chan time.Time { panic("the clock panicked") }

// panickyNowClock is a consumer's clock whose every reading panics.
type panickyNowClock struct{ clock.Timed }

func (panickyNowClock) Now() time.Time { panic("the clock panicked") }

// panickyIsError is an error whose Is method panics.
type panickyIsError struct{}

func (panickyIsError) Error() string { return "the bus failed" }

func (panickyIsError) Is(error) bool { panic("the error's Is panicked") }

// busGoroutines counts this test's goroutines running the hub's code. They inherit the label
// the caller set on its own goroutine, so tests running beside it are not counted.
func busGoroutines(t *testing.T, label string) int {
	t.Helper()

	var profile bytes.Buffer

	require.NoError(t, pprof.Lookup("goroutine").WriteTo(&profile, 1))

	count := 0

	for block := range strings.SplitSeq(profile.String(), "\n\n") {
		if !strings.Contains(block, label) || !strings.Contains(block, "(*signalHub)") {
			continue
		}

		n, _, _ := strings.Cut(block, " @")

		// The profile's header shares the first block.
		n = n[strings.LastIndexByte(n, '\n')+1:]

		parsed, err := strconv.Atoi(n)
		require.NoError(t, err)

		count += parsed
	}

	return count
}

func TestSessionSignals_BusOutage(t *testing.T) {
	t.Parallel()

	type ctxKey struct{}

	envelope := func(user identity.UserID) httpsec.SignalEnvelope {
		return httpsec.SignalEnvelope{User: user, Name: "app.outage", Data: json.RawMessage(`{}`)}
	}

	busFixture := func(t *testing.T, bus httpsec.SignalBus, change func(*httpsec.SessionSignals), logs *busLogs) *signalsFixture {
		t.Helper()

		signals := httpsec.SessionSignals{Bus: bus}
		if change != nil {
			change(&signals)
		}

		f := newSignalsFixture(t, signalsSetup{
			signals: signals,
			opts: func(*signalsFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithLogger(logs.logger()),
					httpsec.WithRefusalLogInterval(time.Minute),
				}
			},
		})
		t.Cleanup(httpsec.SignalHubProbeOf(f.chain).Close)

		return f
	}

	t.Run("a failing Publish leaves a logout's outcome unchanged, and is logged with sampling", func(t *testing.T) {
		t.Parallel()

		bus := NewMockSignalBus(gomock.NewController(t))
		subscribeBlocks(bus)

		entered := make(chan struct{}, 8)
		bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
			func(context.Context, httpsec.SignalEnvelope) error {
				entered <- struct{}{}

				return errors.New("the broker said " + busSecret)
			}).AnyTimes()

		logs := &busLogs{}
		f := busFixture(t, bus, nil, logs)
		hub := httpsec.SignalHubProbeOf(f.chain)

		logout := func() {
			s := f.signIn(t, "u-1")

			ended, err := f.sessions.Logout(t.Context(), "u-1", s.FamilyID)
			require.NoError(t, err, "a failing bus must not fail the logout")
			assert.Equal(t, 1, ended, "the sign-in is ended whatever the bus does")

			_, err = f.store.Load(t.Context(), s.ID)
			require.Error(t, err, "the store no longer holds the sign-in")
		}

		// Publish is called from one goroutine, so when the third has begun the first two
		// have been counted and logged.
		logout()
		logout()
		logout()
		waitBus(t, entered)
		waitBus(t, entered)
		waitBus(t, entered)

		// The third may still be returning, so ask only what the first two settle.
		assert.GreaterOrEqual(t, hub.Stats().Failures, uint64(2))

		written := logs.String()
		assert.Equal(t, 1, strings.Count(written, "Publish failed"), "within a window, one record: %s", written)
		assert.NotContains(t, written, busSecret, "a bus's error text can quote a secret")
		assert.Contains(t, written, "errors.errorString")

		// A new window writes the next record, with what the last one held back.
		f.clk.Advance(2 * time.Minute)
		logout()
		waitBus(t, entered)
		logout()
		waitBus(t, entered)

		written = logs.String()
		assert.Equal(t, 2, strings.Count(written, "Publish failed"), "%s", written)
		assert.Contains(t, written, "suppressed=")
	})

	t.Run("a Publish that hangs does not hold up a logout", func(t *testing.T) {
		t.Parallel()

		bus := NewMockSignalBus(gomock.NewController(t))
		subscribeBlocks(bus)

		entered := make(chan struct{}, 1)
		release := make(chan struct{})

		// It ignores its context too, which is the worst a bus can do.
		bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
			func(context.Context, httpsec.SignalEnvelope) error {
				entered <- struct{}{}
				<-release

				return nil
			}).AnyTimes()
		t.Cleanup(func() { close(release) })

		f := busFixture(t, bus, nil, &busLogs{})
		s := f.signIn(t, "u-1")

		requireReturns(t, func() {
			_, err := f.sessions.Logout(t.Context(), "u-1", s.FamilyID)
			assert.NoError(t, err)
		})

		waitBus(t, entered)

		// A second logout while the bus still hangs is no slower.
		second := f.signIn(t, "u-1")
		requireReturns(t, func() {
			_, err := f.sessions.Logout(t.Context(), "u-1", second.FamilyID)
			assert.NoError(t, err)
		})

		// Nor does the bus hold a shutdown.
		requireReturns(t, httpsec.SignalHubProbeOf(f.chain).Close)
	})

	t.Run("a Publish that hangs is abandoned after the timeout", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name    string
			change  func(*httpsec.SessionSignals)
			timeout time.Duration
			assert  func(t *testing.T, took time.Duration, stats httpsec.SignalHubStats, err error)
		}

		cases := []testCase{
			{
				name:    "the default is 5 seconds",
				timeout: 5 * time.Second,
				assert: func(t *testing.T, took time.Duration, stats httpsec.SignalHubStats, err error) {
					assert.Equal(t, 5*time.Second, took)
					assert.Equal(t, uint64(1), stats.Failures)
					assert.ErrorIs(t, err, context.DeadlineExceeded)
				},
			},
			{
				name:    "a consumer's BusTimeout is used",
				change:  func(s *httpsec.SessionSignals) { s.BusTimeout = 1500 * time.Millisecond },
				timeout: 1500 * time.Millisecond,
				assert: func(t *testing.T, took time.Duration, stats httpsec.SignalHubStats, err error) {
					assert.Equal(t, 1500*time.Millisecond, took)
					assert.Equal(t, uint64(1), stats.Failures)
					assert.ErrorIs(t, err, context.DeadlineExceeded)
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				// What the chain settled on is what the hub holds.
				settled := NewMockSignalBus(gomock.NewController(t))
				f := busFixture(t, settled, tc.change, &busLogs{})
				queue, timeout := httpsec.SignalHubProbeOf(f.chain).Settings()
				require.Equal(t, tc.timeout, timeout)
				require.Equal(t, 1024, queue)

				synctest.Test(t, func(t *testing.T) {
					bus := NewMockSignalBus(gomock.NewController(t))
					subscribeBlocks(bus)

					var (
						took   time.Duration
						hung   error
						second = make(chan struct{})
						first  = true
					)

					bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
						func(ctx context.Context, _ httpsec.SignalEnvelope) error {
							if !first {
								close(second)

								return nil
							}

							first = false
							began := time.Now()
							<-ctx.Done()
							took, hung = time.Since(began), ctx.Err()

							return ctx.Err()
						}).Times(2)

					h := newBusHub(t, httpsec.SignalHubSetup{Bus: bus, Timeout: timeout, Clock: clock.System()})
					require.NoError(t, h.Raise(envelope("u-1")))
					require.NoError(t, h.Raise(envelope("u-1")))

					// The second call shows the publisher went on to the next envelope.
					<-second
					tc.assert(t, took, h.Stats(), hung)
				})
			})
		}
	})

	t.Run("a full queue drops with a sampled log and a counted drop, on a consumer's BusQueue", func(t *testing.T) {
		t.Parallel()

		bus := NewMockSignalBus(gomock.NewController(t))
		subscribeBlocks(bus)

		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
			func(context.Context, httpsec.SignalEnvelope) error {
				entered <- struct{}{}
				<-release

				return nil
			}).AnyTimes()
		t.Cleanup(func() { close(release) })

		logs := &busLogs{}
		f := busFixture(t, bus, func(s *httpsec.SessionSignals) { s.BusQueue = 2 }, logs)
		hub := httpsec.SignalHubProbeOf(f.chain)

		// One is taken by the publisher and hangs, and two then fill the queue.
		require.NoError(t, hub.Raise(envelope("u-marker")))
		waitBus(t, entered)
		require.NoError(t, hub.Raise(envelope("u-marker")))
		require.NoError(t, hub.Raise(envelope("u-marker")))

		require.ErrorIs(t, hub.Raise(envelope("u-marker")), httpsec.ErrSignalsBusy)
		require.ErrorIs(t, hub.Raise(envelope("u-marker")), httpsec.ErrSignalsBusy)
		require.ErrorIs(t, hub.Raise(envelope("u-marker")), httpsec.ErrSignalsBusy)
		assert.Equal(t, uint64(3), hub.Stats().Dropped)

		written := logs.String()
		assert.Equal(t, 1, strings.Count(written, "queue is full"), "%s", written)
		assert.NotContains(t, written, "u-marker")

		f.clk.Advance(2 * time.Minute)
		require.ErrorIs(t, hub.Raise(envelope("u-marker")), httpsec.ErrSignalsBusy)
		assert.Contains(t, logs.String(), "suppressed=2")

		// An end report that is dropped says nothing to the logout.
		s := f.signIn(t, "u-1")
		_, err := f.sessions.Logout(t.Context(), "u-1", s.FamilyID)
		require.NoError(t, err)
		assert.Equal(t, uint64(5), hub.Stats().Dropped)
	})

	t.Run("Publish receives none of the request's values, nor its cancellation", func(t *testing.T) {
		t.Parallel()

		bus := NewMockSignalBus(gomock.NewController(t))
		subscribeBlocks(bus)

		type seen struct {
			value       any
			alive       error
			hasDeadline bool
		}

		saw := make(chan seen, 1)
		cancelled := make(chan struct{})

		bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, _ httpsec.SignalEnvelope) error {
				<-cancelled

				_, hasDeadline := ctx.Deadline()
				saw <- seen{value: ctx.Value(ctxKey{}), alive: ctx.Err(), hasDeadline: hasDeadline}

				return nil
			}).AnyTimes()

		// The observer beside the hub shows what the hub's own context held.
		observed := make(chan any, 1)

		signals := httpsec.SessionSignals{Bus: bus}
		f := newSignalsFixture(t, signalsSetup{
			signals: signals,
			sessionOpts: []session.Option{session.WithEndObserver(session.EndObserverFunc(
				func(ctx context.Context, _ session.EndReport) { observed <- ctx.Value(ctxKey{}) },
			))},
		})
		t.Cleanup(httpsec.SignalHubProbeOf(f.chain).Close)

		s := f.signIn(t, "u-1")

		ctx, cancel := context.WithCancel(context.WithValue(t.Context(), ctxKey{}, "the request's value"))
		defer cancel()

		_, err := f.sessions.Logout(ctx, "u-1", s.FamilyID)
		require.NoError(t, err)
		require.Equal(t, "the request's value", waitBus(t, observed), "the report's context does hold it")

		cancel()
		close(cancelled)

		got := waitBus(t, saw)
		assert.Nil(t, got.value, "Publish's context holds none of the request's values")
		assert.NoError(t, got.alive, "a request that ended does not end its signal's Publish")
		assert.True(t, got.hasDeadline, "every Publish has a timeout")
	})

	t.Run("a bus's failures are retried with backoff", func(t *testing.T) {
		t.Parallel()

		delays := []time.Duration{
			time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
			30 * time.Second, 30 * time.Second,
		}

		// stepThrough waits for each attempt, and shows the next comes at its delay and no
		// sooner: at a nanosecond before it, the wait is still on the clock.
		stepThrough := func(t *testing.T, clk *clockwork.FakeClock, attempts <-chan struct{}) {
			t.Helper()

			ctx, cancel := context.WithTimeout(t.Context(), signalsTestBound)
			defer cancel()

			for _, delay := range delays {
				require.NoError(t, clk.BlockUntilContext(ctx, 1))
				clk.Advance(delay - time.Nanosecond)
				require.NoError(t, clk.BlockUntilContext(ctx, 1), "the retry came before %s", delay)
				require.Empty(t, attempts, "the retry came before %s", delay)
				clk.Advance(time.Nanosecond)
				waitBus(t, attempts)
			}
		}

		type testCase struct {
			name   string
			fail   func() error
			assert func(t *testing.T, h *busHub)
		}

		cases := []testCase{
			{
				name: "a failing Subscribe",
				fail: func() error { return errors.New("the broker said " + busSecret) },
				assert: func(t *testing.T, h *busHub) {
					assert.Contains(t, h.logs.String(), "Subscribe failed")
					assert.NotContains(t, h.logs.String(), busSecret)
				},
			},
			{
				name: "a Subscribe returning early with no error",
				fail: func() error { return nil },
				assert: func(t *testing.T, h *busHub) {
					assert.Contains(t, h.logs.String(), "Subscribe returned early")
				},
			},
			{
				name: "a Subscribe that panics",
				fail: func() error { panic(busSecretPanic{Token: busSecret}) },
				assert: func(t *testing.T, h *busHub) {
					logs := h.logs.String()
					assert.Contains(t, logs, "busSecretPanic", "the record names the value's type")
					assert.Contains(t, logs, "phase=bus")
					assert.Contains(t, logs, "signals_bus_test.go:", "the record names the frames")
					assert.NotContains(t, logs, busSecret, "the record never holds the value")
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				bus := NewMockSignalBus(gomock.NewController(t))
				attempts := make(chan struct{}, 16)

				bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).DoAndReturn(
					func(context.Context, func(httpsec.SignalEnvelope)) error {
						attempts <- struct{}{}

						return tc.fail()
					}).AnyTimes()

				h := newBusHub(t, httpsec.SignalHubSetup{Bus: bus})
				h.Start()
				waitBus(t, attempts)

				stepThrough(t, h.clk, attempts)

				tc.assert(t, h)
			})
		}

		t.Run("a Publish that panics, and goes on to the next envelope after each delay", func(t *testing.T) {
			t.Parallel()

			bus := NewMockSignalBus(gomock.NewController(t))
			subscribeBlocks(bus)

			attempts := make(chan struct{}, 16)
			var healed sync.Mutex

			panics := true
			bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
				func(context.Context, httpsec.SignalEnvelope) error {
					healed.Lock()
					defer healed.Unlock()

					attempts <- struct{}{}

					if panics {
						panic(busSecretPanic{Token: busSecret})
					}

					return nil
				}).AnyTimes()

			h := newBusHub(t, httpsec.SignalHubSetup{Bus: bus, Queue: 32})

			for range len(delays) + 3 {
				require.NoError(t, h.Raise(envelope("u-1")))
			}

			waitBus(t, attempts)
			stepThrough(t, h.clk, attempts)

			logs := h.logs.String()
			assert.Contains(t, logs, "busSecretPanic")
			assert.Contains(t, logs, "phase=bus")
			assert.Contains(t, logs, "signals_bus_test.go:")
			assert.NotContains(t, logs, busSecret)
			assert.GreaterOrEqual(t, h.Stats().Failures, uint64(len(delays)), "a panicking Publish is a failed one")

			// One that returns starts the backoff over: the panic after it waits 1 second.
			healed.Lock()
			panics = false
			healed.Unlock()

			ctx, cancel := context.WithTimeout(t.Context(), signalsTestBound)
			defer cancel()

			require.NoError(t, h.clk.BlockUntilContext(ctx, 1))
			h.clk.Advance(30 * time.Second)
			waitBus(t, attempts)
			waitBus(t, attempts) // The next goes straight on, with no wait.

			healed.Lock()
			panics = true
			healed.Unlock()

			require.NoError(t, h.Raise(envelope("u-1")))
			waitBus(t, attempts)

			require.NoError(t, h.Raise(envelope("u-1")))
			require.NoError(t, h.clk.BlockUntilContext(ctx, 1))
			h.clk.Advance(time.Second)
			waitBus(t, attempts)
		})
	})

	t.Run("the backoff starts over after a healthy subscription", func(t *testing.T) {
		t.Parallel()

		// A row's assertion is the retry it steps through, so it states when the next one
		// comes rather than a value it compares.
		type testCase struct {
			name string
			up   time.Duration
			next time.Duration
		}

		cases := []testCase{
			{name: "up as long as counts as healthy", up: busHealthyAfter, next: time.Second},
			{name: "up for less keeps backing off", up: busHealthyAfter - time.Nanosecond, next: 8 * time.Second},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				bus := NewMockSignalBus(gomock.NewController(t))
				attempts := make(chan struct{}, 8)
				finish := make(chan struct{})

				var calls int

				bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).DoAndReturn(
					func(context.Context, func(httpsec.SignalEnvelope)) error {
						calls++
						attempts <- struct{}{}

						// The fourth attempt stays up until the test ends it.
						if calls == 4 {
							<-finish
						}

						return errors.New("the bus failed")
					}).AnyTimes()

				h := newBusHub(t, httpsec.SignalHubSetup{Bus: bus})
				h.Start()
				waitBus(t, attempts)

				ctx, cancel := context.WithTimeout(t.Context(), signalsTestBound)
				defer cancel()

				for _, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
					require.NoError(t, h.clk.BlockUntilContext(ctx, 1))
					h.clk.Advance(delay)
					waitBus(t, attempts)
				}

				require.True(t, h.Stats().Subscribed, "a subscription is reported while it runs")

				h.clk.Advance(tc.up)
				close(finish)

				require.NoError(t, h.clk.BlockUntilContext(ctx, 1))
				assert.False(t, h.Stats().Subscribed, "none is running during a backoff")

				h.clk.Advance(tc.next - time.Nanosecond)
				require.NoError(t, h.clk.BlockUntilContext(ctx, 1), "the retry came before %s", tc.next)
				require.Empty(t, attempts, "the retry came before %s", tc.next)
				h.clk.Advance(time.Nanosecond)
				waitBus(t, attempts)
			})
		}
	})

	t.Run("deliver and raise are safe concurrently, and do nothing after close", func(t *testing.T) {
		t.Parallel()

		bus := NewMockSignalBus(gomock.NewController(t))
		subscribeBlocks(bus)
		bus.EXPECT().Publish(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		h := newBusHub(t, httpsec.SignalHubSetup{Bus: bus, Queue: 4})
		stream := h.admit(t, httpsec.RegistryStream{User: "u-1", Family: familyOne})

		const workers = 16

		var wg sync.WaitGroup

		begin := make(chan struct{})

		for i := range workers {
			wg.Go(func() {
				<-begin

				for range 50 {
					h.Deliver(httpsec.SignalEnvelope{Family: familyOne, Name: string(httpsec.SignalSessionEnded), Reason: "ended"})
					h.Deliver(httpsec.SignalEnvelope{User: "u-1", Name: "app.load", Data: json.RawMessage(`{}`)})
					_ = h.Raise(envelope("u-1"))
					h.Start()
					_ = h.Stats()

					// Half close partway through, so that close races all of the above.
					if i%2 == 0 {
						h.Close()
					}
				}
			})
		}

		close(begin)
		requireReturns(t, wg.Wait)

		stream.TakeWake()
		stream.TakeQueued()

		before := h.Stats()

		h.Deliver(httpsec.SignalEnvelope{Family: familyOne, Name: string(httpsec.SignalSessionEnded), Reason: "ended"})
		h.Deliver(httpsec.SignalEnvelope{User: "u-1", Name: "app.late", Data: json.RawMessage(`{}`)})

		assert.False(t, stream.Woken(), "deliver does nothing after a close")
		assert.Empty(t, stream.TakeQueued(), "deliver does nothing after a close")

		require.ErrorIs(t, h.Raise(envelope("u-1")), httpsec.ErrSignalsBusy, "a signal raised after close was not sent")
		assert.Equal(t, before.Dropped, h.Stats().Dropped, "that is no drop of the bus's")
	})

	t.Run("a close cuts a Publish short, publishes nothing more, and counts no failure", func(t *testing.T) {
		t.Parallel()

		// A select over the closed context and the queue picks either at random, so one run
		// shows a missing recheck only half the time. Sixteen show it all but always.
		for range 16 {
			synctest.Test(t, func(t *testing.T) {
				bus := NewMockSignalBus(gomock.NewController(t))
				subscribeBlocks(bus)

				// Times(1) fails the test if what was queued is published after the close.
				bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, _ httpsec.SignalEnvelope) error {
						<-ctx.Done()

						return ctx.Err()
					}).Times(1)

				h := newBusHub(t, httpsec.SignalHubSetup{Bus: bus, Timeout: time.Hour, Clock: clock.System()})

				for range 4 {
					require.NoError(t, h.Raise(envelope("u-1")))
				}

				synctest.Wait()
				h.Close()
				synctest.Wait()

				assert.Zero(t, h.Stats().Failures)
				assert.False(t, h.Stats().Subscribed)
			})
		}
	})

	t.Run("after a close nothing reaches a consumer's bus", func(t *testing.T) {
		t.Parallel()

		// With no expectations, any call fails the test.
		bus := NewMockSignalBus(gomock.NewController(t))

		h := newBusHub(t, httpsec.SignalHubSetup{Bus: bus})
		h.Close()
		h.Close()
		h.Start()

		require.ErrorIs(t, h.Raise(envelope("u-1")), httpsec.ErrSignalsBusy)
		assert.Equal(t, httpsec.SignalHubStats{}, h.Stats())
	})

	t.Run("after a close the default bus reaches nothing", func(t *testing.T) {
		t.Parallel()

		h := newBusHub(t, httpsec.SignalHubSetup{})
		stream := h.admit(t, httpsec.RegistryStream{User: "u-1"})
		h.Close()

		require.ErrorIs(t, h.Raise(envelope("u-1")), httpsec.ErrSignalsBusy)
		assert.Empty(t, stream.TakeQueued())
	})

	t.Run("no goroutine runs before first use, or after close", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name   string
			act    func(h *httpsec.SignalHubProbe)
			bus    bool
			assert func(t *testing.T, running func() int, h *httpsec.SignalHubProbe)
		}

		settled := func(t *testing.T, running func() int, h *httpsec.SignalHubProbe) {
			t.Helper()

			assert.Equal(t, 2, running(), "the publisher and the subscription")

			h.Close()
			synctest.Wait()
			assert.Zero(t, running(), "close ends them")
		}

		cases := []testCase{
			{
				name: "a consumer's bus never used runs none",
				bus:  true,
				act:  func(*httpsec.SignalHubProbe) {},
				assert: func(t *testing.T, running func() int, _ *httpsec.SignalHubProbe) {
					assert.Zero(t, running())
				},
			},
			{
				name:   "start runs them",
				bus:    true,
				act:    func(h *httpsec.SignalHubProbe) { h.Start() },
				assert: settled,
			},
			{
				name: "a second start and a raise run no more",
				bus:  true,
				act: func(h *httpsec.SignalHubProbe) {
					h.Start()
					h.Start()
					_ = h.Raise(envelope("u-1"))
				},
				assert: settled,
			},
			{
				name:   "a raise starts them",
				bus:    true,
				act:    func(h *httpsec.SignalHubProbe) { _ = h.Raise(envelope("u-1")) },
				assert: settled,
			},
			{
				name: "a start after a close runs none",
				bus:  true,
				act: func(h *httpsec.SignalHubProbe) {
					h.Close()
					h.Start()
				},
				assert: func(t *testing.T, running func() int, _ *httpsec.SignalHubProbe) {
					assert.Zero(t, running())
				},
			},
			{
				name: "the default bus runs none",
				act: func(h *httpsec.SignalHubProbe) {
					h.Start()
					_ = h.Raise(envelope("u-1"))
				},
				assert: func(t *testing.T, running func() int, _ *httpsec.SignalHubProbe) {
					assert.Zero(t, running())
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				synctest.Test(t, func(t *testing.T) {
					label := "bus-goroutines-" + t.Name()
					pprof.SetGoroutineLabels(pprof.WithLabels(t.Context(), pprof.Labels("bus-test", label)))

					setup := httpsec.SignalHubSetup{Clock: clock.System()}

					if tc.bus {
						bus := NewMockSignalBus(gomock.NewController(t))
						subscribeBlocks(bus)
						bus.EXPECT().Publish(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
						setup.Bus = bus
					}

					h := newBusHub(t, setup)
					tc.act(h.SignalHubProbe)
					synctest.Wait()

					tc.assert(t, func() int { return busGoroutines(t, label) }, h.SignalHubProbe)

					h.Close()
					synctest.Wait()
				})
			})
		}
	})

	t.Run("a Publish error whose Is method panics leaves the publisher running", func(t *testing.T) {
		t.Parallel()

		bus := NewMockSignalBus(gomock.NewController(t))
		subscribeBlocks(bus)

		entered := make(chan struct{}, 2)

		bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
			func(context.Context, httpsec.SignalEnvelope) error {
				entered <- struct{}{}

				return panickyIsError{}
			}).Times(2)

		h := newBusHub(t, httpsec.SignalHubSetup{Bus: bus})

		require.NoError(t, h.Raise(envelope("u-1")))
		require.NoError(t, h.Raise(envelope("u-1")))
		waitBus(t, entered)
		waitBus(t, entered)

		// The count follows the second call's return, so it is awaited.
		require.Eventually(t, func() bool { return h.Stats().Failures == 2 }, signalsTestBound, time.Millisecond)
	})

	t.Run("a raised signal does not share the buffer its caller goes on using", func(t *testing.T) {
		t.Parallel()

		bus := NewMockSignalBus(gomock.NewController(t))
		subscribeBlocks(bus)

		entered, release, got := make(chan struct{}), make(chan struct{}), make(chan string, 1)
		first := true

		bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, e httpsec.SignalEnvelope) error {
				if first {
					first = false

					close(entered)
					<-release

					return nil
				}

				got <- string(e.Data)

				return nil
			}).AnyTimes()

		h := newBusHub(t, httpsec.SignalHubSetup{Bus: bus})

		require.NoError(t, h.Raise(httpsec.SignalEnvelope{User: "u", Name: "app.a", Data: json.RawMessage(`{}`)}))
		waitBus(t, entered)

		buffer := []byte(`{"seen":"before"}`)
		require.NoError(t, h.Raise(httpsec.SignalEnvelope{User: "u", Name: "app.b", Data: buffer}))
		copy(buffer, `{"seen":"AFTER!"}`)
		close(release)

		assert.JSONEq(t, `{"seen":"before"}`, waitBus(t, got))
	})

	t.Run("a deliver that panics writes a bounded number of records", func(t *testing.T) {
		t.Parallel()

		h := newBusHub(t, httpsec.SignalHubSetup{
			Clock: panickyNowClock{Timed: clockwork.NewFakeClockAt(endedAt)},
		})

		for range 1000 {
			h.Deliver(httpsec.SignalEnvelope{Family: familyOne, Name: string(httpsec.SignalSessionEnded)})
		}

		logs := h.logs.String()
		assert.Equal(t, 1, strings.Count(logs, "a panic was recovered"), "1000 envelopes within a window leave one record: %s", logs)
		assert.Contains(t, logs, "phase=bus")
	})

	t.Run("a start from many goroutines subscribes once", func(t *testing.T) {
		t.Parallel()

		bus := NewMockSignalBus(gomock.NewController(t))
		subscribed := make(chan struct{}, 64)

		bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, _ func(httpsec.SignalEnvelope)) error {
				subscribed <- struct{}{}
				<-ctx.Done()

				return ctx.Err()
			}).Times(1)

		h := newBusHub(t, httpsec.SignalHubSetup{Bus: bus})

		var wg sync.WaitGroup
		for range 32 {
			wg.Go(h.Start)
		}

		requireReturns(t, wg.Wait)
		waitBus(t, subscribed)
	})

	t.Run("with the default bus, a second chain's streams are not reached", func(t *testing.T) {
		t.Parallel()

		replicaA := newSignalsFixture(t, signalsSetup{signals: httpsec.SessionSignals{
			Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalCredentialChanged},
		}})
		replicaB := newSignalsFixture(t, signalsSetup{signals: httpsec.SessionSignals{
			Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalCredentialChanged},
		}})

		s := replicaA.signIn(t, "u-1")
		spec := httpsec.RegistryStream{
			User: "u-1", Family: s.FamilyID, Library: []httpsec.Signal{httpsec.SignalCredentialChanged},
		}

		hubA, hubB := httpsec.SignalHubProbeOf(replicaA.chain), httpsec.SignalHubProbeOf(replicaB.chain)

		onA, onB := httpsec.NewRegistryStream(spec), httpsec.NewRegistryStream(spec)

		releaseA, err := hubA.Registry().Admit(onA)
		require.NoError(t, err)
		t.Cleanup(releaseA)

		releaseB, err := hubB.Registry().Admit(onB)
		require.NoError(t, err)
		t.Cleanup(releaseB)

		require.NoError(t, hubA.Raise(httpsec.SignalEnvelope{
			User: "u-1", Name: string(httpsec.SignalCredentialChanged), Data: json.RawMessage(`{"kind":"password"}`),
		}))

		_, err = replicaA.sessions.Logout(t.Context(), "u-1", s.FamilyID)
		require.NoError(t, err)

		assert.Len(t, onA.TakeQueued(), 1, "the raising chain's own stream hears the signal")
		assert.True(t, onA.Woken(), "a real logout wakes the raising chain's own stream")
		assert.Empty(t, onB.TakeQueued(), "the other chain's stream does not")
		assert.False(t, onB.Woken(), "the other chain's stream does not")
	})

	t.Run("a consumer's logger or clock that panics does not end the process", func(t *testing.T) {
		t.Parallel()

		panicky := slog.New(panickyHandler{})

		type testCase struct {
			name   string
			setup  func(bus *MockSignalBus) httpsec.SignalHubSetup
			act    func(t *testing.T, h *busHub, bus *MockSignalBus)
			assert func(t *testing.T, h *busHub)
		}

		cases := []testCase{
			{
				name: "a dropped envelope's record, on a bus's own goroutine",
				setup: func(*MockSignalBus) httpsec.SignalHubSetup {
					return httpsec.SignalHubSetup{Log: panicky}
				},
				act: func(_ *testing.T, h *busHub, _ *MockSignalBus) {
					h.Deliver(httpsec.SignalEnvelope{Name: "nonsense"})
				},
				assert: func(*testing.T, *busHub) {},
			},
			{
				name: "a full queue's record, in a caller's transaction",
				setup: func(bus *MockSignalBus) httpsec.SignalHubSetup {
					subscribeBlocks(bus)

					return httpsec.SignalHubSetup{Bus: bus, Log: panicky, Queue: 1}
				},
				act: func(t *testing.T, h *busHub, bus *MockSignalBus) {
					entered := make(chan struct{}, 1)
					release := make(chan struct{})
					t.Cleanup(func() { close(release) })

					bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
						func(context.Context, httpsec.SignalEnvelope) error {
							entered <- struct{}{}
							<-release

							return nil
						}).AnyTimes()

					require.NoError(t, h.Raise(envelope("u-1")))
					waitBus(t, entered)
					require.NoError(t, h.Raise(envelope("u-1")))
					require.ErrorIs(t, h.Raise(envelope("u-1")), httpsec.ErrSignalsBusy)
				},
				assert: func(t *testing.T, h *busHub) {
					assert.Equal(t, uint64(1), h.Stats().Dropped)
				},
			},
			{
				name: "a failed Publish's record leaves the publisher running",
				setup: func(bus *MockSignalBus) httpsec.SignalHubSetup {
					subscribeBlocks(bus)

					return httpsec.SignalHubSetup{Bus: bus, Log: panicky}
				},
				act: func(t *testing.T, h *busHub, bus *MockSignalBus) {
					entered := make(chan struct{}, 2)

					bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
						func(context.Context, httpsec.SignalEnvelope) error {
							entered <- struct{}{}

							return errors.New("the bus failed")
						}).Times(2)

					require.NoError(t, h.Raise(envelope("u-1")))
					waitBus(t, entered)
					require.NoError(t, h.Raise(envelope("u-1")))
					waitBus(t, entered)
				},
				assert: func(*testing.T, *busHub) {},
			},
			{
				name: "a panic's own record, when the logger panics too",
				setup: func(bus *MockSignalBus) httpsec.SignalHubSetup {
					return httpsec.SignalHubSetup{Bus: bus, Log: panicky}
				},
				act: func(t *testing.T, h *busHub, bus *MockSignalBus) {
					attempts := make(chan struct{}, 8)

					bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).DoAndReturn(
						func(context.Context, func(httpsec.SignalEnvelope)) error {
							attempts <- struct{}{}
							panic("a bus's own panic")
						}).AnyTimes()

					h.Start()
					waitBus(t, attempts)

					ctx, cancel := context.WithTimeout(t.Context(), signalsTestBound)
					defer cancel()

					require.NoError(t, h.clk.BlockUntilContext(ctx, 1))
					h.clk.Advance(time.Second)
					waitBus(t, attempts)
				},
				assert: func(*testing.T, *busHub) {},
			},
			{
				name: "a clock reading that panics in deliver, on a bus's own goroutine",
				setup: func(*MockSignalBus) httpsec.SignalHubSetup {
					return httpsec.SignalHubSetup{Clock: panickyNowClock{Timed: clockwork.NewFakeClockAt(endedAt)}}
				},
				act: func(_ *testing.T, h *busHub, _ *MockSignalBus) {
					h.Deliver(httpsec.SignalEnvelope{Family: familyOne, Name: string(httpsec.SignalSessionEnded)})
				},
				assert: func(t *testing.T, h *busHub) {
					logs := h.logs.String()
					assert.Contains(t, logs, "phase=bus")
					assert.NotContains(t, logs, "the clock panicked", "the record never holds the value")
				},
			},
			{
				name: "a clock whose wait panics ends only the subscription's loop",
				setup: func(bus *MockSignalBus) httpsec.SignalHubSetup {
					return httpsec.SignalHubSetup{
						Bus:   bus,
						Clock: panickyClock{Timed: clockwork.NewFakeClockAt(endedAt)},
					}
				},
				act: func(t *testing.T, h *busHub, bus *MockSignalBus) {
					attempted := make(chan struct{}, 1)

					bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).DoAndReturn(
						func(context.Context, func(httpsec.SignalEnvelope)) error {
							attempted <- struct{}{}

							return errors.New("the bus failed")
						}).Times(1)

					h.Start()
					waitBus(t, attempted)
				},
				assert: func(t *testing.T, h *busHub) {
					// The loop's own recover writes the record. Without it the process ends first.
					require.Eventually(t, func() bool {
						return strings.Contains(h.logs.String(), "a panic was recovered")
					}, signalsTestBound, time.Millisecond)
				},
			},
			{
				name: "a clock whose wait panics ends only the publisher's loop",
				setup: func(bus *MockSignalBus) httpsec.SignalHubSetup {
					subscribeBlocks(bus)

					return httpsec.SignalHubSetup{
						Bus:   bus,
						Clock: panickyClock{Timed: clockwork.NewFakeClockAt(endedAt)},
					}
				},
				act: func(t *testing.T, h *busHub, bus *MockSignalBus) {
					published := make(chan struct{}, 1)

					bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
						func(context.Context, httpsec.SignalEnvelope) error {
							published <- struct{}{}

							panic("a bus's own panic")
						}).Times(1)

					require.NoError(t, h.Raise(envelope("u-1")))
					waitBus(t, published)
				},
				assert: func(t *testing.T, h *busHub) {
					// Two records: the Publish's panic, and the backoff's, which the loop's own
					// recover writes. Without that recover the process ends first.
					require.Eventually(t, func() bool {
						return strings.Count(h.logs.String(), "a panic was recovered") == 2
					}, signalsTestBound, time.Millisecond)
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				bus := NewMockSignalBus(gomock.NewController(t))
				h := newBusHub(t, tc.setup(bus))

				tc.act(t, h, bus)
				tc.assert(t, h)
			})
		}
	})
}
