// The tests here that stand outside a table each have a setup of their own: racing goroutines,
// or a sequence of releases asserted at each step.
package httpsec_test

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

var (
	familyOne   = id.MustParse("018f0000-0000-7000-8000-000000000001")
	familyTwo   = id.MustParse("018f0000-0000-7000-8000-000000000002")
	familyThree = id.MustParse("018f0000-0000-7000-8000-000000000003")

	defaultCaps = httpsec.RegistryCaps{PerSignIn: 4, PerUser: 16, Total: 10_000}
	endedAt     = time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
)

// familyN is a family of its own for each n, for a test that needs many.
func familyN(n int) id.ID {
	return id.MustParse(fmt.Sprintf("018f0000-0000-7000-8000-%012x", 0x1000+n))
}

// admitted admits stream and requires it to get a place.
func admitted(t *testing.T, r *httpsec.SignalRegistryProbe, stream *httpsec.SignalStreamProbe) func() {
	t.Helper()

	release, err := r.Admit(stream)
	require.NoError(t, err)

	return release
}

func TestSessionSignals_Bus(t *testing.T) {
	t.Parallel()

	const digest = "digest-of-the-upstream-session"

	// Three streams of u-1, two of them on one sign-in, one with an upstream session, and
	// one of u-2 on a sign-in of its own.
	streams := map[string]httpsec.RegistryStream{
		"one-a": {User: "u-1", Family: familyOne, Upstream: digest},
		"one-b": {User: "u-1", Family: familyOne},
		"two":   {User: "u-1", Family: familyTwo},
		"other": {User: "u-2", Family: familyThree},
	}

	// reached is what one action left: the streams woken or holding a signal, by name.
	type reached struct {
		woken, signalled []string
		dropped          int
	}

	type testCase struct {
		name    string
		streams map[string]httpsec.RegistryStream // nil means streams
		act     func(r *httpsec.SignalRegistryProbe) int
		assert  func(t *testing.T, got reached)
	}

	cases := []testCase{
		{
			name: "a signal reaches only its user's streams",
			act: func(r *httpsec.SignalRegistryProbe) int {
				return r.DeliverSignal("u-1", "app.ping", `{}`)
			},
			assert: func(t *testing.T, got reached) {
				assert.Equal(t, []string{"one-a", "one-b", "two"}, got.signalled)
				assert.Empty(t, got.woken)
				assert.Zero(t, got.dropped)
			},
		},
		{
			name: "a signal of a user with no stream reaches none",
			act: func(r *httpsec.SignalRegistryProbe) int {
				return r.DeliverSignal("u-9", "app.ping", `{}`)
			},
			assert: func(t *testing.T, got reached) {
				assert.Empty(t, got.signalled)
				assert.Zero(t, got.dropped)
			},
		},
		{
			name: "a signal naming no user reaches a stream holding none",
			streams: map[string]httpsec.RegistryStream{
				"no-user": {Family: familyOne},
			},
			act: func(r *httpsec.SignalRegistryProbe) int {
				return r.DeliverSignal("", "app.ping", `{}`)
			},
			assert: func(t *testing.T, got reached) {
				assert.Empty(t, got.signalled)
			},
		},
		{
			name: "a signal reaches only the streams that want it, and one unwanted is no drop",
			streams: map[string]httpsec.RegistryStream{
				"everything": {User: "u-1", Family: familyOne, Library: []httpsec.Signal{httpsec.SignalCredentialChanged}},
				"narrowed":   {User: "u-1", Family: familyOne, Library: []httpsec.Signal{httpsec.SignalCredentialChanged}, Narrowed: true},
				"off-chain":  {User: "u-1", Family: familyTwo},
			},
			act: func(r *httpsec.SignalRegistryProbe) int {
				return r.DeliverSignal("u-1", string(httpsec.SignalCredentialChanged), `{}`)
			},
			assert: func(t *testing.T, got reached) {
				assert.Equal(t, []string{"everything"}, got.signalled)
				assert.Zero(t, got.dropped)
			},
		},
		{
			name: "a family's end reaches that family, leaving the user's other family un-noted",
			act: func(r *httpsec.SignalRegistryProbe) int {
				r.DeliverEndToFamily(familyOne, "ended", endedAt)

				return 0
			},
			assert: func(t *testing.T, got reached) {
				assert.Equal(t, []string{"one-a", "one-b"}, got.woken)
				assert.Empty(t, got.signalled)
			},
		},
		{
			name: "the nil family reaches a stream holding none",
			streams: map[string]httpsec.RegistryStream{
				"no-family": {User: "u-1"},
			},
			act: func(r *httpsec.SignalRegistryProbe) int {
				r.DeliverEndToFamily(id.Nil, "ended", endedAt)

				return 0
			},
			assert: func(t *testing.T, got reached) {
				assert.Empty(t, got.woken)
			},
		},
		{
			name: "a user's end reaches every stream of the user but kept's",
			act: func(r *httpsec.SignalRegistryProbe) int {
				r.DeliverEndToUser("u-1", familyTwo, "all_ended", endedAt)

				return 0
			},
			assert: func(t *testing.T, got reached) {
				assert.Equal(t, []string{"one-a", "one-b"}, got.woken)
			},
		},
		{
			name: "a nil kept spares nothing, a stream holding no family included",
			streams: map[string]httpsec.RegistryStream{
				"one":       {User: "u-1", Family: familyOne},
				"two":       {User: "u-1", Family: familyTwo},
				"no-family": {User: "u-1"},
				"other":     {User: "u-2", Family: familyThree},
			},
			act: func(r *httpsec.SignalRegistryProbe) int {
				r.DeliverEndToUser("u-1", id.Nil, "all_ended", endedAt)

				return 0
			},
			assert: func(t *testing.T, got reached) {
				assert.Equal(t, []string{"no-family", "one", "two"}, got.woken)
			},
		},
		{
			name: "a user's end naming no user reaches a stream holding none",
			streams: map[string]httpsec.RegistryStream{
				"no-user": {Family: familyOne},
			},
			act: func(r *httpsec.SignalRegistryProbe) int {
				r.DeliverEndToUser("", id.Nil, "all_ended", endedAt)

				return 0
			},
			assert: func(t *testing.T, got reached) {
				assert.Empty(t, got.woken)
			},
		},
		{
			name: "an upstream digest reaches the streams holding it",
			act: func(r *httpsec.SignalRegistryProbe) int {
				r.DeliverEndToUpstream(digest, "provider_logout", endedAt)

				return 0
			},
			assert: func(t *testing.T, got reached) {
				assert.Equal(t, []string{"one-a"}, got.woken)
			},
		},
		{
			name: "an empty digest reaches no stream, though some hold none",
			act: func(r *httpsec.SignalRegistryProbe) int {
				r.DeliverEndToUpstream("", "provider_logout", endedAt)

				return 0
			},
			assert: func(t *testing.T, got reached) {
				assert.Empty(t, got.woken)
			},
		},
		{
			name: "a digest no stream holds reaches none",
			act: func(r *httpsec.SignalRegistryProbe) int {
				r.DeliverEndToUpstream("another", "provider_logout", endedAt)

				return 0
			},
			assert: func(t *testing.T, got reached) {
				assert.Empty(t, got.woken)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			specs := tc.streams
			if specs == nil {
				specs = streams
			}

			r := httpsec.NewSignalRegistryProbe(defaultCaps)
			probes := map[string]*httpsec.SignalStreamProbe{}

			for name, spec := range specs {
				probes[name] = httpsec.NewRegistryStream(spec)
				admitted(t, r, probes[name])
			}

			got := reached{dropped: tc.act(r)}

			for name, probe := range probes {
				if probe.Woken() {
					got.woken = append(got.woken, name)
				}

				if probe.Queued() > 0 {
					got.signalled = append(got.signalled, name)
				}
			}

			slices.Sort(got.woken)
			slices.Sort(got.signalled)

			tc.assert(t, got)
		})
	}
}

// TestSessionSignals_Bus_Notice pins what reaches a stream, unchanged, beside who it reaches.
func TestSessionSignals_Bus_Notice(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(r *httpsec.SignalRegistryProbe)
		assert func(t *testing.T, stream *httpsec.SignalStreamProbe)
	}

	cases := []testCase{
		{
			name: "a family's end keeps its reason and time",
			act:  func(r *httpsec.SignalRegistryProbe) { r.DeliverEndToFamily(familyOne, "ended", endedAt) },
			assert: func(t *testing.T, stream *httpsec.SignalStreamProbe) {
				reason, at := stream.Notice()
				assert.Equal(t, "ended", reason)
				assert.Equal(t, endedAt, at)
			},
		},
		{
			name: "a user's end keeps its reason and time",
			act:  func(r *httpsec.SignalRegistryProbe) { r.DeliverEndToUser("u-1", id.Nil, "all_ended", endedAt) },
			assert: func(t *testing.T, stream *httpsec.SignalStreamProbe) {
				reason, at := stream.Notice()
				assert.Equal(t, "all_ended", reason)
				assert.Equal(t, endedAt, at)
			},
		},
		{
			name: "an upstream end keeps its reason and time",
			act:  func(r *httpsec.SignalRegistryProbe) { r.DeliverEndToUpstream("d", "provider_logout", endedAt) },
			assert: func(t *testing.T, stream *httpsec.SignalStreamProbe) {
				reason, at := stream.Notice()
				assert.Equal(t, "provider_logout", reason)
				assert.Equal(t, endedAt, at)
			},
		},
		{
			name: "a signal keeps its name and data",
			act:  func(r *httpsec.SignalRegistryProbe) { r.DeliverSignal("u-1", "app.ping", `{"n":1}`) },
			assert: func(t *testing.T, stream *httpsec.SignalStreamProbe) {
				assert.Equal(t, []httpsec.QueuedSignalView{{Name: "app.ping", Data: `{"n":1}`}}, stream.TakeQueued())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := httpsec.NewSignalRegistryProbe(defaultCaps)
			stream := httpsec.NewRegistryStream(httpsec.RegistryStream{User: "u-1", Family: familyOne, Upstream: "d"})
			admitted(t, r, stream)

			tc.act(r)

			tc.assert(t, stream)
		})
	}
}

// TestSessionSignals_Bus_SendsOutsideTheLock has every delivery reach some of its streams and
// not yet the others while the registry's lock is free. Under one lock held across the sends,
// a moment both free and half delivered does not exist, so this can never pass wrongly. Sends
// never block, so nothing else can tell the two apart. It only looks for such a moment for as
// long as it takes one to come up, and is bounded for a machine that never lets it.
//
// The watcher looks only while delivering holds, and only trusts a look that began and ended
// within it, because emptying the queues between rounds is half done with the lock free too.
func TestSessionSignals_Bus_SendsOutsideTheLock(t *testing.T) {
	t.Parallel()

	const (
		streamCount = 4000
		samples     = 16
		digest      = "d"
	)

	type testCase struct {
		name   string
		act    func(r *httpsec.SignalRegistryProbe)
		assert func(t *testing.T, seen bool)
	}

	sawIt := func(t *testing.T, seen bool) {
		assert.True(t, seen, "no moment seen with the lock free and the delivery half done")
	}

	cases := []testCase{
		{
			name:   "signals",
			act:    func(r *httpsec.SignalRegistryProbe) { r.DeliverSignal("u-1", "app.ping", `{}`) },
			assert: sawIt,
		},
		{
			name:   "a family's end",
			act:    func(r *httpsec.SignalRegistryProbe) { r.DeliverEndToFamily(familyOne, "ended", endedAt) },
			assert: sawIt,
		},
		{
			name:   "a user's end",
			act:    func(r *httpsec.SignalRegistryProbe) { r.DeliverEndToUser("u-1", id.Nil, "all_ended", endedAt) },
			assert: sawIt,
		},
		{
			name:   "an upstream's end",
			act:    func(r *httpsec.SignalRegistryProbe) { r.DeliverEndToUpstream(digest, "ended", endedAt) },
			assert: sawIt,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httpsec.NewSignalRegistryProbe(httpsec.RegistryCaps{
				PerSignIn: streamCount, PerUser: streamCount, Total: streamCount,
			})

			probes := make([]*httpsec.SignalStreamProbe, streamCount)
			for i := range probes {
				probes[i] = httpsec.NewRegistryStream(httpsec.RegistryStream{User: "u-1", Family: familyOne, Upstream: digest})
				admitted(t, r, probes[i])
			}

			var seen, delivering atomic.Bool

			stop := make(chan struct{})

			var watcher sync.WaitGroup

			watcher.Go(func() {
				for !seen.Load() {
					select {
					case <-stop:
						return
					default:
					}

					r.IfUnlocked(func() {
						if !delivering.Load() {
							return
						}

						var some, others bool

						for _, probe := range probes[:samples] {
							if probe.Queued() > 0 || probe.Woken() {
								some = true
							} else {
								others = true
							}
						}

						if some && others && delivering.Load() {
							seen.Store(true)
						}
					})
				}
			})

			for deadline := time.Now().Add(signalsTestBound); !seen.Load() && time.Now().Before(deadline); {
				delivering.Store(true)
				tc.act(r)
				delivering.Store(false)

				for _, probe := range probes {
					probe.TakeQueued()
					probe.TakeWake()
				}
			}

			close(stop)
			watcher.Wait()

			tc.assert(t, seen.Load())
		})
	}
}

// TestSessionSignals_Bus_KeysRemoved pins that no key outlives its streams.
func TestSessionSignals_Bus_KeysRemoved(t *testing.T) {
	t.Parallel()

	r := httpsec.NewSignalRegistryProbe(defaultCaps)

	first := admitted(t, r, httpsec.NewRegistryStream(httpsec.RegistryStream{
		User: "u-1", Family: familyOne, Upstream: "d", Source: "10.0.0.1",
	}))
	second := admitted(t, r, httpsec.NewRegistryStream(httpsec.RegistryStream{
		User: "u-1", Family: familyOne, Upstream: "d", Source: "10.0.0.1",
	}))
	third := admitted(t, r, httpsec.NewRegistryStream(httpsec.RegistryStream{
		User: "u-2", Family: familyTwo, Upstream: "e", Source: "10.0.0.2",
	}))

	assert.Equal(t, httpsec.RegistryKeys{Streams: 3, Users: 2, Families: 2, Upstreams: 2, Sources: 2}, r.Keys())

	first()
	assert.Equal(t, httpsec.RegistryKeys{Streams: 2, Users: 2, Families: 2, Upstreams: 2, Sources: 2}, r.Keys(),
		"a key with a stream left stays")

	third()
	assert.Equal(t, httpsec.RegistryKeys{Streams: 1, Users: 1, Families: 1, Upstreams: 1, Sources: 1}, r.Keys())

	second()
	assert.Equal(t, httpsec.RegistryKeys{}, r.Keys())

	// A stream holding nothing but its place adds no key at all, so no empty or nil key
	// can be delivered to.
	bare := admitted(t, r, httpsec.NewRegistryStream(httpsec.RegistryStream{}))
	assert.Equal(t, httpsec.RegistryKeys{Streams: 1}, r.Keys())

	bare()
	assert.Equal(t, httpsec.RegistryKeys{}, r.Keys())
}

// TestSessionSignals_Bus_DeliveryRacesRelease has deliveries overlap the releases of their
// targets. A notice on a stream just released is harmless, so all this asserts is that
// nothing panics or races, and no key is left.
func TestSessionSignals_Bus_DeliveryRacesRelease(t *testing.T) {
	t.Parallel()

	const rounds = 200

	r := httpsec.NewSignalRegistryProbe(httpsec.RegistryCaps{PerSignIn: 16, PerUser: 16, Total: 16})

	for range rounds {
		start := make(chan struct{})

		var racers sync.WaitGroup

		for range 4 {
			release := admitted(t, r, httpsec.NewRegistryStream(httpsec.RegistryStream{
				User: "u-1", Family: familyOne, Upstream: "d", Source: "10.0.0.1",
			}))

			racers.Go(func() {
				<-start
				release()
			})
		}

		racers.Go(func() {
			<-start
			r.DeliverSignal("u-1", "app.ping", `{}`)
			r.DeliverEndToFamily(familyOne, "ended", endedAt)
			r.DeliverEndToUser("u-1", id.Nil, "all_ended", endedAt)
			r.DeliverEndToUpstream("d", "provider_logout", endedAt)
		})

		close(start)
		racers.Wait()
	}

	assert.Equal(t, httpsec.RegistryKeys{}, r.Keys())

	open, _ := r.Stats()
	assert.Zero(t, open)
}

func TestSessionSignals_Caps(t *testing.T) {
	t.Parallel()

	spec := func(user identity.UserID, family id.ID, source string) httpsec.RegistryStream {
		return httpsec.RegistryStream{User: user, Family: family, Source: source}
	}

	// repeated is count streams of one spec.
	repeated := func(count int, s httpsec.RegistryStream) []httpsec.RegistryStream {
		return slices.Repeat([]httpsec.RegistryStream{s}, count)
	}

	// sixteenAcross is 16 streams of u-1 over four sign-ins.
	var sixteenAcross []httpsec.RegistryStream
	for f := range 4 {
		sixteenAcross = append(sixteenAcross, repeated(4, spec("u-1", familyN(f), ""))...)
	}

	type testCase struct {
		name      string
		caps      httpsec.RegistryCaps
		existing  []httpsec.RegistryStream
		candidate httpsec.RegistryStream
		assert    func(t *testing.T, err error, refused uint64)
	}

	refusedOnce := func(t *testing.T, err error, refused uint64) {
		require.ErrorIs(t, err, httpsec.ErrTooManyStreams)
		assert.Equal(t, uint64(1), refused)
	}

	admittedNone := func(t *testing.T, err error, refused uint64) {
		require.NoError(t, err)
		assert.Zero(t, refused)
	}

	cases := []testCase{
		{
			name:      "a fifth stream of a sign-in",
			caps:      defaultCaps,
			existing:  repeated(4, spec("u-1", familyOne, "")),
			candidate: spec("u-1", familyOne, ""),
			assert:    refusedOnce,
		},
		{
			name:      "a fifth stream of another sign-in of the user is its own",
			caps:      defaultCaps,
			existing:  repeated(4, spec("u-1", familyOne, "")),
			candidate: spec("u-1", familyTwo, ""),
			assert:    admittedNone,
		},
		{
			name:      "a seventeenth stream of a user, on a sign-in with fewer than four",
			caps:      defaultCaps,
			existing:  sixteenAcross,
			candidate: spec("u-1", familyN(100), ""),
			assert:    refusedOnce,
		},
		{
			name:      "a seventeenth stream counts only that user's",
			caps:      defaultCaps,
			existing:  sixteenAcross,
			candidate: spec("u-2", familyN(100), ""),
			assert:    admittedNone,
		},
		{
			name:      "one over the total",
			caps:      httpsec.RegistryCaps{PerSignIn: 4, PerUser: 16, Total: 2},
			existing:  []httpsec.RegistryStream{spec("u-1", familyOne, ""), spec("u-2", familyTwo, "")},
			candidate: spec("u-3", familyThree, ""),
			assert:    refusedOnce,
		},
		{
			name:      "one over per-source",
			caps:      httpsec.RegistryCaps{PerSignIn: 4, PerUser: 16, Total: 100, PerSource: 2},
			existing:  []httpsec.RegistryStream{spec("u-1", familyOne, "10.0.0.1"), spec("u-2", familyTwo, "10.0.0.1")},
			candidate: spec("u-3", familyThree, "10.0.0.1"),
			assert:    refusedOnce,
		},
		{
			name:      "per-source counts only that address",
			caps:      httpsec.RegistryCaps{PerSignIn: 4, PerUser: 16, Total: 100, PerSource: 2},
			existing:  []httpsec.RegistryStream{spec("u-1", familyOne, "10.0.0.1"), spec("u-2", familyTwo, "10.0.0.1")},
			candidate: spec("u-3", familyThree, "10.0.0.2"),
			assert:    admittedNone,
		},
		{
			name:      "per-source of 0 is off",
			caps:      defaultCaps,
			existing:  repeated(4, spec("u-1", familyOne, "10.0.0.1")),
			candidate: spec("u-2", familyTwo, "10.0.0.1"),
			assert:    admittedNone,
		},
		{
			name:      "no address is no shared address",
			caps:      httpsec.RegistryCaps{PerSignIn: 4, PerUser: 16, Total: 100, PerSource: 1},
			existing:  []httpsec.RegistryStream{spec("u-1", familyOne, "")},
			candidate: spec("u-2", familyTwo, ""),
			assert:    admittedNone,
		},
		{
			name:      "a consumer's per-sign-in cap is used",
			caps:      httpsec.RegistryCaps{PerSignIn: 1, PerUser: 16, Total: 100},
			existing:  []httpsec.RegistryStream{spec("u-1", familyOne, "")},
			candidate: spec("u-1", familyOne, ""),
			assert:    refusedOnce,
		},
		{
			name:      "a consumer's per-user cap is used",
			caps:      httpsec.RegistryCaps{PerSignIn: 4, PerUser: 2, Total: 100},
			existing:  []httpsec.RegistryStream{spec("u-1", familyOne, ""), spec("u-1", familyTwo, "")},
			candidate: spec("u-1", familyThree, ""),
			assert:    refusedOnce,
		},
		{
			name:      "the nil family is no sign-in the unrelated share",
			caps:      httpsec.RegistryCaps{PerSignIn: 1, PerUser: 16, Total: 100},
			existing:  []httpsec.RegistryStream{spec("u-1", id.Nil, "")},
			candidate: spec("u-2", id.Nil, ""),
			assert:    admittedNone,
		},
		{
			name:      "the nil family still counts to its user",
			caps:      httpsec.RegistryCaps{PerSignIn: 1, PerUser: 1, Total: 100},
			existing:  []httpsec.RegistryStream{spec("u-1", id.Nil, "")},
			candidate: spec("u-1", id.Nil, ""),
			assert:    refusedOnce,
		},
		{
			name:      "no user is no user the unrelated share",
			caps:      httpsec.RegistryCaps{PerSignIn: 4, PerUser: 1, Total: 100},
			existing:  []httpsec.RegistryStream{spec("", familyOne, "")},
			candidate: spec("", familyTwo, ""),
			assert:    admittedNone,
		},
		{
			name:      "no user and no family still count to the total",
			caps:      httpsec.RegistryCaps{PerSignIn: 4, PerUser: 16, Total: 1},
			existing:  []httpsec.RegistryStream{{}},
			candidate: httpsec.RegistryStream{},
			assert:    refusedOnce,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := httpsec.NewSignalRegistryProbe(tc.caps)

			existing := make([]*httpsec.SignalStreamProbe, len(tc.existing))
			for i, s := range tc.existing {
				existing[i] = httpsec.NewRegistryStream(s)
				admitted(t, r, existing[i])
			}

			keysBefore := r.Keys()
			candidate := httpsec.NewRegistryStream(tc.candidate)

			release, err := r.Admit(candidate)

			openNow, refused := r.Stats()
			tc.assert(t, err, refused)

			for _, stream := range existing {
				assert.False(t, stream.Closing(), "no existing stream is closed")
			}

			if err == nil {
				assert.Equal(t, len(tc.existing)+1, openNow)
				release()
				openNow, _ = r.Stats()
			}

			// Whether refused or released, the candidate is charged to nothing.
			assert.Equal(t, len(tc.existing), openNow)
			assert.Equal(t, keysBefore, r.Keys())

			if tc.candidate.User != "" {
				r.DeliverSignal(tc.candidate.User, "app.ping", `{}`)
				assert.Zero(t, candidate.Queued(), "the candidate holds no place")
			}
		})
	}
}

// TestSessionSignals_Caps_Release pins that a release frees exactly the place it was given,
// however often and from wherever it is called.
func TestSessionSignals_Caps_Release(t *testing.T) {
	t.Parallel()

	stream := func() *httpsec.SignalStreamProbe {
		return httpsec.NewRegistryStream(httpsec.RegistryStream{User: "u-1", Family: familyOne, Upstream: "d", Source: "s"})
	}

	type testCase struct {
		name   string
		act    func(t *testing.T, r *httpsec.SignalRegistryProbe, release func())
		assert func(t *testing.T, r *httpsec.SignalRegistryProbe)
	}

	// oneLeft asserts that releasing the first stream left the second holding its place,
	// and that exactly one more can now be admitted.
	oneLeft := func(t *testing.T, r *httpsec.SignalRegistryProbe) {
		openNow, _ := r.Stats()
		assert.Equal(t, 1, openNow)
		assert.Equal(t, httpsec.RegistryKeys{Streams: 1, Users: 1, Families: 1, Upstreams: 1, Sources: 1}, r.Keys())

		_, err := r.Admit(stream())
		require.NoError(t, err)

		_, err = r.Admit(stream())
		require.ErrorIs(t, err, httpsec.ErrTooManyStreams)
	}

	cases := []testCase{
		{
			name:   "a release frees the place",
			act:    func(_ *testing.T, _ *httpsec.SignalRegistryProbe, release func()) { release() },
			assert: oneLeft,
		},
		{
			name: "a second release frees nothing more",
			act: func(_ *testing.T, _ *httpsec.SignalRegistryProbe, release func()) {
				release()
				release()
			},
			assert: oneLeft,
		},
		{
			name: "releases racing free it once",
			act: func(_ *testing.T, _ *httpsec.SignalRegistryProbe, release func()) {
				start := make(chan struct{})

				var racers sync.WaitGroup
				for range 8 {
					racers.Go(func() {
						<-start
						release()
					})
				}

				close(start)
				racers.Wait()
			},
			assert: oneLeft,
		},
		{
			name: "a refused admit leaves a release's place alone",
			act: func(t *testing.T, r *httpsec.SignalRegistryProbe, release func()) {
				refusedRelease, err := r.Admit(stream())
				require.ErrorIs(t, err, httpsec.ErrTooManyStreams)

				refusedRelease()
				release()
			},
			assert: oneLeft,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := httpsec.NewSignalRegistryProbe(httpsec.RegistryCaps{PerSignIn: 2, PerUser: 2, Total: 2, PerSource: 2})

			release := admitted(t, r, stream())
			admitted(t, r, stream())

			tc.act(t, r, release)

			tc.assert(t, r)
		})
	}
}

// TestSessionSignals_Caps_Misuse pins what a wrong call to admit answers. It registers
// nothing, and is no cap's refusal.
func TestSessionSignals_Caps_Misuse(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		act  func(t *testing.T, r *httpsec.SignalRegistryProbe) (func(), error)
	}

	cases := []testCase{
		{
			name: "a nil stream",
			act: func(_ *testing.T, r *httpsec.SignalRegistryProbe) (func(), error) {
				return r.Admit(nil)
			},
		},
		{
			name: "a stream already registered",
			act: func(t *testing.T, r *httpsec.SignalRegistryProbe) (func(), error) {
				stream := httpsec.NewRegistryStream(httpsec.RegistryStream{User: "u-2", Family: familyTwo})

				release := admitted(t, r, stream)
				t.Cleanup(release)

				return r.Admit(stream)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := httpsec.NewSignalRegistryProbe(defaultCaps)

			before, _ := r.Stats()

			release, err := tc.act(t, r)
			require.Error(t, err)
			assert.NotErrorIs(t, err, httpsec.ErrTooManyStreams)

			openNow, refused := r.Stats()
			assert.Zero(t, refused)
			assert.LessOrEqual(t, openNow-before, 1, "only the first registration holds a place")

			require.NotNil(t, release)
			release() // Frees nothing, and does not panic.

			afterRelease, _ := r.Stats()
			assert.Equal(t, openNow, afterRelease)
		})
	}
}

// TestSessionSignals_Caps_Race has two requests race for each cap's last place, released at
// one barrier, many times over. Exactly one may get it.
func TestSessionSignals_Caps_Race(t *testing.T) {
	t.Parallel()

	const rounds = 3000

	type testCase struct {
		name     string
		caps     httpsec.RegistryCaps
		existing httpsec.RegistryStream
		racer    func(n int) httpsec.RegistryStream
		assert   func(t *testing.T, won, lost int, refused uint64)
	}

	exactlyOne := func(t *testing.T, won, lost int, refused uint64) {
		assert.Equal(t, rounds, won, "every round has exactly one winner")
		assert.Equal(t, rounds, lost, "every round has exactly one loser")
		assert.Equal(t, uint64(rounds), refused, "each loss is counted")
	}

	cases := []testCase{
		{
			name:     "per sign-in",
			caps:     httpsec.RegistryCaps{PerSignIn: 2, PerUser: 100, Total: 100},
			existing: httpsec.RegistryStream{User: "u-1", Family: familyOne},
			racer: func(int) httpsec.RegistryStream {
				return httpsec.RegistryStream{User: "u-1", Family: familyOne}
			},
			assert: exactlyOne,
		},
		{
			name:     "per user",
			caps:     httpsec.RegistryCaps{PerSignIn: 100, PerUser: 2, Total: 100},
			existing: httpsec.RegistryStream{User: "u-1", Family: familyOne},
			racer: func(n int) httpsec.RegistryStream {
				return httpsec.RegistryStream{User: "u-1", Family: familyN(n)}
			},
			assert: exactlyOne,
		},
		{
			name:     "total",
			caps:     httpsec.RegistryCaps{PerSignIn: 100, PerUser: 100, Total: 2},
			existing: httpsec.RegistryStream{User: "u-0", Family: familyOne},
			racer: func(n int) httpsec.RegistryStream {
				return httpsec.RegistryStream{User: identity.UserID(fmt.Sprintf("u-%d", n+1)), Family: familyN(n)}
			},
			assert: exactlyOne,
		},
		{
			name:     "per source",
			caps:     httpsec.RegistryCaps{PerSignIn: 100, PerUser: 100, Total: 100, PerSource: 2},
			existing: httpsec.RegistryStream{User: "u-0", Family: familyOne, Source: "10.0.0.1"},
			racer: func(n int) httpsec.RegistryStream {
				return httpsec.RegistryStream{User: identity.UserID(fmt.Sprintf("u-%d", n+1)), Family: familyN(n), Source: "10.0.0.1"}
			},
			assert: exactlyOne,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := httpsec.NewSignalRegistryProbe(tc.caps)
			admitted(t, r, httpsec.NewRegistryStream(tc.existing))

			var won, lost int

			for round := range rounds {
				first := httpsec.NewRegistryStream(tc.racer(2 * round))
				second := httpsec.NewRegistryStream(tc.racer(2*round + 1))

				type outcome struct {
					release func()
					err     error
				}

				var firstOut, secondOut outcome

				var ready, racers sync.WaitGroup

				start := make(chan struct{})

				ready.Add(2)

				racers.Go(func() {
					ready.Done()
					<-start
					firstOut.release, firstOut.err = r.Admit(first)
				})
				racers.Go(func() {
					ready.Done()
					<-start
					secondOut.release, secondOut.err = r.Admit(second)
				})

				ready.Wait()
				close(start)
				racers.Wait()

				for _, o := range []outcome{firstOut, secondOut} {
					if o.err == nil {
						won++
					} else {
						require.ErrorIs(t, o.err, httpsec.ErrTooManyStreams)

						lost++
					}
				}

				// Free what this round won, so that the next has a last place to race for.
				for _, o := range []outcome{firstOut, secondOut} {
					if o.err == nil {
						o.release()
					}
				}
			}

			_, refused := r.Stats()
			tc.assert(t, won, lost, refused)
		})
	}
}

func TestSessionSignals_SlowStream(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(r *httpsec.SignalRegistryProbe) // after the slow stream's queue is full
		assert func(t *testing.T, slow *httpsec.SignalStreamProbe)
	}

	cases := []testCase{
		{
			name: "a family's end still reaches it",
			act:  func(r *httpsec.SignalRegistryProbe) { r.DeliverEndToFamily(familyOne, "ended", endedAt) },
			assert: func(t *testing.T, slow *httpsec.SignalStreamProbe) {
				reason, _ := slow.Notice()
				assert.Equal(t, "ended", reason)
				assert.True(t, slow.TakeWake())
			},
		},
		{
			name: "a user's end still reaches it",
			act:  func(r *httpsec.SignalRegistryProbe) { r.DeliverEndToUser("u-1", id.Nil, "all_ended", endedAt) },
			assert: func(t *testing.T, slow *httpsec.SignalStreamProbe) {
				reason, _ := slow.Notice()
				assert.Equal(t, "all_ended", reason)
				assert.True(t, slow.TakeWake())
			},
		},
		{
			name: "an upstream's end still reaches it",
			act:  func(r *httpsec.SignalRegistryProbe) { r.DeliverEndToUpstream("d", "provider_logout", endedAt) },
			assert: func(t *testing.T, slow *httpsec.SignalStreamProbe) {
				reason, _ := slow.Notice()
				assert.Equal(t, "provider_logout", reason)
				assert.True(t, slow.TakeWake())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := httpsec.NewSignalRegistryProbe(defaultCaps)

			slow := httpsec.NewRegistryStream(httpsec.RegistryStream{User: "u-1", Family: familyOne, Upstream: "d"})
			fast := httpsec.NewRegistryStream(httpsec.RegistryStream{User: "u-1", Family: familyTwo})

			admitted(t, r, slow)
			admitted(t, r, fast)

			var read []httpsec.QueuedSignalView

			total := httpsec.StreamQueueSize + 1
			for n := range total {
				var dropped int

				// The bound is what shows a full queue does not hold the publisher up.
				requireReturns(t, func() {
					dropped = r.DeliverSignal("u-1", "app.ping", fmt.Sprintf(`{"n":%d}`, n))
				})

				if n < httpsec.StreamQueueSize {
					assert.Zero(t, dropped, "signal %d fits", n)
				} else {
					assert.Equal(t, 1, dropped, "signal %d is the slow stream's to lose", n)
				}

				read = append(read, fast.TakeQueued()...)
			}

			require.Len(t, read, total, "the fast stream gets all of them")

			for n, sig := range read {
				assert.JSONEq(t, fmt.Sprintf(`{"n":%d}`, n), sig.Data, "in order")
			}

			assert.False(t, slow.Woken(), "a dropped signal wakes nothing")

			tc.act(r)
			tc.assert(t, slow)

			kept := slow.TakeQueued()
			require.Len(t, kept, httpsec.StreamQueueSize, "the slow stream keeps what fit")
			assert.JSONEq(t, `{"n":0}`, kept[0].Data)
		})
	}
}

// TestSessionSignals_SlowStream_CountsEachDrop pins that each stream's loss is its own, in
// what deliverSignal reports.
func TestSessionSignals_SlowStream_CountsEachDrop(t *testing.T) {
	t.Parallel()

	r := httpsec.NewSignalRegistryProbe(defaultCaps)

	for range 2 {
		admitted(t, r, httpsec.NewRegistryStream(httpsec.RegistryStream{User: "u-1", Family: familyOne}))
	}

	for range httpsec.StreamQueueSize {
		require.Zero(t, r.DeliverSignal("u-1", "app.ping", `{}`))
	}

	assert.Equal(t, 2, r.DeliverSignal("u-1", "app.ping", `{}`))
}

// priorityRepeats is how many times a row repeats a Close whose context has ended and whose
// registry has drained. The two are both ready to a select, which picks between them at
// random, so a registry that did not put the drain first would still pass a single call;
// 64 calls miss it with a chance of 2 to the power of -64.
const priorityRepeats = 64

func TestSessionSignals_Close(t *testing.T) {
	t.Parallel()

	// Each row runs in a bubble, so that "has not returned" and "a deadline passed" need no
	// wall clock: synctest.Wait returns only when everything in the bubble is blocked on
	// something else in it.
	type testCase struct {
		name string
		// ctx builds the context a row's Close runs with, inside the bubble, so a deadline
		// runs on the bubble's clock. Nil means the test's own.
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe)
	}

	stream := func() *httpsec.SignalStreamProbe {
		return httpsec.NewRegistryStream(httpsec.RegistryStream{User: "u-1", Family: familyOne, Upstream: "d", Source: "s"})
	}

	// closing starts a close in the background, and reports its result on the channel.
	closing := func(ctx context.Context, r *httpsec.SignalRegistryProbe) <-chan error {
		result := make(chan error, 1)

		go func() { result <- r.Close(ctx) }()

		return result
	}

	cases := []testCase{
		{
			name: "with nothing open it returns at once, whatever its context",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				// An ended context and a drained registry are both ready to select, so one call
				// would pass half the time by chance with no priority between them.
				for range priorityRepeats {
					require.NoError(t, r.Close(ctx))
				}
			},
		},
		{
			name: "it signals each stream, and waits for every release",
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				first, second := stream(), stream()
				releaseFirst := admitted(t, r, first)
				releaseSecond := admitted(t, r, second)

				result := closing(t.Context(), r)

				synctest.Wait()
				assert.True(t, first.Closing())
				assert.True(t, second.Closing())
				assert.Empty(t, result, "two streams are still open")

				releaseFirst()
				synctest.Wait()
				assert.Empty(t, result, "one stream is still open")

				releaseSecond()
				synctest.Wait()
				require.Len(t, result, 1)
				require.NoError(t, <-result)

				assert.Equal(t, httpsec.RegistryKeys{}, r.Keys(), "no key remains")
			},
		},
		{
			name: "it returns its context's error when a stream never releases",
			ctx: func(ctx context.Context) context.Context {
				tctx, cancel := context.WithTimeout(ctx, time.Second)
				context.AfterFunc(ctx, cancel)

				return tctx
			},
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				admitted(t, r, stream())

				require.ErrorIs(t, r.Close(ctx), context.DeadlineExceeded)
			},
		},
		{
			name: "it returns a cancelled context's error when a stream is open",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				admitted(t, r, stream())

				require.ErrorIs(t, r.Close(ctx), context.Canceled)
			},
		},
		{
			name: "a second call ends nothing new, and waits on its own context",
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				release := admitted(t, r, stream())

				first, cancelFirst := context.WithTimeout(t.Context(), time.Second)
				defer cancelFirst()

				require.ErrorIs(t, r.Close(first), context.DeadlineExceeded)

				result := closing(t.Context(), r) // Would panic, closing a closed channel.

				synctest.Wait()
				assert.Empty(t, result, "a stream the first call timed out on is still open")

				release()
				synctest.Wait()
				require.Len(t, result, 1)
				require.NoError(t, <-result)
			},
		},
		{
			name: "a second call times out on its own context too",
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				admitted(t, r, stream())

				first, cancelFirst := context.WithCancel(t.Context())
				cancelFirst()
				require.ErrorIs(t, r.Close(first), context.Canceled)

				second, cancelSecond := context.WithTimeout(t.Context(), time.Second)
				defer cancelSecond()
				require.ErrorIs(t, r.Close(second), context.DeadlineExceeded)
			},
		},
		{
			name: "a close after every stream has gone returns at once",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				release := admitted(t, r, stream())

				result := closing(t.Context(), r)
				synctest.Wait()
				release()
				require.NoError(t, <-result)

				// Drained wins over the ended context every time, not by the select's luck.
				for range priorityRepeats {
					require.NoError(t, r.Close(ctx))
				}
			},
		},
		{
			name: "calls at once all return when the last stream is released, signalling it once",
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				release := admitted(t, r, stream())

				results := []<-chan error{closing(t.Context(), r), closing(t.Context(), r), closing(t.Context(), r)}

				synctest.Wait()

				for _, result := range results {
					assert.Empty(t, result)
				}

				release()
				synctest.Wait()

				for _, result := range results {
					require.Len(t, result, 1)
					require.NoError(t, <-result)
				}
			},
		},
		{
			name: "a release after a close, and a second one, are harmless",
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				release := admitted(t, r, stream())

				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				require.ErrorIs(t, r.Close(ctx), context.Canceled)

				release()
				release()

				require.NoError(t, r.Close(t.Context()))
				assert.Equal(t, httpsec.RegistryKeys{}, r.Keys())
			},
		},
		{
			name: "an admit afterwards is refused, and registers nothing",
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				require.NoError(t, r.Close(t.Context()))

				late := stream()
				release, err := r.Admit(late)
				require.ErrorIs(t, err, httpsec.ErrStreamsClosed)
				assert.NotErrorIs(t, err, httpsec.ErrTooManyStreams)

				require.NotNil(t, release)
				release()

				openNow, refused := r.Stats()
				assert.Zero(t, openNow)
				assert.Zero(t, refused, "a close is no cap's refusal")
				assert.Equal(t, httpsec.RegistryKeys{}, r.Keys())

				r.DeliverSignal("u-1", "app.ping", `{}`)
				assert.Zero(t, late.Queued())
				assert.False(t, late.Closing(), "a stream never registered is not the registry's to close")
			},
		},
		{
			name: "an admit while closing is refused, and a stream still closing can be told of an end",
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				open := stream()
				release := admitted(t, r, open)

				result := closing(t.Context(), r)
				synctest.Wait()

				_, err := r.Admit(stream())
				require.ErrorIs(t, err, httpsec.ErrStreamsClosed)

				r.DeliverEndToFamily(familyOne, "ended", endedAt)
				assert.True(t, open.Woken())

				release()
				require.NoError(t, <-result)
			},
		},
		{
			name: "stats count what is open",
			assert: func(t *testing.T, ctx context.Context, r *httpsec.SignalRegistryProbe) {
				release := admitted(t, r, stream())

				openNow, _ := r.Stats()
				assert.Equal(t, 1, openNow)

				result := closing(t.Context(), r)
				synctest.Wait()

				openNow, _ = r.Stats()
				assert.Equal(t, 1, openNow, "a stream closing still holds its place")

				release()
				require.NoError(t, <-result)

				openNow, _ = r.Stats()
				assert.Zero(t, openNow)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()
				if tc.ctx != nil {
					ctx = tc.ctx(ctx)
				}

				tc.assert(t, ctx, httpsec.NewSignalRegistryProbe(defaultCaps))
			})
		})
	}
}

// TestSessionSignals_Close_RacesAdmit has a close overlap admissions and releases, so a
// stream admitted just before it is signalled, and waited for, and one after is refused,
// with none falling between. A stream waits for the signal before it releases, so a close
// that does not signal it leaves it hanging, and one that does not wait is seen returning
// with a stream still open.
func TestSessionSignals_Close_RacesAdmit(t *testing.T) {
	t.Parallel()

	const (
		rounds  = 200
		admits  = 8
		closers = 2
	)

	for range rounds {
		if t.Failed() {
			return
		}

		r := httpsec.NewSignalRegistryProbe(httpsec.RegistryCaps{PerSignIn: admits, PerUser: admits, Total: admits})

		var (
			ready     sync.WaitGroup
			racers    sync.WaitGroup
			start     = make(chan struct{})
			closed    = make([]error, closers)
			stillOpen = make([]int, closers)
		)

		ready.Add(admits + closers)

		for range admits {
			racers.Go(func() {
				stream := httpsec.NewRegistryStream(httpsec.RegistryStream{User: "u-1", Family: familyOne, Upstream: "d", Source: "s"})

				ready.Done()
				<-start

				release, err := r.Admit(stream)
				if err != nil {
					assert.ErrorIs(t, err, httpsec.ErrStreamsClosed)

					return
				}

				// Bounded, so a close that never signals fails here rather than hanging.
				select {
				case <-stream.ClosingChan():
				case <-time.After(signalsTestBound):
					assert.Fail(t, "a stream admitted around a close was never signalled")
				}

				// Long enough that a close which does not wait returns first.
				time.Sleep(time.Millisecond)

				release()
				release()
			})
		}

		for i := range closers {
			racers.Go(func() {
				ready.Done()
				<-start

				closed[i] = r.Close(t.Context())
				stillOpen[i], _ = r.Stats()
			})
		}

		ready.Wait()
		close(start)
		requireReturns(t, racers.Wait)

		for i, err := range closed {
			require.NoError(t, err)
			assert.Zero(t, stillOpen[i], "a close returned with a stream still open")
		}

		assert.Equal(t, httpsec.RegistryKeys{}, r.Keys())
	}
}

// TestSessionSignals_Close_SignalsAdmittedBeforeIt pins that a stream admitted before a close
// that overlaps it hears of that close. Admit and Close each run in a goroutine of their
// own, released together, so the two land on either side of each other about as often as
// not, instead of the admit nearly always winning.
func TestSessionSignals_Close_SignalsAdmittedBeforeIt(t *testing.T) {
	t.Parallel()

	const rounds = 500

	var admittedRounds, refusedRounds int

	for range rounds {
		if t.Failed() {
			return
		}

		r := httpsec.NewSignalRegistryProbe(defaultCaps)
		stream := httpsec.NewRegistryStream(httpsec.RegistryStream{User: "u-1", Family: familyOne})

		var (
			ready     sync.WaitGroup
			racers    sync.WaitGroup
			start     = make(chan struct{})
			closeDone = make(chan error, 1)
			release   func()
			admitErr  error
		)

		ready.Add(2)

		// The close is not waited for here: an admitted stream holds it until released.
		go func() {
			ready.Done()
			<-start

			closeDone <- r.Close(t.Context())
		}()

		racers.Go(func() {
			ready.Done()
			<-start

			release, admitErr = r.Admit(stream)
		})

		ready.Wait()
		close(start)
		requireReturns(t, racers.Wait)

		if admitErr != nil {
			refusedRounds++

			require.ErrorIs(t, admitErr, httpsec.ErrStreamsClosed)
			require.NoError(t, <-closeDone)

			continue
		}

		admittedRounds++

		// Admitted: the close either had yet to start, or ran and must have signalled this stream.
		select {
		case <-stream.ClosingChan():
		case <-time.After(signalsTestBound):
			require.FailNow(t, "a stream admitted around a close was never signalled")
		}

		release()
		require.NoError(t, <-closeDone)
	}

	// Without both sides, the test would not be the overlap it names.
	assert.NotZero(t, admittedRounds, "no admit won the race")
	assert.NotZero(t, refusedRounds, "no close won the race")
}
