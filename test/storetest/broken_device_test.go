package storetest_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// deviceDefect is what a clockDevices gets wrong.
type deviceDefect int

const (
	// deviceLoadsByWallClock judges a user-code lookup's expiry by the wall clock.
	deviceLoadsByWallClock deviceDefect = iota
	// deviceLoadsByLaterOfWallClock trusts the caller's time only so far as the wall clock
	// agrees, which a fixture dated after the wall clock cannot show.
	deviceLoadsByLaterOfWallClock
	// deviceClaimsByWallClock judges a claim's expiry by the wall clock.
	deviceClaimsByWallClock
	// deviceDeletesByWallClock sweeps by the wall clock.
	deviceDeletesByWallClock
	// deviceDecidesByWallClock judges a decision's expiry by the wall clock.
	deviceDecidesByWallClock
	// deviceSpendsByWallClock judges a spend's expiry by the wall clock.
	deviceSpendsByWallClock
	// deviceCreatesByWallClock judges whether a user code's holder has expired by the wall
	// clock.
	deviceCreatesByWallClock
)

// clockDevices is the memory store with one of its judgements of time made by a clock
// of its own, as a consumer's store comparing with NOW() in SQL would.
type clockDevices struct {
	*oidcprovider.MemoryDeviceAuthorizationStore

	defect deviceDefect
}

func (c clockDevices) LoadByUserCode(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
	switch c.defect {
	case deviceLoadsByWallClock:
		now = time.Now()
	case deviceLoadsByLaterOfWallClock:
		now = laterOfWallClock(now)
	default:
	}

	return c.MemoryDeviceAuthorizationStore.LoadByUserCode(ctx, digest, now)
}

func (c clockDevices) Claim(ctx context.Context, deviceID id.ID, flowDigest []byte, now time.Time) error {
	if c.defect == deviceClaimsByWallClock {
		now = time.Now()
	}

	return c.MemoryDeviceAuthorizationStore.Claim(ctx, deviceID, flowDigest, now)
}

func (c clockDevices) Decide(ctx context.Context, deviceID id.ID, approval *oidcprovider.DeviceApproval, now time.Time) error {
	if c.defect == deviceDecidesByWallClock {
		now = time.Now()
	}

	return c.MemoryDeviceAuthorizationStore.Decide(ctx, deviceID, approval, now)
}

func (c clockDevices) Spend(ctx context.Context, deviceID id.ID, now time.Time) error {
	if c.defect == deviceSpendsByWallClock {
		now = time.Now()
	}

	return c.MemoryDeviceAuthorizationStore.Spend(ctx, deviceID, now)
}

func (c clockDevices) Create(ctx context.Context, record *oidcprovider.DeviceAuthorization, now time.Time) error {
	if c.defect == deviceCreatesByWallClock {
		now = time.Now()
	}

	return c.MemoryDeviceAuthorizationStore.Create(ctx, record, now)
}

func (c clockDevices) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	if c.defect == deviceDeletesByWallClock {
		now = time.Now()
	}

	return c.MemoryDeviceAuthorizationStore.DeleteExpired(ctx, now)
}

// deviceVariant runs the device suite against the memory store carrying d.
func deviceVariant(name string, d deviceDefect, failsCase, failsWith string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: "device-" + name,
		Run: inBackend(func(t *testing.T) {
			storetest.DeviceAuthorizationSuite(t, func(*testing.T) oidcprovider.DeviceAuthorizationStore {
				return clockDevices{MemoryDeviceAuthorizationStore: oidcprovider.NewMemoryDeviceAuthorizationStore(), defect: d}
			})
		}),
		FailsCase: failsCase,
		FailsWith: failsWith,
	}
}

// The case a store judging a user-code lookup by its own clock fails, and what it says.
const (
	deviceClockCase    = "load by user code judges expiry by the time given, never its own clock"
	deviceClockMessage = "LoadByUserCode judged expiry by its own clock"
)

var deviceVariants = []storefix.BrokenVariant{
	deviceVariant("load-by-the-wall-clock", deviceLoadsByWallClock, deviceClockCase, deviceClockMessage),
	deviceVariant("load-by-the-wall-clock-too", deviceLoadsByLaterOfWallClock, deviceClockCase, deviceClockMessage),
	deviceVariant("claim-by-the-wall-clock", deviceClaimsByWallClock,
		deviceTransitionClockCase, "claim judged expiry by its own clock"),
	deviceVariant("delete-by-the-wall-clock", deviceDeletesByWallClock,
		"delete expired judges by the caller's time, never the wall clock", ""),
	deviceVariant("decide-by-the-wall-clock", deviceDecidesByWallClock,
		deviceTransitionClockCase, "decide judged expiry by its own clock"),
	deviceVariant("spend-by-the-wall-clock", deviceSpendsByWallClock,
		deviceTransitionClockCase, "spend judged expiry by its own clock"),
	deviceVariant("create-by-the-wall-clock", deviceCreatesByWallClock,
		"create judges a holder's expiry by the time given, never its own clock",
		"Create judged a holder's expiry by its own clock"),
	{
		Name: "device-keeps-seconds",
		Run: inBackend(func(t *testing.T) {
			storetest.DeviceAuthorizationSuite(t, precisionDevicesOf(func(tm time.Time) time.Time { return tm.Truncate(time.Second) }))
		}),
		FailsCase: "create and load by device code return every field",
		FailsWith: "at microsecond precision or finer",
	},
	{
		Name: "device-releases-before-checking",
		Run: inBackend(func(t *testing.T) {
			storetest.DeviceAuthorizationSuite(t, func(*testing.T) oidcprovider.DeviceAuthorizationStore {
				return &releaseFirstDevices{MemoryDeviceAuthorizationStore: oidcprovider.NewMemoryDeviceAuthorizationStore()}
			})
		}),
		FailsCase: "a refused create leaves an expired holder's user code where it was",
		FailsWith: "a refused create released the holder's user code",
	},
	{
		// Serialised under a lock of each instance, it passes on one instance and must be
		// caught once its racers are split between two.
		Name: "device-races-instance-lock",
		Run: inBackend(func(t *testing.T) {
			storetest.RunDeviceAuthorizationRaces(t, raceDeviceHarness(deviceRaceInstanceLock, true))
		}),
		FailsCase: storetest.DeviceClaimRaceName,
		FailsWith: "more than one successful claim",
	},
	{
		// It releases an expired holder and inserts in two steps, and decides every other
		// create in one, so only the race over an expired holder meets the gap.
		Name: "device-races-release-then-insert",
		Run: inBackend(func(t *testing.T) {
			storetest.RunDeviceAuthorizationRaces(t, raceDeviceHarness(deviceRaceReleaseThenInsert, false))
		}),
		FailsCase: storetest.DeviceCreateOverExpiredRaceName,
		FailsWith: "more than one successful create",
	},
}

// deviceTransitionClockCase is the case a store judging a transition's expiry by its own
// clock fails.
const deviceTransitionClockCase = "transitions judge expiry by the time given, never their own clock"

// deviceBrokenVar names the variant TestBrokenDeviceConformance runs.
const deviceBrokenVar = "STORETEST_BROKEN_DEVICE"

// TestBrokenDeviceConformance is the child half of TestBrokenDeviceStoresAreCaught.
func TestBrokenDeviceConformance(t *testing.T) {
	storefix.RunBrokenChild(t, deviceBrokenVar, "TestBrokenDeviceStoresAreCaught", deviceVariants)
}

// TestBrokenDeviceStoresAreCaught checks that the device authorization suite fails against
// a store judging time by a clock of its own, at the case guarding it, and says so.
func TestBrokenDeviceStoresAreCaught(t *testing.T) {
	t.Parallel()

	storefix.CatchBrokenVariants(t, deviceBrokenVar, "TestBrokenDeviceConformance", providerBackend, deviceVariants)
}

// precisionDevices is the memory store keeping every time it is given, stored or compared
// against, at the precision keep leaves, as a database column of that precision does.
type precisionDevices struct {
	*oidcprovider.MemoryDeviceAuthorizationStore

	keep func(time.Time) time.Time
}

// precisionDevicesOf returns a factory of precisionDevices keeping times by keep.
func precisionDevicesOf(keep func(time.Time) time.Time) func(*testing.T) oidcprovider.DeviceAuthorizationStore {
	return func(*testing.T) oidcprovider.DeviceAuthorizationStore {
		return precisionDevices{MemoryDeviceAuthorizationStore: oidcprovider.NewMemoryDeviceAuthorizationStore(), keep: keep}
	}
}

func (p precisionDevices) Create(ctx context.Context, record *oidcprovider.DeviceAuthorization, now time.Time) error {
	if record != nil {
		kept := *record
		kept.IssuedAt, kept.ExpiresAt, kept.LastPolledAt = p.keep(kept.IssuedAt), p.keep(kept.ExpiresAt), p.keep(kept.LastPolledAt)
		record = &kept
	}

	return p.MemoryDeviceAuthorizationStore.Create(ctx, record, p.keep(now))
}

func (p precisionDevices) LoadByUserCode(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
	return p.MemoryDeviceAuthorizationStore.LoadByUserCode(ctx, digest, p.keep(now))
}

func (p precisionDevices) Claim(ctx context.Context, deviceID id.ID, flowDigest []byte, now time.Time) error {
	return p.MemoryDeviceAuthorizationStore.Claim(ctx, deviceID, flowDigest, p.keep(now))
}

func (p precisionDevices) Decide(ctx context.Context, deviceID id.ID, approval *oidcprovider.DeviceApproval, now time.Time) error {
	return p.MemoryDeviceAuthorizationStore.Decide(ctx, deviceID, approval, p.keep(now))
}

func (p precisionDevices) RecordPoll(ctx context.Context, deviceID id.ID, seenPolls int, at time.Time, interval time.Duration) error {
	return p.MemoryDeviceAuthorizationStore.RecordPoll(ctx, deviceID, seenPolls, p.keep(at), interval)
}

func (p precisionDevices) Spend(ctx context.Context, deviceID id.ID, now time.Time) error {
	return p.MemoryDeviceAuthorizationStore.Spend(ctx, deviceID, p.keep(now))
}

func (p precisionDevices) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	return p.MemoryDeviceAuthorizationStore.DeleteExpired(ctx, p.keep(now))
}

// releaseFirstDevices is the memory store releasing an expired holder's user code before
// it checks the record a Create is given, so a refused create still releases it. It does
// so through a decoy: a record of its own over the same user code, expired when created,
// whose create releases the holder.
type releaseFirstDevices struct {
	*oidcprovider.MemoryDeviceAuthorizationStore

	decoys atomic.Int64
}

func (r *releaseFirstDevices) Create(ctx context.Context, record *oidcprovider.DeviceAuthorization, now time.Time) error {
	if record != nil && len(record.UserCodeDigest) > 0 {
		n := r.decoys.Add(1)
		decoy := &oidcprovider.DeviceAuthorization{
			ID:               id.MustParse(fmt.Sprintf("01926a4e-0000-7000-9000-%012x", n)),
			DeviceCodeDigest: fmt.Appendf(nil, "decoy-%d", n),
			UserCodeDigest:   record.UserCodeDigest,
			IssuedAt:         now,
			ExpiresAt:        now,
		}
		// A live holder refuses the decoy, which is all this defect needs: the release is
		// the point, and only an expired holder is released.
		_ = r.MemoryDeviceAuthorizationStore.Create(ctx, decoy, now)
	}

	return r.MemoryDeviceAuthorizationStore.Create(ctx, record, now)
}

// deviceRaceDefect is what a raceDevices gets wrong.
type deviceRaceDefect int

const (
	// deviceRaceConforming decides every write in one step.
	deviceRaceConforming deviceRaceDefect = iota
	// deviceRaceInstanceLock reads, yields and writes under a lock of its own instance,
	// which serialises the callers of one instance and no others.
	deviceRaceInstanceLock
	// deviceRaceReleaseThenInsert releases an expired holder's user code and inserts the
	// new record in two steps, and decides every other write in one.
	deviceRaceReleaseThenInsert
)

// deviceTable is the state the instances of one raceDevices share, as replicas share a
// database. mu guards every field and every record in it.
type deviceTable struct {
	mu       sync.Mutex
	records  map[id.ID]*oidcprovider.DeviceAuthorization
	byDevice map[string]id.ID
	byUser   map[string]id.ID
}

// raceDevices is one instance of a device authorization store over a shared table, for
// RunDeviceAuthorizationRaces alone: it implements the calls those races make, and
// embeds the port, nil, for the rest.
type raceDevices struct {
	oidcprovider.DeviceAuthorizationStore

	defect   deviceRaceDefect
	table    *deviceTable
	instance sync.Mutex
}

// raceDeviceHarness is a harness over one shared table of raceDevices carrying d. With
// replicas, NewReplica returns another instance over that table; without, both return one.
func raceDeviceHarness(d deviceRaceDefect, replicas bool) storetest.DurableHarness[oidcprovider.DeviceAuthorizationStore] {
	table := &deviceTable{
		records:  make(map[id.ID]*oidcprovider.DeviceAuthorization),
		byDevice: make(map[string]id.ID),
		byUser:   make(map[string]id.ID),
	}
	one := &raceDevices{defect: d, table: table}
	h := fakeHarness(func(*testing.T) oidcprovider.DeviceAuthorizationStore { return one })
	if replicas {
		h.NewReplica = func(*testing.T) oidcprovider.DeviceAuthorizationStore {
			return &raceDevices{defect: d, table: table}
		}
	}
	h.PoolSize = storetest.DeviceRaceRacers

	return h
}

// errDeviceHeld refuses a create whose identifier or device digest is held.
var errDeviceHeld = errors.New("device authorization held")

// copyDevice returns a copy of r that shares nothing a caller could change.
func copyDevice(r *oidcprovider.DeviceAuthorization) *oidcprovider.DeviceAuthorization {
	out := *r
	out.DeviceCodeDigest = slices.Clone(r.DeviceCodeDigest)
	out.UserCodeDigest = slices.Clone(r.UserCodeDigest)
	out.ClaimFlowDigest = slices.Clone(r.ClaimFlowDigest)
	if r.Approval != nil {
		a := *r.Approval
		out.Approval = &a
	}

	return &out
}

// gap is the window between a read and a write that a real store's round trips open.
func gap() { time.Sleep(time.Millisecond) }

func (s *raceDevices) Create(_ context.Context, record *oidcprovider.DeviceAuthorization, now time.Time) error {
	if s.defect == deviceRaceInstanceLock {
		s.instance.Lock()
		defer s.instance.Unlock()
	}

	t := s.table
	t.mu.Lock()
	if _, held := t.records[record.ID]; held {
		t.mu.Unlock()
		return errDeviceHeld
	}
	if _, held := t.byDevice[string(record.DeviceCodeDigest)]; held {
		t.mu.Unlock()
		return errDeviceHeld
	}
	holderID, held := t.byUser[string(record.UserCodeDigest)]
	if held && now.Before(t.records[holderID].ExpiresAt) {
		t.mu.Unlock()
		return oidcprovider.ErrUserCodeTaken
	}
	if s.defect == deviceRaceInstanceLock || (s.defect == deviceRaceReleaseThenInsert && held) {
		t.mu.Unlock()
		gap()
		t.mu.Lock()
	}
	defer t.mu.Unlock()

	if held {
		t.records[holderID].UserCodeDigest = nil
	}
	stored := copyDevice(record)
	t.records[stored.ID] = stored
	t.byDevice[string(stored.DeviceCodeDigest)] = stored.ID
	t.byUser[string(stored.UserCodeDigest)] = stored.ID

	return nil
}

func (s *raceDevices) LoadByDeviceCode(_ context.Context, digest []byte) (*oidcprovider.DeviceAuthorization, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	deviceID, ok := s.table.byDevice[string(digest)]
	if !ok {
		return nil, oidcprovider.ErrNotFound
	}

	return copyDevice(s.table.records[deviceID]), nil
}

func (s *raceDevices) LoadByUserCode(_ context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	deviceID, ok := s.table.byUser[string(digest)]
	if !ok || !now.Before(s.table.records[deviceID].ExpiresAt) {
		return nil, oidcprovider.ErrNotFound
	}

	return copyDevice(s.table.records[deviceID]), nil
}

// transition moves record deviceID by apply when allowed holds of it, and answers
// oidcprovider.ErrNotFound otherwise.
func (s *raceDevices) transition(deviceID id.ID, allowed func(*oidcprovider.DeviceAuthorization) bool, apply func(*oidcprovider.DeviceAuthorization)) error {
	t := s.table
	if s.defect == deviceRaceInstanceLock {
		s.instance.Lock()
		defer s.instance.Unlock()

		t.mu.Lock()
		r := t.records[deviceID]
		pass := r != nil && allowed(r)
		t.mu.Unlock()
		if !pass {
			return oidcprovider.ErrNotFound
		}
		gap()
		t.mu.Lock()
		apply(r)
		t.mu.Unlock()

		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	r := t.records[deviceID]
	if r == nil || !allowed(r) {
		return oidcprovider.ErrNotFound
	}
	apply(r)

	return nil
}

// liveIn returns whether a record is in state and unexpired at now.
func liveIn(state oidcprovider.DeviceState, now time.Time) func(*oidcprovider.DeviceAuthorization) bool {
	return func(r *oidcprovider.DeviceAuthorization) bool { return r.State == state && now.Before(r.ExpiresAt) }
}

func (s *raceDevices) Claim(_ context.Context, deviceID id.ID, flowDigest []byte, now time.Time) error {
	return s.transition(deviceID, liveIn(oidcprovider.DeviceIssued, now), func(r *oidcprovider.DeviceAuthorization) {
		r.State, r.ClaimFlowDigest = oidcprovider.DeviceClaimed, slices.Clone(flowDigest)
	})
}

func (s *raceDevices) Decide(_ context.Context, deviceID id.ID, approval *oidcprovider.DeviceApproval, now time.Time) error {
	return s.transition(deviceID, liveIn(oidcprovider.DeviceClaimed, now), func(r *oidcprovider.DeviceAuthorization) {
		if approval == nil {
			r.State = oidcprovider.DeviceDenied
			return
		}
		a := *approval
		r.State, r.Approval = oidcprovider.DeviceApproved, &a
	})
}

func (s *raceDevices) RecordPoll(_ context.Context, deviceID id.ID, seenPolls int, at time.Time, interval time.Duration) error {
	return s.transition(deviceID, func(r *oidcprovider.DeviceAuthorization) bool {
		return (r.State == oidcprovider.DeviceIssued || r.State == oidcprovider.DeviceClaimed) && r.PollCount == seenPolls
	}, func(r *oidcprovider.DeviceAuthorization) {
		r.PollCount++
		r.LastPolledAt, r.Interval = at, interval
	})
}

func (s *raceDevices) Spend(_ context.Context, deviceID id.ID, now time.Time) error {
	return s.transition(deviceID, liveIn(oidcprovider.DeviceApproved, now), func(r *oidcprovider.DeviceAuthorization) {
		r.State = oidcprovider.DeviceSpent
	})
}

// TestDeviceConformingStoresPass checks that the device authorization suite and races
// pass stores that keep their contract in ways the memory store does not: times kept to
// the microsecond, as PostgreSQL keeps them, and writes decided in one step on a table
// that two instances share. A suite failing one of them holds stores to more than the
// contract asks.
func TestDeviceConformingStoresPass(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "a store truncating times to the microsecond",
			run: func(t *testing.T) {
				storetest.DeviceAuthorizationSuite(t, precisionDevicesOf(func(tm time.Time) time.Time { return tm.Truncate(time.Microsecond) }))
			},
		},
		{
			name: "a store rounding times to the microsecond",
			run: func(t *testing.T) {
				storetest.DeviceAuthorizationSuite(t, precisionDevicesOf(func(tm time.Time) time.Time { return tm.Round(time.Microsecond) }))
			},
		},
		{
			name: "a store deciding each write in one step, raced over two instances",
			run: func(t *testing.T) {
				storetest.RunDeviceAuthorizationRaces(t, raceDeviceHarness(deviceRaceConforming, true))
			},
		},
		{
			// The defect needs a second instance to show: on one, it conforms.
			name: "a store serialising under a lock of its instance, raced on one instance",
			run: func(t *testing.T) {
				storetest.RunDeviceAuthorizationRaces(t, raceDeviceHarness(deviceRaceInstanceLock, false))
			},
		},
	}

	// Every row must pass: each is a store keeping the contract.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t)
		})
	}
}
