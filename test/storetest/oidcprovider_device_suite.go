package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// The device suite's instants. Records are issued at suiteStart and expire at
// deviceExpires; deviceLive is a time between the two.
var (
	deviceExpires = suiteStart.Add(10 * time.Minute)
	deviceLive    = suiteStart.Add(time.Minute)
)

// deviceKeptPastExpiry is how long past its expiry a spent device authorization is kept,
// so that a replay of its code is still detected.
const deviceKeptPastExpiry = time.Minute

// deviceRecord returns an issued record n of opClient: identifier n, device-code digest n,
// user-code digest n+100, issued at suiteStart and expiring at deviceExpires.
func deviceRecord(n byte) *oidcprovider.DeviceAuthorization {
	return &oidcprovider.DeviceAuthorization{
		ID:               suiteID(int(n)),
		DeviceCodeDigest: opDigest(n),
		UserCodeDigest:   opDigest(n + 100),
		ClientID:         opClient,
		Scopes:           []string{"openid", "profile", "offline_access"},
		Resources:        []string{"https://api.example.com"},
		IssuedAt:         suiteStart,
		ExpiresAt:        deviceExpires,
		Interval:         5 * time.Second,
		State:            oidcprovider.DeviceIssued,
	}
}

// deviceApproval returns an approval by user under sign-in family n, of grant family
// 200+n, with every field set.
func deviceApproval(user string, n int) *oidcprovider.DeviceApproval {
	return &oidcprovider.DeviceApproval{
		User:          identity.UserID(user),
		GrantedScopes: []string{"openid", "profile"},
		SignIn:        opSignIn(user, n),
		GrantFamily:   suiteID(200 + n),
	}
}

// deviceIn returns deviceRecord(n) in state, with an approval when the state has one.
func deviceIn(n byte, state oidcprovider.DeviceState) *oidcprovider.DeviceAuthorization {
	r := deviceRecord(n)
	r.State = state
	if state != oidcprovider.DeviceIssued {
		r.ClaimFlowDigest = opDigest(n + 50)
	}
	if state == oidcprovider.DeviceApproved || state == oidcprovider.DeviceSpent {
		r.Approval = deviceApproval("u-1", int(n))
	}

	return r
}

// normalDevice returns r with its times in UTC, for an exact comparison.
func normalDevice(r *oidcprovider.DeviceAuthorization) oidcprovider.DeviceAuthorization {
	out := *r
	out.IssuedAt, out.ExpiresAt, out.LastPolledAt = utc(r.IssuedAt), utc(r.ExpiresAt), utc(r.LastPolledAt)
	if r.Approval != nil {
		a := *r.Approval
		a.SignIn = normalSignIn(a.SignIn)
		out.Approval = &a
	}

	return out
}

// withoutTimes returns a copy of r with its times zeroed, for a comparison of the rest when
// the times are compared at the precision a store keeps.
func withoutTimes(r *oidcprovider.DeviceAuthorization) *oidcprovider.DeviceAuthorization {
	out := *r
	out.IssuedAt, out.ExpiresAt, out.LastPolledAt = time.Time{}, time.Time{}, time.Time{}

	return &out
}

// loadDevice loads the record whose device-code digest is n, which must exist.
func loadDevice(ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, n byte) *oidcprovider.DeviceAuthorization {
	t.Helper()

	got, err := s.LoadByDeviceCode(ctx, opDigest(n))
	require.NoError(t, err)
	require.NotNil(t, got)

	return got
}

// requireDeviceAbsent requires no record to be found by device-code digest n.
func requireDeviceAbsent(ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, n byte) {
	t.Helper()

	_, err := s.LoadByDeviceCode(ctx, opDigest(n))
	require.ErrorIs(t, err, oidcprovider.ErrNotFound)
}

// DeviceAuthorizationSuite holds a device authorization store to the contract
// oidcprovider.DeviceAuthorizationStore documents, RunDeviceAuthorizationRaces's races
// included. newStore returns an empty store of its own for each case.
//
// The races run on the one store newStore returns, as the suite knows no other instance,
// so its store must take DeviceRaceRacers calls at once. A store that may be serialised
// under a lock of its own instance needs RunDeviceAuthorizationRaces as well, with a
// harness giving it a second one.
func DeviceAuthorizationSuite(t *testing.T, newStore func(t *testing.T) oidcprovider.DeviceAuthorizationStore) {
	t.Helper()

	runSuite(t, slices.Concat(
		deviceCases(),
		deviceTransitionCases(),
		deviceUnspentCases(),
		deviceSweepCases(),
	), withoutClock(newStore))

	h := oneInstanceHarness(newStore)
	h.PoolSize = DeviceRaceRacers
	RunDeviceAuthorizationRaces(t, h)
}

func deviceCases() []suiteCase[oidcprovider.DeviceAuthorizationStore] {
	type store = oidcprovider.DeviceAuthorizationStore

	return []suiteCase[store]{
		{
			name: "create and load by device code return every field",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				// Times carrying nanoseconds, which a store may keep to the microsecond and no coarser.
				r := deviceIn(1, oidcprovider.DeviceApproved)
				r.IssuedAt, r.ExpiresAt = preciseStart, preciseStart.Add(10*time.Minute)
				r.LastPolledAt, r.PollCount = preciseStart.Add(30*time.Second), 3
				r.Approval.Offline, r.Approval.EndsWithSignIn, r.Approval.SurvivesSignInEnd = true, true, true
				r.Approval.SignIn = federatedSignIn("u-1", 1, opIssuer, opUpstream)
				require.NoError(t, s.Create(ctx, r, deviceLive))

				got := loadDevice(ctx, t, s, 1)
				assertTimeMicro(t, r.IssuedAt, got.IssuedAt, "IssuedAt")
				assertTimeMicro(t, r.ExpiresAt, got.ExpiresAt, "ExpiresAt")
				assertTimeMicro(t, r.LastPolledAt, got.LastPolledAt, "LastPolledAt")
				assert.Equal(t, normalDevice(withoutTimes(r)), normalDevice(withoutTimes(got)))
			},
		},
		{
			name: "load by user code returns the unexpired record",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := deviceRecord(1)
				require.NoError(t, s.Create(ctx, r, deviceLive))

				got, err := s.LoadByUserCode(ctx, opDigest(101), deviceLive)
				require.NoError(t, err)
				assert.Equal(t, normalDevice(loadDevice(ctx, t, s, 1)), normalDevice(got))
			},
		},
		{
			name: "a missing record is not found, by either digest, and the error carries neither",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := deviceIn(1, oidcprovider.DeviceClaimed)
				require.NoError(t, s.Create(ctx, r, deviceLive))

				for name, digest := range map[string][]byte{
					"another device code":                opDigest(2),
					"the user code taken as device code": opDigest(101),
					"the flow digest":                    opDigest(51),
					"an empty digest":                    nil,
				} {
					_, err := s.LoadByDeviceCode(ctx, digest)
					require.ErrorIs(t, err, oidcprovider.ErrNotFound, name)
					if len(digest) > 0 {
						assertNoDigest(t, err, digest)
					}
				}
				for name, digest := range map[string][]byte{
					"another user code":                  opDigest(102),
					"the device code taken as user code": opDigest(1),
					"the flow digest":                    opDigest(51),
					"an empty digest":                    nil,
				} {
					_, err := s.LoadByUserCode(ctx, digest, deviceLive)
					require.ErrorIs(t, err, oidcprovider.ErrNotFound, name)
					if len(digest) > 0 {
						assertNoDigest(t, err, digest)
					}
				}
			},
		},
		{
			name: "a device digest already held is refused, and the record stays",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceRecord(1), deviceLive))
				before := loadDevice(ctx, t, s, 1)

				other := deviceRecord(2)
				other.DeviceCodeDigest = opDigest(1)
				other.ClientID = opOtherClient
				err := s.Create(ctx, other, deviceLive)
				require.Error(t, err)
				assertNoDigest(t, err, opDigest(1))

				assert.Equal(t, normalDevice(before), normalDevice(loadDevice(ctx, t, s, 1)))
				_, err = s.LoadByUserCode(ctx, opDigest(102), deviceLive)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "nothing of the refused record is stored")
			},
		},
		{
			name: "an identifier already held is refused, and the record stays",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceRecord(1), deviceLive))
				before := loadDevice(ctx, t, s, 1)

				other := deviceRecord(2)
				other.ID = suiteID(1)
				require.Error(t, s.Create(ctx, other, deviceLive))

				assert.Equal(t, normalDevice(before), normalDevice(loadDevice(ctx, t, s, 1)))
				requireDeviceAbsent(ctx, t, s, 2)
			},
		},
		{
			name: "a user code an unexpired record holds is taken, and nothing is stored",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceRecord(1), deviceLive))
				before := loadDevice(ctx, t, s, 1)

				other := deviceRecord(2)
				other.UserCodeDigest = opDigest(101)
				err := s.Create(ctx, other, deviceExpires.Add(-time.Microsecond))
				require.ErrorIs(t, err, oidcprovider.ErrUserCodeTaken, "the holder has not expired at the time given")
				assertNoDigest(t, err, opDigest(101))

				requireDeviceAbsent(ctx, t, s, 2)
				assert.Equal(t, normalDevice(before), normalDevice(loadDevice(ctx, t, s, 1)))
				got, err := s.LoadByUserCode(ctx, opDigest(101), deviceLive)
				require.NoError(t, err)
				assert.Equal(t, suiteID(1), got.ID)
			},
		},
		{
			name: "an expired record does not hold its user code against a new record",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceIn(1, oidcprovider.DeviceClaimed), deviceLive))

				next := deviceRecord(2)
				next.UserCodeDigest = opDigest(101)
				next.IssuedAt, next.ExpiresAt = deviceExpires, deviceExpires.Add(10*time.Minute)
				require.NoError(t, s.Create(ctx, next, deviceExpires), "the holder expired exactly at the time given")

				got, err := s.LoadByUserCode(ctx, opDigest(101), deviceExpires)
				require.NoError(t, err)
				assert.Equal(t, suiteID(2), got.ID, "the lookup finds the new record")
				assert.Equal(t, normalDevice(next), normalDevice(loadDevice(ctx, t, s, 2)))
			},
		},
		{
			name: "a spent record releasing its user code keeps its device code, for replay detection",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceIn(1, oidcprovider.DeviceSpent), deviceLive))

				next := deviceRecord(2)
				next.UserCodeDigest = opDigest(101)
				next.ExpiresAt = deviceExpires.Add(10 * time.Minute)
				require.NoError(t, s.Create(ctx, next, deviceExpires))

				spent := loadDevice(ctx, t, s, 1)
				assert.Equal(t, oidcprovider.DeviceSpent, spent.State)
				require.NotNil(t, spent.Approval)
				assert.Equal(t, suiteID(201), spent.Approval.GrantFamily)
				got, err := s.LoadByUserCode(ctx, opDigest(101), deviceExpires)
				require.NoError(t, err)
				assert.Equal(t, suiteID(2), got.ID)
			},
		},
		{
			name: "a record missing its identifier or a digest is refused, and nothing is stored",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.Error(t, s.Create(ctx, nil, deviceLive), "a nil record")

				noID := deviceRecord(1)
				noID.ID = id.Nil
				noDevice := deviceRecord(2)
				noDevice.DeviceCodeDigest = nil
				noUser := deviceRecord(3)
				noUser.UserCodeDigest = []byte{}
				for name, r := range map[string]*oidcprovider.DeviceAuthorization{
					"a zero identifier":         noID,
					"an empty device digest":    noDevice,
					"an empty user-code digest": noUser,
				} {
					require.Error(t, s.Create(ctx, r, deviceLive), name)
				}

				requireDeviceAbsent(ctx, t, s, 1)
				requireDeviceAbsent(ctx, t, s, 3)
				for _, user := range []byte{101, 102} {
					_, err := s.LoadByUserCode(ctx, opDigest(user), deviceLive)
					require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				}
			},
		},
		{
			name: "load by user code is not found from the instant the record expires",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceRecord(1), deviceLive))

				// A microsecond, the finest a store need keep.
				_, err := s.LoadByUserCode(ctx, opDigest(101), deviceExpires.Add(-time.Microsecond))
				require.NoError(t, err, "a microsecond before its expiry it is live")

				_, err = s.LoadByUserCode(ctx, opDigest(101), deviceExpires)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "at its expiry it has expired")
				assertNoDigest(t, err, opDigest(101))

				_, err = s.LoadByDeviceCode(ctx, opDigest(1))
				require.NoError(t, err, "by its device code an expired record is still returned, for the provider to judge")
			},
		},
		{
			name: "load by user code judges expiry by the time given, never its own clock",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				// A record the wall clock has long passed, asked for at a time before its expiry.
				past := deviceRecord(1)
				past.IssuedAt, past.ExpiresAt = longAgo, longAgo.Add(10*time.Minute)
				require.NoError(t, s.Create(ctx, past, longAgo))
				if _, err := s.LoadByUserCode(ctx, opDigest(101), longAgo.Add(time.Minute)); err != nil {
					t.Errorf("LoadByUserCode judged expiry by its own clock: a record live at the time given was refused: %v", err)
				}

				// A record the wall clock will not reach for decades, asked for after its expiry.
				future := deviceRecord(2)
				future.IssuedAt = time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC)
				future.ExpiresAt = future.IssuedAt.Add(10 * time.Minute)
				require.NoError(t, s.Create(ctx, future, future.IssuedAt))
				if got, err := s.LoadByUserCode(ctx, opDigest(102), future.ExpiresAt.Add(time.Hour)); err == nil {
					t.Errorf("LoadByUserCode judged expiry by its own clock: a record expired at the time given was returned (%v)", got.ID)
				}
			},
		},
		{
			name: "transitions judge expiry by the time given, never their own clock",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				at := longAgo.Add(time.Minute)
				for n, state := range map[byte]oidcprovider.DeviceState{
					1: oidcprovider.DeviceIssued, 2: oidcprovider.DeviceClaimed, 3: oidcprovider.DeviceApproved,
				} {
					r := deviceIn(n, state)
					r.IssuedAt, r.ExpiresAt = longAgo, longAgo.Add(10*time.Minute)
					require.NoError(t, s.Create(ctx, r, longAgo))
				}
				assert.NoError(t, s.Claim(ctx, suiteID(1), opDigest(51), at), "claim judged expiry by its own clock")
				assert.NoError(t, s.Decide(ctx, suiteID(2), nil, at), "decide judged expiry by its own clock")
				assert.NoError(t, s.Spend(ctx, suiteID(3), at), "spend judged expiry by its own clock")
			},
		},
		{
			name: "create judges a holder's expiry by the time given, never its own clock",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				// A holder the wall clock has long passed, live at the time given.
				past := deviceRecord(1)
				past.IssuedAt, past.ExpiresAt = longAgo, longAgo.Add(10*time.Minute)
				require.NoError(t, s.Create(ctx, past, longAgo))
				other := deviceRecord(2)
				other.UserCodeDigest = opDigest(101)
				other.IssuedAt, other.ExpiresAt = longAgo.Add(time.Minute), longAgo.Add(11*time.Minute)
				if err := s.Create(ctx, other, longAgo.Add(time.Minute)); !errors.Is(err, oidcprovider.ErrUserCodeTaken) {
					t.Errorf("Create judged a holder's expiry by its own clock: a holder live at the time given lost its user code (%v)", err)
				}

				// A holder the wall clock will not reach for decades, expired at the time given.
				future := deviceRecord(3)
				future.IssuedAt = time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC)
				future.ExpiresAt = future.IssuedAt.Add(10 * time.Minute)
				require.NoError(t, s.Create(ctx, future, future.IssuedAt))
				next := deviceRecord(4)
				next.UserCodeDigest = opDigest(103)
				next.IssuedAt, next.ExpiresAt = future.ExpiresAt.Add(time.Hour), future.ExpiresAt.Add(time.Hour+10*time.Minute)
				if err := s.Create(ctx, next, next.IssuedAt); err != nil {
					t.Errorf("Create judged a holder's expiry by its own clock: a holder expired at the time given kept its user code: %v", err)
				}
			},
		},
		{
			name: "a refused create leaves an expired holder's user code where it was",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				// Two holders expired at the time of the refused creates: one spent, kept a
				// minute past its expiry for replay detection, and one that expired moments
				// before. Both were created within the minute, so a store sweeping as it
				// creates has not yet forgotten either.
				at := deviceExpires
				spent := deviceIn(1, oidcprovider.DeviceSpent)
				claimed := deviceIn(2, oidcprovider.DeviceClaimed)
				claimed.ExpiresAt = at.Add(-10 * time.Second)
				holders := map[byte]*oidcprovider.DeviceAuthorization{1: spent, 2: claimed}
				for _, n := range []byte{1, 2} {
					require.NoError(t, s.Create(ctx, holders[n], at.Add(-40*time.Second)))
				}

				for _, n := range []byte{1, 2} {
					holder := holders[n]
					heldID := deviceRecord(n + 10)
					heldID.ID, heldID.UserCodeDigest = holder.ID, holder.UserCodeDigest
					heldID.IssuedAt, heldID.ExpiresAt = at, at.Add(10*time.Minute)
					require.Error(t, s.Create(ctx, heldID, at), "holder %d: its identifier is held", n)

					heldDevice := deviceRecord(n + 20)
					heldDevice.DeviceCodeDigest, heldDevice.UserCodeDigest = holder.DeviceCodeDigest, holder.UserCodeDigest
					heldDevice.IssuedAt, heldDevice.ExpiresAt = at, at.Add(10*time.Minute)
					require.Error(t, s.Create(ctx, heldDevice, at), "holder %d: its device digest is held", n)

					got := loadDevice(ctx, t, s, n)
					assert.Equal(t, holder.UserCodeDigest, got.UserCodeDigest,
						"holder %d: a refused create released the holder's user code", n)
				}

				for _, n := range []byte{1, 2} {
					holder := holders[n]
					next := deviceRecord(n + 30)
					next.UserCodeDigest = holder.UserCodeDigest
					next.IssuedAt, next.ExpiresAt = at, at.Add(10*time.Minute)
					require.NoError(t, s.Create(ctx, next, at), "holder %d expired, so a valid create takes its user code", n)

					got, err := s.LoadByUserCode(ctx, holder.UserCodeDigest, at)
					require.NoError(t, err)
					assert.Equal(t, next.ID, got.ID, "holder %d: the user code finds the new record", n)
				}
			},
		},
		{
			name: "a recorded poll keeps its time to the microsecond",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceRecord(1), deviceLive))

				at := preciseStart.Add(time.Minute)
				require.NoError(t, s.RecordPoll(ctx, suiteID(1), 0, at, 10*time.Second))

				got := loadDevice(ctx, t, s, 1)
				assertTimeMicro(t, at, got.LastPolledAt, "LastPolledAt")
				assert.Equal(t, 1, got.PollCount)
				assert.Equal(t, 10*time.Second, got.Interval)
			},
		},
		{
			name: "a stored record is a copy of the caller's",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := deviceIn(1, oidcprovider.DeviceApproved)
				require.NoError(t, s.Create(ctx, r, deviceLive))
				want := normalDevice(deviceIn(1, oidcprovider.DeviceApproved))
				scribbleDevice(r)

				assert.Equal(t, want, normalDevice(loadDevice(ctx, t, s, 1)))
			},
		},
		{
			name: "a loaded record is a copy of the stored one",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceIn(1, oidcprovider.DeviceApproved), deviceLive))
				want := normalDevice(loadDevice(ctx, t, s, 1))

				scribbleDevice(loadDevice(ctx, t, s, 1))
				byUser, err := s.LoadByUserCode(ctx, opDigest(101), deviceLive)
				require.NoError(t, err)
				scribbleDevice(byUser)

				assert.Equal(t, want, normalDevice(loadDevice(ctx, t, s, 1)))
			},
		},
		{
			name: "the approval and flow digest a transition stores are copies of the caller's",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceRecord(1), deviceLive))
				flow := opDigest(51)
				require.NoError(t, s.Claim(ctx, suiteID(1), flow, deviceLive))
				flow[0] ^= 0xff

				approval := deviceApproval("u-1", 1)
				require.NoError(t, s.Decide(ctx, suiteID(1), approval, deviceLive))
				approval.GrantedScopes[0], approval.SignIn.AMR[0], approval.User = "scribbled", "scribbled", "scribbled"

				got := loadDevice(ctx, t, s, 1)
				assert.Equal(t, opDigest(51), got.ClaimFlowDigest)
				require.NotNil(t, got.Approval)
				want := normalDevice(&oidcprovider.DeviceAuthorization{Approval: deviceApproval("u-1", 1)})
				assert.Equal(t, want.Approval, normalDevice(got).Approval)
			},
		},
	}
}

// deviceTransition is one of the store's transitions, as the table drives it.
type deviceTransition struct {
	name string
	// from are the states the transition leaves.
	from []oidcprovider.DeviceState
	// expires says the transition is refused at or after the record's expiry.
	expires bool
	// do runs the transition on record id at now, the record's poll count being polls.
	do func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore, id id.ID, polls int, now time.Time) error
	// apply changes want as the transition, succeeding at now, must have.
	apply func(want *oidcprovider.DeviceAuthorization, now time.Time)
}

// deviceTransitions returns every transition, with the states it leaves.
func deviceTransitions() []deviceTransition {
	claim := deviceTransition{
		name: "claim", from: []oidcprovider.DeviceState{oidcprovider.DeviceIssued}, expires: true,
		do: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore, id id.ID, _ int, now time.Time) error {
			return s.Claim(ctx, id, opDigest(77), now)
		},
		apply: func(want *oidcprovider.DeviceAuthorization, _ time.Time) {
			want.State, want.ClaimFlowDigest = oidcprovider.DeviceClaimed, opDigest(77)
		},
	}
	approve := deviceTransition{
		name: "approve", from: []oidcprovider.DeviceState{oidcprovider.DeviceClaimed}, expires: true,
		do: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore, id id.ID, _ int, now time.Time) error {
			return s.Decide(ctx, id, deviceApproval("u-7", 7), now)
		},
		apply: func(want *oidcprovider.DeviceAuthorization, _ time.Time) {
			want.State, want.Approval = oidcprovider.DeviceApproved, deviceApproval("u-7", 7)
		},
	}
	deny := deviceTransition{
		name: "deny", from: []oidcprovider.DeviceState{oidcprovider.DeviceClaimed}, expires: true,
		do: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore, id id.ID, _ int, now time.Time) error {
			return s.Decide(ctx, id, nil, now)
		},
		apply: func(want *oidcprovider.DeviceAuthorization, _ time.Time) {
			want.State, want.Approval = oidcprovider.DeviceDenied, nil
		},
	}
	// A poll is recorded only while the user has not answered, and judges no expiry.
	poll := deviceTransition{
		name: "record a poll", from: []oidcprovider.DeviceState{oidcprovider.DeviceIssued, oidcprovider.DeviceClaimed},
		do: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore, id id.ID, polls int, now time.Time) error {
			return s.RecordPoll(ctx, id, polls, now, 10*time.Second)
		},
		apply: func(want *oidcprovider.DeviceAuthorization, now time.Time) {
			want.PollCount++
			want.LastPolledAt, want.Interval = now, 10*time.Second
		},
	}
	spend := deviceTransition{
		name: "spend", from: []oidcprovider.DeviceState{oidcprovider.DeviceApproved}, expires: true,
		do: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore, id id.ID, _ int, now time.Time) error {
			return s.Spend(ctx, id, now)
		},
		apply: func(want *oidcprovider.DeviceAuthorization, _ time.Time) { want.State = oidcprovider.DeviceSpent },
	}

	return []deviceTransition{claim, approve, deny, poll, spend}
}

// deviceStates are every state a record can be in.
var deviceStates = []oidcprovider.DeviceState{
	oidcprovider.DeviceIssued, oidcprovider.DeviceClaimed, oidcprovider.DeviceApproved,
	oidcprovider.DeviceDenied, oidcprovider.DeviceSpent,
}

// deviceStateNames names the states in case names.
var deviceStateNames = map[oidcprovider.DeviceState]string{
	oidcprovider.DeviceIssued: "issued", oidcprovider.DeviceClaimed: "claimed", oidcprovider.DeviceApproved: "approved",
	oidcprovider.DeviceDenied: "denied", oidcprovider.DeviceSpent: "spent",
}

// requireRefusedUnchanged requires err to be a lost compare carrying no digest, and the
// record to be what before holds.
func requireRefusedUnchanged(
	ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, err error, before *oidcprovider.DeviceAuthorization, why string,
) {
	t.Helper()

	require.ErrorIs(t, err, oidcprovider.ErrNotFound, why)
	for _, digest := range [][]byte{before.DeviceCodeDigest, before.UserCodeDigest, opDigest(77)} {
		assertNoDigest(t, err, digest)
	}
	got, loadErr := s.LoadByDeviceCode(ctx, before.DeviceCodeDigest)
	require.NoError(t, loadErr)
	assert.Equal(t, normalDevice(before), normalDevice(got), "a refused transition writes nothing")
}

// deviceTransitionCases drive every transition from every state, at a live time, at the
// record's expiry, and against an unknown record.
func deviceTransitionCases() []suiteCase[oidcprovider.DeviceAuthorizationStore] {
	type store = oidcprovider.DeviceAuthorizationStore

	var cases []suiteCase[store]
	for _, tr := range deviceTransitions() {
		for _, state := range deviceStates {
			allowed := slices.Contains(tr.from, state)
			outcome := "is refused, and writes nothing"
			if allowed {
				outcome = "succeeds, and changes only what it moves"
			}
			cases = append(cases, suiteCase[store]{
				name: fmt.Sprintf("%s from %s %s", tr.name, deviceStateNames[state], outcome),
				assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
					r := deviceIn(1, state)
					r.PollCount, r.LastPolledAt = 2, suiteStart.Add(20*time.Second)
					require.NoError(t, s.Create(ctx, r, deviceLive))
					before := loadDevice(ctx, t, s, 1)

					err := tr.do(ctx, s, suiteID(1), 2, deviceLive)
					if !allowed {
						requireRefusedUnchanged(ctx, t, s, err, before, "a transition from a state it does not leave")
						return
					}
					require.NoError(t, err)
					want := before
					tr.apply(want, deviceLive)
					assert.Equal(t, normalDevice(want), normalDevice(loadDevice(ctx, t, s, 1)))
				},
			})
		}

		cases = append(cases, suiteCase[store]{
			name: tr.name + " of an unknown record is not found",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceIn(1, tr.from[0]), deviceLive))
				before := loadDevice(ctx, t, s, 1)

				err := tr.do(ctx, s, suiteID(9), 0, deviceLive)
				requireRefusedUnchanged(ctx, t, s, err, before, "no record has this identifier")
			},
		})

		if !tr.expires {
			continue
		}
		cases = append(cases, suiteCase[store]{
			name: tr.name + " at the record's expiry is refused, and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceIn(1, tr.from[0]), deviceLive))
				before := loadDevice(ctx, t, s, 1)

				err := tr.do(ctx, s, suiteID(1), 0, deviceExpires)
				requireRefusedUnchanged(ctx, t, s, err, before, "expired exactly at the time given")
			},
		})
	}

	return append(cases,
		suiteCase[store]{
			name: "record a poll with a stale count is refused, and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := deviceRecord(1)
				r.PollCount = 2
				require.NoError(t, s.Create(ctx, r, deviceLive))
				before := loadDevice(ctx, t, s, 1)

				for _, seen := range []int{0, 1, 3} {
					err := s.RecordPoll(ctx, suiteID(1), seen, deviceLive, 10*time.Second)
					requireRefusedUnchanged(ctx, t, s, err, before, fmt.Sprintf("seen %d polls, and %d are recorded", seen, 2))
				}

				require.NoError(t, s.RecordPoll(ctx, suiteID(1), 2, deviceLive, 10*time.Second))
				err := s.RecordPoll(ctx, suiteID(1), 2, deviceLive, 10*time.Second)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "the count a poll saw is spent by recording it")
				assert.Equal(t, 3, loadDevice(ctx, t, s, 1).PollCount)
			},
		},
		suiteCase[store]{
			name: "claim with an empty flow digest is refused, and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, deviceRecord(1), deviceLive))
				before := loadDevice(ctx, t, s, 1)

				for _, flow := range [][]byte{nil, {}} {
					require.Error(t, s.Claim(ctx, suiteID(1), flow, deviceLive))
					assert.Equal(t, normalDevice(before), normalDevice(loadDevice(ctx, t, s, 1)))
				}
			},
		},
	)
}

// deviceUnspentCases hold the store's UnspentCodes to listing the families of approved
// records, as a grant store reaches an approval the device has not exchanged.
func deviceUnspentCases() []suiteCase[oidcprovider.DeviceAuthorizationStore] {
	type store = oidcprovider.DeviceAuthorizationStore

	// approved returns approved record n under signIn, of grant family 200+n.
	approved := func(n byte, signIn oidcprovider.SignIn) *oidcprovider.DeviceAuthorization {
		r := deviceIn(n, oidcprovider.DeviceApproved)
		r.Approval.User, r.Approval.SignIn = signIn.User, signIn

		return r
	}
	create := func(ctx context.Context, t *testing.T, s store, records ...*oidcprovider.DeviceAuthorization) {
		t.Helper()
		for _, r := range records {
			require.NoError(t, s.Create(ctx, r, deviceLive))
		}
	}

	cases := []suiteCase[store]{
		{
			name: "only approved and spent records are listed, expired ones included",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				for n, state := range deviceStates {
					create(ctx, t, s, deviceIn(byte(n+1), state))
				}
				expired := deviceIn(9, oidcprovider.DeviceApproved)
				expired.IssuedAt, expired.ExpiresAt = longAgo, longAgo.Add(time.Minute)
				require.NoError(t, s.Create(ctx, expired, longAgo))
				want := []id.ID{suiteID(203), suiteID(205), suiteID(209)}

				got, err := s.UnspentBySignIn(ctx, oidcprovider.SignInSelector{User: "u-1"}, true)
				require.NoError(t, err)
				assert.ElementsMatch(t, want, got, "by sign-in")

				got, err = s.UnspentByClient(ctx, "u-1", opClient)
				require.NoError(t, err)
				assert.ElementsMatch(t, want, got, "by client")
			},
		},
		{
			name: "a record is listed once approved, and not before",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				create(ctx, t, s, deviceRecord(1))
				require.NoError(t, s.Claim(ctx, suiteID(1), opDigest(51), deviceLive))

				got, err := s.UnspentByClient(ctx, "u-1", opClient)
				require.NoError(t, err)
				assert.Empty(t, got, "a claimed record has no grant family yet")

				require.NoError(t, s.Decide(ctx, suiteID(1), deviceApproval("u-1", 1), deviceLive))
				got, err = s.UnspentByClient(ctx, "u-1", opClient)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(201)}, got)
			},
		},
		{
			name: "records of a client are listed for that user and client, offline and survivors included",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				online := approved(1, opSignIn("u-1", 1))
				offline := approved(2, opSignIn("u-1", 1))
				offline.Approval.Offline = true
				survivor := approved(3, opSignIn("u-1", 1))
				survivor.Approval.SurvivesSignInEnd = true
				otherClient := approved(4, opSignIn("u-1", 1))
				otherClient.ClientID = opOtherClient
				otherUser := approved(5, opSignIn("u-2", 1))
				create(ctx, t, s, online, offline, survivor, otherClient, otherUser)

				got, err := s.UnspentByClient(ctx, "u-1", opClient)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(201), suiteID(202), suiteID(203)}, got)
			},
		},
		{
			name: "an invalid selector is refused rather than matching everyone",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				create(ctx, t, s, approved(1, opSignIn("u-1", 1)))

				for name, sel := range invalidSelectors() {
					got, err := s.UnspentBySignIn(ctx, sel, true)
					require.ErrorIs(t, err, oidcprovider.ErrConfig, name)
					assert.Empty(t, got, name)
				}
			},
		},
		{
			name: "a selector naming a user stays within that user",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				create(ctx, t, s, approved(1, federatedSignIn("u-2", 2, opIssuer, opUpstream)))

				for name, sel := range selectorsWithinUser() {
					got, err := s.UnspentBySignIn(ctx, sel, true)
					require.NoError(t, err, name)
					assert.Empty(t, got, name)
				}
			},
		},
		{
			name: "no approval leaves nothing to list",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				got, err := s.UnspentBySignIn(ctx, oidcprovider.SignInSelector{User: "u-1"}, true)
				require.NoError(t, err)
				assert.Empty(t, got)

				got, err = s.UnspentByClient(ctx, "u-1", opClient)
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
	}

	for _, shape := range selectorShapes() {
		cases = append(cases, suiteCase[store]{
			name: "unspent by " + shape.name + ": lists the selected, and offline and survivors only when asked",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				online := approved(1, shape.in)
				offline := approved(2, shape.in)
				offline.Approval.Offline = true
				survivor := approved(3, shape.in)
				survivor.Approval.SurvivesSignInEnd = true
				tied := approved(4, shape.in)
				tied.Approval.Offline, tied.Approval.EndsWithSignIn = true, true
				unselected := approved(5, shape.out)
				create(ctx, t, s, online, offline, survivor, tied, unselected)

				got, err := s.UnspentBySignIn(ctx, shape.sel, false)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(201), suiteID(204)}, got,
					"offline and surviving records are left out unless asked, and one tied to its sign-in is not")

				got, err = s.UnspentBySignIn(ctx, shape.sel, true)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(201), suiteID(202), suiteID(203), suiteID(204)}, got)
			},
		})
	}

	return cases
}

// deviceSweepCases hold DeleteExpired to the caller's time and to the replay window.
func deviceSweepCases() []suiteCase[oidcprovider.DeviceAuthorizationStore] {
	type store = oidcprovider.DeviceAuthorizationStore

	return []suiteCase[store]{
		{
			name: "delete expired removes what has expired, but keeps a spent record a minute past its expiry",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				now := suiteStart.Add(time.Hour)
				records := []struct {
					n       byte
					state   oidcprovider.DeviceState
					expires time.Time
					kept    bool
				}{
					{1, oidcprovider.DeviceIssued, now.Add(-time.Second), false},
					{2, oidcprovider.DeviceClaimed, now.Add(-time.Second), false},
					{3, oidcprovider.DeviceApproved, now.Add(-time.Second), false},
					{4, oidcprovider.DeviceDenied, now.Add(-time.Second), false},
					{5, oidcprovider.DeviceIssued, now, false},
					{6, oidcprovider.DeviceIssued, now.Add(time.Second), true},
					{7, oidcprovider.DeviceApproved, now.Add(time.Second), true},
					{8, oidcprovider.DeviceSpent, now.Add(-30 * time.Second), true},
					{9, oidcprovider.DeviceSpent, now.Add(-deviceKeptPastExpiry + time.Microsecond), true},
					{10, oidcprovider.DeviceSpent, now.Add(-deviceKeptPastExpiry), false},
					{11, oidcprovider.DeviceSpent, now.Add(-2 * deviceKeptPastExpiry), false},
				}
				removed := 0
				for _, rec := range records {
					r := deviceIn(rec.n, rec.state)
					r.ExpiresAt = rec.expires
					require.NoError(t, s.Create(ctx, r, suiteStart))
					if !rec.kept {
						removed++
					}
				}

				n, err := s.DeleteExpired(ctx, now)
				require.NoError(t, err)
				assert.Equal(t, removed, n)
				for _, rec := range records {
					_, err := s.LoadByDeviceCode(ctx, opDigest(rec.n))
					if rec.kept {
						assert.NoError(t, err, "record %d (%s, expiring %v) must be kept", rec.n, deviceStateNames[rec.state], rec.expires)
					} else {
						assert.ErrorIs(t, err, oidcprovider.ErrNotFound,
							"record %d (%s, expiring %v) must be removed", rec.n, deviceStateNames[rec.state], rec.expires)
					}
				}
			},
		},
		{
			name: "delete expired judges by the caller's time, never the wall clock",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				past := deviceRecord(1)
				past.IssuedAt, past.ExpiresAt = longAgo, longAgo.Add(time.Hour)
				require.NoError(t, s.Create(ctx, past, longAgo))

				n, err := s.DeleteExpired(ctx, longAgo)
				require.NoError(t, err)
				assert.Zero(t, n, "at the caller's time it has not expired, though the wall clock has passed it")

				require.NoError(t, s.Create(ctx, deviceRecord(2), longAgo))
				n, err = s.DeleteExpired(ctx, suiteStart.Add(time.Hour))
				require.NoError(t, err)
				assert.Equal(t, 2, n, "at the caller's time both have expired, wherever the wall clock is")
			},
		},
	}
}

// scribbleDevice overwrites every value of r a store could have kept by reference.
func scribbleDevice(r *oidcprovider.DeviceAuthorization) {
	r.DeviceCodeDigest[0] ^= 0xff
	r.UserCodeDigest[0] ^= 0xff
	r.ClaimFlowDigest[0] ^= 0xff
	r.Scopes[0], r.Resources[0] = "scribbled", "scribbled"
	if r.Approval != nil {
		r.Approval.User = "scribbled"
		r.Approval.GrantedScopes[0] = "scribbled"
		r.Approval.SignIn.AMR[0] = "scribbled"
	}
}
