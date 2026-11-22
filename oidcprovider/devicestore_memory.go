package oidcprovider

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// deviceKeptPastExpiry is how long past its expiry the default store keeps a spent device
// authorization: the window in which a replay of its device code still revokes the grant
// it created, as a code's replay does within codeKeptPastExpiry.
const deviceKeptPastExpiry = time.Minute

// The default store's refusals. Their text is fixed, so none can carry a digest.
var (
	errDeviceNil        = errors.New("oidcprovider: a device authorization must not be nil")
	errDeviceIncomplete = errors.New("oidcprovider: a device authorization needs an identifier, a device-code digest and a user-code digest")
	errDeviceHeld       = errors.New("oidcprovider: a device authorization with this identifier or device code is already stored")
	errDeviceNoFlow     = errors.New("oidcprovider: a claim needs the flow digest of the claiming browser")
)

// cloneDeviceApproval returns an approval sharing nothing with a.
func cloneDeviceApproval(a *DeviceApproval) *DeviceApproval {
	if a == nil {
		return nil
	}
	out := *a
	out.GrantedScopes = slices.Clone(a.GrantedScopes)
	out.SignIn = cloneSignIn(a.SignIn)

	return &out
}

// cloneDevice returns a record sharing nothing with r.
func cloneDevice(r *DeviceAuthorization) *DeviceAuthorization {
	out := *r
	out.DeviceCodeDigest = bytes.Clone(r.DeviceCodeDigest)
	out.UserCodeDigest = bytes.Clone(r.UserCodeDigest)
	out.ClaimFlowDigest = bytes.Clone(r.ClaimFlowDigest)
	out.Scopes = slices.Clone(r.Scopes)
	out.Resources = slices.Clone(r.Resources)
	out.Approval = cloneDeviceApproval(r.Approval)

	return &out
}

// expiredAt reports whether r has expired at now: when now is not before its ExpiresAt.
func (r *DeviceAuthorization) expiredAt(now time.Time) bool { return !now.Before(r.ExpiresAt) }

// sweptAt reports whether the default store forgets r at now: once it has expired, and a
// spent record only once its replay window has passed too.
func (r *DeviceAuthorization) sweptAt(now time.Time) bool {
	if r.State == DeviceSpent {
		return !now.Before(r.ExpiresAt.Add(deviceKeptPastExpiry))
	}

	return r.expiredAt(now)
}

// MemoryDeviceAuthorizationStore is the default DeviceAuthorizationStore, safe for
// concurrent use. It holds its own copies of records, on the way in and on the way out,
// and decides every transition under one lock, so no write is ever half applied.
//
// It is per process and not durable, so a device authorization does not survive a
// restart, and a deployment of more than one instance needs a shared store. Anyone may
// start a device authorization, so what it holds must stay bounded: a Create forgets
// every record DeleteExpired would, judged by the time the Create is given, at most once
// a minute of that time. It reads no clock of its own. A spent record is kept until a
// minute past its expiry, the window in which a replay of its device code is detected.
//
// Its zero value is an empty store, ready to use.
type MemoryDeviceAuthorizationStore struct {
	mu sync.Mutex
	// records holds every record by its ID, and byDevice and byUser index them by their
	// digests. byUser holds only a digest a record still holds: a released one is gone.
	records  map[id.ID]*DeviceAuthorization
	byDevice map[string]id.ID
	byUser   map[string]id.ID
	// lastSweep and nextSweep are the times, as Create was given them, of the last sweep
	// and of the next one due.
	lastSweep, nextSweep time.Time
}

var _ DeviceAuthorizationStore = (*MemoryDeviceAuthorizationStore)(nil)

// NewMemoryDeviceAuthorizationStore returns an empty store.
func NewMemoryDeviceAuthorizationStore() *MemoryDeviceAuthorizationStore {
	return &MemoryDeviceAuthorizationStore{}
}

// initLocked makes the zero value usable. The caller holds m.mu.
func (m *MemoryDeviceAuthorizationStore) initLocked() {
	if m.records == nil {
		m.records = make(map[id.ID]*DeviceAuthorization)
		m.byDevice = make(map[string]id.ID)
		m.byUser = make(map[string]id.ID)
	}
}

// sweepIfDueLocked forgets what DeleteExpired would at now, when a minute of the callers'
// time has passed since the last sweep, or when now is before it, as a caller's clock
// stepping back would otherwise put off every sweep until it caught up again.
func (m *MemoryDeviceAuthorizationStore) sweepIfDueLocked(now time.Time) {
	if now.Before(m.nextSweep) && !now.Before(m.lastSweep) {
		return
	}
	m.lastSweep, m.nextSweep = now, now.Add(memorySweepEvery)
	m.deleteExpiredLocked(now)
}

// Create implements DeviceAuthorizationStore.
func (m *MemoryDeviceAuthorizationStore) Create(_ context.Context, record *DeviceAuthorization, now time.Time) error {
	if record == nil {
		return errDeviceNil
	}
	if record.ID.IsZero() || len(record.DeviceCodeDigest) == 0 || len(record.UserCodeDigest) == 0 {
		return errDeviceIncomplete
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.initLocked()
	m.sweepIfDueLocked(now)

	if _, held := m.records[record.ID]; held {
		return errDeviceHeld
	}
	if _, held := m.byDevice[string(record.DeviceCodeDigest)]; held {
		return errDeviceHeld
	}
	userKey := string(record.UserCodeDigest)
	if holderID, held := m.byUser[userKey]; held {
		holder := m.records[holderID]
		if !holder.expiredAt(now) {
			return ErrUserCodeTaken
		}
		// Every check has passed, so releasing the expired holder's digest cannot be
		// left half done by a refusal.
		holder.UserCodeDigest = nil
	}

	stored := cloneDevice(record)
	m.records[stored.ID] = stored
	m.byDevice[string(stored.DeviceCodeDigest)] = stored.ID
	m.byUser[userKey] = stored.ID

	return nil
}

// LoadByDeviceCode implements DeviceAuthorizationStore.
func (m *MemoryDeviceAuthorizationStore) LoadByDeviceCode(_ context.Context, digest []byte) (*DeviceAuthorization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	recordID, ok := m.byDevice[string(digest)]
	if !ok || len(digest) == 0 {
		return nil, ErrNotFound
	}

	return cloneDevice(m.records[recordID]), nil
}

// LoadByUserCode implements DeviceAuthorizationStore.
func (m *MemoryDeviceAuthorizationStore) LoadByUserCode(_ context.Context, digest []byte, now time.Time) (*DeviceAuthorization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	recordID, ok := m.byUser[string(digest)]
	if !ok || len(digest) == 0 {
		return nil, ErrNotFound
	}
	r := m.records[recordID]
	if r.expiredAt(now) {
		return nil, ErrNotFound
	}

	return cloneDevice(r), nil
}

// transitionLocked returns the record deviceID names when it is in state from and, when
// judged, has not expired at now, or nil. The caller holds m.mu.
func (m *MemoryDeviceAuthorizationStore) transitionLocked(deviceID id.ID, from DeviceState, now time.Time) *DeviceAuthorization {
	r, ok := m.records[deviceID]
	if !ok || r.State != from || r.expiredAt(now) {
		return nil
	}

	return r
}

// Claim implements DeviceAuthorizationStore.
func (m *MemoryDeviceAuthorizationStore) Claim(_ context.Context, deviceID id.ID, flowDigest []byte, now time.Time) error {
	if len(flowDigest) == 0 {
		return errDeviceNoFlow
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	r := m.transitionLocked(deviceID, DeviceIssued, now)
	if r == nil {
		return ErrNotFound
	}
	r.State, r.ClaimFlowDigest = DeviceClaimed, bytes.Clone(flowDigest)

	return nil
}

// Decide implements DeviceAuthorizationStore.
func (m *MemoryDeviceAuthorizationStore) Decide(_ context.Context, deviceID id.ID, approval *DeviceApproval, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r := m.transitionLocked(deviceID, DeviceClaimed, now)
	if r == nil {
		return ErrNotFound
	}
	if approval == nil {
		r.State, r.Approval = DeviceDenied, nil

		return nil
	}
	r.State, r.Approval = DeviceApproved, cloneDeviceApproval(approval)

	return nil
}

// RecordPoll implements DeviceAuthorizationStore.
func (m *MemoryDeviceAuthorizationStore) RecordPoll(
	_ context.Context, deviceID id.ID, seenPolls int, at time.Time, interval time.Duration,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.records[deviceID]
	if !ok || (r.State != DeviceIssued && r.State != DeviceClaimed) || r.PollCount != seenPolls {
		return ErrNotFound
	}
	r.PollCount++
	r.LastPolledAt, r.Interval = at, interval

	return nil
}

// Spend implements DeviceAuthorizationStore.
func (m *MemoryDeviceAuthorizationStore) Spend(_ context.Context, deviceID id.ID, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r := m.transitionLocked(deviceID, DeviceApproved, now)
	if r == nil {
		return ErrNotFound
	}
	r.State = DeviceSpent

	return nil
}

// DeleteExpired implements DeviceAuthorizationStore.
func (m *MemoryDeviceAuthorizationStore) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.deleteExpiredLocked(now), nil
}

// deleteExpiredLocked forgets every record swept at now, with its index entries. The
// caller holds m.mu.
func (m *MemoryDeviceAuthorizationStore) deleteExpiredLocked(now time.Time) int {
	removed := 0
	for recordID, r := range m.records {
		if !r.sweptAt(now) {
			continue
		}
		delete(m.records, recordID)
		delete(m.byDevice, string(r.DeviceCodeDigest))
		if len(r.UserCodeDigest) > 0 && m.byUser[string(r.UserCodeDigest)] == recordID {
			delete(m.byUser, string(r.UserCodeDigest))
		}
		removed++
	}

	return removed
}

// UnspentBySignIn implements UnspentCodes.
func (m *MemoryDeviceAuthorizationStore) UnspentBySignIn(_ context.Context, sel SignInSelector, includeOffline bool) ([]id.ID, error) {
	if err := sel.Validate(); err != nil {
		return nil, err
	}

	return m.families(func(r *DeviceAuthorization) bool {
		a := r.Approval

		return (includeOffline || endsWithSignIn(a.Offline, a.EndsWithSignIn, a.SurvivesSignInEnd)) &&
			sel.matches(a.User, a.SignIn.Family, a.SignIn.ExternalIssuer, a.SignIn.ExternalSessionID)
	}), nil
}

// UnspentByClient implements UnspentCodes.
func (m *MemoryDeviceAuthorizationStore) UnspentByClient(_ context.Context, user identity.UserID, clientID string) ([]id.ID, error) {
	return m.families(func(r *DeviceAuthorization) bool { return r.Approval.User == user && r.ClientID == clientID }), nil
}

// families returns the grant family of each approved or spent record selected.
func (m *MemoryDeviceAuthorizationStore) families(selected func(*DeviceAuthorization) bool) []id.ID {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []id.ID
	for _, r := range m.records {
		if r.Approval != nil && (r.State == DeviceApproved || r.State == DeviceSpent) && selected(r) {
			out = append(out, r.Approval.GrantFamily)
		}
	}

	return out
}
