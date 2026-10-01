package recovery_test

import (
	"context"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// The operations a faults set can make fail. Each names the store and the
// method.
const (
	faultCodesReplaceSet   = "codes.ReplaceSet"
	faultCodesRemaining    = "codes.Remaining"
	faultCodesDeleteUser   = "codes.DeleteUser"
	faultSessionsDelete    = "sessions.DeleteByUser"
	faultSessionsCreate    = "sessions.Create"
	faultSessionsSave      = "sessions.Save"
	faultRecordsInsert     = "records.Insert"
	faultRecordsFind       = "records.Find"
	faultRecordsComplete   = "records.Complete"
	faultRecordsCancel     = "records.Cancel"
	faultTokensInsert      = "tokens.Insert"
	faultTokensConsume     = "tokens.Consume"
	faultRecordsNoComplete = "records.Complete=false"
)

// faults is a set of armed failures the wrapper stores below consult before
// passing a call to the real in-memory store they wrap. An armed operation
// fails without reaching the real store, so the store is left exactly as a
// failed write would leave it.
type faults struct {
	mu   sync.Mutex
	errs map[string]error
}

func newFaults() *faults { return &faults{errs: map[string]error{}} }

// arm makes op fail with err; a nil err disarms it.
func (f *faults) arm(op string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err == nil {
		delete(f.errs, op)

		return
	}

	f.errs[op] = err
}

func (f *faults) err(op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.errs[op]
}

// faultyCodeStore is a saved-code store that fails on demand.
type faultyCodeStore struct {
	recovery.CodeStore

	f *faults
}

func (s faultyCodeStore) ReplaceSet(ctx context.Context, user identity.UserID, hashes [][]byte, at time.Time) error {
	if err := s.f.err(faultCodesReplaceSet); err != nil {
		return err
	}

	return s.CodeStore.ReplaceSet(ctx, user, hashes, at)
}

func (s faultyCodeStore) Remaining(ctx context.Context, user identity.UserID) (int, error) {
	if err := s.f.err(faultCodesRemaining); err != nil {
		return 0, err
	}

	return s.CodeStore.Remaining(ctx, user)
}

func (s faultyCodeStore) DeleteUser(ctx context.Context, user identity.UserID) (int, error) {
	if err := s.f.err(faultCodesDeleteUser); err != nil {
		return 0, err
	}

	return s.CodeStore.DeleteUser(ctx, user)
}

// faultySessionStore is a session store that fails on demand.
type faultySessionStore struct {
	session.Store

	f *faults
}

func (s faultySessionStore) DeleteByUser(ctx context.Context, user identity.UserID) error {
	if err := s.f.err(faultSessionsDelete); err != nil {
		return err
	}

	return s.Store.DeleteByUser(ctx, user)
}

func (s faultySessionStore) Create(ctx context.Context, sess *session.Session) error {
	if err := s.f.err(faultSessionsCreate); err != nil {
		return err
	}

	return s.Store.Create(ctx, sess)
}

func (s faultySessionStore) Save(ctx context.Context, sess *session.Session) error {
	if err := s.f.err(faultSessionsSave); err != nil {
		return err
	}

	return s.Store.Save(ctx, sess)
}

// faultyRecordStore is a recovery record store that fails on demand. With
// faultRecordsNoComplete armed, Complete reports that it lost the race without
// writing anything.
type faultyRecordStore struct {
	recovery.RecordStore

	f *faults
}

func (s faultyRecordStore) Insert(ctx context.Context, r recovery.Record) error {
	if err := s.f.err(faultRecordsInsert); err != nil {
		return err
	}

	return s.RecordStore.Insert(ctx, r)
}

func (s faultyRecordStore) Find(ctx context.Context, rid id.ID) (*recovery.Record, error) {
	if err := s.f.err(faultRecordsFind); err != nil {
		return nil, err
	}

	return s.RecordStore.Find(ctx, rid)
}

func (s faultyRecordStore) Complete(ctx context.Context, rid id.ID, at time.Time) (bool, error) {
	if err := s.f.err(faultRecordsComplete); err != nil {
		return false, err
	}
	if s.f.err(faultRecordsNoComplete) != nil {
		return false, nil
	}

	return s.RecordStore.Complete(ctx, rid, at)
}

func (s faultyRecordStore) Cancel(ctx context.Context, rid id.ID, at time.Time) (int, error) {
	if err := s.f.err(faultRecordsCancel); err != nil {
		return 0, err
	}

	return s.RecordStore.Cancel(ctx, rid, at)
}

// recordingTokenStore is a one-time store that fails on demand and records
// every token inserted and consumed, as a consumer's store would see them.
type recordingTokenStore struct {
	*onetime.MemoryStore

	f *faults

	mu       sync.Mutex
	inserted []onetime.Token
	consumed []id.ID
}

func (s *recordingTokenStore) Insert(ctx context.Context, tok onetime.Token) error {
	if err := s.f.err(faultTokensInsert); err != nil {
		return err
	}

	s.mu.Lock()
	s.inserted = append(s.inserted, tok)
	s.mu.Unlock()

	return s.MemoryStore.Insert(ctx, tok)
}

func (s *recordingTokenStore) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	if err := s.f.err(faultTokensConsume); err != nil {
		return err
	}

	s.mu.Lock()
	s.consumed = append(s.consumed, tokenID)
	s.mu.Unlock()

	return s.MemoryStore.Consume(ctx, tokenID, at)
}

// purposes reports the purpose and subject of every token inserted, in order.
func (s *recordingTokenStore) purposes() [][2]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([][2]string, len(s.inserted))
	for i, t := range s.inserted {
		out[i] = [2]string{t.Purpose, t.Subject}
	}

	return out
}

// consumedPurposes reports the purpose of every token consumed, in order.
func (s *recordingTokenStore) consumedPurposes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []string
	for _, cid := range s.consumed {
		for _, t := range s.inserted {
			if t.ID == cid {
				out = append(out, t.Purpose)
			}
		}
	}

	return out
}
