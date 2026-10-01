package storetest_test

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// The passkey stores' suites and races are proven here against in-process
// fakes: a conforming form, which every suite and race must pass, and forms
// carrying one defect each, which the suite or race guarding that defect must
// fail. The read-then-write forms check, yield the processor, then write, as
// a durable store would with a SELECT followed by an unconditional write.

// credDefect names the one defect a credFake carries.
type credDefect string

const (
	credConforming          credDefect = "conforming"
	credInsertReplaces      credDefect = "insert-replaces-duplicate"
	credInsertReadThenWrite credDefect = "insert-read-then-write"
	credFindAcrossUsers     credDefect = "find-across-users"
	credListUnordered       credDefect = "list-unordered"
	credCountActiveOnly     credDefect = "count-active-only"
	credFindSharesRecord    credDefect = "find-shares-record"
	credRecordEqual         credDefect = "record-accepts-equal-counter"
	credRecordRefusesZero   credDefect = "record-refuses-zero-counter"
	credRecordPending       credDefect = "record-pending"
	credRecordReadThenWrite credDefect = "record-read-then-write"
	credSuspendPending      credDefect = "suspend-pending"
	credUseSetsCounter      credDefect = "use-sets-counter"
	credUsePending          credDefect = "use-records-pending"
	credClearCombination    credDefect = "clear-accepts-combination"
	credClearKeepsCode      credDefect = "clear-keeps-code"
	credChargeNoCap         credDefect = "charge-no-cap"
	credChargeAtExpiry      credDefect = "charge-at-expiry"
	credRenameAcrossUsers   credDefect = "rename-across-users"
	credDeleteAwaitingAll   credDefect = "delete-awaiting-all-users"
)

// credTable is the state the instances of one fake credential store share,
// as replicas share a database.
type credTable struct {
	mu   sync.Mutex
	rows map[id.ID]*passkey.Credential
}

// credFake is one instance of an in-process CredentialStore over a shared
// table.
type credFake struct {
	defect credDefect
	table  *credTable
}

func newCredFake(d credDefect) *credFake {
	return &credFake{defect: d, table: &credTable{rows: map[id.ID]*passkey.Credential{}}}
}

// cloneCred is a deep copy of c.
func cloneCred(c *passkey.Credential) *passkey.Credential {
	cp := *c
	cp.CredentialID = bytes.Clone(c.CredentialID)
	cp.PublicKey = bytes.Clone(c.PublicKey)
	cp.Transports = slices.Clone(c.Transports)
	cp.AAGUID = bytes.Clone(c.AAGUID)
	cp.AttestationStatement = bytes.Clone(c.AttestationStatement)
	if c.EmailCode != nil {
		code := *c.EmailCode
		cp.EmailCode = &code
	}
	return &cp
}

// byCredID is the stored credential with credential ID credID, or nil. The
// caller holds the table lock.
func (s *credFake) byCredID(credID []byte) *passkey.Credential {
	for _, c := range s.table.rows {
		if bytes.Equal(c.CredentialID, credID) {
			return c
		}
	}
	return nil
}

func (s *credFake) Insert(_ context.Context, c *passkey.Credential) error {
	cp := cloneCred(c)

	if s.defect == credInsertReadThenWrite {
		s.table.mu.Lock()
		taken := s.byCredID(cp.CredentialID) != nil || s.table.rows[cp.ID] != nil
		s.table.mu.Unlock()
		if taken {
			return passkey.ErrDuplicateCredential
		}
		runtime.Gosched()
		s.table.mu.Lock()
		s.table.rows[cp.ID] = cp
		s.table.mu.Unlock()
		return nil
	}

	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	if old := s.byCredID(cp.CredentialID); old != nil {
		if s.defect != credInsertReplaces {
			return passkey.ErrDuplicateCredential
		}
		delete(s.table.rows, old.ID)
	}
	if s.table.rows[cp.ID] != nil {
		return passkey.ErrDuplicateCredential
	}
	s.table.rows[cp.ID] = cp
	return nil
}

func (s *credFake) out(c *passkey.Credential) *passkey.Credential {
	if s.defect == credFindSharesRecord {
		return c
	}
	return cloneCred(c)
}

func (s *credFake) FindByCredentialID(_ context.Context, credID []byte) (*passkey.Credential, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	c := s.byCredID(credID)
	if c == nil {
		return nil, passkey.ErrNotFound
	}
	return s.out(c), nil
}

func (s *credFake) Find(_ context.Context, user identity.UserID, cid id.ID) (*passkey.Credential, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	c := s.table.rows[cid]
	if c == nil || (c.User != user && s.defect != credFindAcrossUsers) {
		return nil, passkey.ErrNotFound
	}
	return s.out(c), nil
}

func (s *credFake) List(_ context.Context, user identity.UserID) ([]*passkey.Credential, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	var out []*passkey.Credential
	for _, c := range s.table.rows {
		if c.User == user {
			out = append(out, s.out(c))
		}
	}
	slices.SortFunc(out, func(a, b *passkey.Credential) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), bytes.Compare(a.ID[:], b.ID[:]))
	})
	if s.defect == credListUnordered {
		slices.Reverse(out)
	}
	return out, nil
}

func (s *credFake) Count(_ context.Context, user identity.UserID) (int, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	n := 0
	for _, c := range s.table.rows {
		if c.User == user && (s.defect != credCountActiveOnly || c.State == passkey.StateActive) {
			n++
		}
	}
	return n, nil
}

// recordable reports whether c may record signCount.
func (s *credFake) recordable(c *passkey.Credential, signCount uint32) bool {
	if c == nil {
		return false
	}
	if c.State != passkey.StateActive && (s.defect != credRecordPending || c.State != passkey.StatePending) {
		return false
	}
	switch s.defect {
	case credRecordEqual:
		return c.SignCount <= signCount
	case credRecordRefusesZero:
		return c.SignCount < signCount
	default:
		return c.SignCount < signCount || (c.SignCount == 0 && signCount == 0)
	}
}

func (s *credFake) RecordAssertion(
	_ context.Context, cid id.ID, signCount uint32, backupState bool, at time.Time,
) (bool, error) {
	if s.defect == credRecordReadThenWrite {
		s.table.mu.Lock()
		ok := s.recordable(s.table.rows[cid], signCount)
		s.table.mu.Unlock()
		if !ok {
			return false, nil
		}
		runtime.Gosched()
		s.table.mu.Lock()
		defer s.table.mu.Unlock()
		c := s.table.rows[cid]
		c.SignCount, c.BackupState, c.LastUsedAt = signCount, backupState, at
		return true, nil
	}

	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	c := s.table.rows[cid]
	if !s.recordable(c, signCount) {
		return false, nil
	}
	c.SignCount, c.BackupState, c.LastUsedAt = signCount, backupState, at
	return true, nil
}

func (s *credFake) RecordUse(_ context.Context, cid id.ID, backupState bool, at time.Time) (bool, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	c := s.table.rows[cid]
	if c == nil || (c.State != passkey.StateActive && (s.defect != credUsePending || c.State != passkey.StatePending)) {
		return false, nil
	}
	c.BackupState, c.LastUsedAt = backupState, at
	if s.defect == credUseSetsCounter {
		c.SignCount++
	}
	return true, nil
}

func (s *credFake) Suspend(_ context.Context, cid id.ID) (bool, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	c := s.table.rows[cid]
	if c == nil || (c.State != passkey.StateActive && (s.defect != credSuspendPending || c.State != passkey.StatePending)) {
		return false, nil
	}
	c.State = passkey.StateSuspended
	return true, nil
}

func (s *credFake) ClearReason(
	_ context.Context, user identity.UserID, cid id.ID, r passkey.PendingReason,
) (passkey.State, bool, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	single := r == passkey.AwaitingSavedCodes || r == passkey.AwaitingEmailCode
	c := s.table.rows[cid]
	if (!single && s.defect != credClearCombination) || c == nil || c.User != user ||
		c.State != passkey.StatePending || c.Pending&r == 0 {
		return 0, false, nil
	}
	c.Pending &^= r
	if r&passkey.AwaitingEmailCode != 0 && s.defect != credClearKeepsCode {
		c.EmailCode = nil
	}
	if c.Pending == 0 {
		c.State = passkey.StateActive
	}
	return c.State, true, nil
}

func (s *credFake) ChargeEmailAttempt(
	_ context.Context, user identity.UserID, cid id.ID, at time.Time,
) (*passkey.EmailCode, bool, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	c := s.table.rows[cid]
	if c == nil || c.User != user || c.State != passkey.StatePending ||
		c.Pending&passkey.AwaitingEmailCode == 0 || c.EmailCode == nil {
		return nil, false, nil
	}
	code := c.EmailCode
	expired := !at.Before(code.ExpiresAt)
	if s.defect == credChargeAtExpiry {
		expired = at.After(code.ExpiresAt)
	}
	if expired || (code.Attempts >= passkey.MaxEmailCodeAttempts && s.defect != credChargeNoCap) {
		return nil, false, nil
	}
	code.Attempts++
	out := *code
	return &out, true, nil
}

func (s *credFake) Rename(_ context.Context, user identity.UserID, cid id.ID, name string) (bool, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	c := s.table.rows[cid]
	if c == nil || (c.User != user && s.defect != credRenameAcrossUsers) {
		return false, nil
	}
	c.Name = name
	return true, nil
}

func (s *credFake) Delete(_ context.Context, user identity.UserID, cid id.ID) (bool, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	c := s.table.rows[cid]
	if c == nil || c.User != user {
		return false, nil
	}
	delete(s.table.rows, cid)
	return true, nil
}

func (s *credFake) deleteWhere(match func(*passkey.Credential) bool) int {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	n := 0
	for cid, c := range s.table.rows {
		if match(c) {
			delete(s.table.rows, cid)
			n++
		}
	}
	return n
}

func (s *credFake) DeleteAwaitingSavedCodes(_ context.Context, user identity.UserID) (int, error) {
	return s.deleteWhere(func(c *passkey.Credential) bool {
		return (c.User == user || s.defect == credDeleteAwaitingAll) && c.Pending&passkey.AwaitingSavedCodes != 0
	}), nil
}

func (s *credFake) DeleteUser(_ context.Context, user identity.UserID) (int, error) {
	return s.deleteWhere(func(c *passkey.Credential) bool { return c.User == user }), nil
}

// handleDefect names the one defect a handleFake carries.
type handleDefect string

const (
	handleConforming      handleDefect = "conforming"
	handleOverwrites      handleDefect = "assign-overwrites"
	handleReadThenWrite   handleDefect = "assign-read-then-write"
	handleAnyLength       handleDefect = "assign-accepts-any-length"
	handleEchoesTaken     handleDefect = "assign-echoes-taken-handle"
	handleReturnsOffer    handleDefect = "assign-returns-offer"
	handleUserForAnyUser  handleDefect = "userfor-finds-unknown"
	handleKeepsCallerCopy handleDefect = "assign-keeps-caller-slice"
)

// handleTable is the state the instances of one fake handle store share.
type handleTable struct {
	mu     sync.Mutex
	byUser map[identity.UserID][]byte
}

// handleFake is one instance of an in-process HandleStore over a shared
// table.
type handleFake struct {
	defect handleDefect
	table  *handleTable
}

func newHandleFake(d handleDefect) *handleFake {
	return &handleFake{defect: d, table: &handleTable{byUser: map[identity.UserID][]byte{}}}
}

// holder is the user holding h, or "". The caller holds the table lock.
func (s *handleFake) holder(h []byte) identity.UserID {
	for user, held := range s.table.byUser {
		if bytes.Equal(held, h) {
			return user
		}
	}
	return ""
}

func (s *handleFake) Assign(_ context.Context, user identity.UserID, offered []byte) ([]byte, error) {
	if len(offered) != passkey.HandleSize && s.defect != handleAnyLength {
		return nil, fmt.Errorf("%w: a user handle is %d bytes", passkey.ErrConfig, passkey.HandleSize)
	}
	stored := bytes.Clone(offered)
	if s.defect == handleKeepsCallerCopy {
		stored = offered
	}

	if s.defect == handleReadThenWrite {
		s.table.mu.Lock()
		held, ok := s.table.byUser[user]
		s.table.mu.Unlock()
		if ok {
			return bytes.Clone(held), nil
		}
		runtime.Gosched()
		s.table.mu.Lock()
		s.table.byUser[user] = stored
		s.table.mu.Unlock()
		return bytes.Clone(offered), nil
	}

	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	if held, ok := s.table.byUser[user]; ok && s.defect != handleOverwrites {
		if s.defect == handleReturnsOffer {
			return bytes.Clone(offered), nil
		}
		return bytes.Clone(held), nil
	}
	if other := s.holder(offered); other != "" && other != user {
		if s.defect == handleEchoesTaken {
			return nil, fmt.Errorf("handle %s is already held", hex.EncodeToString(offered))
		}
		return nil, errors.New("offered handle is already held")
	}
	s.table.byUser[user] = stored
	return bytes.Clone(stored), nil
}

func (s *handleFake) UserFor(_ context.Context, handle []byte) (identity.UserID, bool, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	user := s.holder(handle)
	if user == "" && s.defect == handleUserForAnyUser {
		for u := range s.table.byUser {
			return u, true, nil
		}
	}
	return user, user != "", nil
}

var (
	_ passkey.CredentialStore = (*credFake)(nil)
	_ passkey.HandleStore     = (*handleFake)(nil)
)

// passkeyBackend is the subtest every passkey variant runs under, so the
// guard finds the failed case beneath it.
const passkeyBackend = "fake"

func credSuiteVariant(d credDefect, failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: "passkey-credential-" + string(d),
		Run: func(t *testing.T) {
			t.Run(passkeyBackend, func(t *testing.T) {
				storetest.RunPasskeyCredentialStoreSuite(t, func(*testing.T) passkey.CredentialStore {
					return newCredFake(d)
				})
			})
		},
		FailsCase: failsCase,
	}
}

func handleSuiteVariant(d handleDefect, failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: "passkey-handle-" + string(d),
		Run: func(t *testing.T) {
			t.Run(passkeyBackend, func(t *testing.T) {
				storetest.RunPasskeyHandleStoreSuite(t, func(*testing.T) passkey.HandleStore {
					return newHandleFake(d)
				})
			})
		},
		FailsCase: failsCase,
	}
}

// credInstances is a fake harness whose instances carry d over one table.
func credInstances(d credDefect) storetest.DurableHarness[*credFake] {
	table := newCredFake(d).table
	return fakeHarness(func(*testing.T) *credFake { return &credFake{defect: d, table: table} })
}

// handleInstances is a fake harness whose instances carry d over one table.
func handleInstances(d handleDefect) storetest.DurableHarness[*handleFake] {
	table := newHandleFake(d).table
	return fakeHarness(func(*testing.T) *handleFake { return &handleFake{defect: d, table: table} })
}

func counterRace(t *testing.T, d credDefect) {
	storetest.RunConsumeRace(t, credInstances(d), storefix.PasskeyCounterRace[*credFake]())
}

func insertRace(t *testing.T, d credDefect) {
	storetest.RunLinkInsertRace(t, credInstances(d), storefix.PasskeyInsertRace[*credFake]())
}

func handleRace(t *testing.T, d handleDefect) {
	storetest.RunConsumeRace(t, handleInstances(d), storefix.PasskeyHandleRace[*handleFake]())
}

// passkeyRaceVariant runs race under the passkey backend subtest.
func passkeyRaceVariant(name string, race func(t *testing.T), failsCase, failsWith string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name:      "passkey-race-" + name,
		Run:       func(t *testing.T) { t.Run(passkeyBackend, race) },
		FailsCase: failsCase,
		FailsWith: failsWith,
	}
}

// passkeyVariants are the passkey variants the guard must see fail.
var passkeyVariants = []storefix.BrokenVariant{
	credSuiteVariant(credInsertReplaces,
		"a duplicate credential ID is refused whatever its user, and the stored one is unchanged"),
	credSuiteVariant(credFindAcrossUsers, "find is within the user: another user's credential is not found"),
	credSuiteVariant(credListUnordered, "list is every state of the user, oldest first, ties by library ID"),
	credSuiteVariant(credCountActiveOnly, "count is every state of the user"),
	credSuiteVariant(credFindSharesRecord, "a returned credential is the caller's own copy"),
	credSuiteVariant(credRecordEqual, "a counter going backwards, or equal and not zero, is refused and changes nothing"),
	credSuiteVariant(credRecordRefusesZero, "zero over zero is recorded and moves the last use"),
	credSuiteVariant(credRecordPending, "a pending or suspended credential is not recorded"),
	credSuiteVariant(credSuspendPending, "a pending or suspended credential is not suspended"),
	credSuiteVariant(credUseSetsCounter, "use is recorded for an active credential only, leaving the counter"),
	credSuiteVariant(credUsePending, "use is recorded for an active credential only, leaving the counter"),
	credSuiteVariant(credClearCombination,
		"a reason that is not exactly one known reason is refused and changes nothing"),
	credSuiteVariant(credClearKeepsCode,
		"two reasons cleared one by one: pending, then active, the emailed code dropped"),
	credSuiteVariant(credChargeNoCap, "the fifth attempt is the last, and a sixth is refused"),
	credSuiteVariant(credChargeAtExpiry, "a charge at the expiry is refused"),
	credSuiteVariant(credRenameAcrossUsers, "rename is within the user"),
	credSuiteVariant(credDeleteAwaitingAll,
		"delete awaiting saved codes removes only the user's credentials with the reason, and counts them"),
	handleSuiteVariant(handleOverwrites, "a later assignment returns the held handle and stores no other"),
	handleSuiteVariant(handleReturnsOffer, "a later assignment returns the held handle and stores no other"),
	handleSuiteVariant(handleAnyLength, "an offer of the wrong length is refused as a configuration error"),
	handleSuiteVariant(handleEchoesTaken, "an offer another user holds is refused, naming no handle bytes"),
	handleSuiteVariant(handleUserForAnyUser, "an unknown handle is held by no user"),
	handleSuiteVariant(handleKeepsCallerCopy, "the store keeps its own copies"),
	passkeyRaceVariant(string(credRecordReadThenWrite), func(t *testing.T) { counterRace(t, credRecordReadThenWrite) },
		consumeCase, "more than one successful consumption"),
	passkeyRaceVariant(string(credInsertReadThenWrite), func(t *testing.T) { insertRace(t, credInsertReadThenWrite) },
		insertCase, "more than one successful insert"),
	passkeyRaceVariant(string(handleReadThenWrite), func(t *testing.T) { handleRace(t, handleReadThenWrite) },
		consumeCase, "more than one successful consumption"),
}

// passkeyBrokenVar names the variant TestBrokenPasskeyConformance runs.
const passkeyBrokenVar = "STORETEST_BROKEN_PASSKEY"

// TestBrokenPasskeyConformance is the child half of
// TestPasskeySuitesCatchBrokenStores.
func TestBrokenPasskeyConformance(t *testing.T) {
	storefix.RunBrokenChild(t, passkeyBrokenVar, "TestPasskeySuitesCatchBrokenStores", passkeyVariants)
}

// TestPasskeySuitesCatchBrokenStores checks that each passkey suite and race
// fails against every fake carrying the defect it guards, at the case
// guarding it.
func TestPasskeySuitesCatchBrokenStores(t *testing.T) {
	t.Parallel()

	storefix.CatchBrokenVariants(t, passkeyBrokenVar, "TestBrokenPasskeyConformance", passkeyBackend, passkeyVariants)
}

// TestPasskeyFakesConform runs every passkey suite and race against the
// conforming fakes and the in-memory stores, which must pass: the defective
// forms differ from the conforming ones by their defect alone.
func TestPasskeyFakesConform(t *testing.T) {
	t.Parallel()

	t.Run("credential suite", func(t *testing.T) {
		storetest.RunPasskeyCredentialStoreSuite(t, func(*testing.T) passkey.CredentialStore {
			return newCredFake(credConforming)
		})
	})
	t.Run("handle suite", func(t *testing.T) {
		storetest.RunPasskeyHandleStoreSuite(t, func(*testing.T) passkey.HandleStore {
			return newHandleFake(handleConforming)
		})
	})
	t.Run("counter race", func(t *testing.T) { counterRace(t, credConforming) })
	t.Run("insert race", func(t *testing.T) { insertRace(t, credConforming) })
	t.Run("handle race", func(t *testing.T) { handleRace(t, handleConforming) })
	t.Run("memory counter race", func(t *testing.T) {
		storetest.RunConsumeRace(t, sharedHarness(passkey.NewMemoryCredentialStore),
			storefix.PasskeyCounterRace[*passkey.MemoryCredentialStore]())
	})
	t.Run("memory insert race", func(t *testing.T) {
		storetest.RunLinkInsertRace(t, sharedHarness(passkey.NewMemoryCredentialStore),
			storefix.PasskeyInsertRace[*passkey.MemoryCredentialStore]())
	})
	t.Run("memory handle race", func(t *testing.T) {
		storetest.RunConsumeRace(t, sharedHarness(passkey.NewMemoryHandleStore),
			storefix.PasskeyHandleRace[*passkey.MemoryHandleStore]())
	})
}
