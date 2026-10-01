package storefix

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/test/storetest"
)

// ErrRecoveryRefused is what the recovery stores' ambient probes return for a
// refusal. The recovery contracts refuse by reporting false or 0, never by an
// error, so the probes turn that report into this sentinel for the ambient
// suite to match.
var ErrRecoveryRefused = errors.New("storefix: the recovery store refused")

// RecoveryRaceRacers is how many callers race for each record of
// RecoveryRecordRace: 8 completions and 8 cancellations.
const RecoveryRaceRacers = 16

// recoveryCodeHash is the hash of the n-th code of user's race set.
func recoveryCodeHash(user string, n int) []byte {
	h := sha256.Sum256(fmt.Appendf(nil, "%s-code-%d", user, n))
	return h[:]
}

// recoveryRaceUser is the user of the i-th record of a recovery race.
func recoveryRaceUser(i int) identity.UserID {
	return identity.UserID(fmt.Sprintf("recovery-race-user-%d", i))
}

// RecoverySpendRace is the race over saved-code spends: Seed stores a set of
// 10 codes for user i, and every racer spends that user's first code, whose
// refusal is (false, nil) already. Check then requires the code spent and the
// other 9 left.
func RecoverySpendRace[S recovery.CodeStore]() storetest.Race[S] {
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			user := recoveryRaceUser(i)
			hashes := make([][]byte, 10)
			for n := range hashes {
				hashes[n] = recoveryCodeHash(string(user), n)
			}
			require.NoError(t, s.ReplaceSet(ctx, user, hashes, RaceProvenAt))
			return string(user)
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			return s.Spend(ctx, identity.UserID(key), recoveryCodeHash(key, 0), RaceAttemptAt)
		},
		Check: func(ctx context.Context, t *testing.T, s S, key string) {
			t.Helper()

			user := identity.UserID(key)
			matched, err := s.Match(ctx, user, recoveryCodeHash(key, 0))
			require.NoError(t, err)
			assert.False(t, matched, "%q: the raced code must be spent", key)
			n, err := s.Remaining(ctx, user)
			require.NoError(t, err)
			assert.Equal(t, 9, n, "%q: the codes left after the race", key)
		},
	}
}

// recoveryRaceRecord is a pending record of user, completable at
// RaceProvenAt, before every racer's RaceAttemptAt.
func recoveryRaceRecord(rid id.ID, user identity.UserID) recovery.Record {
	return recovery.Record{
		ID:        rid,
		User:      user,
		StartedAt: EnrolmentBegun,
		NotBefore: RaceProvenAt,
		Proven:    []recovery.AuthenticatorRef{{Kind: "saved", ID: "code"}, {Kind: "password", ID: "password"}},
		Reported:  []recovery.AuthenticatorRef{{Kind: recovery.MFAKind, ID: "totp"}},
	}
}

// RecoveryRecordRace is the race of completions against cancellations: Seed
// inserts user i's pending record, completable before the racers write, and
// of its RecoveryRaceRacers racers half complete it and half cancel it, each
// half split across both store instances. Exactly one of them must succeed,
// and Check then requires exactly one of the completion and cancellation
// times set.
func RecoveryRecordRace[S recovery.RecordStore]() storetest.Race[S] {
	gen := id.NewV7Generator()
	return storetest.Race[S]{
		Racers: RecoveryRaceRacers,
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			rid, err := gen.NewID()
			require.NoError(t, err)
			require.NoError(t, s.Insert(ctx, recoveryRaceRecord(rid, recoveryRaceUser(i))))
			return rid.String()
		},
		Attempt: func(ctx context.Context, s S, key string, racer int) (bool, error) {
			rid, err := id.Parse(key)
			if err != nil {
				return false, err
			}
			// The instance is racer%2, so the operation is taken from the
			// next bit: each operation runs on both instances.
			if (racer/2)%2 == 0 {
				return s.Complete(ctx, rid, RaceAttemptAt)
			}
			n, err := s.Cancel(ctx, rid, RaceAttemptAt)
			return n == 1, err
		},
		Check: func(ctx context.Context, t *testing.T, s S, key string) {
			t.Helper()

			r, err := s.Find(ctx, id.MustParse(key))
			require.NoError(t, err)
			assert.NotEqual(t, r.CompletedAt.IsZero(), r.CancelledAt.IsZero(),
				"record %s: exactly one of completed and cancelled must be set", key)
		},
	}
}

// recoveryAmbientUser is the user of the ambient suite's record i.
func recoveryAmbientUser(i int) identity.UserID {
	return identity.UserID(fmt.Sprintf("recovery-ambient-user-%d", i))
}

// RecoveryCodeAmbient is the ambient suite's view of the saved-code store:
// record i is a replacement of its own user's set, and the refusal a spend of
// a code the user does not hold, made after a replacement through the same
// context.
func RecoveryCodeAmbient[S recovery.CodeStore]() storetest.Ambient[S] {
	return storetest.Ambient[S]{
		Write: func(ctx context.Context, s S, i int) error {
			user := recoveryAmbientUser(i)
			return s.ReplaceSet(ctx, user, [][]byte{recoveryCodeHash(string(user), 0)}, time.Now())
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM recovery_codes WHERE user_id = $1)`,
				string(recoveryAmbientUser(i)))
		},
		Refuse: func(ctx context.Context, s S) error {
			const user identity.UserID = "recovery-ambient-refused"
			if err := s.ReplaceSet(ctx, user, [][]byte{recoveryCodeHash(string(user), 0)}, time.Now()); err != nil {
				return err
			}
			ok, err := s.Spend(ctx, user, recoveryCodeHash(string(user), 1), time.Now())
			if err != nil {
				return err
			}
			if ok {
				return errors.New("storefix: a code the user does not hold was spent")
			}
			return ErrRecoveryRefused
		},
		Refusal: ErrRecoveryRefused,
	}
}

// recoveryAmbientID is the identifier of the ambient suite's record i.
func recoveryAmbientID(i int) id.ID {
	return id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", 0x20000+i))
}

// RecoveryRecordAmbient is the ambient suite's view of the recovery-record
// store: record i is a pending record, and the refusal, through one context,
// a completion before the completable instant and then an insert over an
// identifier already stored. The contract makes that insert an error, which
// the probe reports as the refusal: a store that let it fail a statement
// would abort the caller's transaction, and the suite's next write fails.
func RecoveryRecordAmbient[S recovery.RecordStore]() storetest.Ambient[S] {
	return storetest.Ambient[S]{
		Write: func(ctx context.Context, s S, i int) error {
			return s.Insert(ctx, recoveryRaceRecord(recoveryAmbientID(i), recoveryAmbientUser(i)))
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM account_recoveries WHERE id = $1)`,
				recoveryAmbientID(i))
		},
		Refuse: func(ctx context.Context, s S) error {
			r := recoveryRaceRecord(recoveryAmbientID(999), "recovery-ambient-refused")
			if err := s.Insert(ctx, r); err != nil {
				return err
			}
			ok, err := s.Complete(ctx, r.ID, r.NotBefore.Add(-time.Minute))
			if err != nil {
				return err
			}
			if ok {
				return errors.New("storefix: a record was completed before its completable instant")
			}
			if err := s.Insert(ctx, r); err != nil {
				return fmt.Errorf("%w: %w", ErrRecoveryRefused, err)
			}
			return errors.New("storefix: an insert over a stored identifier succeeded")
		},
		Refusal: ErrRecoveryRefused,
	}
}
