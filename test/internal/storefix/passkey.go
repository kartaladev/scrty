package storefix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/test/storetest"
)

// ErrPasskeyRefused is what the passkey stores' ambient probes return for a
// refusal the contract reports by a false or by an error with no sentinel of
// its own (an offered handle another user holds), so the ambient suite has
// one sentinel to match.
var ErrPasskeyRefused = errors.New("storefix: the passkey store refused")

// PasskeyCreated is the instant the passkey fixtures are created at: whole
// seconds, UTC, so a durable store reads back exactly what was written.
var PasskeyCreated = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

// PasskeyRaceCount is the counter every counter-race credential is seeded
// with; each racer records PasskeyRaceCount+1.
const PasskeyRaceCount = 42

// derivedID is a library identifier derived from label, so fixtures name
// their records without a generator and two labels never share one.
func derivedID(label string) id.ID {
	sum := sha256.Sum256([]byte(label))

	return id.ID(sum[:16])
}

// PasskeyCredential is an active credential of user, with library ID cid and
// WebAuthn credential ID credID, every attribute set, created at
// PasskeyCreated.
func PasskeyCredential(cid id.ID, user identity.UserID, credID string) *passkey.Credential {
	return &passkey.Credential{
		ID:                   cid,
		User:                 user,
		CredentialID:         []byte(credID),
		PublicKey:            []byte("cose-key-" + credID),
		SignCount:            PasskeyRaceCount,
		BackupEligible:       true,
		Transports:           []string{"internal", "hybrid"},
		AAGUID:               bytes.Repeat([]byte{0xAA}, 16),
		AttestationFormat:    "packed",
		AttestationStatement: []byte("statement"),
		Name:                 "Laptop",
		CreatedAt:            PasskeyCreated,
		State:                passkey.StateActive,
	}
}

// PasskeyAwaitingCode returns c pending on its emailed code, code, good for
// ten minutes after PasskeyCreated.
func PasskeyAwaitingCode(c *passkey.Credential, code string) *passkey.Credential {
	c.State = passkey.StatePending
	c.Pending = passkey.AwaitingEmailCode
	c.EmailCode = &passkey.EmailCode{Code: code, ExpiresAt: PasskeyCreated.Add(10 * time.Minute)}

	return c
}

// passkeyRaceCredID is the credential ID of the counter-race credential cid.
func passkeyRaceCredID(cid string) []byte { return []byte("counter-race-" + cid) }

// PasskeyCounterRace is the race over RecordAssertion: Seed inserts an active
// credential i with counter PasskeyRaceCount, and every racer records the
// next counter on it. Exactly one recording wins, and Check then requires the
// counter, backup state and last use the winner recorded.
func PasskeyCounterRace[S passkey.CredentialStore]() storetest.Race[S] {
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			cid := derivedID("counter-race-" + strconv.Itoa(i))
			c := PasskeyCredential(cid, identity.UserID(fmt.Sprintf("counter-race-user-%d", i)), "")
			c.CredentialID = passkeyRaceCredID(cid.String())
			require.NoError(t, s.Insert(ctx, c))
			return cid.String()
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			cid, err := id.Parse(key)
			if err != nil {
				return false, err
			}
			return s.RecordAssertion(ctx, cid, PasskeyRaceCount+1, true, RaceAttemptAt)
		},
		Check: func(ctx context.Context, t *testing.T, s S, key string) {
			t.Helper()

			c, err := s.FindByCredentialID(ctx, passkeyRaceCredID(key))
			require.NoError(t, err)
			assert.Equal(t, uint32(PasskeyRaceCount+1), c.SignCount, "credential %s: the recorded counter", key)
			assert.True(t, c.BackupState, "credential %s: the recorded backup state", key)
			assert.True(t, RaceAttemptAt.Equal(c.LastUsedAt), "credential %s: last use is %v, want %v",
				key, c.LastUsedAt, RaceAttemptAt)
		},
	}
}

// passkeyInsertUser is the user racer racer inserts credential ID key for.
func passkeyInsertUser(key string, racer int) identity.UserID {
	return identity.UserID(key + "-user-" + strconv.Itoa(racer))
}

// PasskeyInsertRace is the race over Insert: record i is a credential ID no
// credential holds yet, and every racer inserts a credential with that ID for
// a user, and a library ID, of its own, so only the credential ID can decide.
// ErrDuplicateCredential is the refusal. Check then requires the credential
// ID held by exactly one of the racers' users.
func PasskeyInsertRace[S passkey.CredentialStore]() storetest.Race[S] {
	var (
		mu     sync.Mutex
		racers = map[string]int{}
	)

	return storetest.Race[S]{
		Seed: func(_ context.Context, _ *testing.T, _ S, i int) string {
			return fmt.Sprintf("insert-race-cred-%d", i)
		},
		Attempt: func(ctx context.Context, s S, key string, racer int) (bool, error) {
			mu.Lock()
			racers[key] = max(racers[key], racer+1)
			mu.Unlock()

			c := PasskeyCredential(derivedID(key+"-"+strconv.Itoa(racer)), passkeyInsertUser(key, racer), key)
			err := s.Insert(ctx, c)
			if errors.Is(err, passkey.ErrDuplicateCredential) {
				return false, nil
			}
			return err == nil, err
		},
		Check: func(ctx context.Context, t *testing.T, s S, key string) {
			t.Helper()

			c, err := s.FindByCredentialID(ctx, []byte(key))
			require.NoError(t, err, "credential ID %s must be stored", key)
			assert.True(t, strings.HasPrefix(string(c.User), key+"-user-"), "credential ID %s: held by %q", key, c.User)

			mu.Lock()
			n := racers[key]
			mu.Unlock()
			held := 0
			for racer := range n {
				count, err := s.Count(ctx, passkeyInsertUser(key, racer))
				require.NoError(t, err)
				held += count
			}
			assert.Equal(t, 1, held, "credential ID %s: credentials stored across the racers' users", key)
		},
	}
}

// PasskeyOffer is the HandleSize offer racer makes for user key, distinct
// for every (key, racer).
func PasskeyOffer(key string, racer int) []byte {
	sum := sha512.Sum512([]byte(key + "-offer-" + strconv.Itoa(racer)))

	return sum[:]
}

// PasskeyHandleRace is the race over Assign: record i is a user who holds no
// handle, and every racer assigns an offer of its own to that user. A racer
// wins when the handle it receives is its own offer, so exactly one wins.
// Check then requires every racer to have received that one handle, the user
// to hold it, and no other racer's offer to be held by anyone.
func PasskeyHandleRace[S passkey.HandleStore]() storetest.Race[S] {
	var (
		mu       sync.Mutex
		received = map[string][][]byte{}
		racers   = map[string]int{}
	)

	return storetest.Race[S]{
		Seed: func(_ context.Context, _ *testing.T, _ S, i int) string {
			return fmt.Sprintf("handle-race-user-%d", i)
		},
		Attempt: func(ctx context.Context, s S, key string, racer int) (bool, error) {
			offer := PasskeyOffer(key, racer)
			h, err := s.Assign(ctx, identity.UserID(key), offer)

			mu.Lock()
			racers[key] = max(racers[key], racer+1)
			if err == nil {
				received[key] = append(received[key], h)
			}
			mu.Unlock()

			return err == nil && bytes.Equal(h, offer), err
		},
		Check: func(ctx context.Context, t *testing.T, s S, key string) {
			t.Helper()

			held, err := s.Assign(ctx, identity.UserID(key), PasskeyOffer(key, -1))
			require.NoError(t, err)

			mu.Lock()
			got, n := received[key], racers[key]
			mu.Unlock()
			assert.Len(t, got, n, "user %s: every racer receives a handle", key)
			for _, h := range got {
				assert.Equal(t, held, h, "user %s: a racer received a handle the user does not hold", key)
			}

			user, ok, err := s.UserFor(ctx, held)
			require.NoError(t, err)
			assert.True(t, ok, "user %s: the held handle is not found", key)
			assert.Equal(t, identity.UserID(key), user)

			for racer := range n {
				offer := PasskeyOffer(key, racer)
				if bytes.Equal(offer, held) {
					continue
				}
				_, ok, err := s.UserFor(ctx, offer)
				require.NoError(t, err)
				assert.False(t, ok, "user %s: racer %d's refused offer is held", key, racer)
			}
		},
	}
}

// passkeyAmbientID is the library identifier of the ambient suite's
// credential i.
func passkeyAmbientID(i int) id.ID { return derivedID("passkey-ambient-" + strconv.Itoa(i)) }

// passkeyAmbientCredential is the ambient suite's credential i.
func passkeyAmbientCredential(i int) *passkey.Credential {
	return PasskeyCredential(passkeyAmbientID(i), identity.UserID(fmt.Sprintf("passkey-ambient-user-%d", i)),
		fmt.Sprintf("passkey-ambient-cred-%d", i))
}

// PasskeyCredentialAmbient is the ambient suite's view of the credential
// store: record i is an inserted credential, and the refusal, through one
// context, a recording of a counter that goes backwards and then an insert of
// a credential ID already stored. Both must leave the caller's transaction
// usable.
func PasskeyCredentialAmbient[S passkey.CredentialStore]() storetest.Ambient[S] {
	return storetest.Ambient[S]{
		Write: func(ctx context.Context, s S, i int) error {
			return s.Insert(ctx, passkeyAmbientCredential(i))
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM passkey_credentials WHERE id = $1)`,
				passkeyAmbientID(i))
		},
		Refuse: func(ctx context.Context, s S) error {
			c := passkeyAmbientCredential(999)
			if err := s.Insert(ctx, c); err != nil {
				return err
			}
			ok, err := s.RecordAssertion(ctx, c.ID, PasskeyRaceCount-1, false, RaceAttemptAt)
			if err != nil {
				return err
			}
			if ok {
				return errors.New("storefix: a counter going backwards was recorded")
			}
			dup := passkeyAmbientCredential(998)
			dup.CredentialID = c.CredentialID
			return s.Insert(ctx, dup)
		},
		Refusal: passkey.ErrDuplicateCredential,
	}
}

// passkeyAmbientUser is the user of the ambient suite's handle i.
func passkeyAmbientUser(i int) identity.UserID {
	return identity.UserID(fmt.Sprintf("passkey-ambient-handle-user-%d", i))
}

// PasskeyHandleAmbient is the ambient suite's view of the handle store: record
// i is a handle assigned to a user of its own, and the refusal an assignment
// to a second user of the handle the first holds, through the same context.
func PasskeyHandleAmbient[S passkey.HandleStore]() storetest.Ambient[S] {
	return storetest.Ambient[S]{
		Write: func(ctx context.Context, s S, i int) error {
			user := passkeyAmbientUser(i)
			_, err := s.Assign(ctx, user, PasskeyOffer(string(user), 0))
			return err
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM passkey_user_handles WHERE user_id = $1)`,
				string(passkeyAmbientUser(i)))
		},
		Refuse: func(ctx context.Context, s S) error {
			first := passkeyAmbientUser(999)
			held, err := s.Assign(ctx, first, PasskeyOffer(string(first), 0))
			if err != nil {
				return err
			}
			h, err := s.Assign(ctx, passkeyAmbientUser(998), held)
			if err == nil {
				return fmt.Errorf("storefix: a handle another user holds was assigned (%d bytes returned)", len(h))
			}
			if errors.Is(err, passkey.ErrConfig) {
				return err
			}
			return fmt.Errorf("%w: %w", ErrPasskeyRefused, err)
		},
		Refusal: ErrPasskeyRefused,
	}
}

// passkeySealedCredential is the credential whose emailed code is owner's
// sealed value: pending on its emailed code, of user owner.
func passkeySealedCredential(owner string, code []byte) *passkey.Credential {
	return PasskeyAwaitingCode(
		PasskeyCredential(derivedID("sealed-"+owner), identity.UserID(owner), "sealed-"+owner), string(code))
}

// SealedPasskeyCodes is the sealed-column suite's view of the emailed code
// the passkey credential store keeps, built by newWith over handle and a
// cipher. Put inserts owner's credential, of user owner, awaiting the
// suite's secret as its emailed code; the column is email_code. The code is
// never re-sealed on read.
func SealedPasskeyCodes[H any](
	handle H, newWith func(t *testing.T, handle H, c seal.Cipher) passkey.CredentialStore,
) storetest.Sealed[passkey.CredentialStore] {
	return storetest.Sealed[passkey.CredentialStore]{
		Encoding:       storetest.SealedBase64URL,
		Rotation:       storetest.UnchangedOnRead,
		NewWithKeyring: storeOver(handle, newWith),
		Put: func(ctx context.Context, s passkey.CredentialStore, owner string, secret []byte) error {
			return s.Insert(ctx, passkeySealedCredential(owner, secret))
		},
		Get: func(ctx context.Context, s passkey.CredentialStore, owner string) ([]byte, bool, error) {
			c, err := s.FindByCredentialID(ctx, []byte("sealed-"+owner))
			if errors.Is(err, passkey.ErrNotFound) {
				return nil, false, nil
			}
			if err != nil {
				return nil, false, err
			}
			if c.EmailCode == nil {
				return nil, true, nil
			}
			return []byte(c.EmailCode.Code), true, nil
		},
		RawColumn: func(t *testing.T, raw *sql.DB, owner string) []byte {
			return []byte(passkeyCodeColumn(t, raw, "sealed-"+owner).String)
		},
		CopySealed: func(t *testing.T, raw *sql.DB, from, to string) {
			_, err := raw.ExecContext(t.Context(), `UPDATE passkey_credentials
SET email_code = (SELECT email_code FROM passkey_credentials WHERE credential_id = $1) WHERE credential_id = $2`,
				[]byte("sealed-"+from), []byte("sealed-"+to))
			require.NoError(t, err)
		},
	}
}

// passkeyCodeColumn is the email_code column of the credential with
// credential ID credID, as stored, read out of band.
func passkeyCodeColumn(t *testing.T, raw *sql.DB, credID string) sql.NullString {
	t.Helper()

	var col sql.NullString
	require.NoError(t, raw.QueryRowContext(t.Context(),
		`SELECT email_code FROM passkey_credentials WHERE credential_id = $1`, []byte(credID)).Scan(&col))

	return col
}

// PasskeySentinel is the emailed code RunPasskeyCodeAtRest stores.
const PasskeySentinel = "SENTINEL-PASSKEY"

// RunPasskeyCodeAtRest stores a credential awaiting the emailed code
// PasskeySentinel through s, reads its email_code column out of band through
// raw, and requires neither the stored text nor its base64url decoding to
// equal or hold the code, while s still reads the code back.
func RunPasskeyCodeAtRest(t *testing.T, raw *sql.DB, s passkey.CredentialStore) {
	t.Helper()

	t.Run("Emailed code sealed at rest", func(t *testing.T) {
		c := passkeySealedCredential("at-rest-sentinel", []byte(PasskeySentinel))
		require.NoError(t, s.Insert(t.Context(), c))

		got, err := s.FindByCredentialID(t.Context(), c.CredentialID)
		require.NoError(t, err)
		require.NotNil(t, got.EmailCode)
		assert.Equal(t, PasskeySentinel, got.EmailCode.Code, "the store does not read back what it stored")

		col := passkeyCodeColumn(t, raw, string(c.CredentialID))
		require.True(t, col.Valid, "the emailed code column is NULL")
		assert.NotContains(t, col.String, PasskeySentinel, "the column holds the code")
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(col.String, "="))
		require.NoError(t, err, "the column does not hold base64url")
		assert.NotContains(t, string(decoded), PasskeySentinel, "the decoded column holds the code")
	})
}
