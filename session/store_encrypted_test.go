package session_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// federatedPlaintext is the provider ID token every sealing case starts from.
// It is deliberately long and recognisable, so a field that merely passed
// through is obvious in a failure message.
const federatedPlaintext = "eyJhbGciOiJSUzI1NiJ9.provider-id-token-payload.signature"

// federatedSession is a session carrying everything a federated login records.
func federatedSession(id string) *session.Session {
	s := storedSession(id)
	s.ExternalProvider = "okta"
	s.ExternalIssuer = "https://a"
	s.ExternalSessionID = "s-1"
	s.ExternalIDToken = federatedPlaintext

	return s
}

func TestNewEncryptedStore(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		inner  session.Store
		cipher session.Cipher
		assert func(t *testing.T, s session.Store, err error)
	}

	var typedNilCipher *fakeCipher

	cases := []testCase{
		{
			name:   "an inner store and a cipher are enough",
			inner:  must.Must(session.NewMemoryStore()),
			cipher: fakeCipher{key: 0x2a},
			assert: func(t *testing.T, s session.Store, err error) {
				require.NoError(t, err)
				assert.NotNil(t, s)
			},
		},
		{
			name:   "a nil inner store is a configuration error",
			cipher: fakeCipher{key: 0x2a},
			assert: func(t *testing.T, s session.Store, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, s)
			},
		},
		{
			name:  "a nil cipher is a configuration error",
			inner: must.Must(session.NewMemoryStore()),
			assert: func(t *testing.T, s session.Store, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, s)
			},
		},
		{
			// What an unchecked constructor error hands over: the interface is
			// not nil, so `if c == nil` misses it and the first seal panics.
			name:   "a typed-nil cipher is a configuration error",
			inner:  must.Must(session.NewMemoryStore()),
			cipher: typedNilCipher,
			assert: func(t *testing.T, s session.Store, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, s)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := session.NewEncryptedStore(tc.inner, tc.cipher)
			tc.assert(t, s, err)
		})
	}
}

func TestEncryptedStoreSealsOnlyTheIDToken(t *testing.T) {
	t.Parallel()

	t.Run("the ID token reaches the inner store sealed, and every other field unchanged", func(t *testing.T) {
		t.Parallel()

		sealing, inner := sealingStore(t, 0x2a)
		require.NoError(t, sealing.Create(t.Context(), federatedSession("sealed")))

		stored, err := inner.Load(t.Context(), "sealed")
		require.NoError(t, err)

		assert.NotEqual(t, federatedPlaintext, stored.ExternalIDToken, "the ID token was stored in the clear")
		assert.NotContains(t, stored.ExternalIDToken, federatedPlaintext)
		assert.NotContains(t, stored.ExternalIDToken, "provider-id-token-payload")

		assert.Equal(t, "okta", stored.ExternalProvider, "a field that should pass through was sealed")
		assert.Equal(t, "https://a", stored.ExternalIssuer, "a field that should pass through was sealed")
		assert.Equal(t, "s-1", stored.ExternalSessionID, "a field that should pass through was sealed")
		assert.Equal(t, testUser, stored.UserID)
		assert.Equal(t, map[string]string{"k": "v"}, stored.Data)
	})

	t.Run("the sealed value is base64url text, so any store can hold it", func(t *testing.T) {
		t.Parallel()

		sealing, inner := sealingStore(t, 0x2a)
		require.NoError(t, sealing.Create(t.Context(), federatedSession("encoded")))

		stored, err := inner.Load(t.Context(), "encoded")
		require.NoError(t, err)

		_, err = base64.RawURLEncoding.DecodeString(stored.ExternalIDToken)
		require.NoError(t, err, "the envelope is not unpadded base64url, so a text column could mangle it")
	})

	t.Run("an empty ID token is stored unsealed", func(t *testing.T) {
		t.Parallel()

		sealing, inner := sealingStore(t, 0x2a)

		s := federatedSession("no-token")
		s.ExternalIDToken = ""
		require.NoError(t, sealing.Create(t.Context(), s))

		stored, err := inner.Load(t.Context(), "no-token")
		require.NoError(t, err)
		assert.Empty(t, stored.ExternalIDToken, "an envelope was written where there was nothing to seal")

		loaded, err := sealing.Load(t.Context(), "no-token")
		require.NoError(t, err)
		assert.Empty(t, loaded.ExternalIDToken)
	})

	t.Run("a sealed token round-trips back to the caller as plaintext", func(t *testing.T) {
		t.Parallel()

		sealing, _ := sealingStore(t, 0x2a)
		require.NoError(t, sealing.Create(t.Context(), federatedSession("round-trip")))

		loaded, err := sealing.Load(t.Context(), "round-trip")
		require.NoError(t, err)
		assert.Equal(t, federatedPlaintext, loaded.ExternalIDToken)
	})

	t.Run("saving seals too, so an updated token is never stored in the clear", func(t *testing.T) {
		t.Parallel()

		sealing, inner := sealingStore(t, 0x2a)
		require.NoError(t, sealing.Create(t.Context(), federatedSession("saved")))

		updated := federatedSession("saved")
		updated.ExternalIDToken = "refreshed." + federatedPlaintext
		require.NoError(t, sealing.Save(t.Context(), updated))

		stored, err := inner.Load(t.Context(), "saved")
		require.NoError(t, err)
		assert.NotContains(t, stored.ExternalIDToken, "refreshed.", "a refreshed ID token was stored in the clear")

		loaded, err := sealing.Load(t.Context(), "saved")
		require.NoError(t, err)
		assert.Equal(t, "refreshed."+federatedPlaintext, loaded.ExternalIDToken)
	})
}

func TestEncryptedStoreCopiesAndFailures(t *testing.T) {
	t.Parallel()

	t.Run("the caller keeps plaintext after creating and after saving", func(t *testing.T) {
		t.Parallel()

		sealing, _ := sealingStore(t, 0x2a)

		s := federatedSession("caller-copy")
		require.NoError(t, sealing.Create(t.Context(), s))
		assert.Equal(t, federatedPlaintext, s.ExternalIDToken, "the caller's record was sealed in place on create")

		require.NoError(t, sealing.Save(t.Context(), s))
		assert.Equal(t, federatedPlaintext, s.ExternalIDToken, "the caller's record was sealed in place on save")
	})

	t.Run("a token sealed under a retired key is unreadable, not missing", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		inner := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))

		retired, err := session.NewEncryptedStore(inner, fakeCipher{key: 0x2a})
		require.NoError(t, err)
		require.NoError(t, retired.Create(t.Context(), federatedSession("rotated")))

		current, err := session.NewEncryptedStore(inner, fakeCipher{key: 0x5c})
		require.NoError(t, err)

		loaded, err := current.Load(t.Context(), "rotated")
		require.ErrorIs(t, err, session.ErrUnreadable)
		assert.NotErrorIs(t, err, session.ErrNotFound,
			"a retired-key mistake was hidden as a missing session")
		assert.Nil(t, loaded, "a session came back with its token blanked instead of an error")
	})

	t.Run("a sealed value moved to another session will not open", func(t *testing.T) {
		t.Parallel()

		sealing, inner := sealingStore(t, 0x2a)
		require.NoError(t, sealing.Create(t.Context(), federatedSession("session-a")))

		victim := federatedSession("session-b")
		victim.ExternalIDToken = ""
		require.NoError(t, sealing.Create(t.Context(), victim))

		// An attacker with write access to the store copies A's envelope into
		// B's row. The additional data names A, so it must not open under B.
		stolen, err := inner.Load(t.Context(), "session-a")
		require.NoError(t, err)
		moved, err := inner.Load(t.Context(), "session-b")
		require.NoError(t, err)
		moved.ExternalIDToken = stolen.ExternalIDToken
		require.NoError(t, inner.Save(t.Context(), moved))

		loaded, err := sealing.Load(t.Context(), "session-b")
		require.ErrorIs(t, err, session.ErrUnreadable,
			"a sealed ID token opened under a session it was not sealed for")
		assert.Nil(t, loaded)
	})

	t.Run("a value that is not an envelope at all is unreadable", func(t *testing.T) {
		t.Parallel()

		sealing, inner := sealingStore(t, 0x2a)

		s := federatedSession("not-base64")
		s.ExternalIDToken = ""
		require.NoError(t, sealing.Create(t.Context(), s))

		stored, err := inner.Load(t.Context(), "not-base64")
		require.NoError(t, err)
		stored.ExternalIDToken = "not base64url at all!!"
		require.NoError(t, inner.Save(t.Context(), stored))

		_, err = sealing.Load(t.Context(), "not-base64")
		require.ErrorIs(t, err, session.ErrUnreadable)
	})

	t.Run("loading issues no write", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		inner := NewMockStore(ctrl)

		sealed := federatedSession("no-rewrite")
		envelope, err := fakeCipher{key: 0x2a}.Seal(
			t.Context(),
			[]byte(federatedPlaintext),
			[]byte("scrty/session:external-id-token:no-rewrite"),
		)
		require.NoError(t, err)
		sealed.ExternalIDToken = base64.RawURLEncoding.EncodeToString(envelope)

		// No EXPECT for Create or Save: a write on read is the resurrection
		// race of the create-versus-save split, arriving through the back
		// door. A re-seal on load would also churn every row on every request.
		inner.EXPECT().Load(gomock.Any(), "no-rewrite").
			DoAndReturn(func(_ context.Context, _ string) (*session.Session, error) {
				return sealed, nil
			}).
			Times(1)

		sealing, err := session.NewEncryptedStore(inner, fakeCipher{key: 0x2a})
		require.NoError(t, err)

		loaded, err := sealing.Load(t.Context(), "no-rewrite")
		require.NoError(t, err)
		assert.Equal(t, federatedPlaintext, loaded.ExternalIDToken)
	})

	t.Run("every other operation passes straight through", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		inner := NewMockStore(ctrl)
		inner.EXPECT().Delete(gomock.Any(), "id").Return(nil).Times(1)
		inner.EXPECT().DeleteByUser(gomock.Any(), testUser).Return(nil).Times(1)
		inner.EXPECT().DeleteByUserExcept(gomock.Any(), testUser, "id").Return(4, nil).Times(1)
		inner.EXPECT().CountActiveByUser(gomock.Any(), testUser).Return(3, nil).Times(1)
		inner.EXPECT().DeleteExpired(gomock.Any()).Return(7, nil).Times(1)
		inner.EXPECT().DeleteByExternalSession(gomock.Any(), "https://a", "s-1").Return(1, nil).Times(1)
		inner.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), testUser, "https://a").Return(2, nil).Times(1)

		sealing, err := session.NewEncryptedStore(inner, fakeCipher{key: 0x2a})
		require.NoError(t, err)

		ctx := t.Context()
		require.NoError(t, sealing.Delete(ctx, "id"))
		require.NoError(t, sealing.DeleteByUser(ctx, testUser))

		n, err := sealing.DeleteByUserExcept(ctx, testUser, "id")
		require.NoError(t, err)
		assert.Equal(t, 4, n)

		n, err = sealing.CountActiveByUser(ctx, testUser)
		require.NoError(t, err)
		assert.Equal(t, 3, n)

		n, err = sealing.DeleteExpired(ctx)
		require.NoError(t, err)
		assert.Equal(t, 7, n)

		n, err = sealing.DeleteByExternalSession(ctx, "https://a", "s-1")
		require.NoError(t, err)
		assert.Equal(t, 1, n)

		n, err = sealing.DeleteByUserAndExternalIssuer(ctx, testUser, "https://a")
		require.NoError(t, err)
		assert.Equal(t, 2, n)
	})

	t.Run("the additional data names the session the token belongs to", func(t *testing.T) {
		t.Parallel()

		sealing, inner := sealingStore(t, 0x2a)
		require.NoError(t, sealing.Create(t.Context(), federatedSession("aad-check")))

		stored, err := inner.Load(t.Context(), "aad-check")
		require.NoError(t, err)
		envelope, err := base64.RawURLEncoding.DecodeString(stored.ExternalIDToken)
		require.NoError(t, err)

		assert.True(t, strings.Contains(string(envelope), "scrty/session:external-id-token:aad-check"),
			"the additional data does not name the session, so an envelope could be moved between sessions")
	})
}

func TestEncryptedStoreFamilyOperations(t *testing.T) {
	t.Parallel()

	family := id.MustParse("01926a4e-0000-7000-8000-000000000001")

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore)
	}

	cases := []testCase{
		{
			name: "supersede seals the successor's ID token, bound to the successor, and leaves the caller's plaintext",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore) {
				oldSession := federatedSession("old")
				oldSession.FamilyID = family
				require.NoError(t, sealing.Create(ctx, oldSession))
				successor := federatedSession("new")
				successor.FamilyID = family

				require.NoError(t, sealing.Supersede(ctx, firstRotation("old", successor)))

				assert.Equal(t, federatedPlaintext, successor.ExternalIDToken, "the caller's successor was sealed in place")
				stored, err := inner.Load(ctx, "new")
				require.NoError(t, err)
				assert.NotContains(t, stored.ExternalIDToken, "provider-id-token-payload", "the successor's token reached the store in the clear")
				opened, err := sealing.Load(ctx, "new")
				require.NoError(t, err)
				assert.Equal(t, federatedPlaintext, opened.ExternalIDToken)
				old, err := sealing.Load(ctx, "old")
				require.NoError(t, err)
				assert.Equal(t, createdAt, old.SupersededAt)
			},
		},
		{
			name: "a lost supersession keeps the renewal-conflict error, and a missing one the not-found error",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, _ *session.MemoryStore) {
				require.NoError(t, sealing.Create(ctx, familyOf("old", family)))
				require.NoError(t, sealing.Supersede(ctx, firstRotation("old", storedSession("first"))))

				err := sealing.Supersede(ctx, firstRotation("old", storedSession("second")))
				require.ErrorIs(t, err, session.ErrRenewalConflict)

				err = sealing.Supersede(ctx, firstRotation("missing", storedSession("third")))
				require.ErrorIs(t, err, session.ErrNotFound)
			},
		},
		{
			name: "record activity reaches the inner store",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore) {
				require.NoError(t, sealing.Create(ctx, storedSession("s")))
				at := createdAt.Add(5 * time.Minute)

				require.NoError(t, sealing.RecordActivity(ctx, "s", at, at.Add(30*time.Minute), at))

				stored, err := inner.Load(ctx, "s")
				require.NoError(t, err)
				assert.Equal(t, at, stored.LastAccessedAt)
				require.ErrorIs(t, sealing.RecordActivity(ctx, "missing", at, at, at), session.ErrNotFound)
			},
		},
		{
			name: "mark presented reaches the inner store",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore) {
				require.NoError(t, sealing.Create(ctx, storedSession("s")))

				require.NoError(t, sealing.MarkPresented(ctx, "s", createdAt))

				stored, err := inner.Load(ctx, "s")
				require.NoError(t, err)
				assert.Equal(t, createdAt, stored.FirstPresentedAt)
				require.ErrorIs(t, sealing.MarkPresented(ctx, "missing", createdAt), session.ErrNotFound)
			},
		},
		{
			name: "mark presented of a superseded session returns the inner store's sentinel bare",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore) {
				require.NoError(t, sealing.Create(ctx, familyOf("old", family)))
				require.NoError(t, sealing.Supersede(ctx, firstRotation("old", familyOf("new", family))))

				err := sealing.MarkPresented(ctx, "old", createdAt)

				require.Equal(t, session.ErrSuperseded, err) //nolint:errorlint // the sentinel bare, as a store returns it
				stored, err := inner.Load(ctx, "old")
				require.NoError(t, err)
				assert.True(t, stored.FirstPresentedAt.IsZero(), "a superseded session was marked presented")
			},
		},
		{
			name: "delete family reaches the inner store and reports its count",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore) {
				require.NoError(t, sealing.Create(ctx, familyOf("a", family)))
				require.NoError(t, sealing.Create(ctx, familyOf("b", family)))
				require.NoError(t, sealing.Create(ctx, storedSession("other")))

				n, err := sealing.DeleteFamily(ctx, family)
				require.NoError(t, err)

				assert.Equal(t, 2, n)
				assert.Equal(t, 1, inner.Len())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sealing, inner := sealingStore(t, 0x2a)
			tc.assert(t, t.Context(), sealing, inner)
		})
	}
}

// A store refusing a supersession with a sentinel of this package bare hands
// back that same value through the sealing store, as Load and Save do, so a
// caller comparing it by identity still matches.
func TestEncryptedStoreSupersedeReturnsSentinelsBare(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		sentinel error
		assert   func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:     "renewal conflict",
			sentinel: session.ErrRenewalConflict,
			assert:   isBare(session.ErrRenewalConflict),
		},
		{
			name:     "not found",
			sentinel: session.ErrNotFound,
			assert:   isBare(session.ErrNotFound),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := NewMockStore(gomock.NewController(t))
			inner.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(tc.sentinel)
			sealing, err := session.NewEncryptedStore(inner, fakeCipher{key: 0x2a})
			require.NoError(t, err)

			err = sealing.Supersede(t.Context(), firstRotation("old", storedSession("new")))

			tc.assert(t, err)
		})
	}
}

// TestEncryptedStoreCreatePassesOnTheNilFamilyRefusal pins that the sealing
// store neither hides nor works around the inner store's refusal of a
// session in no family: the error comes back and nothing is stored.
// Standalone: it creates through the sealing store and reads the inner store's count.
func TestEncryptedStoreCreatePassesOnTheNilFamilyRefusal(t *testing.T) {
	t.Parallel()

	sealing, inner := sealingStore(t, 0x2a)
	orphan := storedSession("orphan")
	orphan.FamilyID = id.Nil

	err := sealing.Create(t.Context(), orphan)

	require.Error(t, err)
	assert.NotErrorIs(t, err, session.ErrNotFound)
	assert.Zero(t, inner.Len(), "a refused session was stored")
}

func TestSealingStore_OpenFailureClassification(t *testing.T) {
	t.Parallel()

	errKMSTimeout := errors.New("kms: dependency timeout")

	type testCase struct {
		name      string
		openError error
		assert    func(t *testing.T, loaded *session.Session, err error)
	}

	cases := []testCase{
		{
			name:      "a deadline is a store failure wrapping it, not an unreadable session",
			openError: context.DeadlineExceeded,
			assert: func(t *testing.T, loaded *session.Session, err error) {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.NotErrorIs(t, err, session.ErrUnreadable,
					"an abandoned open was reported as a session that cannot be read")
				assert.Nil(t, loaded)
			},
		},
		{
			name:      "a wrapped cancellation is a store failure wrapping it, not an unreadable session",
			openError: fmt.Errorf("kms: %w", context.Canceled),
			assert: func(t *testing.T, loaded *session.Session, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, session.ErrUnreadable,
					"an abandoned open was reported as a session that cannot be read")
				assert.Nil(t, loaded)
			},
		},
		{
			name:      "an error the cipher marks as an outage is a store failure matching the marker, not an unreadable session",
			openError: errors.Join(session.ErrCipherUnavailable, errKMSTimeout),
			assert: func(t *testing.T, loaded *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrCipherUnavailable)
				require.ErrorIs(t, err, errKMSTimeout, "the cipher's own error is no longer reachable")
				assert.NotErrorIs(t, err, session.ErrUnreadable,
					"a marked outage was reported as a session that cannot be read")
				assert.Nil(t, loaded)
			},
		},
		{
			name:      "the marker wins over an error of the cipher's own joined with it",
			openError: errors.Join(session.ErrCipherUnavailable, errors.New("bad tag")),
			assert: func(t *testing.T, loaded *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrCipherUnavailable)
				assert.NotErrorIs(t, err, session.ErrUnreadable,
					"a marked outage was reported as a session that cannot be read")
				assert.Nil(t, loaded)
			},
		},
		{
			name:      "an error of the cipher's own stays unreadable",
			openError: errors.New("bad tag"),
			assert: func(t *testing.T, loaded *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrUnreadable)
				assert.Nil(t, loaded)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sealing, inner := sealingStore(t, 0x2a)
			require.NoError(t, sealing.Create(t.Context(), federatedSession("classified")))

			cipher := NewMockCipher(gomock.NewController(t))
			cipher.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, tc.openError).Times(1)

			failing, err := session.NewEncryptedStore(inner, cipher)
			require.NoError(t, err)

			loaded, err := failing.Load(t.Context(), "classified")
			tc.assert(t, loaded, err)
		})
	}
}

// cipherContextKey keys the value TestSealingStore_CipherCarriesContext puts
// in the context of each store operation.
type cipherContextKey struct{}

// contextCipher delegates to fakeCipher and records the value every call's
// context carries under cipherContextKey, with the method's name.
type contextCipher struct {
	fakeCipher

	mu    sync.Mutex
	calls []string
}

func (c *contextCipher) record(ctx context.Context, method string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, _ := ctx.Value(cipherContextKey{}).(string)
	c.calls = append(c.calls, method+":"+value)
}

func (c *contextCipher) Seal(ctx context.Context, plaintext, additionalData []byte) ([]byte, error) {
	c.record(ctx, "Seal")
	return c.fakeCipher.Seal(ctx, plaintext, additionalData)
}

func (c *contextCipher) Open(ctx context.Context, ciphertext, additionalData []byte) ([]byte, error) {
	c.record(ctx, "Open")
	return c.fakeCipher.Open(ctx, ciphertext, additionalData)
}

func (c *contextCipher) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

func TestSealingStore_CipherCarriesContext(t *testing.T) {
	t.Parallel()

	family := id.MustParse("01926a4e-0000-7000-8000-000000000002")

	type testCase struct {
		name string
		// setup stores what the call needs through the sealing store, under
		// a context carrying no value.
		setup  func(t *testing.T, sealing session.Store)
		call   func(ctx context.Context, sealing session.Store) error
		assert func(t *testing.T, calls []string, err error)
	}

	cases := []testCase{
		{
			name:  "create seals under the create's context",
			setup: func(*testing.T, session.Store) {},
			call: func(ctx context.Context, sealing session.Store) error {
				return sealing.Create(ctx, federatedSession("created"))
			},
			assert: func(t *testing.T, calls []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"Seal:operation"}, calls)
			},
		},
		{
			name: "save seals under the save's context",
			setup: func(t *testing.T, sealing session.Store) {
				require.NoError(t, sealing.Create(t.Context(), federatedSession("saved")))
			},
			call: func(ctx context.Context, sealing session.Store) error {
				return sealing.Save(ctx, federatedSession("saved"))
			},
			assert: func(t *testing.T, calls []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"Seal:operation"}, calls)
			},
		},
		{
			name: "supersede seals the successor under the supersession's context",
			setup: func(t *testing.T, sealing session.Store) {
				require.NoError(t, sealing.Create(t.Context(), familyOf("old", family)))
			},
			call: func(ctx context.Context, sealing session.Store) error {
				successor := federatedSession("new")
				successor.FamilyID = family

				return sealing.Supersede(ctx, firstRotation("old", successor))
			},
			assert: func(t *testing.T, calls []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"Seal:operation"}, calls)
			},
		},
		{
			name: "load opens under the load's context",
			setup: func(t *testing.T, sealing session.Store) {
				require.NoError(t, sealing.Create(t.Context(), federatedSession("loaded")))
			},
			call: func(ctx context.Context, sealing session.Store) error {
				loaded, err := sealing.Load(ctx, "loaded")
				if err == nil && loaded.ExternalIDToken != federatedPlaintext {
					return fmt.Errorf("the load opened %q", loaded.ExternalIDToken)
				}

				return err
			},
			assert: func(t *testing.T, calls []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"Open:operation"}, calls)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			inner := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
			c := &contextCipher{fakeCipher: fakeCipher{key: 0x2a}}
			sealing, err := session.NewEncryptedStore(inner, c)
			require.NoError(t, err)

			tc.setup(t, sealing)
			before := len(c.seen())

			err = tc.call(context.WithValue(t.Context(), cipherContextKey{}, "operation"), sealing)
			tc.assert(t, c.seen()[before:], err)
		})
	}
}

// TestErrCipherUnavailable_IsDistinct pins that the outage marker is a
// sentinel of its own: a caller testing for an unreadable or a missing
// session never mistakes an outage for either.
func TestErrCipherUnavailable_IsDistinct(t *testing.T) {
	t.Parallel()

	assert.NotErrorIs(t, session.ErrCipherUnavailable, session.ErrUnreadable)
	assert.NotErrorIs(t, session.ErrCipherUnavailable, session.ErrNotFound)
	assert.NotErrorIs(t, session.ErrUnreadable, session.ErrCipherUnavailable)
	assert.NotErrorIs(t, session.ErrNotFound, session.ErrCipherUnavailable)
}
