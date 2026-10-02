package session_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/session"
)

// errStoreQuotes is a dependency failure whose text quotes an address and a
// user reference the library never handed it, as a database driver's
// constraint error does. Neither may reach the text of an error session
// returns.
var errStoreQuotes = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// returnedErrorsID is a session identifier shaped like the ones the manager
// mints. It is the bearer credential, so no error session returns may quote
// it.
const returnedErrorsID = "q3Vn8xZr0tLbW2mKc7YpE4sHd9FjA1uNo6GiTeRwXyQ"

// sessionSentinels is every sentinel a session store may return bare.
var sessionSentinels = []error{
	session.ErrSessionNotFound,
	session.ErrSessionExpired,
	session.ErrSessionUnreadable,
}

// returnedErrorsSession is a live session on the fixed clock the table's
// managers read, so Touch reaches the store.
func returnedErrorsSession(idToken string) *session.Session {
	return &session.Session{
		ID:                returnedErrorsID,
		UserID:            testUser,
		CreatedAt:         createdAt,
		LastAccessedAt:    createdAt,
		IdleExpiresAt:     createdAt.Add(time.Hour),
		AbsoluteExpiresAt: createdAt.Add(12 * time.Hour),
		ExternalIDToken:   idToken,
	}
}

// returnedErrorsDoubles are the doubles a row programs before its call.
type returnedErrorsDoubles struct {
	store  *MockStore
	cipher *MockCipher
}

// hidesStoreText asserts err carries none of the dependency's text, still
// matches the dependency's error, and matches exactly the session sentinels
// in want: every one it matched before, and no other.
func hidesStoreText(want ...error) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()

		require.Error(t, err)
		assert.NotContains(t, err.Error(), "alice@example.com")
		assert.NotContains(t, err.Error(), "u-123")
		assert.ErrorIs(t, err, errStoreQuotes)

		for _, sentinel := range sessionSentinels {
			wanted := false
			for _, w := range want {
				wanted = wanted || w == sentinel //nolint:errorlint // identity of sentinels
			}
			assert.Equal(t, wanted, errors.Is(err, sentinel), "errors.Is(err, %v)", sentinel)
		}
	}
}

// isBare asserts err is sentinel itself, text included.
func isBare(sentinel error) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()

		assert.Same(t, sentinel, err) //nolint:testifylint // identity is the point
		if err != nil {
			assert.Equal(t, sentinel.Error(), err.Error())
		}
	}
}

func TestSessionReturnedErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		call   func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error
		assert func(t *testing.T, err error)
	}

	manager := func(t *testing.T, d returnedErrorsDoubles) *session.Manager {
		t.Helper()

		return managerFor(t, session.WithStore(d.store), session.WithClock(clockwork.NewFakeClockAt(createdAt)))
	}
	encrypted := func(t *testing.T, d returnedErrorsDoubles) session.Store {
		t.Helper()

		s, err := session.NewEncryptedStore(d.store, d.cipher)
		require.NoError(t, err)

		return s
	}

	cases := []testCase{
		// Manager: every store call.
		{
			name: "manager create",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				_, err := manager(t, d).Create(ctx, testUser)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager load",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, errStoreQuotes)
				_, err := manager(t, d).Load(ctx, returnedErrorsID)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager touch",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				return manager(t, d).Touch(ctx, returnedErrorsSession(""))
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager save",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				return manager(t, d).Save(ctx, returnedErrorsSession(""))
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Delete(gomock.Any(), returnedErrorsID).Return(errStoreQuotes)
				return manager(t, d).Delete(ctx, returnedErrorsID)
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete by user",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUser(gomock.Any(), testUser).Return(errStoreQuotes)
				return manager(t, d).DeleteByUser(ctx, testUser)
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete by user except one reports fixed text and the store's count",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUserExcept(gomock.Any(), testUser, returnedErrorsID).Return(1, errStoreQuotes)
				n, err := manager(t, d).DeleteByUserExcept(ctx, testUser, returnedErrorsID)
				assert.Equal(t, 1, n, "the count the store reported with its error")
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				hidesStoreText()(t, err)
				assert.EqualError(t, err, "session: the user's other sessions could not be deleted")
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "manager count active by user passes the store's count along",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().CountActiveByUser(gomock.Any(), testUser).Return(3, errStoreQuotes)
				n, err := manager(t, d).CountActiveByUser(ctx, testUser)
				assert.Equal(t, 3, n, "the count the store reported with its error")
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete expired",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteExpired(gomock.Any()).Return(0, errStoreQuotes)
				_, err := manager(t, d).DeleteExpired(ctx)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete by external session",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByExternalSession(gomock.Any(), "https://idp", "sid").Return(0, errStoreQuotes)
				_, err := manager(t, d).DeleteByExternalSession(ctx, "https://idp", "sid")
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager delete by user and external issuer",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), testUser, "https://idp").Return(0, errStoreQuotes)
				_, err := manager(t, d).DeleteByUserAndExternalIssuer(ctx, testUser, "https://idp")
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager rotate: load of the old entry",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, errStoreQuotes)
				_, err := manager(t, d).Rotate(ctx, returnedErrorsSession(""))
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager rotate: create of the new entry",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(returnedErrorsSession(""), nil)
				d.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				_, err := manager(t, d).Rotate(ctx, returnedErrorsSession(""))
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager rotate: delete of the old entry",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(returnedErrorsSession(""), nil)
				d.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				d.store.EXPECT().Delete(gomock.Any(), returnedErrorsID).Return(errStoreQuotes)
				_, err := manager(t, d).Rotate(ctx, returnedErrorsSession(""))
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "manager load: a store error wrapping a sentinel gets fixed text and still matches it",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).
					Return(nil, fmt.Errorf("%w: %w", session.ErrSessionNotFound, errStoreQuotes))
				_, err := manager(t, d).Load(ctx, returnedErrorsID)
				return err
			},
			assert: hidesStoreText(session.ErrSessionNotFound),
		},

		// Encrypted store: the inner store's and the cipher's failures.
		{
			name: "encrypted create: inner store",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				return encrypted(t, d).Create(ctx, returnedErrorsSession(""))
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted create: cipher seal hides the session identifier",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.cipher.EXPECT().Seal(gomock.Any(), gomock.Any()).Return(nil, errStoreQuotes)
				return encrypted(t, d).Create(ctx, returnedErrorsSession("id-token"))
			},
			assert: func(t *testing.T, err error) {
				hidesStoreText()(t, err)
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "encrypted save: inner store",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errStoreQuotes)
				return encrypted(t, d).Save(ctx, returnedErrorsSession(""))
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted save: cipher seal hides the session identifier",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.cipher.EXPECT().Seal(gomock.Any(), gomock.Any()).Return(nil, errStoreQuotes)
				return encrypted(t, d).Save(ctx, returnedErrorsSession("id-token"))
			},
			assert: func(t *testing.T, err error) {
				hidesStoreText()(t, err)
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "encrypted load: inner store",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, errStoreQuotes)
				_, err := encrypted(t, d).Load(ctx, returnedErrorsID)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted load: cipher open stays unreadable and hides the session identifier",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				stored := returnedErrorsSession(base64.RawURLEncoding.EncodeToString([]byte("envelope")))
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(stored, nil)
				d.cipher.EXPECT().Open(gomock.Any(), gomock.Any()).Return(nil, errStoreQuotes)
				_, err := encrypted(t, d).Load(ctx, returnedErrorsID)
				return err
			},
			assert: func(t *testing.T, err error) {
				hidesStoreText(session.ErrSessionUnreadable)(t, err)
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "encrypted load: an invalid envelope stays unreadable and hides the session identifier",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(returnedErrorsSession("not base64!"), nil)
				_, err := encrypted(t, d).Load(ctx, returnedErrorsID)
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, session.ErrSessionUnreadable)
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "encrypted delete",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().Delete(gomock.Any(), returnedErrorsID).Return(errStoreQuotes)
				return encrypted(t, d).Delete(ctx, returnedErrorsID)
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted delete by user",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUser(gomock.Any(), testUser).Return(errStoreQuotes)
				return encrypted(t, d).DeleteByUser(ctx, testUser)
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted delete by user except one",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUserExcept(gomock.Any(), testUser, returnedErrorsID).Return(0, errStoreQuotes)
				_, err := encrypted(t, d).DeleteByUserExcept(ctx, testUser, returnedErrorsID)
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				hidesStoreText()(t, err)
				assert.EqualError(t, err, "session: the inner store could not delete the user's other sessions")
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
		{
			name: "encrypted count active by user",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().CountActiveByUser(gomock.Any(), testUser).Return(0, errStoreQuotes)
				_, err := encrypted(t, d).CountActiveByUser(ctx, testUser)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted delete expired",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteExpired(gomock.Any()).Return(0, errStoreQuotes)
				_, err := encrypted(t, d).DeleteExpired(ctx)
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted delete by external session",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByExternalSession(gomock.Any(), "https://idp", "sid").Return(0, errStoreQuotes)
				_, err := encrypted(t, d).DeleteByExternalSession(ctx, "https://idp", "sid")
				return err
			},
			assert: hidesStoreText(),
		},
		{
			name: "encrypted delete by user and external issuer",
			call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
				d.store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), testUser, "https://idp").Return(0, errStoreQuotes)
				_, err := encrypted(t, d).DeleteByUserAndExternalIssuer(ctx, testUser, "https://idp")
				return err
			},
			assert: hidesStoreText(),
		},

		// Memory store: its own refusal.
		{
			name: "memory create: a stored identifier is refused without quoting it",
			call: func(ctx context.Context, t *testing.T, _ returnedErrorsDoubles) error {
				store := session.NewMemoryStore()
				require.NoError(t, store.Create(ctx, returnedErrorsSession("")))
				return store.Create(ctx, returnedErrorsSession(""))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.NotContains(t, err.Error(), returnedErrorsID)
			},
		},
	}

	// A store answering with a session sentinel bare gets that same value
	// back, text included, through every path that can see one. Rotate's row
	// also pins that nothing is written after a refused load: the strict mock
	// fails on any Create or Delete.
	for _, sentinel := range sessionSentinels {
		cases = append(cases,
			testCase{
				name: "bare " + sentinel.Error() + ": manager load",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, sentinel)
					_, err := manager(t, d).Load(ctx, returnedErrorsID)
					return err
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": manager save",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(sentinel)
					return manager(t, d).Save(ctx, returnedErrorsSession(""))
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": manager touch",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(sentinel)
					return manager(t, d).Touch(ctx, returnedErrorsSession(""))
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": manager rotate refuses and writes nothing",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, sentinel)
					_, err := manager(t, d).Rotate(ctx, returnedErrorsSession(""))
					return err
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": encrypted load",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, sentinel)
					_, err := encrypted(t, d).Load(ctx, returnedErrorsID)
					return err
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": encrypted save",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(sentinel)
					return encrypted(t, d).Save(ctx, returnedErrorsSession(""))
				},
				assert: isBare(sentinel),
			},
			testCase{
				name: "bare " + sentinel.Error() + ": manager over the encrypted store",
				call: func(ctx context.Context, t *testing.T, d returnedErrorsDoubles) error {
					d.store.EXPECT().Load(gomock.Any(), returnedErrorsID).Return(nil, sentinel)
					m := managerFor(t, session.WithStore(encrypted(t, d)))
					_, err := m.Load(ctx, returnedErrorsID)
					return err
				},
				assert: isBare(sentinel),
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			d := returnedErrorsDoubles{store: NewMockStore(ctrl), cipher: NewMockCipher(ctrl)}

			tc.assert(t, tc.call(t.Context(), t, d))
		})
	}
}
