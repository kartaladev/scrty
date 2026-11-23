package admin_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

var testNow = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

// actorCtx returns a context with an authenticated administrator.
func actorCtx(t *testing.T) context.Context {
	t.Helper()

	return identity.WithPrincipal(t.Context(), &identity.Principal{ID: "admin-1"})
}

func fixedClock() *clockwork.FakeClock { return clockwork.NewFakeClockAt(testNow) }

// fixedIDs returns a generator mock that gives uid once.
func fixedIDs(t *testing.T, uid id.ID) *MockGenerator {
	t.Helper()

	g := NewMockGenerator(gomock.NewController(t))
	g.EXPECT().NewID().Return(uid, nil).AnyTimes()

	return g
}

func newUsers(t *testing.T, store admin.UserStore, opts ...admin.UsersOption) *admin.Users {
	t.Helper()

	u, err := admin.NewUsers(store, opts...)
	require.NoError(t, err)

	return u
}

// cursorOf builds a cursor of the documented layout: a version byte, then the
// username as stored and the identifier, each with a two-byte big-endian
// length.
func cursorOf(version byte, username, uid string) string {
	return base64.RawURLEncoding.EncodeToString(cursorBytes(version, username, uid))
}

func cursorBytes(version byte, username, uid string) []byte {
	b := []byte{version, byte(len(username) >> 8), byte(len(username))} //nolint:gosec // test inputs are short
	b = append(b, username...)
	b = append(b, byte(len(uid)>>8), byte(len(uid))) //nolint:gosec // test inputs are short

	return append(b, uid...)
}
