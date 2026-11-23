package admin_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
)

func TestCursor_RoundTrip(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		last      admin.User
		wantNext  string
		wantAfter string
	}

	cases := []testCase{
		{
			name:      "mixed case username is kept as stored",
			last:      admin.User{ID: "u-2", Username: "Bob"},
			wantNext:  cursorOf(1, "Bob", "u-2"),
			wantAfter: "Bob",
		},
		{
			name:      "non ASCII username",
			last:      admin.User{ID: "u-9", Username: "ÅSA/ö"},
			wantNext:  cursorOf(1, "ÅSA/ö", "u-9"),
			wantAfter: "ÅSA/ö",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockUserStore(gomock.NewController(t))
			u := newUsers(t, store)

			store.EXPECT().ListUsers(gomock.Any(), admin.UserQuery{Limit: 1}).
				Return([]admin.User{tc.last}, nil)
			first, err := u.List(t.Context(), admin.UserFilter{PageSize: 1})
			require.NoError(t, err)
			assert.Equal(t, tc.wantNext, first.Next)

			store.EXPECT().ListUsers(gomock.Any(),
				admin.UserQuery{Limit: 1, AfterUsername: tc.wantAfter, AfterID: tc.last.ID}).
				Return(nil, nil)
			second, err := u.List(t.Context(), admin.UserFilter{PageSize: 1, Cursor: first.Next})
			require.NoError(t, err)
			assert.Empty(t, second.Next)
		})
	}
}

func TestCursor_DecodedStrictly(t *testing.T) {
	t.Parallel()

	b64 := base64.RawURLEncoding.EncodeToString
	valid := cursorBytes(1, "bob", "u-2")

	type testCase struct {
		name   string
		cursor string
	}

	cases := []testCase{
		{"not base64", "!!!"},
		{"standard alphabet", base64.StdEncoding.EncodeToString(append(valid, 0xfb, 0xff))},
		{"padded", base64.URLEncoding.EncodeToString(cursorBytes(1, "bo", "u-2"))},
		{"unknown version", cursorOf(2, "bob", "u-2")},
		{"version zero", cursorOf(0, "bob", "u-2")},
		{"trailing bytes", b64(append(append([]byte{}, valid...), 'x'))},
		{"truncated inside the id", b64(valid[:len(valid)-1])},
		{"truncated inside the username", b64(valid[:5])},
		{"only the version", b64([]byte{1})},
		{"empty username", cursorOf(1, "", "u-2")},
		{"empty id", cursorOf(1, "bob", "")},
		{"oversized username length", b64([]byte{1, 0xff, 0xff, 'a'})},
		{"username over the bound", cursorOf(1, strings.Repeat("a", 1025), "u-2")},
		{"id over the bound", cursorOf(1, "bob", strings.Repeat("a", 1025))},
		{"text over the bound", strings.Repeat("A", 100000)},
		{"NUL in the username", cursorOf(1, "bo\x00b", "u-2")},
		{"invalid UTF-8 in the id", cursorOf(1, "bob", "u-\xff")},
		{"non-canonical trailing bits", nonCanonical(b64(valid))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockUserStore(gomock.NewController(t)) // no expectation: no store call
			u := newUsers(t, store)

			_, err := u.List(t.Context(), admin.UserFilter{Cursor: tc.cursor})
			assert.ErrorIs(t, err, admin.ErrInvalidInput)
		})
	}
}

func TestCursor_AcceptsBoundaryLengths(t *testing.T) {
	t.Parallel()

	name := strings.Repeat("a", 1024)
	store := NewMockUserStore(gomock.NewController(t))
	u := newUsers(t, store)

	store.EXPECT().ListUsers(gomock.Any(), admin.UserQuery{Limit: 50, AfterUsername: name, AfterID: "u-2"}).
		Return(nil, nil)
	_, err := u.List(t.Context(), admin.UserFilter{Cursor: cursorOf(1, name, "u-2")})
	assert.NoError(t, err)
}

func TestUsers_List_RefusesToIssueAnUndecodableCursor(t *testing.T) {
	t.Parallel()

	store := NewMockUserStore(gomock.NewController(t))
	u := newUsers(t, store)

	store.EXPECT().ListUsers(gomock.Any(), admin.UserQuery{Limit: 1}).
		Return([]admin.User{{ID: "u-1", Username: strings.Repeat("a", 2000)}}, nil)

	_, err := u.List(t.Context(), admin.UserFilter{PageSize: 1})
	require.Error(t, err)
	// A store whose usernames outgrow the cursor is a storage-side problem, not
	// the caller's invalid input.
	assert.NotErrorIs(t, err, admin.ErrInvalidInput)
}

// nonCanonical sets the unused low bits of the last character of an unpadded
// base64url text whose length leaves some, giving a text that decodes to the
// same bytes leniently but is not the canonical encoding.
func nonCanonical(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	i := strings.IndexByte(alphabet, s[len(s)-1])

	return s[:len(s)-1] + string(alphabet[i|1])
}
