package session_test

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// longUserAgent is 2,000 bytes whose 512th byte (index 511) falls inside a
// three-byte character that starts at index 510.
var longUserAgent = strings.Repeat("a", 510) + "€" + strings.Repeat("b", 2000-513)

func TestSessions_Metadata(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		metadata bool
		// run signs in and acts on the sign-in, returning the session whose
		// stored state is asserted.
		run    func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock) (*session.Session, error)
		assert func(t *testing.T, m *session.Sessions, s *session.Session, err error)
	}

	signIn := func(t *testing.T, m *session.Sessions, ip, ua string) *session.Session {
		t.Helper()
		s, err := m.Create(t.Context(), testUser, session.WithClientMetadata(ip, ua))
		require.NoError(t, err)

		return s
	}
	listedOnce := func(t *testing.T, m *session.Sessions) session.SignIn {
		t.Helper()
		listed, err := m.ListSignIns(t.Context(), testUser, nil)
		require.NoError(t, err)
		require.Len(t, listed, 1)

		return listed[0]
	}
	stored := func(t *testing.T, m *session.Sessions, s *session.Session) *session.Session {
		t.Helper()
		got, err := m.Load(t.Context(), s.ID)
		require.NoError(t, err)

		return got
	}

	cases := []testCase{
		{
			name: "off by default: nothing is recorded, whatever the sign-in supplied",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				return signIn(t, m, "203.0.113.7", "Firefox/140"), nil
			},
			assert: func(t *testing.T, m *session.Sessions, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Empty(t, s.ClientIP)
				assert.Empty(t, s.UserAgent)
				in := listedOnce(t, m)
				assert.Empty(t, in.ClientIP)
				assert.Empty(t, in.UserAgent)
			},
		},
		{
			name:     "invalid UTF-8 in the user agent is replaced",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				return signIn(t, m, "203.0.113.7", "Mozilla/5.0 \xff\xfe"), nil
			},
			assert: func(t *testing.T, m *session.Sessions, s *session.Session, err error) {
				require.NoError(t, err)
				got := stored(t, m, s)
				for _, v := range []string{got.UserAgent, got.ClientIP} {
					assert.True(t, utf8.ValidString(v), "%q", v)
					assert.NotContains(t, v, "\x00")
				}
				assert.Equal(t, "Mozilla/5.0 \uFFFD", got.UserAgent)
			},
		},
		{
			name:     "NUL bytes in the user agent are removed",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				return signIn(t, m, "203.0.113.7", "Fire\x00fox/140"), nil
			},
			assert: func(t *testing.T, m *session.Sessions, s *session.Session, err error) {
				require.NoError(t, err)
				got := stored(t, m, s)
				for _, v := range []string{got.UserAgent, got.ClientIP} {
					assert.True(t, utf8.ValidString(v), "%q", v)
					assert.NotContains(t, v, "\x00")
				}
				assert.Equal(t, "Firefox/140", got.UserAgent)
			},
		},
		{
			name:     "invalid bytes near the cut leave a valid user agent of at most the limit",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				return signIn(t, m, "203.0.113.7", strings.Repeat("a", 508)+"\xff\xfe\xfd\xfc"+strings.Repeat("b", 1488)), nil
			},
			assert: func(t *testing.T, m *session.Sessions, s *session.Session, err error) {
				require.NoError(t, err)
				got := stored(t, m, s)
				for _, v := range []string{got.UserAgent, got.ClientIP} {
					assert.True(t, utf8.ValidString(v), "%q", v)
					assert.NotContains(t, v, "\x00")
				}
				assert.LessOrEqual(t, len(got.UserAgent), session.MaxUserAgentBytes)
			},
		},
		{
			name:     "a NUL in the client address is removed",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				return signIn(t, m, "203.0.\x0013.7", "Firefox/140"), nil
			},
			assert: func(t *testing.T, m *session.Sessions, s *session.Session, err error) {
				require.NoError(t, err)
				got := stored(t, m, s)
				for _, v := range []string{got.UserAgent, got.ClientIP} {
					assert.True(t, utf8.ValidString(v), "%q", v)
					assert.NotContains(t, v, "\x00")
				}
				assert.Equal(t, "203.0.13.7", got.ClientIP)
			},
		},
		{
			name:     "a valid user agent of exactly the limit is kept whole",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				return signIn(t, m, "203.0.113.7", strings.Repeat("é", session.MaxUserAgentBytes/2)), nil
			},
			assert: func(t *testing.T, m *session.Sessions, s *session.Session, err error) {
				require.NoError(t, err)
				got := stored(t, m, s)
				for _, v := range []string{got.UserAgent, got.ClientIP} {
					assert.True(t, utf8.ValidString(v), "%q", v)
					assert.NotContains(t, v, "\x00")
				}
				assert.Len(t, got.UserAgent, session.MaxUserAgentBytes)
			},
		},
		{
			name:     "opted in: the address and user agent are listed",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				return signIn(t, m, "203.0.113.7", "Firefox/140"), nil
			},
			assert: func(t *testing.T, m *session.Sessions, s *session.Session, err error) {
				require.NoError(t, err)
				in := listedOnce(t, m)
				assert.Equal(t, "203.0.113.7", in.ClientIP)
				assert.Equal(t, "Firefox/140", in.UserAgent)
				assert.Equal(t, "203.0.113.7", stored(t, m, s).ClientIP)
			},
		},
		{
			name:     "opted in: a renewal keeps the metadata",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock) (*session.Session, error) {
				s := signIn(t, m, "203.0.113.7", "Firefox/140")
				clk.Advance(time.Minute)
				next, _, err := m.RotateWithGrace(t.Context(), s, 10*time.Second)

				return next, err
			},
			assert: func(t *testing.T, m *session.Sessions, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, "203.0.113.7", s.ClientIP)
				assert.Equal(t, "Firefox/140", s.UserAgent)
				in := listedOnce(t, m)
				assert.Equal(t, "203.0.113.7", in.ClientIP)
				assert.Equal(t, "Firefox/140", in.UserAgent)
			},
		},
		{
			// The successor's metadata is the stored record's, never the
			// caller's copy's.
			name:     "opted in: a rotation of a copy with the metadata changed keeps the stored metadata",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				s := signIn(t, m, "203.0.113.7", "Firefox/140")
				copied := *s
				copied.ClientIP, copied.UserAgent = "198.51.100.1", "curl/8"

				return m.Rotate(t.Context(), &copied)
			},
			assert: func(t *testing.T, m *session.Sessions, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, "203.0.113.7", s.ClientIP)
				assert.Equal(t, "Firefox/140", s.UserAgent)
				got := stored(t, m, s)
				assert.Equal(t, "203.0.113.7", got.ClientIP)
				assert.Equal(t, "Firefox/140", got.UserAgent)
			},
		},
		{
			name:     "opted in: a long user agent is cut to 512 bytes at a character boundary",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				return signIn(t, m, "203.0.113.7", longUserAgent), nil
			},
			assert: func(t *testing.T, m *session.Sessions, _ *session.Session, err error) {
				require.NoError(t, err)
				ua := listedOnce(t, m).UserAgent
				assert.LessOrEqual(t, len(ua), session.MaxUserAgentBytes)
				assert.True(t, utf8.ValidString(ua), "the cut user agent is not valid UTF-8")
				assert.Equal(t, strings.Repeat("a", 510), ua, "cut before the character that crosses the limit")
			},
		},
		{
			name:     "opted in: a user agent of exactly 512 bytes is kept whole",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				return signIn(t, m, "", strings.Repeat("x", 512)), nil
			},
			assert: func(t *testing.T, m *session.Sessions, _ *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, strings.Repeat("x", 512), listedOnce(t, m).UserAgent)
			},
		},
		{
			name:     "opted in: an unattributable address is recorded as absent",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				return signIn(t, m, "", "Firefox/140"), nil
			},
			assert: func(t *testing.T, m *session.Sessions, _ *session.Session, err error) {
				require.NoError(t, err)
				in := listedOnce(t, m)
				assert.Empty(t, in.ClientIP)
				assert.Equal(t, "Firefox/140", in.UserAgent)
			},
		},
		{
			name:     "opted in: saving a copy with the metadata changed keeps the stored metadata",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				s := signIn(t, m, "203.0.113.7", "Firefox/140")
				copied := *s
				copied.ClientIP, copied.UserAgent = "", ""

				return s, m.Save(t.Context(), &copied)
			},
			assert: func(t *testing.T, m *session.Sessions, s *session.Session, err error) {
				require.NoError(t, err)
				got := stored(t, m, s)
				assert.Equal(t, "203.0.113.7", got.ClientIP)
				assert.Equal(t, "Firefox/140", got.UserAgent)
			},
		},
		{
			name:     "opted in: a built session whose metadata changed before storing is refused",
			metadata: true,
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) (*session.Session, error) {
				p, err := m.Prepare(testUser, session.WithClientMetadata("203.0.113.7", "Firefox/140"))
				require.NoError(t, err)
				p.Session().UserAgent = "curl/8"

				return p.Commit(t.Context())
			},
			assert: func(t *testing.T, m *session.Sessions, s *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, s)
				listed, listErr := m.ListSignIns(t.Context(), testUser, nil)
				require.NoError(t, listErr)
				assert.Empty(t, listed, "nothing was stored")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			var opts []session.Option
			if tc.metadata {
				opts = append(opts, session.WithSessionMetadata())
			}
			m, _ := managerOnClock(t, clk, opts...)

			s, err := tc.run(t, m, clk)
			tc.assert(t, m, s, err)
		})
	}
}
