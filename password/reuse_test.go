package password_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/password"
)

// fixedClock is a consumer's own read-only clock: the "Read-only source for a
// read-only component" scenario (time-source spec). It carries only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// memHistory is a map-backed History honouring the port's contract: newest
// first, the same-bytes rule, pruning to keep, and the caller's context. It
// counts reads so a case can assert that history was, or was not, consulted.
type memHistory struct {
	mu      sync.Mutex
	byUser  map[identity.UserID][][]byte
	reads   int
	lastN   int
	retires int
}

func newMemHistory() *memHistory {
	return &memHistory{byUser: map[identity.UserID][][]byte{}}
}

// seed stores hashes for user, newest first, as if retired earlier.
func (h *memHistory) seed(user identity.UserID, hashes ...[]byte) *memHistory {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, hash := range hashes {
		h.byUser[user] = append(h.byUser[user], bytes.Clone(hash))
	}

	return h
}

func (h *memHistory) entries(user identity.UserID) [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()

	return slices.Clone(h.byUser[user])
}

func (h *memHistory) RecentPasswords(ctx context.Context, user identity.UserID, n int) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.reads++
	h.lastN = n
	list := h.byUser[user]

	return slices.Clone(list[:min(n, len(list))]), nil
}

func (h *memHistory) RetirePassword(ctx context.Context, user identity.UserID, hash []byte, keep int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.retires++
	if keep <= 0 {
		delete(h.byUser, user)
		return nil
	}

	list := h.byUser[user]
	if len(list) == 0 || !bytes.Equal(list[0], hash) {
		list = append([][]byte{bytes.Clone(hash)}, list...)
	}
	h.byUser[user] = list[:min(keep, len(list))]

	return nil
}

func (h *memHistory) ForgetPasswords(ctx context.Context, user identity.UserID) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.byUser, user)

	return nil
}

// fastArgon2id is Argon2id at its parameter floor, to keep the runs short.
func fastArgon2id(t *testing.T) password.Encoder {
	t.Helper()

	enc, err := password.NewArgon2idEncoder(
		password.WithArgon2idIterations(2),
		password.WithArgon2idMemory(19*1024),
		password.WithArgon2idThreads(1),
	)
	require.NoError(t, err)

	return enc
}

func mustEncode(t *testing.T, enc password.Encoder, plain string) []byte {
	t.Helper()

	hash, err := enc.Encode(plain)
	require.NoError(t, err)

	return hash
}

func TestNewReuseGuard_RefusesWiringMistakes(t *testing.T) {
	t.Parallel()

	enc := fastArgon2id(t)

	type testCase struct {
		name    string
		history func(ctrl *gomock.Controller) password.History
		enc     password.Encoder
		depth   int
		opts    []password.ReuseOption
		assert  func(t *testing.T, g *password.ReuseGuard, err error)
	}

	consumerHistory := func(ctrl *gomock.Controller) password.History { return NewMockHistory(ctrl) }

	// consumerClockAt is what a consumer's own read-only clock reports, for
	// the "consumer clock" row below.
	consumerClockAt := time.Date(2032, time.March, 3, 4, 5, 6, 0, time.UTC)

	refused := func(word string) func(t *testing.T, g *password.ReuseGuard, err error) {
		return func(t *testing.T, g *password.ReuseGuard, err error) {
			require.ErrorIs(t, err, password.ErrConfig)
			assert.Contains(t, err.Error(), word)
			assert.Nil(t, g)
		}
	}

	cases := []testCase{
		{
			name:   "a nil history port",
			enc:    enc,
			depth:  5,
			assert: refused("history port"),
		},
		{
			name:    "a typed-nil history port",
			history: func(*gomock.Controller) password.History { return (*memHistory)(nil) },
			enc:     enc,
			depth:   5,
			assert:  refused("history port"),
		},
		{
			name:    "a nil encoder",
			history: consumerHistory,
			depth:   5,
			assert:  refused("encoder"),
		},
		{
			name:    "a typed-nil encoder",
			history: consumerHistory,
			enc:     (*plainEncoder)(nil),
			depth:   5,
			assert:  refused("encoder"),
		},
		{
			name:    "depth zero",
			history: consumerHistory,
			enc:     enc,
			depth:   0,
			assert:  refused("depth"),
		},
		{
			name:    "a negative depth",
			history: consumerHistory,
			enc:     enc,
			depth:   -1,
			assert:  refused("depth"),
		},
		{
			name:    "a nil matcher",
			history: consumerHistory,
			enc:     enc,
			depth:   5,
			opts:    []password.ReuseOption{password.WithReuseMatchers(nil)},
			assert:  refused("matcher"),
		},
		{
			name:    "a typed-nil matcher",
			history: consumerHistory,
			enc:     enc,
			depth:   5,
			opts:    []password.ReuseOption{password.WithReuseMatchers(plainEncoder{}, (*plainEncoder)(nil))},
			assert:  refused("matcher"),
		},
		{
			name:    "a nil clock",
			history: consumerHistory,
			enc:     enc,
			depth:   5,
			opts:    []password.ReuseOption{password.WithReuseClock(nil)},
			assert:  refused("clock"),
		},
		{
			// *clockwork.FakeClock implements Now through a pointer receiver,
			// so a nil one is an interface holding a nil pointer: `== nil`
			// misses it, and only the reflect-based check the constructor now
			// uses catches it before the first Change reads from a nil
			// receiver.
			name:    "a typed-nil clock",
			history: consumerHistory,
			enc:     enc,
			depth:   5,
			opts:    []password.ReuseOption{password.WithReuseClock((*clockwork.FakeClock)(nil))},
			assert:  refused("clock"),
		},
		{
			// A Now-only consumer type: `time-source` "Read-only source for a
			// read-only component". Construction succeeds, and Change reads
			// the change time from the consumer's clock: depth 1 over a fresh
			// user touches no history, so the write is the only place the
			// clock could have come from.
			name:    "a consumer's own read-only clock is the guard's time source",
			history: consumerHistory,
			enc:     enc,
			depth:   1,
			opts:    []password.ReuseOption{password.WithReuseClock(fixedClock{at: consumerClockAt})},
			assert: func(t *testing.T, g *password.ReuseGuard, err error) {
				require.NoError(t, err)
				require.NotNil(t, g)

				user := &identity.Details{ID: identity.UserID("u-consumer-clock")}
				w := &recordingWrite{}
				require.NoError(t, g.Change(t.Context(), user, "p1", w.write))
				assert.True(t, consumerClockAt.Equal(w.at),
					"the write did not get the consumer clock's time")
			},
		},
		{
			name:    "the consumer's own history port, depth 5",
			history: consumerHistory,
			enc:     enc,
			depth:   5,
			assert: func(t *testing.T, g *password.ReuseGuard, err error) {
				require.NoError(t, err)
				assert.NotNil(t, g)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var h password.History
			if tc.history != nil {
				h = tc.history(gomock.NewController(t))
			}

			g, err := password.NewReuseGuard(h, tc.enc, tc.depth, tc.opts...)
			tc.assert(t, g, err)
		})
	}
}

// plainEncoder is a consumer's own algorithm: it "hashes" by prefixing, which
// no built-in encoder recognises.
type plainEncoder struct{}

func (plainEncoder) Encode(input string) ([]byte, error) { return []byte("plain:" + input), nil }

func (plainEncoder) Match(input string, encoded []byte) bool {
	return string(encoded) == "plain:"+input
}

func TestReuseGuard_Check(t *testing.T) {
	t.Parallel()

	fast := fastArgon2id(t)
	hP1, hP2, hP3, hP4 := mustEncode(t, fast, "p1"), mustEncode(t, fast, "p2"), mustEncode(t, fast, "p3"), mustEncode(t, fast, "p4")

	argon64, err := password.NewArgon2idEncoder(password.WithArgon2idMemory(64 * 1024))
	require.NoError(t, err)
	argon128, err := password.NewArgon2idEncoder(password.WithArgon2idMemory(128 * 1024))
	require.NoError(t, err)
	bcrypt12, err := password.NewBcryptEncoder(password.WithBcryptCost(12))
	require.NoError(t, err)
	scryptDefault, err := password.NewScryptEncoder()
	require.NoError(t, err)

	hArgon64P1 := mustEncode(t, argon64, "p1")
	hBcrypt12P1 := mustEncode(t, bcrypt12, "p1")
	hScryptP1 := mustEncode(t, scryptDefault, "p1")
	hPlainP1 := mustEncode(t, plainEncoder{}, "p1")

	const user = identity.UserID("u-1")

	mem := func(h *memHistory) func(*gomock.Controller) password.History {
		return func(*gomock.Controller) password.History { return h }
	}
	depth3 := func() *memHistory { return newMemHistory().seed(user, hP3, hP2, hP1) }

	type testCase struct {
		name      string
		enc       password.Encoder // nil means fast
		depth     int
		opts      []password.ReuseOption
		history   func(ctrl *gomock.Controller) password.History
		user      *identity.Details
		candidate string
		ctx       func(ctx context.Context) context.Context
		assert    func(t *testing.T, err error)
	}

	reused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, password.ErrPasswordReused)
	}

	h3Current, h3Newest, h3Oldest, h3Free := depth3(), depth3(), depth3(), depth3()
	h1Current, h1History := newMemHistory().seed(user, hP1), newMemHistory().seed(user, hP1)
	portErr := errors.New("history store is down")

	cases := []testCase{
		{
			name:      "a nil user is a wiring mistake and reads nothing",
			depth:     3,
			history:   func(ctrl *gomock.Controller) password.History { return NewMockHistory(ctrl) },
			candidate: "p1",
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, password.ErrConfig)
				assert.Contains(t, err.Error(), "user")
			},
		},
		{
			name:      "depth 3 refuses the current password",
			depth:     3,
			history:   mem(h3Current),
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p4",
			assert:    reused,
		},
		{
			name:      "depth 3 refuses the newest retired password",
			depth:     3,
			history:   mem(h3Newest),
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p3",
			assert: func(t *testing.T, err error) {
				reused(t, err)
				assert.Equal(t, 2, h3Newest.lastN, "depth 3 reads the current plus depth-1 retired hashes")
			},
		},
		{
			name:      "depth 3 refuses the second retired password",
			depth:     3,
			history:   mem(h3Oldest),
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p2",
			assert:    reused,
		},
		{
			name:      "depth 3 accepts a password older than the window",
			depth:     3,
			history:   mem(h3Free),
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p1",
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
				assert.Equal(t, 2, h3Free.lastN)
			},
		},
		{
			name:      "depth 1 refuses the current password",
			depth:     1,
			history:   mem(h1Current),
			user:      &identity.Details{ID: user, Password: hP2},
			candidate: "p2",
			assert: func(t *testing.T, err error) {
				reused(t, err)
				assert.Zero(t, h1Current.reads, "depth 1 never reads history")
			},
		},
		{
			name:      "depth 1 accepts the previous password without reading history",
			depth:     1,
			history:   mem(h1History),
			user:      &identity.Details{ID: user, Password: hP2},
			candidate: "p1",
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
				assert.Zero(t, h1History.reads, "depth 1 never reads history")
			},
		},
		{
			name:      "a user with no local password and no history is accepted",
			depth:     3,
			history:   mem(newMemHistory()),
			user:      &identity.Details{ID: user},
			candidate: "p1",
			assert:    func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:      "a hash written with older Argon2id parameters still matches",
			enc:       argon128,
			depth:     3,
			history:   mem(newMemHistory().seed(user, hArgon64P1)),
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p1",
			assert:    reused,
		},
		{
			name:      "a bcrypt hash matches under an Argon2id guard by default",
			depth:     3,
			history:   mem(newMemHistory().seed(user, hBcrypt12P1)),
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p1",
			assert:    reused,
		},
		{
			name:      "a scrypt hash matches under an Argon2id guard by default",
			depth:     3,
			history:   mem(newMemHistory().seed(user, hScryptP1)),
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p1",
			assert:    reused,
		},
		{
			name:      "a consumer algorithm's hash is not matched by default",
			depth:     3,
			history:   mem(newMemHistory().seed(user, hPlainP1)),
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p1",
			assert:    func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:      "a consumer matcher recognises its own algorithm's hash",
			depth:     3,
			opts:      []password.ReuseOption{password.WithReuseMatchers(plainEncoder{})},
			history:   mem(newMemHistory().seed(user, hPlainP1)),
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p1",
			assert:    reused,
		},
		{
			name:      "consumer matchers replace the default extras",
			depth:     3,
			opts:      []password.ReuseOption{password.WithReuseMatchers(plainEncoder{})},
			history:   mem(newMemHistory().seed(user, hBcrypt12P1)),
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p1",
			assert:    func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:      "the guard's own encoder still matches when consumer matchers replace the extras",
			depth:     1,
			opts:      []password.ReuseOption{password.WithReuseMatchers(plainEncoder{})},
			history:   mem(newMemHistory()),
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p4",
			assert:    reused,
		},
		{
			name:  "the consumer's own history port refuses a reused password",
			depth: 5,
			history: func(ctrl *gomock.Controller) password.History {
				m := NewMockHistory(ctrl)
				m.EXPECT().RecentPasswords(gomock.Any(), user, 4).Return([][]byte{hP3, hP1}, nil)
				return m
			},
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p1",
			assert:    reused,
		},
		{
			name:  "a history that cannot be read refuses",
			depth: 3,
			history: func(ctrl *gomock.Controller) password.History {
				m := NewMockHistory(ctrl)
				m.EXPECT().RecentPasswords(gomock.Any(), user, 2).Return(nil, portErr)
				return m
			},
			user:      &identity.Details{ID: user, Password: hP4},
			candidate: "p9",
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, password.ErrHistoryUnavailable)
				assert.ErrorIs(t, err, portErr)
			},
		},
		{
			name:    "a cancelled context reaches the port and refuses",
			depth:   3,
			history: mem(newMemHistory()),
			user:    &identity.Details{ID: user, Password: hP4},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			candidate: "p9",
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, password.ErrHistoryUnavailable)
				assert.ErrorIs(t, err, context.Canceled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			enc := tc.enc
			if enc == nil {
				enc = fast
			}

			g, err := password.NewReuseGuard(tc.history(gomock.NewController(t)), enc, tc.depth, tc.opts...)
			require.NoError(t, err)

			tc.assert(t, g.Check(ctx, tc.user, tc.candidate))
		})
	}
}

// recordingWrite is a consumer WriteFunc that records what it was handed and,
// unless told to fail, stores the new hash on the record as a store would.
type recordingWrite struct {
	calls int
	user  *identity.Details
	hash  []byte
	at    time.Time
	fail  error
	log   *[]string
}

func (w *recordingWrite) write(_ context.Context, user *identity.Details, hash []byte, at time.Time) error {
	w.calls++
	w.user, w.hash, w.at = user, bytes.Clone(hash), at

	if w.log != nil {
		*w.log = append(*w.log, "write")
	}

	if w.fail != nil {
		return w.fail
	}

	user.Password = bytes.Clone(hash)

	return nil
}

// changeTo changes user's password to plain through g, requiring success.
func changeTo(t *testing.T, g *password.ReuseGuard, user *identity.Details, plain string) {
	t.Helper()

	w := &recordingWrite{}
	require.NoError(t, g.Change(t.Context(), user, plain, w.write))
}

func TestReuseGuard_Change(t *testing.T) {
	t.Parallel()

	fast := fastArgon2id(t)
	hP1, hP2 := mustEncode(t, fast, "p1"), mustEncode(t, fast, "p2")
	bcrypt10, err := password.NewBcryptEncoder()
	require.NoError(t, err)

	fixed := time.Date(2031, time.June, 1, 0, 0, 0, 0, time.UTC)
	errWrite := errors.New("the consumer's store refused the write")

	const user = identity.UserID("u-1")

	type testCase struct {
		name    string
		enc     password.Encoder // nil means fast
		depth   int
		opts    []password.ReuseOption
		arrange func(t *testing.T, g *password.ReuseGuard, h *memHistory) (*identity.Details, string, *recordingWrite)
		assert  func(t *testing.T, err error, h *memHistory, u *identity.Details, w *recordingWrite)
	}

	cases := []testCase{
		{
			name:  "the write receives the record, the new hash and the clock's time",
			depth: 3,
			opts:  []password.ReuseOption{password.WithReuseClock(clockwork.NewFakeClockAt(fixed))},
			arrange: func(_ *testing.T, _ *password.ReuseGuard, _ *memHistory) (*identity.Details, string, *recordingWrite) {
				return &identity.Details{ID: user, Password: hP1}, "p2", &recordingWrite{}
			},
			assert: func(t *testing.T, err error, _ *memHistory, u *identity.Details, w *recordingWrite) {
				require.NoError(t, err)
				require.Equal(t, 1, w.calls)
				assert.Same(t, u, w.user)
				assert.True(t, fast.Match("p2", w.hash), "the write gets the candidate's new hash")
				assert.True(t, fixed.Equal(w.at), "the write gets the guard clock's time")
			},
		},
		{
			name:  "depth 3 over p1 to p5 keeps p4 and p3, newest first",
			depth: 3,
			arrange: func(t *testing.T, g *password.ReuseGuard, _ *memHistory) (*identity.Details, string, *recordingWrite) {
				u := &identity.Details{ID: user, Password: hP1}
				for _, p := range []string{"p2", "p3", "p4"} {
					changeTo(t, g, u, p)
				}

				return u, "p5", &recordingWrite{}
			},
			assert: func(t *testing.T, err error, h *memHistory, _ *identity.Details, w *recordingWrite) {
				require.NoError(t, err)
				got := h.entries(user)
				require.Len(t, got, 2)
				assert.True(t, fast.Match("p4", got[0]), "newest retired is p4")
				assert.True(t, fast.Match("p3", got[1]), "then p3")
				assert.True(t, fast.Match("p5", w.hash), "the write stored p5")
			},
		},
		{
			name:  "a failed write returns its error unchanged and leaves the retired entry",
			depth: 3,
			arrange: func(_ *testing.T, _ *password.ReuseGuard, h *memHistory) (*identity.Details, string, *recordingWrite) {
				h.seed(user, hP1)
				return &identity.Details{ID: user, Password: hP2}, "p3", &recordingWrite{fail: errWrite}
			},
			assert: func(t *testing.T, err error, h *memHistory, _ *identity.Details, w *recordingWrite) {
				require.ErrorIs(t, err, errWrite)
				assert.Equal(t, 1, w.calls)
				assert.Equal(t, [][]byte{hP2, hP1}, h.entries(user))
			},
		},
		{
			name:  "a retry after a failed write does not double-count",
			depth: 3,
			arrange: func(t *testing.T, g *password.ReuseGuard, h *memHistory) (*identity.Details, string, *recordingWrite) {
				h.seed(user, hP1)
				u := &identity.Details{ID: user, Password: hP2}
				failing := &recordingWrite{fail: errWrite}
				require.ErrorIs(t, g.Change(t.Context(), u, "p3", failing.write), errWrite)

				return u, "p3", &recordingWrite{}
			},
			assert: func(t *testing.T, err error, h *memHistory, _ *identity.Details, w *recordingWrite) {
				require.NoError(t, err)
				assert.Equal(t, 1, w.calls)
				assert.Equal(t, [][]byte{hP2, hP1}, h.entries(user))
			},
		},
		{
			name:  "another user's history is not consulted",
			depth: 3,
			arrange: func(_ *testing.T, _ *password.ReuseGuard, h *memHistory) (*identity.Details, string, *recordingWrite) {
				h.seed("user-a", hP1)
				return &identity.Details{ID: "user-b", Password: hP2}, "p1", &recordingWrite{}
			},
			assert: func(t *testing.T, err error, h *memHistory, _ *identity.Details, w *recordingWrite) {
				require.NoError(t, err)
				assert.Equal(t, 1, w.calls)
				assert.Equal(t, [][]byte{hP1}, h.entries("user-a"), "user a's history is untouched")
			},
		},
		{
			name:  "lowering the depth prunes at the user's next change",
			depth: 2,
			arrange: func(t *testing.T, _ *password.ReuseGuard, h *memHistory) (*identity.Details, string, *recordingWrite) {
				wider, err := password.NewReuseGuard(h, fast, 3)
				require.NoError(t, err)

				u := &identity.Details{ID: user, Password: hP1}
				for _, p := range []string{"p2", "p3", "p4"} {
					changeTo(t, wider, u, p)
				}
				require.Len(t, h.entries(user), 2, "depth 3 built [p3, p2]")

				return u, "p5", &recordingWrite{}
			},
			assert: func(t *testing.T, err error, h *memHistory, _ *identity.Details, _ *recordingWrite) {
				require.NoError(t, err)
				got := h.entries(user)
				require.Len(t, got, 1)
				assert.True(t, fast.Match("p4", got[0]))
			},
		},
		{
			name:  "depth 1 keeps no retired hashes",
			depth: 1,
			arrange: func(_ *testing.T, _ *password.ReuseGuard, h *memHistory) (*identity.Details, string, *recordingWrite) {
				h.seed(user, hP1)
				return &identity.Details{ID: user, Password: hP2}, "p3", &recordingWrite{}
			},
			assert: func(t *testing.T, err error, h *memHistory, _ *identity.Details, w *recordingWrite) {
				require.NoError(t, err)
				assert.Equal(t, 1, w.calls)
				assert.Empty(t, h.entries(user))
			},
		},
		{
			name:  "a reused password is refused before anything is recorded or written",
			depth: 3,
			arrange: func(_ *testing.T, _ *password.ReuseGuard, h *memHistory) (*identity.Details, string, *recordingWrite) {
				h.seed(user, hP1)
				return &identity.Details{ID: user, Password: hP2}, "p1", &recordingWrite{}
			},
			assert: func(t *testing.T, err error, h *memHistory, u *identity.Details, w *recordingWrite) {
				require.ErrorIs(t, err, password.ErrPasswordReused)
				assert.Zero(t, w.calls)
				assert.Zero(t, h.retires)
				assert.Equal(t, hP2, u.Password)
			},
		},
		{
			name:  "a user with no current hash retires nothing",
			depth: 3,
			arrange: func(_ *testing.T, _ *password.ReuseGuard, _ *memHistory) (*identity.Details, string, *recordingWrite) {
				return &identity.Details{ID: user}, "p1", &recordingWrite{}
			},
			assert: func(t *testing.T, err error, h *memHistory, _ *identity.Details, w *recordingWrite) {
				require.NoError(t, err)
				assert.Equal(t, 1, w.calls)
				assert.Zero(t, h.retires)
			},
		},
		{
			name:  "an encoder error is returned as is and nothing is written",
			enc:   bcrypt10,
			depth: 3,
			arrange: func(_ *testing.T, _ *password.ReuseGuard, _ *memHistory) (*identity.Details, string, *recordingWrite) {
				return &identity.Details{ID: user, Password: hP1}, strings.Repeat("a", 73), &recordingWrite{}
			},
			assert: func(t *testing.T, err error, h *memHistory, _ *identity.Details, w *recordingWrite) {
				require.ErrorIs(t, err, password.ErrPasswordTooLong)
				assert.Zero(t, w.calls)
				assert.Equal(t, [][]byte{hP1}, h.entries(user), "the retired entry holds the hash that is still current")
			},
		},
		{
			name:  "a nil user is a wiring mistake and touches nothing",
			depth: 3,
			arrange: func(_ *testing.T, _ *password.ReuseGuard, _ *memHistory) (*identity.Details, string, *recordingWrite) {
				return nil, "p1", &recordingWrite{}
			},
			assert: func(t *testing.T, err error, h *memHistory, _ *identity.Details, w *recordingWrite) {
				require.ErrorIs(t, err, password.ErrConfig)
				assert.Zero(t, h.reads)
				assert.Zero(t, h.retires)
				assert.Zero(t, w.calls)
			},
		},
		{
			name:  "a nil write is a wiring mistake and touches nothing",
			depth: 3,
			arrange: func(_ *testing.T, _ *password.ReuseGuard, _ *memHistory) (*identity.Details, string, *recordingWrite) {
				return &identity.Details{ID: user, Password: hP1}, "p2", nil
			},
			assert: func(t *testing.T, err error, h *memHistory, _ *identity.Details, _ *recordingWrite) {
				require.ErrorIs(t, err, password.ErrConfig)
				assert.Contains(t, err.Error(), "write")
				assert.Zero(t, h.reads)
				assert.Zero(t, h.retires)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc := tc.enc
			if enc == nil {
				enc = fast
			}

			h := newMemHistory()
			g, err := password.NewReuseGuard(h, enc, tc.depth, tc.opts...)
			require.NoError(t, err)

			u, candidate, w := tc.arrange(t, g, h)

			var write password.WriteFunc
			if w != nil {
				write = w.write
			}

			tc.assert(t, g.Change(t.Context(), u, candidate, write), h, u, w)
		})
	}
}

func TestReuseGuard_Change_FailsClosed(t *testing.T) {
	t.Parallel()

	fast := fastArgon2id(t)
	hP1 := mustEncode(t, fast, "p1")
	portErr := errors.New("history store is down")

	type testCase struct {
		name    string
		history func(ctx context.Context, m *MockHistory, u *identity.Details, log *[]string)
		assert  func(t *testing.T, err error, w *recordingWrite, log []string)
	}

	cases := []testCase{
		{
			name: "a read failure refuses and nothing is recorded or written",
			history: func(ctx context.Context, m *MockHistory, u *identity.Details, _ *[]string) {
				m.EXPECT().RecentPasswords(ctx, u.ID, 2).Return(nil, portErr)
				m.EXPECT().RetirePassword(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			},
			assert: func(t *testing.T, err error, w *recordingWrite, _ []string) {
				require.ErrorIs(t, err, password.ErrHistoryUnavailable)
				assert.ErrorIs(t, err, portErr)
				assert.Zero(t, w.calls)
			},
		},
		{
			name: "a retire failure refuses before the password changes",
			history: func(ctx context.Context, m *MockHistory, u *identity.Details, _ *[]string) {
				gomock.InOrder(
					m.EXPECT().RecentPasswords(ctx, u.ID, 2).Return(nil, nil),
					m.EXPECT().RetirePassword(ctx, u.ID, u.Password, 2).Return(portErr),
				)
			},
			assert: func(t *testing.T, err error, w *recordingWrite, _ []string) {
				require.ErrorIs(t, err, password.ErrHistoryUnavailable)
				assert.ErrorIs(t, err, portErr)
				assert.Zero(t, w.calls)
			},
		},
		{
			name: "read, then retire the current hash keeping depth-1, then write",
			history: func(ctx context.Context, m *MockHistory, u *identity.Details, log *[]string) {
				gomock.InOrder(
					m.EXPECT().RecentPasswords(ctx, u.ID, 2).DoAndReturn(
						func(context.Context, identity.UserID, int) ([][]byte, error) {
							*log = append(*log, "read")
							return [][]byte{}, nil
						}),
					m.EXPECT().RetirePassword(ctx, u.ID, u.Password, 2).DoAndReturn(
						func(context.Context, identity.UserID, []byte, int) error {
							*log = append(*log, "retire")
							return nil
						}),
				)
			},
			assert: func(t *testing.T, err error, w *recordingWrite, log []string) {
				require.NoError(t, err)
				assert.Equal(t, 1, w.calls)
				assert.Equal(t, []string{"read", "retire", "write"}, log)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			m := NewMockHistory(gomock.NewController(t))
			u := &identity.Details{ID: "u-1", Password: bytes.Clone(hP1)}
			var log []string
			tc.history(ctx, m, u, &log)

			g, err := password.NewReuseGuard(m, fast, 3)
			require.NoError(t, err)

			w := &recordingWrite{log: &log}
			err = g.Change(ctx, u, "p9", w.write)
			tc.assert(t, err, w, log)
		})
	}
}

// quotingError is a port error that quotes a stored hash in its text, as a
// careless store might.
type quotingError struct{ hash []byte }

func (e *quotingError) Error() string { return "boom " + string(e.hash) }

// assertNoCredential fails if text contains any of words, or any 8-byte
// window of any of hashes.
func assertNoCredential(t *testing.T, text string, words []string, hashes ...[]byte) {
	t.Helper()

	for _, w := range words {
		assert.NotContains(t, text, w)
	}

	for _, h := range hashes {
		for i := 0; i+8 <= len(h); i++ {
			if strings.Contains(text, string(h[i:i+8])) {
				t.Errorf("error text quotes part of a stored hash at offset %d", i)
				return
			}
		}
	}
}

func TestReuseGuard_ErrorsCarryNoCredential(t *testing.T) {
	t.Parallel()

	const candidate = "Tr0ub4dor&3"

	fast := fastArgon2id(t)
	current := mustEncode(t, fast, "p0")
	retired := mustEncode(t, fast, candidate)
	words := []string{candidate, "u-123", "ada"}

	type testCase struct {
		name    string
		history func(ctx context.Context, ctrl *gomock.Controller, u *identity.Details) password.History
		assert  func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "a reuse refusal",
			history: func(context.Context, *gomock.Controller, *identity.Details) password.History {
				return newMemHistory().seed("u-123", retired)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, password.ErrPasswordReused)
				assertNoCredential(t, err.Error(), words, current, retired)
			},
		},
		{
			name: "a read failure quoting a stored hash",
			history: func(ctx context.Context, ctrl *gomock.Controller, u *identity.Details) password.History {
				m := NewMockHistory(ctrl)
				m.EXPECT().RecentPasswords(ctx, u.ID, 2).Return(nil, &quotingError{hash: retired})
				return m
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, password.ErrHistoryUnavailable)
				var portErr *quotingError
				require.ErrorAs(t, err, &portErr, "the port's error is reachable by type")
				assert.ErrorIs(t, err, portErr, "and by identity")
				assert.Equal(t, password.ErrHistoryUnavailable.Error(), err.Error())
				assertNoCredential(t, err.Error(), words, current, retired)
			},
		},
		{
			name: "a retire failure quoting the current hash",
			history: func(ctx context.Context, ctrl *gomock.Controller, u *identity.Details) password.History {
				m := NewMockHistory(ctrl)
				m.EXPECT().RecentPasswords(ctx, u.ID, 2).Return(nil, nil)
				m.EXPECT().RetirePassword(ctx, u.ID, u.Password, 2).Return(&quotingError{hash: current})
				return m
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, password.ErrHistoryUnavailable)
				var portErr *quotingError
				require.ErrorAs(t, err, &portErr)
				assert.ErrorIs(t, err, portErr)
				assert.Equal(t, password.ErrHistoryUnavailable.Error(), err.Error())
				assertNoCredential(t, err.Error(), words, current, retired)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			u := &identity.Details{ID: "u-123", Username: "ada", Password: current}

			g, err := password.NewReuseGuard(tc.history(ctx, gomock.NewController(t), u), fast, 3)
			require.NoError(t, err)

			w := &recordingWrite{}
			err = g.Change(ctx, u, candidate, w.write)
			require.Error(t, err)
			assert.Zero(t, w.calls)
			tc.assert(t, err)
		})
	}
}
