package session_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/porterr"
	scrtyid "github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// randomPanicNil is a link whose Unwrap panics with nil.
type randomPanicNil struct{}

func (randomPanicNil) Error() string { return "random panic nil" }
func (randomPanicNil) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// randomFlakyReader answers its first okReads reads with filler bytes and every
// later one with err.
type randomFlakyReader struct {
	mu      sync.Mutex
	okReads int
	err     error
}

func (r *randomFlakyReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.okReads > 0 {
		r.okReads--
		for i := range p {
			p[i] = byte(i + 1)
		}

		return len(p), nil
	}

	return 0, r.err
}

// randomSite is one place the manager reads a consumer's random reader or
// family generator. run builds a manager whose failing source answers err and
// calls the public operation.
type randomSite struct {
	name string
	run  func(t *testing.T, ctx context.Context, logger *slog.Logger, err error) error //nolint:revive // ctx after t is the test's own helper shape
}

func randomSites() []randomSite {
	const id = "porterr-1"

	manager := func(t *testing.T, logger *slog.Logger, extra ...session.Option) (*session.Sessions, *MockStore) {
		t.Helper()

		store := NewMockStore(gomock.NewController(t))
		opts := append([]session.Option{
			session.WithStore(store),
			session.WithClock(clockwork.NewFakeClockAt(createdAt)),
			session.WithLogger(logger),
		}, extra...)

		return managerFor(t, opts...), store
	}

	return []randomSite{
		{
			name: "Create_identifier_reader",
			run: func(t *testing.T, ctx context.Context, logger *slog.Logger, err error) error {
				m, _ := manager(t, logger, session.WithRandom(&randomFlakyReader{err: err}))
				_, got := m.Create(ctx, testUser)

				return got
			},
		},
		{
			name: "Prepare_identifier_reader",
			run: func(t *testing.T, _ context.Context, logger *slog.Logger, err error) error {
				m, _ := manager(t, logger, session.WithRandom(&randomFlakyReader{err: err}))
				_, got := m.Prepare(testUser) //nolint:contextcheck // Prepare is the call under test and takes no context

				return got
			},
		},
		{
			name: "Create_csrf_reader",
			run: func(t *testing.T, ctx context.Context, logger *slog.Logger, err error) error {
				m, _ := manager(t, logger, session.WithRandom(&randomFlakyReader{okReads: 1, err: err}))
				_, got := m.Create(ctx, testUser, session.WithCSRFToken())

				return got
			},
		},
		{
			name: "Create_family_generator",
			run: func(t *testing.T, ctx context.Context, logger *slog.Logger, err error) error {
				gen := NewMockGenerator(gomock.NewController(t))
				gen.EXPECT().NewID().Return(scrtyid.Nil, err).AnyTimes()
				m, _ := manager(t, logger, session.WithFamilyIDGenerator(gen))
				_, got := m.Create(ctx, testUser)

				return got
			},
		},
		{
			name: "RotateIssuing_reader",
			run: func(t *testing.T, ctx context.Context, logger *slog.Logger, err error) error {
				m, store := manager(t, logger, session.WithRandom(&randomFlakyReader{err: err}))
				store.EXPECT().Load(gomock.Any(), id).Return(liveUnpresented(id), nil).AnyTimes()
				_, _, got := m.RotateIssuing(ctx, liveUnpresented(id), func(*session.Session) (string, error) { return "", nil })

				return got
			},
		},
		{
			name: "RotateWithGraceIssuing_reader",
			run: func(t *testing.T, ctx context.Context, logger *slog.Logger, err error) error {
				m, store := manager(t, logger, session.WithRandom(&randomFlakyReader{err: err}))
				store.EXPECT().Load(gomock.Any(), id).Return(liveUnpresented(id), nil).AnyTimes()
				_, _, got := m.RotateWithGrace(ctx, liveUnpresented(id), session.DefaultRenewalGrace)

				return got
			},
		},
	}
}

// TestPortErrors_SessionsRandomSources: a hostile error from the consumer's
// random reader (WithRandom) or family generator (WithFamilyIDGenerator) is
// answered as a plain failure of that source is, within bounds, as the fixed
// fault, with one abort record on the manager's logger and none on
// slog.Default().
//
// Not parallel: it swaps slog.Default to prove the record goes to the
// manager's logger.
func TestPortErrors_SessionsRandomSources(t *testing.T) {
	type testCase struct {
		name   string
		err    func() error
		aborts int
		child  bool
	}

	cases := []testCase{
		{name: "cycle through Unwrap() error", err: func() error { return &storeCycleOne{} }, aborts: 1},
		{name: "cycle through Unwrap() []error", err: func() error { return &storeCycleMany{} }, aborts: 1, child: true},
		{name: "fan-out past the budget", err: func() error { return &storeManyNils{kids: make([]error, 1<<20)} }, aborts: 1},
		{name: "panicking Unwrap", err: func() error { return storePanicUnwrap{} }, aborts: 1},
		{name: "panic(nil) in Unwrap", err: func() error { return randomPanicNil{} }, aborts: 1},
		{name: "typed nil root with safe methods", err: func() error { return (*storeTypedNil)(nil) }, aborts: 0},
	}

	child := childStoreRow()

	for _, site := range randomSites() {
		for _, tc := range cases {
			row := "random/" + site.name + "/" + tc.name
			if child != "" && child != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if child == "" && tc.child {
					inStoreChild(t, row)

					return
				}

				defaultLogs := &captureHandler{}
				previous := slog.Default()
				slog.SetDefault(slog.New(defaultLogs))
				t.Cleanup(func() { slog.SetDefault(previous) })

				call := func(err error) (int, error) {
					logs := &captureHandler{}
					got := withinTwoSeconds(t, func() error { return site.run(t, t.Context(), slog.New(logs), err) })

					return logs.aborts(), got
				}

				plainAborts, plain := call(errors.New("entropy: down"))
				require.Error(t, plain)
				require.Zero(t, plainAborts, "a plain failure writes no abort record")

				aborts, got := call(tc.err())

				assert.Equal(t, tc.aborts, aborts, "abort records on the manager's logger")
				assert.Zero(t, defaultLogs.aborts(), "the manager's logger is used, not slog.Default()")
				require.Error(t, got)
				assert.False(t, isWithin(t, got, session.ErrConfig), "a failing source is no configuration error")
				assert.False(t, isWithin(t, got, session.ErrNotFound))

				if tc.aborts == 1 {
					assert.True(t, isWithin(t, got, porterr.ErrUnwalkable), "the fault matches ErrUnwalkable")
					assert.NotContains(t, got.Error(), "store ", "nothing of the consumer's error reaches the text")
					assert.NotContains(t, got.Error(), "random panic", "nothing of the consumer's error reaches the text")
					assert.NotContains(t, got.Error(), "Unwrap panicked")
					assert.Equal(t, strings.SplitN(plain.Error(), ": entropy", 2)[0],
						strings.SplitN(got.Error(), ": scrty:", 2)[0], "same context as a plain failure")
				}

				if child != "" && !t.Failed() {
					fmt.Println(childRanMarker(row))
				}
			})
		}
	}
}

// TestPortErrors_SessionsRandomSources_EndToEnd reproduces the case that hung a
// caller: a manager whose random source fails after the first read, a
// RotateIssuing on a created session, and the stdlib errors.Is a caller runs
// on the result.
func TestPortErrors_SessionsRandomSources_EndToEnd(t *testing.T) {
	t.Parallel()

	logs := &captureHandler{}
	m := managerFor(t,
		session.WithLogger(slog.New(logs)),
		session.WithClock(clockwork.NewFakeClockAt(createdAt)),
		session.WithRandom(&randomFlakyReader{okReads: 1, err: &storeCycleOne{}}),
	)

	created, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	got := withinTwoSeconds(t, func() error {
		_, _, err := m.RotateIssuing(t.Context(), created, func(*session.Session) (string, error) { return "", nil })

		return err
	})

	require.Error(t, got)
	assert.True(t, isWithin(t, got, porterr.ErrUnwalkable))
	assert.False(t, isWithin(t, got, session.ErrNotFound))
	assert.Equal(t, 1, logs.aborts())
}
