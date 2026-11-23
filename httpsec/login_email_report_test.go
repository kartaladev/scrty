package httpsec_test

// The two tests in this file build structurally different chains: one judged
// and reported by a lockout policy's view, the other over a plain attempt
// store with no lockout at all, so they are kept as separate tables.

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// emailReportOutcome is what a row of TestLogin_EmailReportedOnceUnderAccount
// observed: the lockout observer's reports, the security events and the
// fixture's attempt store.
type emailReportOutcome struct {
	reports []lockout.Report
	events  []event.Event
	f       *emailLoginFixture
}

// identifiersOf lists the identifiers reports name, in order.
func identifiersOf(reports []lockout.Report) []string {
	ids := make([]string, 0, len(reports))
	for _, r := range reports {
		ids = append(ids, r.Identifier)
	}

	return ids
}

// TestLogin_EmailReportedOnceUnderAccount pins that one account gives one
// report: failures and a success presented as the account's verified email
// are told to the lockout observer, and a lock to the security-event sink,
// under the account alone, at both endpoints. The email still carries its own
// failures, for the automation challenge, but writing them reports nothing.
func TestLogin_EmailReportedOnceUnderAccount(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		endpoint emailLoginEndpoint
		run      func(t *testing.T, ep emailLoginEndpoint, c *httpsec.Chain)
		assert   func(t *testing.T, got emailReportOutcome)
	}

	// failures presents n wrong passwords as the email.
	failures := func(t *testing.T, ep emailLoginEndpoint, c *httpsec.Chain, n int) {
		t.Helper()

		for i := range n {
			out := ep.present(t, c, emailLoginAddress, emailLoginWrong)
			require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "failure %d", i+1)
		}
	}

	emailCount := func(t *testing.T, f *emailLoginFixture) int {
		t.Helper()

		n, err := f.attempts.FailureCount(t.Context(), emailLoginAddress, time.Now().Add(-time.Hour))
		require.NoError(t, err)

		return n
	}

	var cases []testCase
	for _, ep := range emailLoginEndpoints {
		cases = append(cases,
			testCase{
				name: ep.name + ": five failures by email lock the account once", endpoint: ep,
				run: func(t *testing.T, ep emailLoginEndpoint, c *httpsec.Chain) {
					t.Helper()
					failures(t, ep, c, 5)
				},
				assert: func(t *testing.T, got emailReportOutcome) {
					assert.Len(t, eventsNamed(got.events, event.AuthnLoginLock), 1,
						"one lock event: events %v", namesOf(got.events))
					assert.Len(t, eventsNamed(got.events, event.AuthnLoginFailMax), 1,
						"one fail-max event: events %v", namesOf(got.events))
					assert.Equal(t, 5, emailCount(t, got.f), "the email still carries its failures for the challenge")

					assert.Equal(t, []string{emailLoginUsername}, identifiersOf(got.reports),
						"the lock is reported under the account, and not again under the email")
					require.Len(t, got.reports, 1)
					assert.Equal(t, lockout.ReportLocked, got.reports[0].Kind)
					assert.Equal(t, 5, got.reports[0].Failures)
				},
			},
			testCase{
				name: ep.name + ": a success by email clears the account once", endpoint: ep,
				run: func(t *testing.T, ep emailLoginEndpoint, c *httpsec.Chain) {
					t.Helper()
					failures(t, ep, c, 4)
					require.NoError(t, ep.present(t, c, emailLoginAddress, emailLoginRight).err)
				},
				assert: func(t *testing.T, got emailReportOutcome) {
					assert.Equal(t, []string{emailLoginUsername}, identifiersOf(got.reports),
						"the clearing is reported under the account, and not again under the email")
					require.Len(t, got.reports, 1)
					assert.Equal(t, lockout.ReportCleared, got.reports[0].Kind)
					assert.Equal(t, 4, got.reports[0].Failures)

					assert.Zero(t, emailCount(t, got.f), "the success clears the email's failures too")
				},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				mu      sync.Mutex
				reports []lockout.Report
				events  []event.Event
			)

			observer := func(_ context.Context, r lockout.Report) {
				mu.Lock()
				defer mu.Unlock()
				reports = append(reports, r)
			}
			sink := func(_ context.Context, e event.Event) {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, e)
			}

			f := newEmailLoginFixture(t, lockout.WithSliding(5, time.Hour), lockout.WithObserver(observer))
			f.allowLogin = true
			f.knowsAda()
			c := f.chain(t, true, httpsec.EnableSecurityEvents(sink))

			tc.run(t, tc.endpoint, c)

			mu.Lock()
			got := emailReportOutcome{reports: slices.Clone(reports), events: slices.Clone(events), f: f}
			mu.Unlock()

			tc.assert(t, got)
		})
	}
}

// unjudgedChain builds form login and Basic, with email login on, over the
// fixture's provider and recording into store, with no lockout policy
// registered, so the chain records straight into store.
func (f *emailLoginFixture) unjudgedChain(t *testing.T, store policy.AttemptStore, log *slog.Logger) *httpsec.Chain {
	t.Helper()

	provider, err := authenticate.NewUsernamePasswordAuthenticator(
		emailUserLoader{MockUserLoader: f.users, MockEmailLoader: f.emails},
		authenticate.WithPasswordEncoder(f.enc),
		authenticate.WithPasswordLogger(slog.New(slog.DiscardHandler)),
		authenticate.WithEmailLogin())
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	tokens := newMockGenerator(ctrl)
	tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("a-token", nil).AnyTimes()
	sessions, err := session.New(session.WithStore(must.Must(session.NewMemoryStore())))
	require.NoError(t, err)

	c, err := httpsec.New(
		httpsec.WithLogger(log),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: provider, Sessions: sessions, Tokens: tokens, Attempts: store,
		}),
		httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: provider, Attempts: store}),
	)
	require.NoError(t, err)

	return c
}

// TestLogin_EmailCountedUnderBothWithPlainStore pins the fallback: with an
// attempt store that reports nothing, and so has nothing to report twice, a
// failure by email is still counted under the account and under the email as
// typed, and a success by email clears both, at both endpoints.
func TestLogin_EmailCountedUnderBothWithPlainStore(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		endpoint emailLoginEndpoint
		success  bool
		assert   func(t *testing.T, attempts *lockout.MemoryAttemptStore)
	}

	countsAre := func(want int) func(t *testing.T, attempts *lockout.MemoryAttemptStore) {
		return func(t *testing.T, attempts *lockout.MemoryAttemptStore) {
			t.Helper()

			for _, id := range []string{emailLoginUsername, emailLoginAddress} {
				n, err := attempts.FailureCount(t.Context(), id, time.Now().Add(-time.Hour))
				require.NoError(t, err)
				assert.Equal(t, want, n, "failures under %s", id)
			}
		}
	}

	var cases []testCase
	for _, ep := range emailLoginEndpoints {
		cases = append(cases,
			testCase{name: ep.name + ": a failure counts under both", endpoint: ep, assert: countsAre(2)},
			testCase{name: ep.name + ": a success clears both", endpoint: ep, success: true, assert: countsAre(0)},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The fixture's lockout is not wired: the chain records straight
			// into the plain memory store.
			f := newEmailLoginFixture(t)
			f.knowsAda()

			c := f.unjudgedChain(t, f.attempts, slog.New(slog.DiscardHandler))

			for range 2 {
				out := tc.endpoint.present(t, c, emailLoginAddress, emailLoginWrong)
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
			}
			if tc.success {
				require.NoError(t, tc.endpoint.present(t, c, emailLoginAddress, emailLoginRight).err)
			}

			tc.assert(t, f.attempts)
		})
	}
}

// unreportedSpyStore is a consumer's attempt store that offers the unreported
// record (policy.UnreportedAttemptRecorder) over a memory store, noting the
// identifiers written through it and failing those writes when told to.
type unreportedSpyStore struct {
	*lockout.MemoryAttemptStore

	recordErr, resetErr error
	// accountRecordErr fails RecordFailure, the account's write, and leaves
	// RecordFailureUnreported, the identifier as typed, alone.
	accountRecordErr error

	mu                sync.Mutex
	recorded, cleared []string
}

func (s *unreportedSpyStore) RecordFailure(ctx context.Context, username string, at time.Time) error {
	if s.accountRecordErr != nil {
		return s.accountRecordErr
	}

	return s.MemoryAttemptStore.RecordFailure(ctx, username, at)
}

func (s *unreportedSpyStore) RecordFailureUnreported(ctx context.Context, identifier string, at time.Time) error {
	s.mu.Lock()
	s.recorded = append(s.recorded, identifier)
	s.mu.Unlock()

	if s.recordErr != nil {
		return s.recordErr
	}

	return s.MemoryAttemptStore.RecordFailure(ctx, identifier, at)
}

func (s *unreportedSpyStore) ResetUnreported(ctx context.Context, identifier string) error {
	s.mu.Lock()
	s.cleared = append(s.cleared, identifier)
	s.mu.Unlock()

	if s.resetErr != nil {
		return s.resetErr
	}

	return s.Reset(ctx, identifier)
}

var _ policy.UnreportedAttemptRecorder = (*unreportedSpyStore)(nil)

// TestLogin_EmailTypedRecordThroughConsumerPort pins that the chain writes the
// identifier as typed through a consumer store's unreported record when the
// store offers one, and that a store failing either write changes nothing the
// client sees: the account's own record still lands, and the failure is
// logged with its fixed record, at both endpoints.
func TestLogin_EmailTypedRecordThroughConsumerPort(t *testing.T) {
	t.Parallel()

	errStoreDown := errors.New("test: attempt store unavailable")

	type testCase struct {
		name     string
		endpoint emailLoginEndpoint
		store    *unreportedSpyStore
		success  bool
		assert   func(t *testing.T, s *unreportedSpyStore, logs string)
	}

	countOf := func(t *testing.T, s *unreportedSpyStore, id string) int {
		t.Helper()

		n, err := s.FailureCount(t.Context(), id, time.Now().Add(-time.Hour))
		require.NoError(t, err)

		return n
	}

	var cases []testCase
	for _, ep := range emailLoginEndpoints {
		cases = append(cases,
			testCase{
				name: ep.name + ": a failed unreported record is logged, the account's still counts", endpoint: ep,
				store: &unreportedSpyStore{recordErr: errStoreDown},
				assert: func(t *testing.T, s *unreportedSpyStore, logs string) {
					assert.Equal(t, []string{emailLoginAddress, emailLoginAddress}, s.recorded,
						"the email is written through the store's unreported record")
					assert.Equal(t, 2, countOf(t, s, emailLoginUsername), "the account's failures still count")
					assert.Zero(t, countOf(t, s, emailLoginAddress))
					assert.Contains(t, logs, "httpsec: a failed login attempt could not be recorded")
					assert.NotContains(t, logs, errStoreDown.Error(), "the store's text stays out of the log")
				},
			},
			testCase{
				name: ep.name + ": a failed account write is logged, the typed record still lands", endpoint: ep,
				store: &unreportedSpyStore{accountRecordErr: errStoreDown},
				assert: func(t *testing.T, s *unreportedSpyStore, logs string) {
					assert.Equal(t, []string{emailLoginAddress, emailLoginAddress}, s.recorded,
						"the email is still written through the store's unreported record")
					assert.Equal(t, 2, countOf(t, s, emailLoginAddress), "the typed record lands")
					assert.Zero(t, countOf(t, s, emailLoginUsername), "the account's write failed")
					assert.Contains(t, logs, "httpsec: a failed login attempt could not be recorded")
					assert.NotContains(t, logs, errStoreDown.Error(), "the store's text stays out of the log")
				},
			},
			testCase{
				name: ep.name + ": a failed unreported reset is logged, the account's still clears", endpoint: ep,
				store: &unreportedSpyStore{resetErr: errStoreDown}, success: true,
				assert: func(t *testing.T, s *unreportedSpyStore, logs string) {
					assert.Equal(t, []string{emailLoginAddress}, s.cleared,
						"the email is cleared through the store's unreported reset")
					assert.Zero(t, countOf(t, s, emailLoginUsername), "the account's failures are cleared")
					assert.Equal(t, 2, countOf(t, s, emailLoginAddress), "the email's failures outlive the failed reset")
					assert.Contains(t, logs, "httpsec: failed login attempts could not be cleared")
					assert.NotContains(t, logs, errStoreDown.Error(), "the store's text stays out of the log")
				},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailLoginFixture(t)
			f.knowsAda()
			tc.store.MemoryAttemptStore = must.Must(lockout.NewMemoryAttemptStore())

			var logs syncBuffer
			c := f.unjudgedChain(t, tc.store, slog.New(slog.NewTextHandler(&logs, nil)))

			for range 2 {
				out := tc.endpoint.present(t, c, emailLoginAddress, emailLoginWrong)
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "the response is unchanged")
			}
			if tc.success {
				require.NoError(t, tc.endpoint.present(t, c, emailLoginAddress, emailLoginRight).err,
					"the login succeeds whatever the store's reset did")
			}

			tc.store.mu.Lock()
			defer tc.store.mu.Unlock()
			tc.assert(t, tc.store, logs.String())
		})
	}
}
