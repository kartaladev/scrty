package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// errFixtureFailure is the dependency error every row below drives its site
// with. Its text quotes an address and a user reference, neither of which may
// reach a written record: this is the reproduction task 3.1 is a defect claim
// against, one per site.
var errFixtureFailure = errors.New(
	"store: Key (username)=(alice@example.com) for user u-123")

// The two values errFixtureFailure quotes, which no record may carry.
const (
	leakedAddress = "alice@example.com"
	leakedUserRef = "u-123"
)

// recordText renders r's message and every attribute as one string, so a test
// can assert on what the record carries without depending on a handler's own
// formatting.
func recordText(r slog.Record) string {
	var sb strings.Builder

	sb.WriteString(r.Message)

	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" ")
		sb.WriteString(a.Key)
		sb.WriteString("=")
		sb.WriteString(a.Value.String())

		return true
	})

	return sb.String()
}

// assertNoLeak asserts that no record in records carries the fixture's
// address or user reference, whatever else it carries.
func assertNoLeak(t *testing.T, records []slog.Record) {
	t.Helper()

	for i, r := range records {
		text := recordText(r)
		assert.NotContains(t, text, leakedAddress, "record %d leaked the address", i)
		assert.NotContains(t, text, leakedUserRef, "record %d leaked the user reference", i)
	}
}

// assertFailureRecord asserts that one of records carries reason and a
// non-empty error_type, and returns it so a caller can assert anything more it
// needs (flow, source).
func assertFailureRecord(t *testing.T, records []slog.Record, reason string) slog.Record {
	t.Helper()

	for _, r := range records {
		v, ok := attrValue(r, "reason")
		if !ok || v.String() != reason {
			continue
		}

		assert.Equal(t, 1, attrCount(r, "reason"),
			"the record carries reason=%s, and must carry it exactly once", reason)

		errType, ok := attrValue(r, "error_type")
		require.True(t, ok, "the record carries reason=%s but no error_type", reason)
		assert.NotEmpty(t, errType.String(), "error_type must not be empty")

		return r
	}

	require.Fail(t, fmt.Sprintf("no record carried reason=%s", reason))

	return slog.Record{}
}

// attrCount is how many of r's attributes are named key. slog keeps every
// attribute it is handed, so a key added twice is written twice by a JSON or
// text handler, and a reader of the record sees two values for one field.
func attrCount(r slog.Record, key string) int {
	n := 0

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			n++
		}

		return true
	})

	return n
}

// assertNoDuplicateKeys asserts that no record in records carries any
// attribute key more than once.
func assertNoDuplicateKeys(t *testing.T, records []slog.Record) {
	t.Helper()

	for i, r := range records {
		seen := map[string]int{}

		r.Attrs(func(a slog.Attr) bool {
			seen[a.Key]++

			return true
		})

		for key, n := range seen {
			assert.Equal(t, 1, n, "record %d (%q) carries %q %d times", i, r.Message, key, n)
		}
	}
}

// recordWithMessage returns the first of records written with msg.
func recordWithMessage(t *testing.T, records []slog.Record, msg string) slog.Record {
	t.Helper()

	for _, r := range records {
		if r.Message == msg {
			return r
		}
	}

	require.Fail(t, fmt.Sprintf("no record was written with message %q", msg))

	return slog.Record{}
}

// failingHandoffStore is an oidc.HandoffStore whose Insert always fails with
// err, quoting whatever a real store's row might. Issue is the only method the
// handoff-issue site exercises; the others are never reached by it.
type failingHandoffStore struct {
	err error
}

func (s failingHandoffStore) Insert(context.Context, oidc.HandoffRecord) error { return s.err }

func (failingHandoffStore) FindByTokenID(context.Context, string) (*oidc.HandoffRecord, error) {
	return nil, oidc.ErrHandoffNotFound
}

func (failingHandoffStore) Consume(context.Context, string, time.Time) error {
	return oidc.ErrHandoffNotFound
}

func (failingHandoffStore) DeleteExpired(context.Context, time.Time) (int, error) {
	return 0, nil
}

// TestHTTPSecFailureRecords is the reproduction for task 3.1: one row per
// site that today writes a failed dependency's own error text into a log
// record. Each row drives the chain so the dependency returns
// errFixtureFailure, and asserts that no written record carries either value
// the error's text quotes, while the record still names what failed.
func TestHTTPSecFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		reason string
		// message picks the record to assert on by its message instead, for
		// a row whose record deliberately names no failed dependency.
		message string
		act     func(t *testing.T) []slog.Record
		assert  func(t *testing.T, r slog.Record)
	}

	cases := []testCase{
		{
			name:   "form login: the attempt store's record could not be written",
			reason: "attempt-store",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectAuthenticationFailed()
				h.attempts.EXPECT().RecordFailure(gomock.Any(), "carol", gomock.Any()).
					Return(errFixtureFailure)

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableFormLogin(h.formLoginDeps()),
				)
				require.NoError(t, err)

				out := serve(t, chain, formRequest(t.Context(), "/login", "username=carol&password=wrong"))
				require.Error(t, out.err)

				return h.logs.records()
			},
		},
		{
			name:   "form login: the attempt store's reset could not be written",
			reason: "attempt-store",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "carol").Return(errFixtureFailure)
				h.expectSessionOpened("issued-token")

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableFormLogin(h.formLoginDeps()),
				)
				require.NoError(t, err)

				out := serve(t, chain, formRequest(t.Context(), "/login", "username=carol&password=s3cret"))
				require.NoError(t, out.err)

				return h.logs.records()
			},
		},
		{
			name:   "basic auth: the attempt store's record could not be written",
			reason: "attempt-store",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectAuthenticationFailed()
				h.attempts.EXPECT().RecordFailure(gomock.Any(), "carol", gomock.Any()).
					Return(errFixtureFailure)

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBasicAuth(h.basicAuthDeps()),
				)
				require.NoError(t, err)

				out := serve(t, chain, basicRequest(t.Context(), "carol", "wrong"))
				require.Error(t, out.err)

				return h.logs.records()
			},
		},
		{
			name:   "session touch: the activity write-back could not be recorded",
			reason: "session-store",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.expectSaved(&savedSessions{}, errFixtureFailure)

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
				)
				require.NoError(t, err)

				out := serve(t, chain, bearerRequest(t.Context(), "Bearer a-token"))
				require.NoError(t, out.err)

				return h.logs.records()
			},
		},
		{
			name:   "oidc callback: the handoff code could not be issued",
			reason: "handoff-issue",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newOIDCHarness(t)

				users := NewMockUserLoader(gomock.NewController(t))
				handoffs, err := oidc.NewHandoffManager(
					failingHandoffStore{err: errFixtureFailure}, users)
				require.NoError(t, err)

				var log capturingHandler

				chain, err := httpsec.New(
					httpsec.WithLogger(slog.New(&log)),
					httpsec.WithRefusalLogInterval(0),
					httpsec.EnableOIDCLogin(h.manager, handoffs,
						httpsec.WithOIDCTokens(h.tokens),
						httpsec.WithOIDCSessions(h.sessions)),
				)
				require.NoError(t, err)

				login := startLogin(t, chain, "")
				out := serve(t, chain, callbackRequest(t.Context(), login.genuineCallback(), login.handle))
				require.Error(t, out.err)

				return log.records()
			},
		},
		{
			name:   "throttle: the rate limiter could not answer",
			reason: "limiter",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				var log capturingHandler

				limiter := NewMockLimiter(gomock.NewController(t))
				limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
					Return(true, errFixtureFailure)

				_, err := httpsec.SourceThrottledForTest(t.Context(), guardOver(t, limiter),
					"198.51.100.7", "login", nil, slog.New(&log), time.Now())
				require.Error(t, err)

				return log.records()
			},
			assert: func(t *testing.T, r slog.Record) {
				t.Helper()

				flow, ok := attrValue(r, "flow")
				require.True(t, ok, "the limiter record must still name its flow")
				assert.Equal(t, "login", flow.String())
			},
		},
		{
			name:   "throttle: the request ended before the rate limiter answered",
			reason: "limiter",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				var log capturingHandler

				wrapped := fmt.Errorf("%w: %s", context.Canceled, errFixtureFailure.Error())

				limiter := NewMockLimiter(gomock.NewController(t))
				limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
					DoAndReturn(func(context.Context, string) (bool, error) {
						return true, wrapped
					})

				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				_, err := httpsec.SourceThrottledForTest(ctx, guardOver(t, limiter),
					"198.51.100.7", "login", nil, slog.New(&log), time.Now())
				require.Error(t, err)

				return log.records()
			},
			assert: func(t *testing.T, r slog.Record) {
				t.Helper()

				assert.Equal(t, "httpsec: the request ended before the rate limiter answered", r.Message)

				flow, ok := attrValue(r, "flow")
				require.True(t, ok, "the limiter record must still name its flow")
				assert.Equal(t, "login", flow.String())

				cancelled, ok := attrValue(r, "cancelled")
				require.True(t, ok, "a request that ended says so")
				assert.True(t, cancelled.Bool())
			},
		},
		{
			// The throttled address is the one value a throttle record carries
			// on purpose: an operator needs to know who was throttled.
			name:    "throttle: a source over its limit stays visible",
			message: guardThrottledMsg,
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				var log capturingHandler

				// The guard writes the one throttled-source record, through the
				// chain's logger, which is what every chain-built guard has.
				g, err := ratelimit.NewSourceGuard("login", limiterThrottling(t),
					ratelimit.WithSourceGuardLogger(slog.New(&log)))
				require.NoError(t, err)

				_, err = httpsec.SourceThrottledForTest(t.Context(), g,
					"198.51.100.7", "login", nil, slog.New(&log), time.Now())
				require.Error(t, err)

				return log.records()
			},
			assert: func(t *testing.T, r slog.Record) {
				t.Helper()

				source, ok := attrValue(r, "source")
				require.True(t, ok, "the throttle record names the throttled source")
				assert.Equal(t, "198.51.100.7", source.String())
			},
		},
		{
			name:   "bearer: the session store could not read the session",
			reason: "session-store",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectVerified()
				h.store.EXPECT().Load(gomock.Any(), testJTI).
					Return(nil, fmt.Errorf("%w: %w", session.ErrSessionUnreadable, errFixtureFailure))

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
				)
				require.NoError(t, err)

				out := serve(t, chain, bearerRequest(t.Context(), "Bearer a-token"))
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)

				return h.logs.records()
			},
		},
		{
			name:   "logout: the end-session step could not build the provider's URL",
			reason: "end-session",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectVerified()
				h.expectResolvedSession(federatedSession())
				h.store.EXPECT().Delete(gomock.Any(), testJTI).Return(nil)

				b := NewMockEndSessionBuilder(gomock.NewController(t))
				b.EXPECT().EndSessionURL(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("", errFixtureFailure)

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions, EndSession: b}),
				)
				require.NoError(t, err)

				out := serve(t, chain, logoutFormRequest(t.Context(), nil))
				require.NoError(t, out.err)

				return h.logs.records()
			},
			assert: func(t *testing.T, r slog.Record) {
				t.Helper()

				provider, ok := attrValue(r, "provider")
				require.True(t, ok, "the record still names the provider")
				assert.Equal(t, "corp", provider.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			records := tc.act(t)
			require.NotEmpty(t, records, "the site under test wrote no record at all")

			assertNoLeak(t, records)
			assertNoDuplicateKeys(t, records)

			var r slog.Record
			if tc.message != "" {
				r = recordWithMessage(t, records, tc.message)
			} else {
				r = assertFailureRecord(t, records, tc.reason)
			}

			if tc.assert != nil {
				tc.assert(t, r)
			}
		})
	}
}
