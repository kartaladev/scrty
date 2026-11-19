package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime/debug"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// renewalPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const renewalPortErrRowEnv = "SCRTY_HTTPSEC_RENEWAL_PORTERR_ROW"

// renewalPortErrRan is what a child prints, as a line of its own followed by
// the row's name, once it has run its row to the end.
const renewalPortErrRan = "renewal-porterr-row-ran:"

// renewalCouldNotAnswer is the record admit writes for a limiter that could
// not answer.
const renewalCouldNotAnswer = "the renewal limiter could not answer; the renewal is refused"

// renewalLimiterOutcome is everything one renewal request through a failing
// limiter produced that a client or the account can observe, and the records
// the chain's logger received.
type renewalLimiterOutcome struct {
	status         int
	header         http.Header
	body           string
	asked, charged int
	superseded     bool
	logs           []slog.Record
}

// renewalThrough serves one renewal on a live session through the chain's
// net/http middleware, as a server does, with the renewal limiter's check
// failing with portErr. When cancelDuring is set the request is cancelled
// inside the check.
func renewalThrough(t *testing.T, portErr error, cancelDuring bool) renewalLimiterOutcome {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var onAsk context.CancelFunc
	if cancelDuring {
		onAsk = cancel
	}

	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))
	sessions, err := session.New(
		session.WithClock(clk),
		session.WithStore(must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))),
	)
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

	logs := &capturingHandler{}
	ask := &limiterAsk{}

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: sessions, Users: users},
			httpsec.WithRenewalLimiter(hostileLimiter(t, ask, portErr, onAsk))))
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
	req.Header.Set("Authorization", "Bearer "+s.ID)

	rec := loginServeWithin(t, chain, req)

	stored, err := sessions.Load(t.Context(), s.ID)
	require.NoError(t, err)

	asked, charged := ask.counts()

	return renewalLimiterOutcome{
		status: rec.Code, header: rec.Header(), body: rec.Body.String(),
		asked: asked, charged: charged, superseded: !stored.SupersededAt.IsZero(),
		logs: logs.records(),
	}
}

// TestPortErrors_RenewalLimiter pins that a hostile error from the renewal
// limiter's check is answered exactly as a plain limiter outage is: the renewal
// is refused as throttled, byte for byte the same response, with nothing
// rotated and nothing charged. It is never "under the limit". It is reported
// once, to the chain's logger, and not to slog.Default().
func TestPortErrors_RenewalLimiter(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(renewalPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	contexts := []struct {
		name         string
		cancelDuring bool
	}{
		{name: "live"},
		{name: "cancelled", cancelDuring: true},
	}

	plainOutage := errors.New("limiter: connection refused")

	for _, c := range contexts {
		for _, kind := range limiterPortErrKinds(httpsec.ErrRenewalThrottled) {
			row := "the renewal limiter's check/" + c.name + "/" + kind.name
			if childRow != "" && childRow != row {
				continue
			}

			if kind.ctx != "" && kind.ctx != c.name {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if kind.child && childRow == "" {
					limiterPortErrInChild(t, renewalPortErrRowEnv, renewalPortErrRan, row)

					return
				}

				defaults := swapDefaultLogger(t)

				plain := renewalThrough(t, plainOutage, c.cancelDuring)
				require.Empty(t, abortRecords(plain.logs), "the plain outage writes no abort record")
				require.Equal(t, http.StatusTooManyRequests, plain.status, "a plain outage refuses as throttled")
				require.Equal(t, 1, plain.asked, "the limiter was asked")
				require.False(t, plain.superseded, "a plain outage rotates nothing")

				got := renewalThrough(t, kind.err, c.cancelDuring)

				assert.Equal(t, plain.status, got.status, "status")
				assert.Equal(t, plain.header, got.header, "headers")
				assert.Equal(t, plain.body, got.body, "body")
				assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")
				assert.Equal(t, plain.asked, got.asked, "checks of the limiter")
				assert.Equal(t, plain.charged, got.charged, "charges to the limiter")
				assert.Equal(t, plain.superseded, got.superseded, "rotation")
				assert.Equal(t, 1, countRecords(got.logs, renewalCouldNotAnswer), "the site's own record")
				assert.Equal(t, nonAbortMessages(plain.logs), nonAbortMessages(got.logs), "the chain's records")

				aborts := abortRecords(got.logs)
				if kind.reason == "" {
					assert.Empty(t, aborts, "a walk that completes writes no abort record")
				} else {
					require.Len(t, aborts, 1, "one abort record, on the chain's logger")
					assertAbortRecord(t, aborts[0], kind.reason)
				}

				assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

				if childRow != "" && !t.Failed() {
					fmt.Fprintln(os.Stdout, renewalPortErrRan+row)
				}
			})
		}
	}
}

// countRecords is how many of recs carry msg.
func countRecords(recs []slog.Record, msg string) int {
	n := 0

	for _, r := range recs {
		if r.Message == msg {
			n++
		}
	}

	return n
}
