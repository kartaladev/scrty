package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// noticePortErrRowEnv names the row a child process of
// TestPortErrors_SignInNotice runs. It is empty in the parent.
const noticePortErrRowEnv = "SCRTY_HTTPSEC_NOTICE_PORTERR_ROW"

// noticePortErrRan is what a child prints, as a line of its own followed by
// the row's name, once it has run its row to the end.
const noticePortErrRan = "notice-porterr-row-ran:"

// issuedToken is the access token a sign-in answers with, which differs on
// every sign-in and is masked so two answers compare.
var issuedToken = regexp.MustCompile(`"access_token":"[^"]*"`)

// noticePortSite is one port call of the sign-in notice's background work.
type noticePortSite struct {
	name string

	// wire fails the site's port with portErr through the options, the
	// seen-devices port or, for the sender, the error it returns. The port
	// calls onCall, which cancels the request when the row asks.
	wire func(portErr error, onCall func(), seen *MockSeenDevices) (opts []httpsec.SignInNoticeOption, sendErr error)
}

// noticeOutcome is what one sign-in produced that the user, the account or the
// consumer can observe, and the chain's records.
type noticeOutcome struct {
	status   int
	body     string
	sends    int32
	sessions int
	logs     []slog.Record
	panicked bool
}

// noticeThrough serves a form login that stores a sign-in beside an earlier
// one from another device, so the notice reaches the site, whose port fails
// with portErr. It waits for the notice's background work.
func noticeThrough(t *testing.T, site noticePortSite, portErr error, cancelDuring bool) noticeOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, cancelDuring)

	clk := clockwork.NewFakeClockAt(time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC))
	ctrl := gomock.NewController(t)

	store := &noticeStore{Store: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))}
	sessions := must.Must(session.New(session.WithClock(clk), session.WithStore(store), session.WithSessionMetadata()))

	authn := NewMockAuthenticator(ctrl)
	authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
			return &authenticate.Authentication{
				Principal: &identity.Principal{ID: "u-1", Username: "ada@example.com"},
				Time:      clk.Now(),
			}, nil
		}).AnyTimes()

	var sends atomic.Int32

	seen := NewMockSeenDevices(ctrl)
	opts, sendErr := site.wire(portErr, onCall, seen)

	sender := NewMockSender(ctrl)
	sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, notify.Message) error {
		sends.Add(1)
		onCall()

		return sendErr
	}).AnyTimes()

	var pending sync.WaitGroup

	logs := &capturingHandler{}

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn, Sessions: sessions, Attempts: must.Must(lockout.New()).Attempts(),
		}),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: NewMockUserLoader(ctrl)}),
		httpsec.EnableSignInNotice(nonBlockingSender{sender},
			append([]httpsec.SignInNoticeOption{httpsec.WithSignInNoticeTracker(&pending)}, opts...)...),
	)
	require.NoError(t, err)

	_, err = sessions.Create(t.Context(), "u-1",
		session.WithClientMetadata("198.51.100.4", uaFirefoxLinux))
	require.NoError(t, err)

	rec, panicked := stepUpServeWithin(t, chain, loginRequest(ctx, uaChromeWindows))

	waited := make(chan struct{})

	go func() {
		pending.Wait()
		close(waited)
	}()

	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the notice's work")
	}

	out := noticeOutcome{panicked: panicked, sends: sends.Load(), logs: logs.records()}
	if rec != nil && !panicked {
		out.status, out.body = rec.Code, issuedToken.ReplaceAllString(rec.Body.String(), `"access_token":"-"`)
	}

	live, err := sessions.ListSignIns(t.Context(), "u-1", &session.Session{UserID: "u-1"})
	require.NoError(t, err)

	out.sessions = len(live)

	return out
}

func noticePortSites() []noticePortSite {
	return []noticePortSite{
		{
			name: "the seen-devices port",
			wire: func(portErr error, onCall func(), seen *MockSeenDevices) ([]httpsec.SignInNoticeOption, error) {
				seen.EXPECT().Seen(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(context.Context, identity.UserID, string) (bool, error) {
						onCall()

						return false, portErr
					})

				return []httpsec.SignInNoticeOption{httpsec.WithSeenDevices(seen)}, nil
			},
		},
		{
			name: "the recipient resolver",
			wire: func(portErr error, onCall func(), _ *MockSeenDevices) ([]httpsec.SignInNoticeOption, error) {
				return []httpsec.SignInNoticeOption{
					httpsec.WithSignInNoticeRecipient(func(context.Context, *identity.Principal) (string, error) {
						onCall()

						return "", portErr
					}),
				}, nil
			},
		},
		{
			name: "the sender",
			wire: func(portErr error, _ func(), _ *MockSeenDevices) ([]httpsec.SignInNoticeOption, error) {
				return nil, portErr
			},
		},
	}
}

// TestPortErrors_SignInNotice pins that a hostile error from the seen-devices
// port, the recipient resolver or the sender, met by the notice's background
// work, is handled exactly as a plain outage of that port is: no notice is
// sent past the failing call, the sign-in is answered and stored unchanged,
// and the notice's own record is the same. The error is only logged at these
// sites, so what shows of it is the one abort record, written to the chain's
// logger and not to slog.Default().
//
// An error whose Is panics only for one sentinel has no sentinel to ask about
// at these sites, which read no port error's identity: the row is not run.
func TestPortErrors_SignInNotice(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(noticePortErrRowEnv)
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

	plainOutage := errors.New("dependency: connection refused")

	for _, site := range noticePortSites() {
		for _, c := range contexts {
			for _, kind := range stepUpPortErrKinds(nil) {
				row := site.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				if kind.ctx != "" && kind.ctx != c.name {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						limiterPortErrInChild(t, noticePortErrRowEnv, noticePortErrRan, row)

						return
					}

					defaults := swapDefaultLogger(t)

					plain := noticeThrough(t, site, plainOutage, c.cancelDuring)
					require.False(t, plain.panicked, "the plain outage does not panic")
					require.Empty(t, abortRecords(plain.logs), "the plain outage writes no abort record")
					require.Contains(t, nonAbortMessages(plain.logs), "ERROR httpsec: a sign-in notice was not sent",
						"the plain outage is logged as a notice not sent")

					got := noticeThrough(t, site, kind.err, c.cancelDuring)
					assert.False(t, got.panicked, "a hostile port error escaped as a panic")
					assert.Equal(t, plain.status, got.status, "the sign-in's status")
					assert.Equal(t, plain.body, got.body, "the sign-in's body")
					assert.Equal(t, plain.sends, got.sends, "the notices sent")
					assert.Equal(t, plain.sessions, got.sessions, "the user's live sign-ins")
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
						_, _ = fmt.Fprintln(os.Stdout, noticePortErrRan+row)
					}
				})
			}
		}
	}
}
