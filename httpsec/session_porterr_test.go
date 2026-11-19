package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// unwrapPanics is an error whose Unwrap panics.
type unwrapPanics struct{}

func (unwrapPanics) Error() string { return hostileSecret }
func (unwrapPanics) Unwrap() error { panic(isPanicMessage) }

// porterrRowEnv names the row a child process runs. It is empty in the parent.
const porterrRowEnv = "SCRTY_HTTPSEC_PORTERR_ROW"

// porterrWithin bounds how long one request through a hostile port may take.
const porterrWithin = 5 * time.Second

// portErrKind is one hostile error a port may return.
type portErrKind struct {
	name string
	err  error

	// reason is the abort record's reason.
	reason string

	// child runs the row in a child process, because it overflows the stack
	// fatally when unsanitized.
	child bool
}

func portErrKinds() []portErrKind {
	return []portErrKind{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "panicking Unwrap", err: unwrapPanics{}, reason: "panic"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
	}
}

// portErrSite is one flow whose port error the sanitizer stands in front of.
// serve runs one request through a chain logging to logger, whose port
// returns err, and answers what the chain wrote.
type portErrSite struct {
	name string

	// status is what a plain outage of the port is answered with: 500, or for
	// the signal stream 200 with only a retry delay, since an EventSource gives
	// up for good on anything else.
	status int
	serve  func(t *testing.T, err error, logger *slog.Logger) *httptest.ResponseRecorder
}

func porterrSessions(t *testing.T) *session.Sessions {
	t.Helper()

	return must.Must(session.New(session.WithStore(must.Must(session.NewMemoryStore()))))
}

func porterrRun(chain *httpsec.Chain, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)

	return rec
}

func porterrBearer(ctx context.Context, credential string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/orders", nil)
	req.Header.Set("Authorization", "Bearer "+credential)

	return req
}

func portErrSites() []portErrSite {
	return []portErrSite{
		{
			name:   "bearer: token verifier",
			status: http.StatusInternalServerError,
			serve: func(t *testing.T, err error, logger *slog.Logger) *httptest.ResponseRecorder {
				t.Helper()

				verifier := NewMockVerifier(gomock.NewController(t))
				verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, err)

				chain, cerr := httpsec.New(httpsec.WithLogger(logger),
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: verifier, Sessions: porterrSessions(t), Users: NewMockUserLoader(gomock.NewController(t)),
					}))
				require.NoError(t, cerr)

				return porterrRun(chain, porterrBearer(t.Context(), "tok"))
			},
		},
		{
			name:   "bearer: user by username",
			status: http.StatusInternalServerError,
			serve: func(t *testing.T, err error, logger *slog.Logger) *httptest.ResponseRecorder {
				t.Helper()

				sessions := porterrSessions(t)
				s, cerr := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
				require.NoError(t, cerr)

				verifier := NewMockVerifier(gomock.NewController(t))
				verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
					Return(token.NewClaims(testUsername, s.ID), nil)

				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, err)

				chain, cerr := httpsec.New(httpsec.WithLogger(logger),
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: verifier, Sessions: sessions, Users: users},
						httpsec.WithBearerUsernameSubject()))
				require.NoError(t, cerr)

				return porterrRun(chain, porterrBearer(t.Context(), "tok"))
			},
		},
		{
			name:   "session resolution: user reload",
			status: http.StatusInternalServerError,
			serve: func(t *testing.T, err error, logger *slog.Logger) *httptest.ResponseRecorder {
				t.Helper()

				sessions := porterrSessions(t)
				s, cerr := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
				require.NoError(t, cerr)

				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, err)

				chain, cerr := httpsec.New(httpsec.WithLogger(logger),
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}))
				require.NoError(t, cerr)

				return porterrRun(chain, porterrBearer(t.Context(), s.ID))
			},
		},
		{
			name:   "session renewal: user reload",
			status: http.StatusInternalServerError,
			serve: func(t *testing.T, err error, logger *slog.Logger) *httptest.ResponseRecorder {
				t.Helper()

				sessions := porterrSessions(t)
				s, cerr := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
				require.NoError(t, cerr)

				// The bearer's reload succeeds, the endpoint's own fails.
				users := NewMockUserLoader(gomock.NewController(t))
				gomock.InOrder(
					users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).Return(storedUser(), nil),
					users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, err),
				)

				chain, cerr := httpsec.New(httpsec.WithLogger(logger),
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
					httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: sessions, Users: users}))
				require.NoError(t, cerr)

				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
				req.Header.Set("Authorization", "Bearer "+s.ID)

				return porterrRun(chain, req)
			},
		},
		{
			name:   "signal stream: user read",
			status: http.StatusOK,
			serve: func(t *testing.T, err error, logger *slog.Logger) *httptest.ResponseRecorder {
				t.Helper()

				sessions := porterrSessions(t)
				s, cerr := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
				require.NoError(t, cerr)

				good := NewMockUserLoader(gomock.NewController(t))
				good.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(storedUser(), nil)

				hostile := NewMockUserLoader(gomock.NewController(t))
				hostile.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, err)

				chain, cerr := httpsec.New(httpsec.WithLogger(logger),
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: good}),
					httpsec.EnableSessionSignals(httpsec.SessionSignals{Users: hostile}))
				require.NoError(t, cerr)

				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, httpsec.DefaultSessionSignalsPath, nil)
				req.Header.Set("Authorization", "Bearer "+s.ID)

				return porterrRun(chain, req)
			},
		},
	}
}

// retryDelay is the jittered reconnection delay a stream's retry-only answer
// carries, which differs between any two requests.
var retryDelay = regexp.MustCompile(`retry: \d+`)

// steadyBody is body with the jittered delay masked.
func steadyBody(body string) string { return retryDelay.ReplaceAllString(body, "retry: N") }

// porterrServe runs site on its own goroutine, and fails the test when it
// does not answer in time or lets a panic escape.
func porterrServe(t *testing.T, site portErrSite, err error, logger *slog.Logger) *httptest.ResponseRecorder {
	t.Helper()

	type result struct {
		rec      *httptest.ResponseRecorder
		panicked bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		var r result

		defer func() {
			if v := recover(); v != nil {
				r.panicked, r.value = true, v
			}

			done <- r
		}()

		r.rec = site.serve(t, err, logger)
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "a hostile port error escaped as a panic: %v", r.value)

		return r.rec
	case <-time.After(porterrWithin):
		require.FailNow(t, "a hostile port error hung the request")

		return nil
	}
}

// porterrInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute: a stack overflow is
// fatal and only a child can watch for one.
func porterrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), porterrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
}

// TestPortErrors_UserAndVerifierSites pins that a hostile error from the token
// verifier or the user loader is answered exactly as a plain outage of that
// port is, through the real request path, and reported once, to the chain's own
// logger and not to slog.Default().
func TestPortErrors_UserAndVerifierSites(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(porterrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	for _, site := range portErrSites() {
		if childRow != "" && childRow != site.name {
			continue
		}

		// The plain outage is the parity row: its answer is what every hostile
		// row must equal, and it writes no abort record.
		defaults := swapDefaultLogger(t)
		plainLogs := &capturingHandler{}
		plain := porterrServe(t, site, errors.New("dependency down"), slog.New(plainLogs))

		require.Equal(t, site.status, plain.Code, "%s: a plain outage is a dependency failure", site.name)
		require.Empty(t, abortRecords(plainLogs.records()), "%s: a plain outage writes no abort record", site.name)
		require.Empty(t, abortRecords(defaults.records()))

		for _, kind := range portErrKinds() {
			if childRow != "" && !kind.child {
				continue
			}

			t.Run(site.name+"/"+kind.name, func(t *testing.T) {
				if kind.child && childRow == "" {
					porterrInChild(t, site.name)

					return
				}

				defaults := swapDefaultLogger(t)
				logs := &capturingHandler{}

				rec := porterrServe(t, site, kind.err, slog.New(logs))

				assert.Equal(t, plain.Code, rec.Code, "the hostile error takes the plain outage's status")
				assert.Equal(t, plain.Header(), rec.Header(), "and its headers")
				assert.Equal(t, steadyBody(plain.Body.String()), steadyBody(rec.Body.String()), "and its body")

				aborts := abortRecords(logs.records())
				require.Len(t, aborts, 1, "one abort record, on the chain's logger")
				assertAbortRecord(t, aborts[0], kind.reason)
				assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")
			})
		}
	}
}

// streamReread is what a stream shows after its user loader fails on a later
// read, the one the stream makes once it is open.
type streamReread struct {
	sent     []string
	comments int
	live     bool
	total    uint64
	inRow    uint64
	reasons  []string
}

// rereadReasons returns the reason of every abort record in a JSON log.
func rereadReasons(log string) []string {
	var out []string

	for line := range strings.SplitSeq(log, "\n") {
		if !strings.Contains(line, msgClassificationAborted) {
			continue
		}

		var rec struct {
			Reason string `json:"reason"`
		}

		if json.Unmarshal([]byte(line), &rec) == nil {
			out = append(out, rec.Reason)
		}
	}

	return out
}

// TestPortErrors_StreamReread pins that a user loader which answers the first
// read and then fails hostilely is answered by the stream's later read as a
// plain outage is: the stream goes on, a comment per beat and the failure
// counted, with one abort record per failed read on the chain's logger and
// none on slog.Default().
func TestPortErrors_StreamReread(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name string
		err  func() error
		// reason is the abort reason expected; empty for a plain outage.
		reason string
	}

	run := func(t *testing.T, err error) (got streamReread, defaults int) {
		t.Helper()

		def := swapDefaultLogger(t)

		synctest.Test(t, func(t *testing.T) {
			r := newStreamRig(t, streamSetup{})
			stream := r.open(t, r.signIn(t).ID)

			r.userAnswers(func(context.Context) (*identity.Details, error) { return nil, err })
			advance(20 * time.Second)

			got.sent = stream.sent()
			got.comments = len(stream.comments())
			got.live = !stream.closed() && r.openStreams() == 1
			got.total, got.inRow = httpsec.SignalReloadCounts(r.chain)
			got.reasons = rereadReasons(r.logs.String())
		})

		return got, len(abortRecords(def.records()))
	}

	cases := []testCase{
		{name: "plain", err: func() error { return errors.New("user store down") }},
		{name: "cycleOne", err: func() error { return &cycleOne{} }, reason: "budget"},
		{name: "panicUnwrap", err: func() error { return unwrapPanics{} }, reason: "panic"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plain, _ := run(t, errors.New("user store down"))
			require.True(t, plain.live, "a plain outage keeps the stream open")
			require.Positive(t, plain.total, "the stream read again")

			got, defaults := run(t, tc.err())

			assert.True(t, got.live, "the stream goes on, as it does for a plain outage")
			assert.Equal(t, plain.sent, got.sent)
			assert.Equal(t, plain.comments, got.comments)
			assert.Equal(t, plain.total, got.total, "the failure is counted as a plain outage's is")
			assert.Equal(t, plain.inRow, got.inRow)
			assert.Zero(t, defaults, "no record on slog.Default()")

			if tc.reason == "" {
				assert.Empty(t, got.reasons)

				return
			}

			require.Len(t, got.reasons, int(got.total), "one abort record per failed read, on the chain's logger")
			for _, reason := range got.reasons {
				assert.Equal(t, tc.reason, reason)
			}
		})
	}
}
