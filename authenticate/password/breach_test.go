package password_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // the range API is keyed by SHA-1; nothing here protects a secret with it
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/outbound"
)

// breachCandidate is long, not common, and so reaches the breach rule.
const breachCandidate = "correcthorsebatterystaple"

// sha1Hex is the upper-case hexadecimal SHA-1 of s, split into the five
// characters that may leave the process and the 35 that may not.
func sha1Hex(s string) (prefix, suffix string) {
	sum := sha1.Sum([]byte(s)) //nolint:gosec // see the import
	full := strings.ToUpper(hex.EncodeToString(sum[:]))

	return full[:5], full[5:]
}

// rangeRequest is what the range server saw.
type rangeRequest struct {
	path, rawQuery, padding string
	header                  http.Header
}

// rangeServer is an HTTPS range API standing in for the real one. Every
// request to any host is dialled to it, so the source under test keeps its own
// URL.
type rangeServer struct {
	mu   sync.Mutex
	seen []rangeRequest
	srv  *httptest.Server
}

func newRangeServer(t *testing.T, answer http.HandlerFunc) *rangeServer {
	t.Helper()

	rs := &rangeServer{}
	rs.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		rs.seen = append(rs.seen, rangeRequest{
			path:     r.URL.Path,
			rawQuery: r.URL.RawQuery,
			padding:  r.Header.Get("Add-Padding"),
			header:   r.Header.Clone(),
		})
		rs.mu.Unlock()

		answer(w, r)
	}))
	t.Cleanup(rs.srv.Close)

	return rs
}

func (rs *rangeServer) requests() []rangeRequest {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	return append([]rangeRequest(nil), rs.seen...)
}

// client is a confined outbound client whose every connection reaches rs.
func (rs *rangeServer) client(t *testing.T, timeout time.Duration) *outbound.Client {
	t.Helper()

	tr := rs.srv.Client().Transport.(*http.Transport).Clone()
	addr := rs.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com" // a name the test certificate carries
	tr.TLSClientConfig.MinVersion = tls.VersionTLS12

	c, err := outbound.New(
		outbound.WithHTTPClient(&http.Client{Transport: tr}),
		outbound.WithTimeout(timeout),
	)
	require.NoError(t, err)

	return c
}

func body(lines ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, strings.Join(lines, "\r\n"))
	}
}

func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

// The client timeouts a row uses. A server that answers needs a long one, so a
// slow machine cannot turn a success into a timeout; hangTimeout only has to
// end a request the server will not answer until it is over, which hang
// guarantees whatever the timeout is.
const (
	answeringTimeout = 10 * time.Second
	hangTimeout      = 100 * time.Millisecond
)

// hang answers only once the request has gone.
func hang(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }

func TestPolicy_Breached(t *testing.T) {
	t.Parallel()

	prefix, suffix := sha1Hex(breachCandidate)
	other := strings.Repeat("0", 35)

	type testCase struct {
		name      string
		answer    http.HandlerFunc
		onFailure password.LookupFailure
		// timeout is the client's timeout. Rows that must succeed leave it at
		// the generous default, so a loaded machine cannot fail them; only a
		// row whose server never answers shortens it.
		timeout time.Duration
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, err error, seen []rangeRequest)
	}

	unavailable := func(t *testing.T, err error, _ []rangeRequest) {
		t.Helper()

		require.ErrorIs(t, err, password.ErrLookupUnavailable)
		assert.NotErrorIs(t, err, password.ErrPasswordRejected, "an outage is not a refusal")
		assert.Equal(t, password.ErrLookupUnavailable.Error(), err.Error(), "fixed text")
	}

	passes := func(t *testing.T, err error, _ []rangeRequest) {
		t.Helper()
		require.NoError(t, err)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	hungUp := func(t *testing.T, err error, _ []rangeRequest) {
		t.Helper()

		require.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, password.ErrLookupUnavailable)
		assert.NotErrorIs(t, err, password.ErrPasswordRejected)
	}

	cases := []testCase{
		{
			name:      "a candidate listed with a count of 3 is refused, and only the prefix leaves",
			answer:    body(other+":12", suffix+":3"),
			onFailure: password.Refuse,
			assert: func(t *testing.T, err error, seen []rangeRequest) {
				rejectedBy(password.RuleBreached)(t, err)

				require.Len(t, seen, 1)
				assert.Equal(t, "/range/"+prefix, seen[0].path)
				assert.Empty(t, seen[0].rawQuery)
				assert.Equal(t, "true", seen[0].padding)

				for name, values := range seen[0].header {
					for _, v := range values {
						assert.NotContains(t, v, suffix, "header %s carries the hash suffix", name)
						assert.NotContains(t, v, breachCandidate, "header %s carries the candidate", name)
					}
				}
			},
		},
		{
			name:      "a suffix compares case-insensitively",
			answer:    body(strings.ToLower(suffix) + ":3"),
			onFailure: password.Refuse,
			assert: func(t *testing.T, err error, _ []rangeRequest) {
				rejectedBy(password.RuleBreached)(t, err)
			},
		},
		{
			name:      "a padding entry with a count of 0 is ignored",
			answer:    body(other+":4", suffix+":0"),
			onFailure: password.Refuse,
			assert:    passes,
		},
		{
			name:      "a candidate not listed is accepted",
			answer:    body(other + ":4"),
			onFailure: password.Refuse,
			assert:    passes,
		},
		{
			name:      "a timeout with failures refusing is the lookup-unavailable error",
			answer:    hang,
			timeout:   hangTimeout,
			onFailure: password.Refuse,
			assert:    unavailable,
		},
		{
			name:      "a timeout with failures accepting lets the candidate through",
			answer:    hang,
			timeout:   hangTimeout,
			onFailure: password.Accept,
			assert:    passes,
		},
		{
			name:      "429 with failures refusing is the lookup-unavailable error",
			answer:    status(http.StatusTooManyRequests),
			onFailure: password.Refuse,
			assert:    unavailable,
		},
		{
			name:      "429 with failures accepting lets the candidate through",
			answer:    status(http.StatusTooManyRequests),
			onFailure: password.Accept,
			assert:    passes,
		},
		{
			name:      "500 with failures refusing is the lookup-unavailable error",
			answer:    status(http.StatusInternalServerError),
			onFailure: password.Refuse,
			assert:    unavailable,
		},
		{
			name:      "a body that is not suffix and count lines is the lookup-unavailable error",
			answer:    body("<html>maintenance</html>"),
			onFailure: password.Refuse,
			assert:    unavailable,
		},
		{
			name:      "a count that is not a number is the lookup-unavailable error",
			answer:    body(suffix + ":three"),
			onFailure: password.Refuse,
			assert:    unavailable,
		},
		{
			name:      "a suffix of the wrong length is the lookup-unavailable error",
			answer:    body(suffix[:34] + ":3"),
			onFailure: password.Refuse,
			assert:    unavailable,
		},
		{
			name:      "an empty body is the lookup-unavailable error",
			answer:    body(),
			onFailure: password.Refuse,
			assert:    unavailable,
		},
		{
			name:      "a malformed body with failures accepting lets the candidate through",
			answer:    body("<html>maintenance</html>"),
			onFailure: password.Accept,
			assert:    passes,
		},
		{
			name:      "a caller that hung up gets the context's error with failures refusing",
			answer:    body(suffix + ":3"),
			onFailure: password.Refuse,
			ctx:       cancelled,
			assert:    hungUp,
		},
		{
			name:      "a caller that hung up gets the context's error with failures accepting",
			answer:    body(suffix + ":3"),
			onFailure: password.Accept,
			ctx:       cancelled,
			assert:    hungUp,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			timeout := tc.timeout
			if timeout == 0 {
				timeout = answeringTimeout
			}

			rs := newRangeServer(t, tc.answer)
			p, err := password.NewPolicy(password.Breached(
				password.PwnedPasswords(rs.client(t, timeout)), tc.onFailure))
			require.NoError(t, err)

			err = p.Check(ctx, checkUser(), breachCandidate)
			tc.assert(t, err, rs.requests())
		})
	}
}

// TestPolicy_BreachedHangUpMidRequest pins that a caller who cancels while the
// range request is in flight gets the context's own error, never the lookup
// failure, whichever failure mode is set: the caller left, the service did not
// fail.
func TestPolicy_BreachedHangUpMidRequest(t *testing.T) {
	t.Parallel()

	for name, mode := range map[string]password.LookupFailure{
		"failures refusing":  password.Refuse,
		"failures accepting": password.Accept,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			arrived := make(chan struct{})

			var once sync.Once

			rs := newRangeServer(t, func(w http.ResponseWriter, r *http.Request) {
				once.Do(func() { close(arrived) })
				hang(w, r)
			})

			p, err := password.NewPolicy(password.Breached(
				password.PwnedPasswords(rs.client(t, answeringTimeout)), mode))
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			go func() {
				<-arrived // the server holds the request, then the caller leaves
				cancel()
			}()

			err = p.Check(ctx, checkUser(), breachCandidate)

			require.ErrorIs(t, err, context.Canceled)
			assert.NotErrorIs(t, err, password.ErrLookupUnavailable)
			assert.NotErrorIs(t, err, password.ErrPasswordRejected)
			assert.Len(t, rs.requests(), 1, "the cancellation came while the request was in flight")
		})
	}
}

func TestPolicy_BreachedReplacedSource(t *testing.T) {
	t.Parallel()

	prefix, suffix := sha1Hex(breachCandidate)

	type testCase struct {
		name   string
		source func(m *MockBreachSource)
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "an offline corpus that lists the candidate refuses it, seeing only the prefix",
			source: func(m *MockBreachSource) {
				m.EXPECT().Range(gomock.Any(), prefix).Return(map[string]int{suffix: 3}, nil)
			},
			assert: rejectedBy(password.RuleBreached),
		},
		{
			name: "an offline corpus that does not list the candidate accepts it",
			source: func(m *MockBreachSource) {
				m.EXPECT().Range(gomock.Any(), prefix).Return(map[string]int{}, nil)
			},
			assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := NewMockBreachSource(gomock.NewController(t))
			tc.source(m)

			p, err := password.NewPolicy(password.Breached(m, password.Refuse))
			require.NoError(t, err)

			tc.assert(t, p.Check(t.Context(), checkUser(), breachCandidate))
		})
	}
}

func TestPolicy_BreachedConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opt    func(ctrl *gomock.Controller) password.PolicyOption
		assert func(t *testing.T, p *password.Policy, err error)
	}

	refused := func(t *testing.T, p *password.Policy, err error) {
		t.Helper()

		require.ErrorIs(t, err, password.ErrConfig)
		assert.Contains(t, err.Error(), "breach")
		assert.Nil(t, p)
	}

	cases := []testCase{
		{
			name: "no failure mode",
			opt: func(ctrl *gomock.Controller) password.PolicyOption {
				return password.Breached(NewMockBreachSource(ctrl), 0)
			},
			assert: refused,
		},
		{
			name: "a failure mode that is neither refuse nor accept",
			opt: func(ctrl *gomock.Controller) password.PolicyOption {
				return password.Breached(NewMockBreachSource(ctrl), password.LookupFailure(9))
			},
			assert: refused,
		},
		{
			name: "no lookup source",
			opt: func(*gomock.Controller) password.PolicyOption {
				return password.Breached(nil, password.Refuse)
			},
			assert: refused,
		},
		{
			name: "a typed-nil lookup source",
			opt: func(*gomock.Controller) password.PolicyOption {
				return password.Breached((*MockBreachSource)(nil), password.Refuse)
			},
			assert: refused,
		},
		{
			name: "the range API over no client",
			opt: func(*gomock.Controller) password.PolicyOption {
				return password.Breached(password.PwnedPasswords(nil), password.Accept)
			},
			assert: refused,
		},
		{
			name: "a source and a failure mode",
			opt: func(ctrl *gomock.Controller) password.PolicyOption {
				return password.Breached(NewMockBreachSource(ctrl), password.Accept)
			},
			assert: func(t *testing.T, p *password.Policy, err error) {
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := password.NewPolicy(tc.opt(gomock.NewController(t)))
			tc.assert(t, p, err)
		})
	}
}

// recordingHandler keeps every slog record it is given, at every level, with
// the message and attributes flattened for leak checks.
type recordingHandler struct {
	mu      sync.Mutex
	records []recordedLog
}

type recordedLog struct {
	level   slog.Level
	message string
	attrs   string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder

	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Resolve().Any())

		return true
	})

	h.mu.Lock()
	h.records = append(h.records, recordedLog{level: r.Level, message: r.Message, attrs: b.String()})
	h.mu.Unlock()

	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) all() []recordedLog {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]recordedLog(nil), h.records...)
}

// TestPolicy_BreachedLeavesATraceWhenTheLookupFailsAndAccepts pins that a
// lookup failure the policy accepts is not silent: one ERROR record says the
// candidate went through unchecked, without the candidate, its hash, its
// prefix or the source's error text. A caller's hang-up and Refuse log nothing.
func TestPolicy_BreachedLeavesATraceWhenTheLookupFailsAndAccepts(t *testing.T) {
	t.Parallel()

	prefix, suffix := sha1Hex(breachCandidate)
	errSource := errors.New("dial tcp: refused")

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name      string
		onFailure password.LookupFailure
		ctx       func(ctx context.Context) context.Context
		result    func(ctx context.Context) error
		assert    func(t *testing.T, err error, records []recordedLog)
	}

	cases := []testCase{
		{
			name:      "accept lets the candidate through and leaves one error that does not leak it",
			onFailure: password.Accept,
			result:    func(context.Context) error { return errSource },
			assert: func(t *testing.T, err error, records []recordedLog) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, records, 1)
				assert.Equal(t, slog.LevelError, records[0].level)
				assert.Equal(t, "password: breach lookup failed; the candidate was accepted unchecked", records[0].message)
				assert.Contains(t, records[0].attrs, "*errors.errorString", "the failure's Go type")

				text := strings.ToUpper(records[0].message + records[0].attrs)
				for _, secret := range []string{breachCandidate, prefix, suffix, prefix + suffix, "dial tcp"} {
					assert.NotContains(t, text, strings.ToUpper(secret), "the record must not carry %q", secret)
				}
			},
		},
		{
			name:      "accept with a caller who hung up logs nothing at error",
			onFailure: password.Accept,
			ctx:       cancelled,
			result:    func(ctx context.Context) error { return ctx.Err() },
			assert: func(t *testing.T, err error, records []recordedLog) {
				t.Helper()

				require.ErrorIs(t, err, context.Canceled)

				for _, r := range records {
					assert.Less(t, r.level, slog.LevelError, "unexpected record %+v", r)
				}
			},
		},
		{
			name:      "refuse fails with ErrLookupUnavailable and writes no record",
			onFailure: password.Refuse,
			result:    func(context.Context) error { return errSource },
			assert: func(t *testing.T, err error, records []recordedLog) {
				t.Helper()

				require.ErrorIs(t, err, password.ErrLookupUnavailable)
				assert.Empty(t, records)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := &recordingHandler{}
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			src := NewMockBreachSource(gomock.NewController(t))
			src.EXPECT().Range(gomock.Any(), prefix).Return(nil, tc.result(ctx))

			p, err := password.NewPolicy(
				password.WithPolicyLogger(slog.New(h)),
				password.Breached(src, tc.onFailure))
			require.NoError(t, err)

			err = p.Check(ctx, checkUser(), breachCandidate)
			tc.assert(t, err, h.all())
		})
	}
}

// TestPolicy_BreachedLogsToTheDefaultLogger pins the default: with no
// WithPolicyLogger, the record goes to slog.Default() as it is when the policy
// is built. It replaces the default logger, so it does not run in parallel.
func TestPolicy_BreachedLogsToTheDefaultLogger(t *testing.T) {
	h := &recordingHandler{}
	previous := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(previous) })

	prefix, _ := sha1Hex(breachCandidate)
	src := NewMockBreachSource(gomock.NewController(t))
	src.EXPECT().Range(gomock.Any(), prefix).Return(nil, errors.New("down"))

	p, err := password.NewPolicy(password.Breached(src, password.Accept))
	require.NoError(t, err)
	require.NoError(t, p.Check(t.Context(), checkUser(), breachCandidate))

	records := h.all()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelError, records[0].level)
}

// lowerKeySource answers with its own keys, whatever their case: the
// BreachSource contract says only "35 hexadecimal characters".
type lowerKeySource struct{ entries map[string]int }

func (s lowerKeySource) Range(context.Context, string) (map[string]int, error) {
	return s.entries, nil
}

// TestPolicy_BreachedMatchesASourceKeyInAnyCase pins that a suffix matches
// whatever the key's case: a custom source with lower-case keys must not make
// the breach screen fail open.
func TestPolicy_BreachedMatchesASourceKeyInAnyCase(t *testing.T) {
	t.Parallel()

	_, suffix := sha1Hex(breachCandidate)

	cases := []struct {
		name string
		key  string
	}{
		{name: "upper-case key", key: strings.ToUpper(suffix)},
		{name: "lower-case key", key: strings.ToLower(suffix)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := password.NewPolicy(password.Breached(
				lowerKeySource{entries: map[string]int{tc.key: 7}}, password.Refuse))
			require.NoError(t, err)

			err = p.Check(t.Context(), checkUser(), breachCandidate)

			var rejected password.RejectedError
			require.ErrorAs(t, err, &rejected)
			assert.Equal(t, password.RuleBreached, rejected.Rule)
		})
	}
}
