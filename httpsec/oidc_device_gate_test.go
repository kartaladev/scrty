package httpsec_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
)

// over is a flow over the same provider and stores as w, answered by ch.
func (w *opFlow) over(ch *httpsec.Chain) *opFlow {
	return &opFlow{
		issuer: w.issuer, clk: w.clk, p: w.p, chain: ch, sessions: w.sessions, users: w.users,
		pending: w.pending, registry: w.registry, consents: w.consents, grants: w.grants,
	}
}

// secondChain builds another chain over w's provider, wired as newOPFlow wires the first,
// with opts added.
func (w *opFlow) secondChain(opts ...httpsec.Option) (*httpsec.Chain, error) {
	return httpsec.New(append([]httpsec.Option{
		httpsec.WithClock(w.clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users}),
		httpsec.EnableJWKSEndpoint(tokenKeys()),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableOIDCProvider(w.p),
	}, opts...)...)
}

// fetchSite sets Sec-Fetch-Site to each of values, as separate header lines.
func fetchSite(values ...string) flowChange {
	return func(r *http.Request) { r.Header["Sec-Fetch-Site"] = values }
}

// The two addresses of one /48, in two different /64s, as a connection names them.
const (
	entryAddrA48 = "[2001:db8:0:1::1]:4711"
	entryAddrB48 = "[2001:db8:0:2::1]:4711"
)

// failAcross48 makes the default number of failed entries through w, alternating between
// the two addresses of one /48, and returns the status of one more from the second.
func failAcross48(t *testing.T, w *opFlow) int {
	t.Helper()

	for i := range oidcprovider.DefaultUserCodeEntryLimit {
		addr := entryAddrA48
		if i%2 == 1 {
			addr = entryAddrB48
		}

		require.Equalf(t, http.StatusBadRequest, w.enter(t, deviceUnknownCode, flowFrom(addr)).status, "failure %d", i+1)
	}

	return w.enter(t, deviceUnknownCode, flowFrom(entryAddrB48)).status
}

// durableFactory stands for a shared limiter backend: every NewLimiter answers a new handle
// over the one store, as a Redis or SQL factory does.
type durableFactory struct {
	store *ratelimit.MemoryLimiter
}

func (f *durableFactory) NewLimiter(namespace string, limit int, window time.Duration) (ratelimit.Limiter, error) {
	if namespace == "oidc-device-entry" {
		return &deviceCountingLimiter{MemoryLimiter: f.store}, nil
	}

	return ratelimit.NewMemoryLimiter(limit, window)
}

func newDurableFactory(t *testing.T) *durableFactory {
	t.Helper()

	return &durableFactory{store: newDeviceCountingLimiter(t, 5, 10*time.Minute).MemoryLimiter}
}

// handOver is what a HandOver row did: the statuses it saw, the errors a second chain or a
// follow-up build answered, and what a refused chain's limiter was charged.
type handOver struct {
	status   int
	statuses []int
	err      error
	again    error
	charges  int64
}

// TestDeviceEntry_HandOver pins what the chain hands the provider's entry throttle: its
// factory, the namespace and its source keying, and that a chain refused for any reason
// leaves the provider as it was.
func TestDeviceEntry_HandOver(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  flowSetup
		act    func(t *testing.T, w *opFlow) handOver
		assert func(t *testing.T, got handOver)
	}

	withChain := func(setup flowSetup, opts ...httpsec.Option) flowSetup {
		setup.chain = func(*testing.T, *opFlow) []httpsec.Option { return opts }

		return setup
	}

	// across48 is the status of the entry past the limit, made from two addresses of one /48.
	across48 := func(t *testing.T, w *opFlow) handOver {
		t.Helper()

		return handOver{status: failAcross48(t, w)}
	}
	statusIs := func(want int) func(t *testing.T, got handOver) {
		return func(t *testing.T, got handOver) {
			t.Helper()
			assert.Equal(t, want, got.status)
		}
	}
	secondErr := func(t *testing.T, w *opFlow, opts ...httpsec.Option) handOver {
		t.Helper()

		_, err := w.secondChain(opts...)

		return handOver{err: err}
	}

	// Each row has a durable factory of its own, so parallel rows never share counts.
	durables := [4]*durableFactory{newDurableFactory(t), newDurableFactory(t), newDurableFactory(t), newDurableFactory(t)}

	cases := []testCase{
		{
			name:   "a /48 chain prefix counts two addresses of one /48 as one source, with a factory",
			setup:  withChain(deviceSetup(""), httpsec.WithIPv6SourcePrefix(48), httpsec.WithRateLimiterFactory(newDurableFactory(t))),
			act:    across48,
			assert: statusIs(http.StatusTooManyRequests),
		},
		{
			name:   "a /48 chain prefix counts two addresses of one /48 as one source, without a factory",
			setup:  withChain(deviceSetup(""), httpsec.WithIPv6SourcePrefix(48)),
			act:    across48,
			assert: statusIs(http.StatusTooManyRequests),
		},
		{
			name:   "the default /64 prefix keeps them two sources",
			setup:  deviceSetup(""),
			act:    across48,
			assert: statusIs(http.StatusBadRequest),
		},
		{
			name: "the provider's own keyer wins over the chain's prefix",
			setup: withChain(deviceSetup("", oidcprovider.WithUserCodeEntryKeyer(must64Keyer(t))),
				httpsec.WithIPv6SourcePrefix(48)),
			act:    across48,
			assert: statusIs(http.StatusBadRequest),
		},
		{
			name:  "two chains over one provider with one durable factory both build, and count together",
			setup: withChain(deviceSetup(""), httpsec.WithRateLimiterFactory(durables[0])),
			act: func(t *testing.T, w *opFlow) handOver {
				t.Helper()

				second, err := w.secondChain(httpsec.WithRateLimiterFactory(durables[0]))
				require.NoError(t, err)
				via := w.over(second)

				var got handOver

				for i := range oidcprovider.DefaultUserCodeEntryLimit {
					flow := w
					if i%2 == 1 {
						flow = via
					}

					got.statuses = append(got.statuses, flow.enter(t, deviceUnknownCode).status)
				}

				got.statuses = append(got.statuses,
					via.enter(t, deviceUnknownCode).status, w.enter(t, deviceUnknownCode).status)

				return got
			},
			assert: func(t *testing.T, got handOver) {
				require.Len(t, got.statuses, oidcprovider.DefaultUserCodeEntryLimit+2)

				for i, status := range got.statuses[:oidcprovider.DefaultUserCodeEntryLimit] {
					assert.Equalf(t, http.StatusBadRequest, status, "failure %d", i+1)
				}

				assert.Equal(t, []int{http.StatusTooManyRequests, http.StatusTooManyRequests},
					got.statuses[oidcprovider.DefaultUserCodeEntryLimit:])
			},
		},
		{
			name:  "a second chain with another factory fails New, and the provider keeps the first",
			setup: withChain(deviceSetup(""), httpsec.WithRateLimiterFactory(durables[1])),
			act: func(t *testing.T, w *opFlow) handOver {
				t.Helper()

				other := &deviceRecordingFactory{t: t, entry: newDeviceCountingLimiter(t, 5, 10*time.Minute)}
				_, err := w.secondChain(httpsec.WithRateLimiterFactory(other))
				got := handOver{err: err}

				for range oidcprovider.DefaultUserCodeEntryLimit {
					got.statuses = append(got.statuses, w.enter(t, deviceUnknownCode).status)
				}

				got.status = w.enter(t, deviceUnknownCode).status
				got.charges = other.entry.charges.Load()

				_, got.again = w.secondChain(httpsec.WithRateLimiterFactory(durables[1]))

				return got
			},
			assert: func(t *testing.T, got handOver) {
				require.ErrorIs(t, got.err, httpsec.ErrConfig)
				assert.ErrorContains(t, got.err, "EnableOIDCProvider")
				assert.ErrorContains(t, got.err, "oidc-device-entry")

				for _, status := range got.statuses {
					require.Equal(t, http.StatusBadRequest, status)
				}

				assert.Equal(t, http.StatusTooManyRequests, got.status, "the first factory's limiter still counts")
				assert.Zero(t, got.charges, "the refused chain's limiter is never charged")
				require.NoError(t, got.again, "the first hand-over still stands, so the same factory is accepted")
			},
		},
		{
			name:  "a second chain with another IPv6 prefix fails New",
			setup: withChain(deviceSetup(""), httpsec.WithRateLimiterFactory(durables[2])),
			act: func(t *testing.T, w *opFlow) handOver {
				t.Helper()

				return secondErr(t, w, httpsec.WithRateLimiterFactory(durables[2]), httpsec.WithIPv6SourcePrefix(48))
			},
			assert: func(t *testing.T, got handOver) { require.ErrorIs(t, got.err, httpsec.ErrConfig) },
		},
		{
			name:  "a second chain with no factory after one with a factory fails New",
			setup: withChain(deviceSetup(""), httpsec.WithRateLimiterFactory(durables[3])),
			act: func(t *testing.T, w *opFlow) handOver {
				t.Helper()

				return secondErr(t, w)
			},
			assert: func(t *testing.T, got handOver) { require.ErrorIs(t, got.err, httpsec.ErrConfig) },
		},
		{
			name:  "two chains with no factory and the same prefix both build",
			setup: deviceSetup(""),
			act: func(t *testing.T, w *opFlow) handOver {
				t.Helper()

				return secondErr(t, w)
			},
			assert: func(t *testing.T, got handOver) { require.NoError(t, got.err) },
		},
		{
			name:  "a chain refused by a check after the hand-over's place hands nothing over",
			setup: deviceSetup(""),
			act: func(t *testing.T, _ *opFlow) handOver {
				t.Helper()

				// w's own chain handed over no factory; build a fresh provider for the row.
				fresh, err := newOPFlowErr(t, withChain(deviceSetup(""),
					httpsec.WithRateLimiterFactory(newDurableFactory(t)), httpsec.WithLateRefusal(errors.New("late"))))
				got := handOver{err: err}

				_, got.again = fresh.secondChain(httpsec.WithRateLimiterFactory(newDurableFactory(t)))

				return got
			},
			assert: func(t *testing.T, got handOver) {
				require.Error(t, got.err)
				assert.NotErrorIs(t, got.err, httpsec.ErrConfig, "the late refusal, not the hand-over, failed New")
				require.NoError(t, got.again, "the refused chain left the provider free for another factory")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.act(t, newOPFlow(t, tc.setup)))
		})
	}
}

// must64Keyer keys IPv6 by /64.
func must64Keyer(t *testing.T) *ratelimit.SourceKeyer {
	t.Helper()

	k, err := ratelimit.NewSourceKeyer(ratelimit.WithIPv6SourcePrefix(64))
	require.NoError(t, err)

	return k
}

// gateOut is what a GETGate row did: the code it used and the answers it got, in order.
type gateOut struct {
	code    string
	answers []flowAnswer
}

// TestDeviceEntry_GETGate pins that a GET at code entry claims only on the browser's own
// navigation, with CSRF protection on and off: any other GET carrying a code is sent to the
// consumer's code-entry page with the code prefilled, with nothing claimed, charged or set.
func TestDeviceEntry_GETGate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// page is the consumer's entry page, deviceEntryPage when empty.
		page   string
		act    func(t *testing.T, w *opFlow) gateOut
		assert func(t *testing.T, w *opFlow, page string, got gateOut)
	}

	toLogin := func(t *testing.T, a flowAnswer) {
		t.Helper()

		require.Equal(t, http.StatusSeeOther, a.status, a.body)
		assert.Equal(t, "/login", a.location(t).Path)
		assert.NotNil(t, a.cookie(flowCookie), "the claiming browser gets its flow cookie")
	}
	// gated asserts a's redirect to the entry page carrying code, and that nothing was
	// claimed: another browser's own navigation still claims it.
	gated := func(t *testing.T, w *opFlow, page, code string, a flowAnswer) {
		t.Helper()

		require.Equal(t, http.StatusSeeOther, a.status, a.body)
		loc := a.location(t)
		want, err := url.Parse(opIssuer + page)
		require.NoError(t, err)
		assert.Equal(t, want.Scheme+"://"+want.Host+want.Path, loc.Scheme+"://"+loc.Host+loc.Path)
		assert.Equal(t, []string{code}, loc.Query()["user_code"])
		for name, values := range want.Query() {
			assert.Equal(t, values, loc.Query()[name], "the page's own query is kept")
		}
		assert.Empty(t, a.header.Values("Set-Cookie"), "no cookie is set")
		assert.NotEqual(t, "no-referrer", a.header.Get("Referrer-Policy"),
			"the gate leaves the referrer to the chain's header policy, so the entry page may see this site's origin")
		assert.Equal(t, "no-store", a.header.Get("Cache-Control"))

		toLogin(t, w.enter(t, code, fetchSite("none")))
	}

	// send issues a code and sends it once, with change.
	send := func(change ...flowChange) func(t *testing.T, w *opFlow) gateOut {
		return func(t *testing.T, w *opFlow) gateOut {
			t.Helper()

			code := w.issueDevice(t, deviceTV).UserCode

			return gateOut{code: code, answers: []flowAnswer{w.enter(t, code, change...)}}
		}
	}
	assertGated := func(t *testing.T, w *opFlow, page string, got gateOut) {
		t.Helper()
		gated(t, w, page, got.code, got.answers[0])
	}
	// notOwn is a row for a Sec-Fetch-Site that is not the browser's own navigation.
	notOwn := func(name string, change flowChange) testCase {
		return testCase{
			name: name,
			act:  send(change),
			assert: func(t *testing.T, w *opFlow, page string, got gateOut) {
				t.Helper()

				a := got.answers[0]
				require.Equal(t, http.StatusSeeOther, a.status)
				assert.Equal(t, page, a.location(t).Path)
				assert.Empty(t, a.header.Values("Set-Cookie"))
				toLogin(t, w.enter(t, got.code))
			},
		}
	}
	// own is a row for a Sec-Fetch-Site (or none, with a nil change) that claims.
	own := func(name string, change flowChange) testCase {
		return testCase{
			name: name,
			act: func(t *testing.T, w *opFlow) gateOut {
				t.Helper()

				var changes []flowChange
				if change != nil {
					changes = append(changes, change)
				}

				return send(changes...)(t, w)
			},
			assert: func(t *testing.T, _ *opFlow, _ string, got gateOut) {
				t.Helper()
				toLogin(t, got.answers[0])
			},
		}
	}
	// tooLong is a row for a code over the cap, sent by send.
	tooLong := func(name string, send func(t *testing.T, w *opFlow, long string) flowAnswer) testCase {
		return testCase{
			name: name,
			act: func(t *testing.T, w *opFlow) gateOut {
				t.Helper()

				return gateOut{answers: []flowAnswer{send(t, w, strings.Repeat("B", 65))}}
			},
			assert: func(t *testing.T, _ *opFlow, _ string, got gateOut) {
				a := got.answers[0]
				assert.Equal(t, http.StatusBadRequest, a.status)
				require.ErrorIs(t, a.err, oidcprovider.ErrInvalidUserCode)
				assert.Empty(t, a.header.Get("Location"))
			},
		}
	}

	cases := []testCase{
		{
			name:   "a cross-site GET claims nothing and goes to the entry page with the code",
			act:    send(fetchSite("cross-site")),
			assert: assertGated,
		},
		{
			name:   "a cross-site GET to a page with a query of its own keeps it",
			page:   deviceEntryPage + "?lang=en",
			act:    send(fetchSite("cross-site")),
			assert: assertGated,
		},
		{
			name: "a cross-site GET is not charged",
			act: func(t *testing.T, w *opFlow) gateOut {
				t.Helper()

				var got gateOut

				for range oidcprovider.DefaultUserCodeEntryLimit + 1 {
					got.answers = append(got.answers, w.enter(t, deviceUnknownCode, fetchSite("cross-site")))
				}

				got.code = w.issueDevice(t, deviceTV).UserCode
				got.answers = append(got.answers, w.enter(t, got.code))

				return got
			},
			assert: func(t *testing.T, _ *opFlow, _ string, got gateOut) {
				last := len(got.answers) - 1

				for _, a := range got.answers[:last] {
					require.Equal(t, http.StatusSeeOther, a.status)
				}

				toLogin(t, got.answers[last])
			},
		},
		notOwn("a value in another case is not the browser's own", fetchSite("Same-Origin")),
		notOwn("an empty value is not the browser's own", fetchSite("")),
		notOwn("two header lines are not the browser's own", fetchSite("same-origin", "cross-site")),
		notOwn("a list in one line is not the browser's own", fetchSite("same-origin, cross-site")),
		own("none claims", fetchSite("none")),
		own("same-origin claims", fetchSite("same-origin")),
		own("same-site claims", fetchSite("same-site")),
		own("an absent header claims", nil),
		{
			name: "a cookieless POST from the entry page, followed through its 303, claims",
			act: func(t *testing.T, w *opFlow) gateOut {
				t.Helper()

				code := w.issueDevice(t, deviceTV).UserCode
				post := w.postForm(t, deviceEntryPath, url.Values{"user_code": {code}}, fetchSite("same-origin"),
					func(r *http.Request) { r.Header.Set("Origin", opIssuer) })
				got := gateOut{code: code, answers: []flowAnswer{post}}

				if post.status == http.StatusSeeOther {
					got.answers = append(got.answers, w.entryGET(t, post.location(t).RawQuery, fetchSite("same-origin")))
				}

				return got
			},
			assert: func(t *testing.T, _ *opFlow, _ string, got gateOut) {
				post := got.answers[0]
				require.Equal(t, http.StatusSeeOther, post.status, post.body)
				assert.Equal(t, deviceEntryPath, post.location(t).Path)
				require.Len(t, got.answers, 2)
				toLogin(t, got.answers[1])
			},
		},
		tooLong("a code longer than the cap is refused as invalid on a cross-site GET",
			func(t *testing.T, w *opFlow, long string) flowAnswer {
				return w.enter(t, long, fetchSite("cross-site"))
			}),
		tooLong("a code longer than the cap is refused as invalid on a plain GET",
			func(t *testing.T, w *opFlow, long string) flowAnswer { return w.enter(t, long) }),
		tooLong("a code longer than the cap is refused as invalid on a POST",
			func(t *testing.T, w *opFlow, long string) flowAnswer {
				return w.postForm(t, deviceEntryPath, url.Values{"user_code": {long}})
			}),
		{
			name: "a code at the cap is still read",
			act: func(t *testing.T, w *opFlow) gateOut {
				t.Helper()

				return gateOut{answers: []flowAnswer{w.enter(t, strings.Repeat("B", 64), fetchSite("cross-site"))}}
			},
			assert: func(t *testing.T, _ *opFlow, page string, got gateOut) {
				require.Equal(t, http.StatusSeeOther, got.answers[0].status)
				assert.Equal(t, page, got.answers[0].location(t).Path)
			},
		},
	}

	for _, csrf := range []bool{true, false} {
		for _, tc := range cases {
			name := tc.name + " (CSRF protection on)"
			if !csrf {
				name = tc.name + " (CSRF protection off)"
			}

			t.Run(name, func(t *testing.T) {
				t.Parallel()

				page := tc.page
				if page == "" {
					page = deviceEntryPage
				}

				setup := flowSetup{
					issuer:  opIssuer,
					clients: deviceClients(),
					provider: []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(opIssuer+page,
						oidcprovider.WithUserCodeKey(deviceKey))},
				}
				if !csrf {
					setup.noCSRF = true
					setup.provider = append(setup.provider, oidcprovider.WithoutBrowserSessions())
				}

				pagePath, err := url.Parse(page)
				require.NoError(t, err)

				w := newOPFlow(t, setup)
				tc.assert(t, w, pagePath.Path, tc.act(t, w))
			})
		}
	}
}

// TestDeviceEntry_GETGateLog pins that a gated redirect leaves a sampled record through the
// chain's logger, naming the source and the Sec-Fetch-Site it carried, never the user code.
func TestDeviceEntry_GETGateLog(t *testing.T) {
	t.Parallel()

	const gatedMsg = "a code-entry link from another site was sent to the entry page"

	type gatedLog struct {
		code    string
		raw     string
		records []map[string]any
	}

	type testCase struct {
		name string
		// act sends requests and returns the code it used.
		act    func(t *testing.T, w *opFlow) string
		assert func(t *testing.T, got gatedLog)
	}

	crossSite := fetchSite("cross-site")

	cases := []testCase{
		{
			name: "a gated GET writes a record naming the source and the fetch site",
			act: func(t *testing.T, w *opFlow) string {
				t.Helper()
				code := w.issueDevice(t, deviceTV).UserCode
				require.Equal(t, http.StatusSeeOther, w.enter(t, code, crossSite).status)

				return code
			},
			assert: func(t *testing.T, got gatedLog) {
				require.Len(t, got.records, 1)
				assert.Equal(t, "192.0.2.20", got.records[0]["source"])
				assert.Equal(t, "cross-site", got.records[0]["sec_fetch_site"])
			},
		},
		{
			name: "no record carries the user code, with or without its hyphen",
			act: func(t *testing.T, w *opFlow) string {
				t.Helper()
				code := w.issueDevice(t, deviceTV).UserCode
				require.Equal(t, http.StatusSeeOther, w.enter(t, code, crossSite).status)

				return code
			},
			assert: func(t *testing.T, got gatedLog) {
				require.NotEmpty(t, got.records)
				assert.NotContains(t, got.raw, got.code)
				assert.NotContains(t, got.raw, strings.ReplaceAll(got.code, "-", ""))
			},
		},
		{
			name: "a burst from one source is sampled to one record",
			act: func(t *testing.T, w *opFlow) string {
				t.Helper()
				code := w.issueDevice(t, deviceTV).UserCode
				for range 25 {
					require.Equal(t, http.StatusSeeOther, w.enter(t, code, crossSite).status)
				}

				return code
			},
			assert: func(t *testing.T, got gatedLog) {
				assert.Len(t, got.records, 1)
			},
		},
		{
			name: "another source is recorded apart",
			act: func(t *testing.T, w *opFlow) string {
				t.Helper()
				code := w.issueDevice(t, deviceTV).UserCode
				require.Equal(t, http.StatusSeeOther, w.enter(t, code, crossSite).status)
				require.Equal(t, http.StatusSeeOther, w.enter(t, code, crossSite, flowFrom(flowOtherAddr)).status)

				return code
			},
			assert: func(t *testing.T, got gatedLog) {
				require.Len(t, got.records, 2)
				assert.NotEqual(t, got.records[0]["source"], got.records[1]["source"])
			},
		},
		{
			name: "a hostile fetch-site value is bounded",
			act: func(t *testing.T, w *opFlow) string {
				t.Helper()
				code := w.issueDevice(t, deviceTV).UserCode
				require.Equal(t, http.StatusSeeOther,
					w.enter(t, code, fetchSite(strings.Repeat("x", 5000))).status)

				return code
			},
			assert: func(t *testing.T, got gatedLog) {
				require.Len(t, got.records, 1)
				assert.LessOrEqual(t, len(got.records[0]["sec_fetch_site"].(string)), 64)
			},
		},
		{
			name: "the browser's own navigation writes no record",
			act: func(t *testing.T, w *opFlow) string {
				t.Helper()
				code := w.issueDevice(t, deviceTV).UserCode
				require.Equal(t, http.StatusSeeOther, w.enter(t, code, fetchSite("none")).status)

				return code
			},
			assert: func(t *testing.T, got gatedLog) {
				assert.Empty(t, got.records)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer

			setup := deviceSetup("")
			setup.chain = func(*testing.T, *opFlow) []httpsec.Option {
				return []httpsec.Option{httpsec.WithLogger(slog.New(slog.NewJSONHandler(&logs,
					&slog.HandlerOptions{Level: slog.LevelDebug})))}
			}

			code := tc.act(t, newOPFlow(t, setup))

			got := gatedLog{code: code, raw: logs.String()}

			for line := range strings.SplitSeq(strings.TrimSpace(got.raw), "\n") {
				if line == "" {
					continue
				}

				var record map[string]any
				require.NoError(t, json.Unmarshal([]byte(line), &record))

				if msg, _ := record["msg"].(string); strings.HasSuffix(msg, gatedMsg) {
					got.records = append(got.records, record)
				}
			}

			tc.assert(t, got)
		})
	}
}

// TestDeviceEntry_GETGateLoopConfig pins that a code-entry page the gate's redirect would
// loop on fails construction, under each spelling a router may serve as the endpoint.
func TestDeviceEntry_GETGateLoopConfig(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		issuer   string
		page     string
		endpoint []httpsec.OIDCProviderOption
		assert   func(t *testing.T, err error)
	}

	loops := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.ErrorContains(t, err, "EnableOIDCProvider")
		assert.ErrorContains(t, err, "WithDeviceAuthorization")
		assert.ErrorContains(t, err, "OIDCDeviceEntry")
	}
	builds := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}

	cases := []testCase{
		{name: "the page is the code-entry endpoint", page: "/oauth2/device", assert: loops},
		{name: "the page is the endpoint with a query", page: "/oauth2/device?lang=en", assert: loops},
		{name: "the page is the endpoint with a trailing slash", page: "/oauth2/device/", assert: loops},
		{name: "the page is the endpoint in other letter case", page: "/OAuth2/Device", assert: loops},
		{name: "the page is the endpoint with an empty segment", page: "/oauth2//device", assert: loops},
		{name: "the page is the endpoint percent-encoded", page: "/oauth2/%64evice", assert: loops},
		{
			name:     "the endpoint moved onto the page",
			page:     deviceEntryPage,
			endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCDeviceEntry, deviceEntryPage)},
			assert:   loops,
		},
		{
			name:   "the page is the endpoint's public URL under an issuer with a path",
			issuer: opIssuer + "/tenant",
			page:   "/tenant/oauth2/device",
			assert: loops,
		},
		{
			// The chain serves code entry at the served path whatever the issuer's path is,
			// so a page at that path loops although it differs from the public path.
			name:   "the page is the served path under an issuer with a path",
			issuer: opIssuer + "/tenant",
			page:   "/oauth2/device",
			assert: loops,
		},
		{
			name:   "a page beside the served path under an issuer with a path builds",
			issuer: opIssuer + "/tenant",
			page:   "/oauth2/device-help",
			assert: builds,
		},
		{
			name:     "the endpoint moved away from the page builds",
			page:     "/oauth2/device",
			endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCDeviceEntry, "/activate")},
			assert:   builds,
		},
		{name: "a page beside the endpoint builds", page: "/oauth2/device-help", assert: builds},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			issuer := tc.issuer
			if issuer == "" {
				issuer = opIssuer
			}

			_, err := newOPFlowErr(t, flowSetup{
				issuer:   issuer,
				clients:  deviceClients(),
				endpoint: tc.endpoint,
				provider: []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(opIssuer+tc.page,
					oidcprovider.WithUserCodeKey(deviceKey))},
			})
			tc.assert(t, err)
		})
	}
}

// TestCSRF_DeviceEndpoints pins that device authorization is exempt from the cross-site
// check only while it is served, and that code entry stays protected.
func TestCSRF_DeviceEndpoints(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		setup flowSetup
		run   func(t *testing.T, w *opFlow)
	}

	crossSite := func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.Header.Set("Origin", "https://elsewhere.example")
	}

	cases := []testCase{
		{
			name:  "a device posts device authorization with no Origin and no Sec-Fetch-Site",
			setup: deviceSetup(""),
			run: func(t *testing.T, w *opFlow) {
				t.Helper()
				a := w.deviceAuthorize(t, url.Values{"scope": {"openid"}, "client_id": {deviceTV}})
				assert.Equal(t, http.StatusOK, a.status, a.body)
			},
		},
		{
			name:  "a cross-site post to device authorization is not refused by CSRF protection",
			setup: deviceSetup(""),
			run: func(t *testing.T, w *opFlow) {
				t.Helper()
				a := w.deviceAuthorize(t, url.Values{"scope": {"openid"}, "client_id": {deviceTV}}, crossSite)
				assert.Equal(t, http.StatusOK, a.status, a.body)
			},
		},
		{
			name:  "a cross-site post to code entry is refused, and nothing is claimed",
			setup: deviceSetup(""),
			run: func(t *testing.T, w *opFlow) {
				t.Helper()
				code := w.issueDevice(t, deviceTV).UserCode
				a := w.postForm(t, deviceEntryPath, url.Values{"user_code": {code}}, crossSite,
					flowCookieOf(flowCookie, "a-flow-secret"))
				assert.Equal(t, http.StatusForbidden, a.status)
				require.ErrorIs(t, a.err, httpsec.ErrCrossSiteRequest)

				b := w.enter(t, code)
				require.Equal(t, http.StatusSeeOther, b.status)
				assert.Equal(t, "/login", b.location(t).Path, "the code is still unclaimed")
			},
		},
		{
			name:  "without the grant, the device authorization path has no exemption",
			setup: flowSetup{},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()
				a := w.deviceAuthorize(t, url.Values{"scope": {"openid"}}, crossSite)
				assert.Equal(t, http.StatusForbidden, a.status)
				require.ErrorIs(t, a.err, httpsec.ErrCrossSiteRequest)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, newOPFlow(t, tc.setup))
		})
	}
}

// TestCORS_DeviceEndpoints pins that neither device endpoint carries a CORS header for an
// allowed origin, preflight or not, and that the paths are the consumer's without the grant.
func TestCORS_DeviceEndpoints(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		grant  bool
		method string
		path   string
		assert func(t *testing.T, a flowAnswer)
	}

	none := func(t *testing.T, a flowAnswer) {
		t.Helper()
		for name := range a.header {
			assert.False(t, strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-"), "%s is set", name)
		}
	}

	var cases []testCase
	for _, path := range []string{deviceAuthorizationPath, deviceEntryPath} {
		for _, method := range []string{http.MethodOptions, http.MethodPost, http.MethodGet} {
			cases = append(cases, testCase{
				name: method + " " + path, grant: true, method: method, path: path, assert: none,
			})
		}
	}
	cases = append(cases, testCase{
		name: "without the grant the path is the consumer's, and its policy applies", method: http.MethodOptions,
		path: deviceEntryPath,
		assert: func(t *testing.T, a flowAnswer) {
			t.Helper()
			assert.Equal(t, allowedOrigin, a.header.Get("Access-Control-Allow-Origin"))
		},
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			setup := flowSetup{}
			if tc.grant {
				setup = deviceSetup("")
			}
			setup.chain = func(*testing.T, *opFlow) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{
					AllowedOrigins: []string{allowedOrigin}, AllowCredentials: true,
				})}
			}
			w := newOPFlow(t, setup)

			r := httptest.NewRequestWithContext(t.Context(), tc.method, opIssuer+tc.path,
				strings.NewReader(url.Values{"user_code": {deviceUnknownCode}}.Encode()))
			r.Header.Set("Origin", allowedOrigin)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.method == http.MethodOptions {
				r.Header.Set("Access-Control-Request-Method", http.MethodPost)
			}

			tc.assert(t, w.serve(t, r, nil))
		})
	}
}

// TestMetadata_Device pins the device grant in both metadata documents.
func TestMetadata_Device(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		grant    bool
		endpoint []httpsec.OIDCProviderOption
		assert   func(t *testing.T, doc map[string]any)
	}

	grants := func(want ...string) func(t *testing.T, doc map[string]any) {
		return func(t *testing.T, doc map[string]any) {
			t.Helper()
			got := []string{}
			for _, g := range doc["grant_types_supported"].([]any) {
				got = append(got, g.(string))
			}
			assert.Equal(t, want, got)
		}
	}
	// noEntry asserts that no member names the code-entry endpoint's URL.
	noEntry := func(t *testing.T, doc map[string]any, entry string) {
		t.Helper()
		for name, v := range doc {
			assert.NotEqualf(t, entry, v, "%s names the code-entry endpoint", name)
		}
	}

	cases := []testCase{
		{
			name:  "with the grant",
			grant: true,
			assert: func(t *testing.T, doc map[string]any) {
				t.Helper()
				grants("authorization_code", "refresh_token", string(oidcprovider.GrantDeviceCode))(t, doc)
				assert.Equal(t, opIssuer+deviceAuthorizationPath, doc["device_authorization_endpoint"])
				noEntry(t, doc, opIssuer+deviceEntryPath)
			},
		},
		{
			name:  "with the grant and both endpoints moved",
			grant: true,
			endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCProviderPath(httpsec.OIDCDeviceAuthorization, "/device/start"),
				httpsec.WithOIDCProviderPath(httpsec.OIDCDeviceEntry, "/activate"),
			},
			assert: func(t *testing.T, doc map[string]any) {
				t.Helper()
				assert.Equal(t, opIssuer+"/device/start", doc["device_authorization_endpoint"])
				noEntry(t, doc, opIssuer+"/activate")
			},
		},
		{
			name: "without the grant",
			assert: func(t *testing.T, doc map[string]any) {
				t.Helper()
				grants("authorization_code", "refresh_token")(t, doc)
				assert.NotContains(t, doc, "device_authorization_endpoint")
			},
		},
	}

	for _, doc := range []string{metadataPath, "/.well-known/oauth-authorization-server"} {
		for _, tc := range cases {
			t.Run(tc.name+" "+doc, func(t *testing.T) {
				t.Parallel()

				setup := flowSetup{}
				if tc.grant {
					setup = deviceSetup("")
				}
				setup.endpoint = tc.endpoint
				w := newOPFlow(t, setup)

				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, opIssuer+doc, nil)
				a := w.serve(t, r, nil)
				require.Equal(t, http.StatusOK, a.status, a.body)

				var body map[string]any
				require.NoError(t, json.Unmarshal([]byte(a.body), &body))
				tc.assert(t, body)
			})
		}
	}
}

// TestMetadata_DeviceMemberReserved pins that a consumer cannot publish the device member.
func TestMetadata_DeviceMemberReserved(t *testing.T) {
	t.Parallel()

	setup := flowSetup{endpoint: []httpsec.OIDCProviderOption{
		httpsec.WithOIDCMetadataMember("device_authorization_endpoint", opIssuer+"/elsewhere"),
	}}
	_, err := newOPFlowErr(t, setup)
	require.ErrorIs(t, err, httpsec.ErrConfig)
	assert.ErrorContains(t, err, "device_authorization_endpoint")
}

// TestErrorPropagation_UserCode pins code entry's refusals through the chain's default
// error handling: the status alone, with nothing rendered.
func TestErrorPropagation_UserCode(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, w *opFlow) flowAnswer
		assert func(t *testing.T, a flowAnswer)
	}

	status := func(want int) func(t *testing.T, a flowAnswer) {
		return func(t *testing.T, a flowAnswer) {
			t.Helper()
			assert.Equal(t, want, a.status)
			assert.Empty(t, a.body)
		}
	}

	cases := []testCase{
		{
			name: "an invalid code is 400",
			run: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.enter(t, deviceUnknownCode)
			},
			assert: status(http.StatusBadRequest),
		},
		{
			name: "a throttled source is 429",
			run: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()
				for range oidcprovider.DefaultUserCodeEntryLimit {
					w.enter(t, deviceUnknownCode)
				}

				return w.enter(t, deviceUnknownCode)
			},
			assert: status(http.StatusTooManyRequests),
		},
		{
			name: "plain HTTP is 400",
			run: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.enter(t, deviceUnknownCode, flowPlainHTTP)
			},
			assert: status(http.StatusBadRequest),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			setup := deviceSetup("")
			setup.noHandler = true
			w := newOPFlow(t, setup)
			tc.assert(t, tc.run(t, w))
		})
	}
}

// TestDeviceEntry_PlainHTTPCause pins that plain HTTP at code entry is answered as an
// invalid code, yet carries a cause of its own a log can tell apart.
func TestDeviceEntry_PlainHTTPCause(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		change []flowChange
		assert func(t *testing.T, a flowAnswer)
	}{
		{
			name:   "plain HTTP",
			change: []flowChange{flowPlainHTTP},
			assert: func(t *testing.T, a flowAnswer) {
				t.Helper()
				assert.Equal(t, http.StatusBadRequest, a.status)
				require.ErrorIs(t, a.err, oidcprovider.ErrInvalidUserCode)
				assert.ErrorContains(t, a.err, "plain HTTP")
			},
		},
		{
			name: "an unknown code over TLS",
			assert: func(t *testing.T, a flowAnswer) {
				t.Helper()
				assert.Equal(t, http.StatusBadRequest, a.status)
				require.ErrorIs(t, a.err, oidcprovider.ErrInvalidUserCode)
				assert.NotContains(t, a.err.Error(), "plain HTTP")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, deviceSetup(""))
			tc.assert(t, w.enter(t, deviceUnknownCode, tc.change...))
		})
	}
}
