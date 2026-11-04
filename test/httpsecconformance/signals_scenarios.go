package httpsecconformance

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

const (
	// signalsBeat is the heartbeat the rows run under: the smallest the configuration
	// allows, so that a row waiting for a reload waits seconds and not a quarter of a
	// minute. With its jitter a beat lands between 4.5 and 5.5 seconds after the last.
	signalsBeat = 5 * time.Second

	// signalsBound fails a row that would otherwise wait for ever. No row waits for it to
	// pass: it is several beats, so a loaded machine does not fail a row that is only slow.
	signalsBound = 60 * time.Second

	// signalsIdleTimeout is the idle timeout the rows' sessions have unless a row says
	// otherwise, long enough that no row outlives it.
	signalsIdleTimeout = time.Hour

	// signalsWarnAfter is how long after it is created a sign-in is within the window of
	// session_expiring, when a row sets SessionSignals.ExpiryWarning to the idle timeout less
	// this. The window cannot be the whole idle timeout, so a stream is never within it at
	// the instant it opens: the warning comes from the stream's timer, this long after.
	signalsWarnAfter = 2 * time.Second
)

// signalsScenarios is every behaviour of the session-signal stream that must be identical
// on every adapter that can stream: what the first bytes are, how a stream ends and
// follows its sign-in, how it is narrowed and refused, what a chain refusing after Stream
// does to its place, and what a panic in a consumer's loader leaves in the logs.
//
// The rows are Stream rows, because a stream needs a real listener and a client reading it
// while it is open. They are skipped on an adapter that is no StreamAdapter.
func signalsScenarios() []Scenario {
	return []Scenario{
		{Name: "signals: the first bytes are retry, then a session event with the deadlines and no identifier", Stream: signalsSnapshot},
		{Name: "signals: a sign-in ended from another sign-in ends the stream with ended", Stream: signalsEndedFromAnotherSignIn},
		{Name: "signals: a logout in another tab ends the stream with logout, never reuse", Stream: signalsLogoutInAnotherTab},
		{Name: "signals: a renewal leaves the stream open", Stream: signalsRenewalLeavesStreamOpen},
		{Name: "signals: a signals parameter narrows the stream and never widens it", Stream: signalsNarrowing},
		{Name: "signals: a cross-site request is refused with 403 and no stream", Stream: signalsCrossSiteRefused},
		{Name: "signals: a chain refusing after Stream frees the place exactly once", Stream: signalsChainRefusesAfterStream},
		{Name: "signals: a stream opened among concurrent requests keeps its own user, family, origin and narrowing", Stream: signalsStreamAmongConcurrentRequests},
		{Name: "signals: a panic in a consumer's loader reaches the chain's logger, and neither that logger nor the process's default logger holds its value", Stream: signalsLoaderPanic},

		{Name: "signals: a stream over a cap is answered 200 with only a retry, and the others stay open", Stream: signalsCapReached},
		{Name: "signals: a session store failing while a stream is admitted is answered 200 with only a retry", Stream: signalsDependencyFailureAtAdmission},
		{Name: "signals: a failure ahead of authentication is answered 200 with only a retry", Stream: signalsDependencyFailureBeforeAuthentication},
		{Name: "signals: a consumer's signal reaches the user's streams byte for byte, and narrowing drops it", Stream: signalsConsumerSignal},
		{Name: "signals: a compressing wrapper in front of the chain leaves the stream readable, or honours no-transform", Stream: signalsGzipInFront},
	}
}

// --- the world a row runs in ---

// newSignalsSpec wires the bearer, logout and the signal stream over a fresh session manager
// whose idle timeout is signalsIdleTimeout, with cfg as the stream's configuration and the heartbeat
// at signalsBeat unless cfg says otherwise. extra are added to the chain's options.
//
// The bearer's user store knows any user, active, because a row that needs a second user
// needs one the fixture's own store would refuse.
func newSignalsSpec(t *testing.T, cfg httpsec.SessionSignals, extra ...httpsec.Option) ChainSpec {
	t.Helper()

	return newSignalsSpecIdle(t, signalsIdleTimeout, cfg, extra...)
}

// newSignalsSpecIdle is newSignalsSpec over sessions with the idle timeout given.
func newSignalsSpecIdle(t *testing.T, idle time.Duration, cfg httpsec.SessionSignals, extra ...httpsec.Option) ChainSpec {
	t.Helper()

	return newSignalsSpecOver(t, idle, nil, cfg, extra...)
}

// newSignalsSpecOver is newSignalsSpecIdle with the sessions reading and writing through
// wrap(store), when wrap is set. Effects.Store stays the memory store itself, so a row can
// still make sign-ins in it without going through the wrapper.
func newSignalsSpecOver(
	t *testing.T,
	idle time.Duration,
	wrap func(session.Store) session.Store,
	cfg httpsec.SessionSignals,
	extra ...httpsec.Option,
) ChainSpec {
	t.Helper()

	store := must.Must(session.NewMemoryStore())

	var over session.Store = store
	if wrap != nil {
		over = wrap(store)
	}

	sessions, err := session.New(session.WithStore(over), session.WithIdleTimeout(idle))
	require.NoError(t, err)

	effects := &Effects{Sessions: sessions, Store: store, Attempts: newEffects(t).Attempts}

	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = signalsBeat
	}

	opts := []httpsec.Option{
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: fixtureTokens{},
			Sessions: sessions,
			Users:    anyActiveUsers{},
		}),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}),
		httpsec.EnableSessionSignals(cfg),
	}

	return ChainSpec{Options: append(opts, extra...), Effects: effects}
}

// anyActiveUsers is a user store that knows every user and finds each active.
type anyActiveUsers struct{}

func (anyActiveUsers) LoadByUsername(_ context.Context, username string) (*identity.Details, error) {
	d := fixtureUserDetails()
	d.Username = username

	return d, nil
}

func (anyActiveUsers) LoadByUserID(_ context.Context, id identity.UserID) (*identity.Details, error) {
	d := fixtureUserDetails()
	d.ID = id

	return d, nil
}

// signalsSignIn stores a new sign-in of user, which owes nothing.
func signalsSignIn(t *testing.T, e *Effects, user identity.UserID) *session.Session {
	t.Helper()

	s, err := e.Sessions.Create(t.Context(), user, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	return s
}

// behindClock reads the wall clock set back by a fixed span.
type behindClock struct{ by time.Duration }

func (c behindClock) Now() time.Time { return time.Now().Add(-c.by) }

// signalsAgedSignIn stores a new sign-in of user, in e's store, that was made age ago: its
// authentication time is that far back, and the sessions of e find it live, since its deadlines
// are measured from its creation and age is within them.
func signalsAgedSignIn(t *testing.T, e *Effects, user identity.UserID, age time.Duration) *session.Session {
	t.Helper()

	older, err := session.New(
		session.WithStore(e.Store), session.WithIdleTimeout(signalsIdleTimeout), session.WithClock(behindClock{by: age}))
	require.NoError(t, err)

	s, err := older.Create(t.Context(), user, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	return s
}

// signalsToken is the bearer a client presents for s.
func signalsToken(s *session.Session) string {
	return issuedTokenFor(string(s.UserID), s.ID)
}

// --- the client ---

// signalsClient is one open request for the stream, and what it has read of it.
type signalsClient struct {
	t      *testing.T
	resp   *http.Response
	r      *bufio.Reader
	cancel context.CancelFunc

	// raw is every byte read, for a row that asserts what was never sent.
	raw strings.Builder
}

// signalFrame is one block of an event stream, up to its blank line.
type signalFrame struct {
	// comment says the block is a comment, a heartbeat.
	comment bool

	// retry is the value of a retry field, and event and data those of an event.
	retry, event, data string
}

// openSignals asks for the stream at its default path, presenting s as a bearer unless s is
// nil, with query appended and mutate applied to the request. The request lasts at most
// signalsBound, and leaving is cancel.
func openSignals(
	t *testing.T, base string, s *session.Session, query string, mutate ...func(*http.Request),
) *signalsClient {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), signalsBound)
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+httpsec.DefaultSessionSignalsPath+query, http.NoBody)
	require.NoError(t, err)

	if s != nil {
		req.Header.Set("Authorization", "Bearer "+signalsToken(s))
	}

	for _, m := range mutate {
		m(req)
	}

	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	require.NoError(t, err)

	t.Cleanup(func() { _ = resp.Body.Close() })

	return &signalsClient{t: t, resp: resp, r: bufio.NewReader(resp.Body), cancel: cancel}
}

// next reads one block. It returns io.EOF when the response has ended between blocks.
func (c *signalsClient) next() (signalFrame, error) {
	var (
		f    signalFrame
		seen bool
	)

	for {
		line, err := c.r.ReadString('\n')
		c.raw.WriteString(line)

		if err != nil {
			if seen {
				return f, fmt.Errorf("the response ended inside a block: %w", err)
			}

			return f, err
		}

		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			return f, nil
		}

		seen = true

		switch {
		case strings.HasPrefix(line, ":"):
			f.comment = true
		case strings.HasPrefix(line, "retry: "):
			f.retry = strings.TrimPrefix(line, "retry: ")
		case strings.HasPrefix(line, "event: "):
			f.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			f.data = strings.TrimPrefix(line, "data: ")
		default:
			c.t.Errorf("a line the stream's grammar has no place for: %q", line)
		}
	}
}

// mustNext reads one block and fails the row if there is none.
func (c *signalsClient) mustNext() signalFrame {
	c.t.Helper()

	f, err := c.next()
	require.NoError(c.t, err, "a block was expected")

	return f
}

// nextEvent reads up to the next event, past heartbeats, and fails the row if the response
// ends first.
func (c *signalsClient) nextEvent() signalFrame {
	c.t.Helper()

	for {
		f := c.mustNext()
		if !f.comment {
			return f
		}
	}
}

// opens reads what every stream starts with, a retry and the session event, and returns the
// session event's data.
func (c *signalsClient) opens() map[string]any {
	c.t.Helper()

	require.Equal(c.t, http.StatusOK, c.resp.StatusCode)
	require.Contains(c.t, c.resp.Header.Get("Content-Type"), "text/event-stream")

	first := c.mustNext()
	require.NotEmpty(c.t, first.retry, "the first block is not a retry: %+v", first)
	require.Empty(c.t, first.event)

	second := c.mustNext()
	require.Equal(c.t, "session", second.event, "the second block is not the session event")

	var data map[string]any
	require.NoError(c.t, json.Unmarshal([]byte(second.data), &data))

	return data
}

// signalsRetryOnly matches the whole body of a request answered with only a retry.
var signalsRetryOnly = regexp.MustCompile(`^retry: ([0-9]+)\n\n$`)

// noPlace requires that the request was given no stream, as design D7 settles it for a cap
// reached or a dependency failure at admission: 200, an event stream, a body of one retry
// line and nothing more, and then the end of the response. It returns the retry the client
// was told to wait.
func (c *signalsClient) noPlace() time.Duration {
	c.t.Helper()

	require.Equal(c.t, http.StatusOK, c.resp.StatusCode)
	require.Contains(c.t, c.resp.Header.Get("Content-Type"), "text/event-stream")

	body, err := io.ReadAll(c.r)
	require.NoError(c.t, err, "the answer did not end")

	m := signalsRetryOnly.FindStringSubmatch(string(body))
	require.NotNil(c.t, m, "the body is not one retry line and nothing more: %q", body)

	ms, err := strconv.Atoi(m[1])
	require.NoError(c.t, err)

	return time.Duration(ms) * time.Millisecond
}

// requireWithinJitter fails the row unless got is within 30% of want.
func requireWithinJitter(t *testing.T, want, got time.Duration) {
	t.Helper()

	assert.GreaterOrEqual(t, got, want*7/10, "the retry is under BusyDelay less 30%")
	assert.LessOrEqual(t, got, want*13/10, "the retry is over BusyDelay plus 30%")
}

// requireEnd reads the stream's end: a session_ended naming reason, and then the close.
func (c *signalsClient) requireEnd(reason string) {
	c.t.Helper()

	assert.Equal(c.t, []string{reason}, c.reasonsToEnd(), "the reasons the stream ended with")
}

// reasonsToEnd reads to the end of the response and returns the reason of every
// session_ended it carried, in order. It fails the row on an event it cannot read, and if
// the response is cut instead of closed.
func (c *signalsClient) reasonsToEnd() []string {
	c.t.Helper()

	var reasons []string

	for {
		f, err := c.next()
		if errors.Is(err, io.EOF) {
			return reasons
		}

		require.NoError(c.t, err, "the stream was cut and not closed")

		if f.event != "session_ended" {
			continue
		}

		var data struct {
			Reason string `json:"reason"`
		}

		require.NoError(c.t, json.Unmarshal([]byte(f.data), &data))

		reasons = append(reasons, data.Reason)
	}
}

// eventsToEnd reads to the end of the response and returns the name of every event it
// carried, in order.
func (c *signalsClient) eventsToEnd() []string {
	c.t.Helper()

	var names []string

	for {
		f, err := c.next()
		if errors.Is(err, io.EOF) {
			return names
		}

		require.NoError(c.t, err, "the stream was cut and not closed")

		if f.event != "" {
			names = append(names, f.event)
		}
	}
}

// heartbeats reads until n comments have arrived, and fails the row on a session_ended or
// the end of the response. A session event on the way is allowed: a deadline moved.
func (c *signalsClient) heartbeats(n int) {
	c.t.Helper()

	for seen := 0; seen < n; {
		f, err := c.next()
		require.NoError(c.t, err, "the stream ended while %d heartbeats were awaited, after %d", n, seen)
		require.NotEqual(c.t, "session_ended", f.event, "the stream ended: %s", f.data)

		if f.comment {
			seen++
		} else {
			c.t.Logf("while awaiting heartbeats: event %s %s", f.event, f.data)
		}
	}
}

// --- the rows ---

func signalsSnapshot(t *testing.T, listen func(ChainSpec) StreamServer) {
	spec := newSignalsSpec(t, httpsec.SessionSignals{})
	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	c := openSignals(t, srv.URL, s, "")
	data := c.opens()

	assert.Contains(t, c.resp.Header.Get("Cache-Control"), "no-store")

	state, err := spec.Effects.Sessions.SignInState(t.Context(), s.UserID, s.FamilyID)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"idle_deadline", "absolute_deadline", "authenticated_at"}, keysOf(data),
		"the session event states the deadlines and the authentication time, and nothing else")

	for field, want := range map[string]time.Time{
		"idle_deadline":     state.IdleDeadline,
		"absolute_deadline": state.AbsoluteDeadline,
		"authenticated_at":  state.AuthenticatedAt,
	} {
		got, ok := data[field].(string)
		require.True(t, ok, "%s is not a time: %v", field, data[field])

		at, err := time.Parse(time.RFC3339Nano, got)
		require.NoError(t, err)
		assert.True(t, want.Equal(at), "%s is %s, the sign-in's is %s", field, got, want)
	}

	// Everything the client was sent so far.
	for what, secret := range map[string]string{
		"the session identifier": s.ID, "the family": s.FamilyID.String(), "the bearer": signalsToken(s),
	} {
		assert.NotContains(t, c.raw.String(), secret, "the stream carried %s", what)
	}
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}

func signalsEndedFromAnotherSignIn(t *testing.T, listen func(ChainSpec) StreamServer) {
	spec := newSignalsSpec(t, httpsec.SessionSignals{})
	srv := listen(spec)
	a, b := signalsSignIn(t, spec.Effects, UserID), signalsSignIn(t, spec.Effects, UserID)

	c := openSignals(t, srv.URL, a, "")
	c.opens()

	// B ends A, by A's handle as a sign-in list names it.
	require.NoError(t, spec.Effects.Sessions.EndSignIn(t.Context(), b.UserID, a.FamilyID.String()))

	c.requireEnd("ended")

	// A is gone for good, and B is not touched: a reconnecting browser is told 401.
	assert.Equal(t, http.StatusUnauthorized, openSignals(t, srv.URL, a, "").resp.StatusCode)

	other := openSignals(t, srv.URL, b, "")
	other.opens()
}

func signalsLogoutInAnotherTab(t *testing.T, listen func(ChainSpec) StreamServer) {
	spec := newSignalsSpec(t, httpsec.SessionSignals{})
	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	c := openSignals(t, srv.URL, s, "")
	c.opens()

	// The other tab is a request of the same sign-in, through the chain's own logout.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+httpsec.DefaultLogoutPath, http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+signalsToken(s))

	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	require.NoError(t, err)

	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Exactly one end, and it is a logout.
	c.requireEnd("logout")
}

func signalsRenewalLeavesStreamOpen(t *testing.T, listen func(ChainSpec) StreamServer) {
	spec := newSignalsSpec(t, httpsec.SessionSignals{})
	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	c := openSignals(t, srv.URL, s, "")
	c.opens()

	renewed, err := spec.Effects.Sessions.Rotate(t.Context(), s)
	require.NoError(t, err)
	require.Equal(t, s.FamilyID, renewed.FamilyID, "a renewal stays in its family")

	// The first heartbeat read may have been sent before the renewal, so the stream is held
	// to the second: its reload began after the renewal was stored. Neither may end it. A
	// beat's comment goes out before its reload is answered, so the third is what shows the
	// second's reload has been dealt with: a logout straight after the second would race
	// that reload, which could then find the family gone before the logout was reported and
	// name the end "ended" (seen in 3 of 48 runs at 16 copies at once).
	c.heartbeats(3)

	_, err = spec.Effects.Sessions.SignInState(t.Context(), s.UserID, s.FamilyID)
	require.NoError(t, err, "a stream's reload harmed the sign-in it follows")

	// The one end the stream ever reports is the one that is asked for, and it is no reuse.
	_, err = spec.Effects.Sessions.Logout(t.Context(), s.UserID, s.FamilyID)
	require.NoError(t, err)

	c.requireEnd("logout")
}

// awaitEvent reads up to the event named name, past heartbeats and the session events a moved
// deadline sends, and fails the row if the stream ends first.
func (c *signalsClient) awaitEvent(name string) {
	c.t.Helper()

	for {
		f := c.nextEvent()
		if f.event == name {
			return
		}

		require.NotEqual(c.t, "session_ended", f.event, "the stream ended before %s: %s", name, f.data)
	}
}

func signalsNarrowing(t *testing.T, listen func(ChainSpec) StreamServer) {
	// Sessions that are an idle half-minute long, with a window that makes session_expiring
	// due signalsWarnAfter after a sign-in is created: long enough for the row to end first,
	// short enough to wait for.
	idle := 30 * time.Second
	spec := newSignalsSpecIdle(t, idle, httpsec.SessionSignals{ExpiryWarning: idle - signalsWarnAfter})
	srv := listen(spec)

	// The streams that must not send session_expiring come first, so that by the time the
	// last stream that must has sent it, the others' sign-ins, made earlier, were due too.
	cases := []struct {
		name, query string
		expiring    bool
	}{
		{"naming session_ended drops session_expiring", "?signals=session_ended", false},
		{"a name outside the chain's set is ignored, not added", "?signals=credential_changed", false},
		{"an empty parameter keeps only what is always sent", "?signals=", false},
		{"no parameter sends the chain's whole set", "", true},
		{"naming session_expiring keeps it", "?signals=session_expiring", true},
	}

	// A sign-in of its own for each, because a sign-in holds four streams at most.
	streams := make([]*signalsClient, len(cases))
	signIns := make([]*session.Session, len(cases))

	for i, tc := range cases {
		signIns[i] = signalsSignIn(t, spec.Effects, UserID)
		streams[i] = openSignals(t, srv.URL, signIns[i], tc.query)
		streams[i].opens()
	}

	for i, tc := range cases {
		if tc.expiring {
			streams[i].awaitEvent("session_expiring")
		}
	}

	// Every sign-in that was to be warned has been, so the warning is due on all of them.
	// Ending the sign-ins ends the streams, and what is left to read is the end alone.
	for _, s := range signIns {
		_, err := spec.Effects.Sessions.Logout(t.Context(), s.UserID, s.FamilyID)
		require.NoError(t, err)
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, []string{"session_ended"}, streams[i].eventsToEnd())
		})
	}

	t.Run("a name the chain lacks is never sent, though the stream would send it by itself", func(t *testing.T) {
		// The chain's set is its default, session_ended and session_expiring: assurance_lapsed is
		// not in it. The sign-ins last authenticated well beyond the assurance window, so were the
		// set not consulted, the stream would say so whether or not the client asked for it.
		// Naming it, or naming nothing, must both leave it unsent.
		spec := newSignalsSpec(t, httpsec.SessionSignals{})
		srv := listen(spec)

		for _, query := range []string{"?signals=assurance_lapsed", ""} {
			s := signalsAgedSignIn(t, spec.Effects, UserID, 2*httpsec.DefaultRecentAuthenticationWindow)
			c := openSignals(t, srv.URL, s, query)
			c.opens()

			// Two heartbeats, each of which looks at what is due.
			c.heartbeats(2)

			_, err := spec.Effects.Sessions.Logout(t.Context(), s.UserID, s.FamilyID)
			require.NoError(t, err)

			assert.Equal(t, []string{"session_ended"}, c.eventsToEnd(), "query %q", query)

			// Everything the stream sent, the heartbeats' stretch included.
			assert.NotContains(t, c.raw.String(), string(httpsec.SignalAssuranceLapsed), "query %q", query)
		}
	})

	t.Run("more than 16 names is refused with 400 and opens no stream", func(t *testing.T) {
		names := make([]string, 17)
		for i := range names {
			names[i] = fmt.Sprintf("n%d", i)
		}

		other := signalsSignIn(t, spec.Effects, UserID)
		c := openSignals(t, srv.URL, other, "?signals="+strings.Join(names, ","))

		assert.Equal(t, http.StatusBadRequest, c.resp.StatusCode)
		assert.NotContains(t, c.resp.Header.Get("Content-Type"), "text/event-stream")
	})
}

func signalsCrossSiteRefused(t *testing.T, listen func(ChainSpec) StreamServer) {
	spec := newSignalsSpec(t, httpsec.SessionSignals{MaxPerSignIn: 1})
	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	crossSite := func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.Header.Set("Origin", "https://evil.example")
	}

	refused := openSignals(t, srv.URL, s, "", crossSite)
	require.Equal(t, http.StatusForbidden, refused.resp.StatusCode)
	assert.NotContains(t, refused.resp.Header.Get("Content-Type"), "text/event-stream")
	assert.Contains(t, refused.resp.Header.Get("Cache-Control"), "no-store")

	body, err := io.ReadAll(refused.resp.Body)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "retry", "the refusal opened no stream")

	// The sign-in's only place was not taken by the refused request, and a same-origin one
	// is admitted. A second request for the place is told there is none.
	first := openSignals(t, srv.URL, s, "")
	first.opens()

	openSignals(t, srv.URL, s, "").noPlace()
}

// refusingAfterStream is a chain's interceptor outside the stream's slot that refuses a
// request once the interceptors behind it have returned, as long as refuse is set, and says
// on refused that it did.
func refusingAfterStream(refuse *atomic.Bool, refused chan<- struct{}) httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			if err := next(ex); err != nil {
				return err
			}

			if !refuse.Load() {
				return nil
			}

			refused <- struct{}{}

			return httpsec.ErrRequestTooLarge
		}), httpsec.OrderJWKS)
}

// awaitPlaceBound is how long awaitPlace polls. A place is freed when a body returns, in
// milliseconds, so this is for a loaded machine and not for a slow one.
const awaitPlaceBound = 20 * time.Second

// awaitPlace opens the stream of s until it is admitted, and returns it. A place freed by a
// body that has not yet returned is the only reason an open is refused, and it is bounded.
func awaitPlace(t *testing.T, base string, s *session.Session) *signalsClient {
	t.Helper()

	deadline := time.Now().Add(awaitPlaceBound)

	for {
		c := openSignals(t, base, s, "")

		if c.resp.StatusCode == http.StatusOK {
			if f, err := c.next(); err == nil && f.retry != "" {
				if second, err := c.next(); err == nil && second.event == "session" {
					return c
				}
			}
		}

		c.cancel()
		require.True(t, time.Now().Before(deadline), "the place was never freed")
		time.Sleep(20 * time.Millisecond) // a poll of admission, which has no event to wait on.
	}
}

func signalsChainRefusesAfterStream(t *testing.T, listen func(ChainSpec) StreamServer) {
	var refuse atomic.Bool

	refuse.Store(true)

	refused := make(chan struct{}, 8)
	// One place for the sign-in, the user and the client address. The address's is a running
	// count and not a set, so a place freed twice shows in it and nowhere else.
	spec := newSignalsSpec(t, httpsec.SessionSignals{MaxPerSignIn: 1, MaxPerUser: 1, MaxStreams: 8, MaxPerSource: 1},
		refusingAfterStream(&refuse, refused))
	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	first := openSignals(t, srv.URL, s, "")

	if srv.BodyRunsLater {
		// The client is given the refusal and no stream: the response is the refusal, and the
		// body ran on an already-ended context.
		assert.Equal(t, http.StatusRequestEntityTooLarge, first.resp.StatusCode)

		body, err := io.ReadAll(first.resp.Body)
		require.NoError(t, err)
		assert.NotContains(t, string(body), "retry")
		waitForStream(t, toSignal(t, refused), "the chain to refuse")
	} else {
		// The body ran inline, and its stream was sent before the chain could refuse: the
		// refusal changes nothing the client received.
		first.opens()

		// The body returns when its client leaves, and the chain refuses after that.
		first.cancel()
		waitForStream(t, toSignal(t, refused), "the chain to refuse")
	}

	refuse.Store(false)

	// The place is freed: it is admitted again. And freed only once: the sign-in's place is
	// then held, and so is the client address's, which another user's sign-in meets. A place
	// freed twice leaves the address's count a place short, and that one is admitted.
	again := awaitPlace(t, srv.URL, s)
	defer again.cancel()

	openSignals(t, srv.URL, s, "").noPlace()
	openSignals(t, srv.URL, signalsSignIn(t, spec.Effects, "u-2"), "").noPlace()
}

// toSignal turns a channel that carries values into one that closes on the first. Its
// goroutine ends with the row, so none waits on after the row has.
func toSignal(t *testing.T, in <-chan struct{}) <-chan struct{} {
	t.Helper()

	out := make(chan struct{})

	go func() {
		select {
		case <-in:
			close(out)
		case <-t.Context().Done():
		}
	}()

	return out
}

// churn sends n requests that reuse the buffers a server keeps per connection: the same
// shapes as the stream's request, with other values. It runs until n are done.
func churn(t *testing.T, base string, n int, workers int, others []*session.Session) {
	t.Helper()

	var wg sync.WaitGroup

	for w := range workers {
		wg.Go(func() {
			client := &http.Client{Transport: &http.Transport{}, Timeout: signalsBound}
			defer client.CloseIdleConnections()

			for i := range n / workers {
				s := others[(w+i)%len(others)]
				path := "/conformance/churn"

				// Alternating a stream request and a plain one, so both the stream's own
				// buffers and the others' are reused.
				if i%2 == 0 {
					path = httpsec.DefaultSessionSignalsPath + "?signals=session_ended"
				}

				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, http.NoBody)
				if err != nil {
					return
				}

				req.Header.Set("Authorization", "Bearer "+signalsToken(s))
				req.Header.Set("Origin", fmt.Sprintf("http://churn-%02d-%02d.example", w, i%100))
				req.Header.Set("Sec-Fetch-Site", "same-origin")

				resp, err := client.Do(req)
				if err != nil {
					continue
				}

				if resp.StatusCode == http.StatusOK {
					// A stream: read its opening and leave, so the place is freed.
					_, _ = bufio.NewReader(resp.Body).ReadString('\n')
				}

				_ = resp.Body.Close()
			}
		})
	}

	wg.Wait()
}

// signalsStreamAmongConcurrentRequests opens a stream while requests of other users, with other
// origins, run on the same server, and shows the stream still speaks for its own user, family,
// origin and narrowing afterwards.
//
// It does not pin the copying of those values: a connected stream's buffers are not reused until
// its client has left, so a body that read them late would pass here. That hazard is pinned in
// the fiber adapter, by TestFiber_StreamBodyMustNotReadExchange.
func signalsStreamAmongConcurrentRequests(t *testing.T, listen func(ChainSpec) StreamServer) {
	lifecycle := &logSink{store: &logStore{}}
	spec := newSignalsSpec(t,
		httpsec.SessionSignals{ExpiryWarning: signalsIdleTimeout - signalsWarnAfter},
		httpsec.WithLogger(slog.New(lifecycle)))
	srv := listen(spec)

	mine := signalsSignIn(t, spec.Effects, "u-1")

	others := make([]*session.Session, 0, 8)
	for i := range 8 {
		others = append(others, signalsSignIn(t, spec.Effects, identity.UserID(fmt.Sprintf("u-%d", i+2))))
	}

	// The same requests as the churn's, in the stream's own shape, run alongside it and
	// afterwards, on connections of their own, so the stream is opened among other users' requests.
	done := make(chan struct{})

	go func() {
		defer close(done)

		churn(t, srv.URL, 240, 8, others)
	}()

	const origin = "http://u-1.example:1"

	c := openSignals(t, srv.URL, mine, "?signals=session_expiring", func(r *http.Request) {
		r.Header.Set("Origin", origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	})
	c.opens()

	waitForStream(t, done, "the churn to finish")
	churn(t, srv.URL, 64, 4, others)

	// The narrowing the stream was opened with still holds: it asked for session_expiring, and
	// the stream, which decides on starting what it will say, says it when it is due.
	c.awaitEvent("session_expiring")

	// Two heartbeats, each of which reloads the stream's user and family: a user copied wrongly
	// is a sign-in that is gone, and ends the stream.
	c.heartbeats(2)

	// The open record holds what the stream copied: the user, and the origin it was asked from.
	record := lifecycle.find(t, "session signal stream opened", "user", "u-1")
	assert.Equal(t, origin, record["origin"], "the origin the stream logged is not the one it was opened with")
	assert.Equal(t, mine.FamilyID.String(), record["family"])

	_, err := spec.Effects.Sessions.Logout(t.Context(), mine.UserID, mine.FamilyID)
	require.NoError(t, err)

	c.requireEnd("logout")
}

// leakySecret is what a consumer's loader panics with: a value that quotes a token.
type leakySecret struct{ token string }

func (e *leakySecret) Error() string { return "the store rejected the token " + e.token }

// panickingUsers is a user loader that panics with a leakySecret once armed.
type panickingUsers struct {
	armed  *atomic.Bool
	secret string
}

func (u panickingUsers) LoadByUsername(ctx context.Context, name string) (*identity.Details, error) {
	return anyActiveUsers{}.LoadByUsername(ctx, name)
}

func (u panickingUsers) LoadByUserID(ctx context.Context, id identity.UserID) (*identity.Details, error) {
	if u.armed.Load() {
		panic(&leakySecret{token: u.secret})
	}

	return anyActiveUsers{}.LoadByUserID(ctx, id)
}

func signalsLoaderPanic(t *testing.T, listen func(ChainSpec) StreamServer) {
	// The default logger is what a chain without WithLogger writes to, and a standard
	// library log of a panic goes to. Both are captured from here on, for the whole process.
	captureDefaultLogs()

	// The row's claim is that the chain's logger and the process's default logger hold no
	// token. A default logger replaced since the capture was installed would pass that
	// vacuously, so a marker, which is no secret, must be seen to land in the capture first.
	requireDefaultLogsCaptured(t)

	secret := "tok-" + hex.EncodeToString(randomBytes(12))

	var armed atomic.Bool

	chainLog := &logSink{store: &logStore{}}
	spec := newSignalsSpec(t,
		httpsec.SessionSignals{MaxPerSignIn: 1, Users: panickingUsers{armed: &armed, secret: secret}},
		httpsec.WithLogger(slog.New(chainLog)))
	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	c := openSignals(t, srv.URL, s, "")
	c.opens()

	// Admitted. The next reload, at the next heartbeat, is the one that panics.
	armed.Store(true)

	for {
		f, err := c.next()
		if errors.Is(err, io.EOF) {
			break
		}

		require.NoError(t, err, "the stream was cut and not closed")
		assert.NotEqual(t, "session_ended", f.event, "a panic in a loader said the sign-in had ended")
	}

	armed.Store(false)

	assert.NotContains(t, c.raw.String(), secret, "the client was sent the panic's value")

	record := chainLog.find(t, "a panic was recovered", "family", s.FamilyID.String())
	assert.Equal(t, "reload", record["phase"], "where the panic happened")
	assert.Contains(t, record["panic_type"], "leakySecret", "the value's type")
	assert.Contains(t, record["frames"], "panickingUsers", "the frames reach the consumer's loader")

	// And again now, so a default replaced during the row cannot make the check below vacuous.
	requireDefaultLogsCaptured(t)

	for _, sink := range []*logSink{chainLog, defaultLogs} {
		assert.NotContains(t, sink.text(), secret, "the chain's logger or the process's default logger holds the panic's value")
	}

	// The place was freed, and the process runs on: the sign-in's only place is admitted.
	again := awaitPlace(t, srv.URL, s)
	defer again.cancel()
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.IntN(256)) //nolint:gosec // a unique marker for a test, not a secret
	}

	return b
}

// --- capturing logs ---

// logStore is what a sink recorded, shared by the handlers derived from it.
type logStore struct {
	mu      sync.Mutex
	records []map[string]string
	lines   []string
}

// logSink is a slog.Handler that records every record, attributes flattened, for a row to
// search.
type logSink struct {
	store *logStore
	attrs []slog.Attr
	group string
}

func (s *logSink) Enabled(context.Context, slog.Level) bool { return true }

func (s *logSink) Handle(_ context.Context, r slog.Record) error {
	fields := map[string]string{"msg": r.Message, "level": r.Level.String()}

	// The attributes of WithAttrs were qualified by the group in force when they were given.
	for _, a := range s.attrs {
		flatten(fields, "", a)
	}

	r.Attrs(func(a slog.Attr) bool {
		flatten(fields, s.group, a)

		return true
	})

	var line strings.Builder
	line.WriteString(r.Message)

	for k, v := range fields {
		line.WriteString(" " + k + "=" + v)
	}

	s.store.mu.Lock()
	s.store.records = append(s.store.records, fields)
	s.store.lines = append(s.store.lines, line.String())
	s.store.mu.Unlock()

	return nil
}

func (s *logSink) WithAttrs(attrs []slog.Attr) slog.Handler {
	held := append([]slog.Attr(nil), s.attrs...)
	for _, a := range attrs {
		held = append(held, slog.Attr{Key: s.group + a.Key, Value: a.Value})
	}

	return &logSink{store: s.store, attrs: held, group: s.group}
}

func (s *logSink) WithGroup(name string) slog.Handler {
	return &logSink{store: s.store, attrs: s.attrs, group: s.group + name + "."}
}

func flatten(into map[string]string, prefix string, a slog.Attr) {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		for _, g := range v.Group() {
			flatten(into, prefix+a.Key+".", g)
		}

		return
	}

	into[prefix+a.Key] = v.String()
}

// text is everything the sink recorded, as one string.
func (s *logSink) text() string {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	return strings.Join(s.store.lines, "\n")
}

// find returns the record whose message contains msg and whose field key is value, and fails
// the row if there is none.
func (s *logSink) find(t *testing.T, msg, key, value string) map[string]string {
	t.Helper()

	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	for _, r := range s.store.records {
		if strings.Contains(r["msg"], msg) && r[key] == value {
			return r
		}
	}

	require.FailNow(t, "no such log record", "wanted one with %q and %s=%s among:\n%s",
		msg, key, value, strings.Join(s.store.lines, "\n"))

	return nil
}

var (
	// defaultLogs is what the process's default logger, and the standard library's log
	// package through it, wrote since captureDefaultLogs ran.
	defaultLogs = &logSink{store: &logStore{}}

	installDefaultLogs sync.Once
)

// captureDefaultLogs routes slog's default logger, and the standard library's log package
// that follows it, into defaultLogs for the rest of the process, once. It never restores the
// previous default, because rows run in parallel and a restore would race: a second row
// restoring what a first had saved would leave a stale handler behind.
//
// Every record it captures is written on to the default handler that was in place before, so
// nothing the process or the standard library's log package wrote vanishes.
func captureDefaultLogs() {
	installDefaultLogs.Do(func() {
		// The original default handler writes through the log package, which slog.SetDefault
		// has pointed back at the handler installed: writing on to it would loop. While the log
		// package still writes to standard error, nothing has replaced that original, so a
		// handler of standard error stands for it.
		var out slog.Handler = slog.NewTextHandler(os.Stderr, nil)
		if log.Default().Writer() != os.Stderr {
			out = slog.Default().Handler()
		}

		slog.SetDefault(slog.New(&teeSink{sink: defaultLogs, out: out}))
	})
}

// requireDefaultLogsCaptured fails the row unless a record of slog's default logger and a line
// of the standard library's log package both reach defaultLogs now. A row that asserts what the
// default logger did not write calls it first, so that a default replaced after
// captureDefaultLogs cannot make the assertion pass for want of anything to find. The marker is
// random and is no secret.
func requireDefaultLogsCaptured(t *testing.T) {
	t.Helper()

	marker := hex.EncodeToString(randomBytes(8))

	slog.Info("conformance canary through slog " + marker)
	log.Print("conformance canary through log " + marker)

	logged := defaultLogs.text()
	require.Contains(t, logged, "conformance canary through slog "+marker,
		"slog's default logger is no longer the capture: a row asserting on it would pass vacuously")
	require.Contains(t, logged, "conformance canary through log "+marker,
		"the standard library's log is no longer captured: a row asserting on it would pass vacuously")
}

// teeSink records every record of Info and above, and writes each on to out, which keeps its
// own level.
type teeSink struct {
	sink *logSink
	out  slog.Handler
}

func (s *teeSink) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

func (s *teeSink) Handle(ctx context.Context, r slog.Record) error {
	_ = s.sink.Handle(ctx, r)

	if s.out.Enabled(ctx, r.Level) {
		return s.out.Handle(ctx, r)
	}

	return nil
}

func (s *teeSink) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &teeSink{sink: s.sink.WithAttrs(attrs).(*logSink), out: s.out.WithAttrs(attrs)} //nolint:forcetypeassert // it is one
}

func (s *teeSink) WithGroup(name string) slog.Handler {
	return &teeSink{sink: s.sink.WithGroup(name).(*logSink), out: s.out.WithGroup(name)} //nolint:forcetypeassert // it is one
}

// --- caps, a consumer's signals and a compressing wrapper ---

// errAdmissionStoreDown is the failure a row's interceptor stands in for a store with.
var errAdmissionStoreDown = errors.New("the session store is down")

// failingAdmission is a chain interceptor that fails every request with errAdmissionStoreDown,
// before anything behind it runs, as long as fail is set. It is inside the stream's answer, so
// it is a dependency failing while a stream is being admitted.
func failingAdmission(fail *atomic.Bool) httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			if fail.Load() {
				return errAdmissionStoreDown
			}

			return next(ex)
		}), httpsec.OrderJWKS)
}

// signalsPublish raises a consumer's signal on chain for user.
func signalsPublish(t *testing.T, chain *httpsec.Chain, user identity.UserID, name, data string) {
	t.Helper()

	require.NotNil(t, chain, "the adapter never built the chain through ChainSpec.NewChain")
	require.NoError(t, chain.PublishSignal(t.Context(), user, name, json.RawMessage(data)))
}

// receivesPing publishes a signal for user and reads it from c, which proves c is open and
// receiving.
func (c *signalsClient) receivesPing(chain *httpsec.Chain, user identity.UserID) {
	c.t.Helper()

	const data = `{"ping":true}`

	signalsPublish(c.t, chain, user, "app.ping", data)

	f := c.nextEvent()
	require.Equal(c.t, "app.ping", f.event)
	require.Equal(c.t, data, f.data)
}

func signalsCapReached(t *testing.T, listen func(ChainSpec) StreamServer) {
	const busy = 10 * time.Second

	var chain *httpsec.Chain

	spec := newSignalsSpec(t, httpsec.SessionSignals{MaxPerSignIn: 1, BusyDelay: busy})
	spec.Built = func(c *httpsec.Chain) { chain = c }

	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	open := openSignals(t, srv.URL, s, "")
	open.opens()

	// The next request for the sign-in is over its cap. It is told to come back later.
	refused := openSignals(t, srv.URL, s, "")
	requireWithinJitter(t, busy, refused.noPlace())

	// And it closed no stream to make room: the open one still receives.
	open.receivesPing(chain, UserID)

	// Nor was anything charged for the refusal: a client that leaves frees the place, and the
	// next request takes it.
	open.cancel()

	again := awaitPlace(t, srv.URL, s)
	again.receivesPing(chain, UserID)
}

// failingStore is a session store that fails a read while its switch is set. loadFails is the read
// that authenticates a request (Load); listFails is the read of the sign-in's state the stream's
// own endpoint makes at admission (ListByUser). Everything else is the wrapped store's.
type failingStore struct {
	session.Store

	loadFails, listFails atomic.Bool
}

func (f *failingStore) Load(ctx context.Context, id string) (*session.Session, error) {
	if f.loadFails.Load() {
		return nil, errAdmissionStoreDown
	}

	return f.Store.Load(ctx, id)
}

func (f *failingStore) ListByUser(ctx context.Context, user identity.UserID, now time.Time) ([]*session.Session, error) {
	if f.listFails.Load() {
		return nil, errAdmissionStoreDown
	}

	return f.Store.ListByUser(ctx, user, now)
}

// signalsDependencyFailureAtAdmission fails the session store while a stream is being admitted,
// first in the endpoint's own first read of the sign-in, on a request already authenticated, and
// then in the read that authenticates the request. Either way the client is told to come back
// later, and nothing is charged: with one place, the next request takes it.
func signalsDependencyFailureAtAdmission(t *testing.T, listen func(ChainSpec) StreamServer) {
	const busy = 10 * time.Second

	type testCase struct {
		name string
		fail func(*failingStore) *atomic.Bool
	}

	cases := []testCase{
		{"the endpoint's own first read fails after authentication", func(f *failingStore) *atomic.Bool { return &f.listFails }},
		{"the read that authenticates the request fails", func(f *failingStore) *atomic.Bool { return &f.loadFails }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				store *failingStore
				chain *httpsec.Chain
			)

			spec := newSignalsSpecOver(t, signalsIdleTimeout,
				func(inner session.Store) session.Store {
					store = &failingStore{Store: inner}

					return store
				},
				httpsec.SessionSignals{MaxPerSignIn: 1, BusyDelay: busy})
			spec.Built = func(c *httpsec.Chain) { chain = c }

			srv := listen(spec)
			s := signalsSignIn(t, spec.Effects, UserID)

			fail := tc.fail(store)
			fail.Store(true)

			requireWithinJitter(t, busy, openSignals(t, srv.URL, s, "").noPlace())

			// The failure charged the sign-in nothing: with one place, the next request, once the
			// dependency is back, takes it.
			fail.Store(false)

			open := openSignals(t, srv.URL, s, "")
			open.opens()
			open.receivesPing(chain, UserID)
		})
	}
}

// signalsDependencyFailureBeforeAuthentication is the same answer when a failure comes from an
// interceptor ahead of authentication, which the endpoint's own read never sees.
func signalsDependencyFailureBeforeAuthentication(t *testing.T, listen func(ChainSpec) StreamServer) {
	const busy = 10 * time.Second

	var (
		fail  atomic.Bool
		chain *httpsec.Chain
	)

	spec := newSignalsSpec(t, httpsec.SessionSignals{MaxPerSignIn: 1, BusyDelay: busy}, failingAdmission(&fail))
	spec.Built = func(c *httpsec.Chain) { chain = c }

	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	fail.Store(true)

	requireWithinJitter(t, busy, openSignals(t, srv.URL, s, "").noPlace())

	fail.Store(false)

	open := openSignals(t, srv.URL, s, "")
	open.opens()
	open.receivesPing(chain, UserID)
}

func signalsConsumerSignal(t *testing.T, listen func(ChainSpec) StreamServer) {
	var chain *httpsec.Chain

	spec := newSignalsSpec(t, httpsec.SessionSignals{})
	spec.Built = func(c *httpsec.Chain) { chain = c }

	srv := listen(spec)

	// Not canonical JSON: the key order, the spaces and the escapes are the consumer's, and
	// reach the browser as they are.
	const data = `{"z": 1,"a":["\u00e9", "é", "</x>"],  "n":1.50}`

	type testCase struct {
		name   string
		user   identity.UserID
		query  string
		assert func(t *testing.T, c *signalsClient)
	}

	receives := func(t *testing.T, c *signalsClient) {
		f := c.nextEvent()
		assert.Equal(t, "app.note", f.event)
		assert.Equal(t, data, f.data)
	}

	neverHears := func(*testing.T, *signalsClient) {}

	cases := []testCase{
		{"an unnarrowed stream of the user is sent it", UserID, "", receives},
		{"a second unnarrowed stream of the user is sent it too", UserID, "", receives},
		{"a stream narrowed to the signal's name is sent it", UserID, "?signals=app.note", receives},
		{"a stream narrowed to another name is not sent it", UserID, "?signals=session_ended", neverHears},
		{"another user's stream is not sent it", "u-2", "", neverHears},
	}

	signIns := make([]*session.Session, len(cases))
	clients := make([]*signalsClient, len(cases))

	for i, tc := range cases {
		signIns[i] = signalsSignIn(t, spec.Effects, tc.user)
		clients[i] = openSignals(t, srv.URL, signIns[i], tc.query)
		clients[i].opens()
	}

	signalsPublish(t, chain, UserID, "app.note", data)

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, clients[i])

			// Ending the sign-in ends the stream with nothing else on it: a stream not sent the
			// signal has nothing before the end, and one that was has had it already.
			_, err := spec.Effects.Sessions.Logout(t.Context(), signIns[i].UserID, signIns[i].FamilyID)
			require.NoError(t, err)

			assert.Equal(t, []string{"session_ended"}, clients[i].eventsToEnd())
		})
	}
}

// signalsGzipInFront puts the framework's response compression in front of the chain. Where the
// adapter compresses the stream (net/http and gin, StreamServer.CompressesStream), the response
// must say gzip, and the events are read through the gzip reader as they are flushed. On fiber the
// compress middleware skips the stream because of Cache-Control: no-transform, so there the row
// shows that no-transform is honoured: no Content-Encoding, and the events arrive plain.
func signalsGzipInFront(t *testing.T, listen func(ChainSpec) StreamServer) {
	var chain *httpsec.Chain

	spec := newSignalsSpec(t, httpsec.SessionSignals{})
	spec.Compress = true
	spec.Built = func(c *httpsec.Chain) { chain = c }

	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	c := openSignals(t, srv.URL, s, "", func(r *http.Request) {
		r.Header.Set("Accept-Encoding", "gzip")
	})

	encoding := c.resp.Header.Get("Content-Encoding")

	if srv.CompressesStream {
		require.Equal(t, "gzip", encoding, "the compressing wrapper did not compress the stream")

		zr, err := gzip.NewReader(c.r)
		require.NoError(t, err)

		c.r = bufio.NewReader(zr)
	} else {
		require.Empty(t, encoding, "the compress middleware compressed a no-transform response")

		head, err := c.r.Peek(2)
		require.NoError(t, err)
		require.NotEqual(t, []byte{0x1f, 0x8b}, head, "gzip arrived with no Content-Encoding")
	}

	// A flushed event arrives readable while the response stays open: the session event
	// first, then one raised afterwards, with the response still open behind it.
	c.opens()
	c.receivesPing(chain, UserID)

	_, err := spec.Effects.Sessions.Logout(t.Context(), s.UserID, s.FamilyID)
	require.NoError(t, err)

	c.requireEnd("logout")
}
