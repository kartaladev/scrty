package httpsec_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/eventsink"
)

// eventRecorder is a sink that keeps every event it receives, with whether
// the context it was handed had ended.
type eventRecorder struct {
	mu     sync.Mutex
	events []event.Event
	ended  []bool

	// before, when set, runs at the start of every delivery.
	before func(ctx context.Context, e event.Event)
}

func (r *eventRecorder) sink(ctx context.Context, e event.Event) {
	if r.before != nil {
		r.before(ctx, e)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, e)
	r.ended = append(r.ended, ctx.Err() != nil)
}

// all is every event received so far, in order.
func (r *eventRecorder) all() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]event.Event(nil), r.events...)
}

// named is every event received so far under name.
func (r *eventRecorder) named(name string) []event.Event {
	var out []event.Event

	for _, e := range r.all() {
		if e.Name == name {
			out = append(out, e)
		}
	}

	return out
}

// names is the name of every event received so far, in order.
func (r *eventRecorder) names() []string {
	var out []string

	for _, e := range r.all() {
		out = append(out, e.Name)
	}

	return out
}

// serveWithContext is serve with the exchange's context chosen by the caller.
func serveWithContext(ctx context.Context, chain *httpsec.Chain, req *http.Request) served {
	out := served{rec: httptest.NewRecorder()}
	run := chain.Assemble(func(ex *httpsec.Exchange) error { //nolint:contextcheck // the exchange carries the request context, and begin reads it through ex.Context()
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	ex := httpsec.NewExchange(ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}

func TestSecurityEvents_Sink(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// sink builds the sink the chain is given from the row's recorder and
		// the request's cancel function, and nil means no sink at all.
		sink func(rec *eventRecorder, cancel context.CancelFunc) event.Sink

		password string

		assert func(t *testing.T, out served, rec *eventRecorder, logs []slog.Record)
	}

	recording := func(rec *eventRecorder, _ context.CancelFunc) event.Sink { return rec.sink }

	cases := []testCase{
		{
			name:     "no sink: a failed login is refused as before and nothing is reported",
			password: "wrong",
			assert: func(t *testing.T, out served, rec *eventRecorder, _ []slog.Record) {
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.Empty(t, rec.all())
			},
		},
		{
			name:     "a failed login reports exactly one authn_login_fail",
			sink:     recording,
			password: "wrong",
			assert: func(t *testing.T, out served, rec *eventRecorder, _ []slog.Record) {
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, []string{event.AuthnLoginFail}, rec.names())

				e := rec.all()[0]
				assert.Equal(t, event.OutcomeFailure, e.Outcome)
				assert.Equal(t, loginGuardSource, e.ClientIP)
				assert.Equal(t, factor.Password, e.Factor)
				assert.Empty(t, e.User, "a failed login names no user")
				assert.False(t, e.At.IsZero())
			},
		},
		{
			name: "a panicking sink: the login still succeeds, and the panic is logged without the event",
			sink: func(rec *eventRecorder, _ context.CancelFunc) event.Sink {
				return func(ctx context.Context, e event.Event) {
					rec.sink(ctx, e)
					panic("sink: " + e.Name + " " + string(e.User) + " " + e.ClientIP + " " + e.Session)
				}
			},
			password: loginGuardRightPassword,
			assert: func(t *testing.T, out served, rec *eventRecorder, logs []slog.Record) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				require.NotEmpty(t, rec.all(), "the sink was called")

				panicked := 0
				for _, r := range logs {
					if r.Message == eventsink.MsgSinkPanicked {
						panicked++
						assert.Zero(t, r.NumAttrs(), "the panic record carries nothing of the event")
					}

					text := recordText(r)
					for _, e := range rec.all() {
						for _, v := range []string{e.Name, string(e.User), e.ClientIP, e.Session} {
							if v != "" {
								assert.NotContains(t, text, v, "a record carries an event's contents")
							}
						}
					}
				}
				assert.Equal(t, len(rec.all()), panicked, "every panic is logged")
			},
		},
		{
			name: "a request context cancelled after the outcome: the sink is still called, on a live context",
			sink: func(rec *eventRecorder, cancel context.CancelFunc) event.Sink {
				rec.before = func(context.Context, event.Event) { cancel() }

				return rec.sink
			},
			password: "wrong",
			assert: func(t *testing.T, out served, rec *eventRecorder, _ []slog.Record) {
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				require.Equal(t, []string{event.AuthnLoginFail}, rec.names())
				assert.Equal(t, []bool{false}, rec.ended, "the sink's context did not end with the request's")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			rec := &eventRecorder{}
			h := newLoginGuardHarness(t)

			var opts []httpsec.Option
			if tc.sink != nil {
				opts = append(opts, httpsec.EnableSecurityEvents(tc.sink(rec, cancel)))
			}

			c := h.chain(t, nil, nil, opts...)

			out := serveWithContext(ctx, c, fromSource(formRequest(ctx, httpsec.DefaultLoginPath,
				"username=alice&password="+strings.ReplaceAll(tc.password, " ", "+")), loginGuardSource))

			tc.assert(t, out, rec, h.logs.records())
		})
	}
}

func TestSecurityEvents_Config(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	sink := func(context.Context, event.Event) {}

	cases := []testCase{
		{
			name: "a sink is accepted",
			opts: []httpsec.Option{httpsec.EnableSecurityEvents(sink)},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, c)
			},
		},
		{
			name: "a nil sink is a configuration error naming the option",
			opts: []httpsec.Option{httpsec.EnableSecurityEvents(nil)},
			assert: func(t *testing.T, _ *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "EnableSecurityEvents")
			},
		},
		{
			name: "the option given twice is a configuration error naming it",
			opts: []httpsec.Option{httpsec.EnableSecurityEvents(sink), httpsec.EnableSecurityEvents(sink)},
			assert: func(t *testing.T, _ *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "EnableSecurityEvents")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.opts...)
			tc.assert(t, c, err)
		})
	}
}
