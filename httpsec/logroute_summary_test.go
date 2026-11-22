package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// summaryCount is how many summary records msg for key recs hold.
func summaryCount(recs []slog.Record, msg, key string) (n int) {
	for _, r := range recs {
		if r.Message != msg {
			continue
		}

		if v, ok := attrValue(r, "key"); ok && v.String() == key {
			n++
		}
	}

	return n
}

// TestLogRoute_SamplerSummaryPerKey pins, for each sampler of the package,
// that a key's suppressed-count summary goes where the key's own records went:
// the component's logger option, else the chain that received the key's record,
// else slog.Default(), and never another chain's logger.
func TestLogRoute_SamplerSummaryPerKey(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const key = "k1"

	type rig struct {
		probe *httpsec.SamplerProbe
		msg   string
	}

	// build makes the sampler's component; own is the component's logger
	// option, or nil when it was given none.
	type builder func(t *testing.T, own *slog.Logger) rig

	chainRig := func(t *testing.T, own *slog.Logger) rig {
		t.Helper()

		opts := []httpsec.Option{
			httpsec.WithRefusalLogInterval(time.Hour),
			httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				return next(ex)
			}), httpsec.OrderBearerToken),
		}
		if own != nil {
			opts = append(opts, httpsec.WithLogger(own))
		}

		c, err := httpsec.New(opts...)
		require.NoError(t, err)

		return rig{probe: httpsec.ChainSamplerProbe(c), msg: "httpsec: refusal logs suppressed"}
	}

	logger := func(own *slog.Logger) *slog.Logger {
		if own != nil {
			return own
		}

		return ctxlog.Routing()
	}

	builders := map[string]builder{
		"chain": chainRig,
		"recovery": func(_ *testing.T, own *slog.Logger) rig {
			return rig{probe: httpsec.RecoverySamplerProbe(logger(own), time.Hour), msg: "httpsec: recovery logs suppressed"}
		},
		"enrolment": func(_ *testing.T, own *slog.Logger) rig {
			return rig{probe: httpsec.EnrolmentSamplerProbe(logger(own), time.Hour), msg: "httpsec: enrolment logs suppressed"}
		},
		"passkey": func(_ *testing.T, own *slog.Logger) rig {
			return rig{probe: httpsec.PasskeySamplerProbe(logger(own), time.Hour), msg: "httpsec: refusal logs suppressed"}
		},
	}

	type logs struct{ a, b, own, def *capturingHandler }

	cases := []struct {
		name   string
		own    bool
		act    func(ctx context.Context, a, b context.Context, p *httpsec.SamplerProbe)
		assert func(t *testing.T, got logs, msg string)
	}{
		{
			name: "written and suppressed in chain A, the summary goes to A",
			act: func(_ context.Context, a, _ context.Context, p *httpsec.SamplerProbe) {
				p.Log(a, key)
				p.Log(a, key)
			},
			assert: func(t *testing.T, got logs, msg string) {
				assert.Equal(t, 1, summaryCount(got.a.records(), msg, key), "the summary did not reach chain A")
				assert.Zero(t, summaryCount(got.b.records(), msg, key), "the summary landed on chain B")
				assert.Zero(t, summaryCount(got.def.records(), msg, key), "the summary landed on the default")
			},
		},
		{
			name: "written in chain A, suppressed in chain B, the summary goes to A only",
			act: func(_ context.Context, a, b context.Context, p *httpsec.SamplerProbe) {
				p.Log(a, key)
				p.Log(b, key)
			},
			assert: func(t *testing.T, got logs, msg string) {
				assert.Equal(t, 1, summaryCount(got.a.records(), msg, key), "the summary did not reach chain A")
				assert.Zero(t, summaryCount(got.b.records(), msg, key), "the summary leaked to chain B")
				assert.Zero(t, summaryCount(got.def.records(), msg, key), "the summary landed on the default")
			},
		},
		{
			name: "two keys in two chains each summarise to their own chain",
			act: func(_ context.Context, a, b context.Context, p *httpsec.SamplerProbe) {
				p.Log(a, key)
				p.Log(a, key)
				p.Log(b, "k2")
				p.Log(b, "k2")
			},
			assert: func(t *testing.T, got logs, msg string) {
				assert.Equal(t, 1, summaryCount(got.a.records(), msg, key), "k1 did not reach chain A")
				assert.Zero(t, summaryCount(got.b.records(), msg, key), "k1 leaked to chain B")
				assert.Equal(t, 1, summaryCount(got.b.records(), msg, "k2"), "k2 did not reach chain B")
				assert.Zero(t, summaryCount(got.a.records(), msg, "k2"), "k2 leaked to chain A")
				assert.Zero(t, summaryCount(got.def.records(), msg, key), "k1 landed on the default")
			},
		},
		{
			name: "written and suppressed in chain B, the summary goes to B",
			act: func(_ context.Context, _, b context.Context, p *httpsec.SamplerProbe) {
				p.Log(b, key)
				p.Log(b, key)
			},
			assert: func(t *testing.T, got logs, msg string) {
				assert.Equal(t, 1, summaryCount(got.b.records(), msg, key), "the summary did not reach chain B")
				assert.Zero(t, summaryCount(got.a.records(), msg, key), "the summary landed on chain A")
				assert.Zero(t, summaryCount(got.def.records(), msg, key), "the summary landed on the default")
			},
		},
		{
			name: "written under no chain, the summary goes to the default",
			act: func(base context.Context, _, _ context.Context, p *httpsec.SamplerProbe) {
				p.Log(base, key)
				p.Log(base, key)
			},
			assert: func(t *testing.T, got logs, msg string) {
				assert.Equal(t, 1, summaryCount(got.def.records(), msg, key), "the summary did not reach the default")
				assert.Zero(t, summaryCount(got.a.records(), msg, key))
				assert.Zero(t, summaryCount(got.b.records(), msg, key))
			},
		},
		{
			name: "the component's own logger wins over the chain",
			own:  true,
			act: func(_ context.Context, a, _ context.Context, p *httpsec.SamplerProbe) {
				p.Log(a, key)
				p.Log(a, key)
			},
			assert: func(t *testing.T, got logs, msg string) {
				assert.Equal(t, 1, summaryCount(got.own.records(), msg, key), "the summary did not reach the option's logger")
				assert.Zero(t, summaryCount(got.a.records(), msg, key), "the summary landed on chain A")
				assert.Zero(t, summaryCount(got.def.records(), msg, key), "the summary landed on the default")
			},
		},
	}

	for name, build := range builders { //nolint:paralleltest // it replaces slog.Default()
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				got := logs{
					a: &capturingHandler{}, b: &capturingHandler{}, own: &capturingHandler{},
					def: swapDefaultLogger(t),
				}

				var own *slog.Logger
				if tc.own {
					own = slog.New(got.own)
				}

				r := build(t, own)

				a := ctxlog.With(t.Context(), slog.New(got.a))
				b := ctxlog.With(t.Context(), slog.New(got.b))

				tc.act(t.Context(), a, b, r.probe)
				r.probe.Flush()

				tc.assert(t, got, r.msg)
			})
		}
	}

}

// TestLogRoute_AbortSummary pins that a classification-abort record, sampled
// under one chain, sends the abort key's summary to that chain: not to the
// default logger and not to another chain.
func TestLogRoute_AbortSummary(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const msg = "httpsec: refusal logs suppressed"

	cases := []struct {
		name   string
		act    func(a, b context.Context, p *httpsec.SamplerProbe)
		assert func(t *testing.T, a, b, def *capturingHandler)
	}{
		{
			name: "sampled under chain A, the summary goes to A",
			act: func(a, _ context.Context, p *httpsec.SamplerProbe) {
				p.Log(a, "")
				p.Log(a, "")
			},
			assert: func(t *testing.T, a, b, def *capturingHandler) {
				assert.Equal(t, 1, summaryCount(a.records(), msg, httpsec.AbortKey), "the summary did not reach chain A")
				assert.Zero(t, summaryCount(b.records(), msg, httpsec.AbortKey), "the summary landed on chain B")
				assert.Zero(t, summaryCount(def.records(), msg, httpsec.AbortKey), "the summary landed on the default")
			},
		},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			a, b, def := &capturingHandler{}, &capturingHandler{}, swapDefaultLogger(t)

			c, err := httpsec.New(httpsec.WithRefusalLogInterval(time.Hour))
			require.NoError(t, err)

			p := httpsec.ChainAbortProbe(c)

			tc.act(ctxlog.With(t.Context(), slog.New(a)), ctxlog.With(t.Context(), slog.New(b)), p)
			p.Flush()

			tc.assert(t, a, b, def)
		})
	}
}

// TestLogRoute_ChainGuardSummary pins that a source guard the chain builds
// sends a key's suppressed-count summary where the key's own records went when
// the chain was given no logger, and to the consumer's reporter when it gave
// one (WithRefusalLogReporter).
func TestLogRoute_ChainGuardSummary(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const (
		addr = "192.0.2.7"
		msg  = summaryGuard
	)

	// summaries counts the guard's summary records in recs, whatever their key.
	summaries := func(recs []slog.Record) (n int) {
		for _, r := range recs {
			if r.Message == msg {
				n++
			}
		}

		return n
	}

	cases := []struct {
		name   string
		own    bool
		report bool
		assert func(t *testing.T, a, b, own, def *capturingHandler, reported []string)
	}{
		{
			name: "no logger: the summary goes to the chain the key's records went to",
			assert: func(t *testing.T, a, b, _, def *capturingHandler, _ []string) {
				assert.Equal(t, 1, summaries(a.records()), "the summary did not reach chain A")
				assert.Zero(t, summaries(b.records()), "the summary landed on chain B")
				assert.Zero(t, summaries(def.records()), "the summary landed on the default")
			},
		},
		{
			name: "WithLogger: the summary goes to the chain's logger",
			own:  true,
			assert: func(t *testing.T, a, b, own, def *capturingHandler, _ []string) {
				assert.Equal(t, 1, summaries(own.records()), "the summary did not reach the option's logger")
				assert.Zero(t, summaries(a.records()), "the summary landed on chain A")
				assert.Zero(t, summaries(b.records()), "the summary landed on chain B")
				assert.Zero(t, summaries(def.records()), "the summary landed on the default")
			},
		},
		{
			name:   "WithRefusalLogReporter: the consumer's reporter receives the summary",
			report: true,
			assert: func(t *testing.T, a, b, _, def *capturingHandler, reported []string) {
				assert.Len(t, reported, 1, "the consumer's reporter did not receive the summary")
				assert.Zero(t, summaries(a.records()))
				assert.Zero(t, summaries(b.records()))
				assert.Zero(t, summaries(def.records()))
			},
		},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			a, b, own := &capturingHandler{}, &capturingHandler{}, &capturingHandler{}
			def := swapDefaultLogger(t)

			var (
				log      *slog.Logger
				reporter func(string, int)
				reported []string
			)

			if tc.own {
				log = slog.New(own)
			}

			if tc.report {
				reporter = func(key string, _ int) { reported = append(reported, key) }
			}

			probe, err := httpsec.GuardSamplerProbe(log, reporter)
			require.NoError(t, err)

			ctxA := ctxlog.With(t.Context(), slog.New(a))

			probe.Log(ctxA, addr)
			probe.Log(ctxA, addr)
			probe.Flush()

			tc.assert(t, a, b, own, def, reported)
		})
	}
}
