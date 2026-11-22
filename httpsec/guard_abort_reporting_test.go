package httpsec_test

// Every row of the test in this file replaces slog.Default() for its duration,
// so none of them runs in parallel, and each restores the logger it found.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
)

// TestGuard_AbortReporting pins the guard's reporting rule for an aborted
// classification of its refusal. The guard's own walks, the refusal's
// security event and the DPoP challenge, return their abort to the guard,
// which reports by its own configuration:
//
//   - with WithGuardErrorHandler, the guard's status lookup is replaced, so
//     any abort writes one record to slog.Default();
//   - without it, the guard's lookup reports its own abort, and the guard
//     writes one only when that lookup does not abort.
//
// Each row's request writes exactly one record, whichever walk met the abort
// and however many did: a cyclic chain and an Is that always panics abort
// every walk, the lookup's included, and a selective Is aborts only the walk
// that asks about the sentinel it panics on, which the lookup never does.
func TestGuard_AbortReporting(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name    string
		err     error
		chain   func(t *testing.T, w *refusalWorld) []httpsec.Option
		handler bool
		assert  func(t *testing.T, g refusalGot)
	}

	teapot := httpsec.WithGuardErrorHandler(func(w http.ResponseWriter, _ *http.Request, _ error) {
		w.WriteHeader(http.StatusTeapot)
	})

	type chainKind struct {
		name      string
		opts      func(t *testing.T, w *refusalWorld) []httpsec.Option
		selective error
	}

	kinds := []chainKind{
		{
			name: "a chain with events",
			opts: func(_ *testing.T, w *refusalWorld) []httpsec.Option {
				return []httpsec.Option{w.logger(), w.securityEvents()}
			},
			selective: selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: authorize.ErrAccessDenied},
		},
		{
			name: "a DPoP chain",
			opts: func(t *testing.T, w *refusalWorld) []httpsec.Option {
				t.Helper()

				bearer, _ := signedInBearer(t)

				return []httpsec.Option{w.logger(), bearer, httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL})}
			},
			selective: selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: httpsec.ErrDPoPNonceRequired},
		},
		{
			name: "a DPoP chain with events",
			opts: func(t *testing.T, w *refusalWorld) []httpsec.Option {
				t.Helper()

				bearer, _ := signedInBearer(t)

				return []httpsec.Option{
					w.logger(), w.securityEvents(), bearer,
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}),
				}
			},
			selective: selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: authorize.ErrAccessDenied},
		},
	}

	oneRecord := func(status int) func(t *testing.T, g refusalGot) {
		return func(t *testing.T, g refusalGot) {
			t.Helper()

			assert.Equal(t, status, g.status)
			assert.Equal(t, 1, len(g.chainAborts)+len(g.defaultAborts),
				"one record per request whose classification aborted (chain %d, default %d)",
				len(g.chainAborts), len(g.defaultAborts))
		}
	}

	var cases []testCase

	for _, k := range kinds {
		errs := []struct {
			name   string
			err    error
			status int
		}{
			{name: "a cycle", err: &cycleOne{}, status: http.StatusInternalServerError},
			{name: "an Is that always panics", err: isPanics{}, status: http.StatusInternalServerError},
			{name: "a selective Is the lookup never meets", err: k.selective, status: http.StatusUnauthorized},
		}

		for _, e := range errs {
			cases = append(cases,
				testCase{
					name: k.name + ", " + e.name + ", the default answer", err: e.err, chain: k.opts,
					assert: oneRecord(e.status),
				},
				testCase{
					name: k.name + ", " + e.name + ", WithGuardErrorHandler", err: e.err, chain: k.opts,
					handler: true, assert: oneRecord(http.StatusTeapot),
				},
			)
		}
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaultLogs := swapDefaultLogger(t)
			w := &refusalWorld{chainLogs: &capturingHandler{}}

			var guardOpts []httpsec.GuardOption
			if tc.handler {
				guardOpts = append(guardOpts, teapot)
			}

			h := behindChain(t, guardRefusing(t, tc.err, guardOpts...), tc.chain(t, w)...)
			rec := serveRefusalWithin(t, h, principalRequest(t.Context()))

			tc.assert(t, refusalGot{
				status:        rec.Code,
				header:        rec.Header(),
				events:        w.emitted(),
				chainRecords:  w.chainLogs.records(),
				chainAborts:   abortRecords(w.chainLogs.records()),
				defaultAborts: abortRecords(defaultLogs.records()),
			})
		})
	}
}
