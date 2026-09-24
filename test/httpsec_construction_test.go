package test_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/fibersec"
	"github.com/kartaladev/scrty/ginsec"
	"github.com/kartaladev/scrty/httpsec"
	httpsecconformance "github.com/kartaladev/scrty/test/httpsecconformance"
)

// TestConformanceConstruction pins that one wiring mistake fails the same way
// whichever framework is in front.
//
// The chain is built before any framework is involved, so a consumer who moves
// a deployment from net/http to gin, or from gin to fiber, must not have to
// learn a second vocabulary for the same mistake. The rows check the whole
// message, not just that an error came back: a message that named a different
// option or a different dependency on one framework would send a consumer
// looking in the wrong place.
//
// Each row then tries to mount what construction returned, which is what the
// refusal buys: there is no partly-configured chain for an adapter to serve
// traffic with.
func TestConformanceConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// mounted reports whether the adapter could be handed a chain at all.
		// Every row must answer false: the chain is nil, so there is nothing to
		// mount, and each adapter refuses a nil chain at wiring time.
		mount func(t *testing.T, chain *httpsec.Chain) (mounted bool)
	}

	cases := []testCase{
		{
			name: "net/http",
			mount: func(t *testing.T, chain *httpsec.Chain) bool {
				t.Helper()

				if chain == nil {
					return false
				}

				return chain.Middleware() != nil
			},
		},
		{
			name: "gin",
			mount: func(t *testing.T, chain *httpsec.Chain) bool {
				t.Helper()

				return mountedWithoutPanic(t, func() { _ = ginsec.Middleware(chain) })
			},
		},
		{
			name: "fiber",
			mount: func(t *testing.T, chain *httpsec.Chain) bool {
				t.Helper()

				return mountedWithoutPanic(t, func() { _ = fibersec.Middleware(chain) })
			},
		},
	}

	// The reference message, produced once. Every row must match it exactly.
	_, reference := httpsec.New(httpsecconformance.MisconfiguredFormLogin())
	require.Error(t, reference)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(httpsecconformance.MisconfiguredFormLogin())

			require.Error(t, err, "form login with no session manager cannot build a chain")
			require.ErrorIs(t, err, httpsec.ErrConfig,
				"a consumer matches every wiring fault with one errors.Is, on every framework")
			assert.Contains(t, err.Error(), "EnableFormLogin", "the message names the option")
			assert.Contains(t, err.Error(), "session manager",
				"the message names the dependency that is missing")
			assert.Equal(t, reference.Error(), err.Error(),
				"the same mistake reads the same on every framework")

			assert.Nil(t, chain, "there is no partly-configured chain to serve traffic with")
			assert.False(t, tc.mount(t, chain),
				"no adapter can be handed the chain that did not build")
		})
	}
}

// mountedWithoutPanic reports whether mount returned rather than panicking.
//
// Both adapters panic on a nil chain at wiring time, deliberately: a nil chain
// would serve every request unguarded, and failing at start-up is the only
// place that can still be noticed. The row therefore reads "was it mounted",
// not "did it panic".
func mountedWithoutPanic(t *testing.T, mount func()) (mounted bool) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			mounted = false
		}
	}()

	mount()

	return true
}
