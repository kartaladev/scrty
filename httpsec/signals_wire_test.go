package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/httpsec"
)

func TestSessionSignals_Narrowing_Wants(t *testing.T) {
	t.Parallel()

	expiring := string(httpsec.SignalSessionExpiring)
	credential := string(httpsec.SignalCredentialChanged)
	chain := []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalSessionExpiring}

	type testCase struct {
		name     string
		chain    []httpsec.Signal
		narrowed bool
		names    []string
		signal   string
		assert   func(t *testing.T, wanted bool)
	}

	wanted := func(t *testing.T, got bool) {
		t.Helper()
		assert.True(t, got)
	}
	unwanted := func(t *testing.T, got bool) {
		t.Helper()
		assert.False(t, got)
	}

	cases := []testCase{
		{name: "the zero filter wants no library signal", signal: expiring, assert: unwanted},
		{name: "the zero filter wants a consumer's", signal: "app.roles", assert: wanted},
		{name: "not narrowed, a signal of the chain's set", chain: chain, signal: expiring, assert: wanted},
		{name: "not narrowed, a library signal outside the chain's set", chain: chain, signal: credential, assert: unwanted},
		{name: "not narrowed, every consumer's", chain: chain, signal: "app.roles", assert: wanted},
		{name: "not narrowed, a name that is neither", chain: chain, signal: "other", assert: unwanted},
		{
			name:  "a name that is neither is unwanted even when named",
			chain: chain, narrowed: true, names: []string{"other"}, signal: "other", assert: unwanted,
		},
		{
			name:  "session_ended is wanted even when narrowed away",
			chain: chain, narrowed: true, names: []string{expiring}, signal: "session_ended", assert: wanted,
		},
		{
			name:   "session_ended is wanted outside the chain's set",
			signal: "session_ended", assert: wanted,
		},
		{
			name:  "session is wanted even when narrowed away",
			chain: chain, narrowed: true, names: []string{expiring}, signal: "session", assert: wanted,
		},
		{
			name:  "narrowed to a signal of the chain's set",
			chain: chain, narrowed: true, names: []string{expiring}, signal: expiring, assert: wanted,
		},
		{
			name:  "narrowing cannot widen the chain's set",
			chain: chain, narrowed: true, names: []string{credential}, signal: credential, assert: unwanted,
		},
		{
			name:  "a signal of the chain's set the client left out",
			chain: chain, narrowed: true, names: []string{"app.roles"}, signal: expiring, assert: unwanted,
		},
		{
			name:  "narrowed to a consumer's",
			chain: chain, narrowed: true, names: []string{"app.roles"}, signal: "app.roles", assert: wanted,
		},
		{
			name:  "a consumer's the client left out",
			chain: chain, narrowed: true, names: []string{expiring}, signal: "app.roles", assert: unwanted,
		},
		{name: "narrowed to nothing, no library signal", chain: chain, narrowed: true, signal: expiring, assert: unwanted},
		{name: "narrowed to nothing, no consumer's", chain: chain, narrowed: true, signal: "app.roles", assert: unwanted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, httpsec.SignalFilterWants(tc.chain, tc.narrowed, tc.names, tc.signal))
		})
	}
}
