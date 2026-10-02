package oidc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

// assuranceManager builds a manager for providers corp and partner with the
// given options, sending no request.
func assuranceManager(t *testing.T, opts ...oidc.ManagerOption) *oidc.Manager {
	t.Helper()

	p := newTestProvider(t)
	reg, err := oidc.NewRegistry(p.Provider("corp"), p.Provider("partner"))
	require.NoError(t, err)
	m, err := oidc.NewManager(reg, stubBroker{}, append([]oidc.ManagerOption{oidc.WithOutboundClient(p.Outbound(t))}, opts...)...)
	require.NoError(t, err)
	return m
}

// TestMatchAssurance decides the asserted values of a verified login against
// corp's resolved configuration, one row per scenario of the requirement
// "Each provider has an assurance configuration with a safe default".
func TestMatchAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []oidc.ManagerOption
		amr    []string
		acr    string
		assert func(t *testing.T, met bool)
	}

	met := func(t *testing.T, got bool) { t.Helper(); assert.True(t, got, "assurance must be met") }
	notMet := func(t *testing.T, got bool) { t.Helper(); assert.False(t, got, "assurance must not be met") }
	corp := func(a oidc.Assurance) []oidc.ManagerOption {
		return []oidc.ManagerOption{oidc.WithProviderAssurance("corp", a)}
	}

	cases := []testCase{
		{name: "default does not accept single-method values", amr: []string{"pwd", "otp"}, assert: notMet},
		{name: "default accepts mfa", amr: []string{"pwd", "mfa"}, assert: met},
		{name: "default with nothing asserted", assert: notMet},
		{name: "default ignores an asserted acr", acr: "urn:corp:loa:2", assert: notMet},
		{
			name: "a consumer accepts an acr and no amr",
			opts: corp(oidc.Assurance{AcceptedACR: []string{"urn:corp:loa:2"}}),
			acr:  "urn:corp:loa:2", assert: met,
		},
		{
			name: "configuring replaces the whole default, so mfa is no longer accepted",
			opts: corp(oidc.Assurance{AcceptedACR: []string{"urn:corp:loa:2"}}),
			amr:  []string{"mfa"}, assert: notMet,
		},
		{
			name: "values match exactly and case-sensitively",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}}),
			amr:  []string{"MFA"}, assert: notMet,
		},
		{
			name: "acr values match exactly",
			opts: corp(oidc.Assurance{AcceptedACR: []string{"gold"}}),
			acr:  "Gold", assert: notMet,
		},
		{
			name: "match any holds on either criterion",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}, AcceptedACR: []string{"gold"}}),
			amr:  []string{"pwd"}, acr: "gold", assert: met,
		},
		{
			name: "match all refuses when one criterion fails",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}, AcceptedACR: []string{"gold"}, Match: oidc.MatchAll}),
			amr:  []string{"mfa"}, acr: "silver", assert: notMet,
		},
		{
			name: "match all holds when every criterion holds",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}, AcceptedACR: []string{"gold"}, Match: oidc.MatchAll}),
			amr:  []string{"pwd", "mfa"}, acr: "gold", assert: met,
		},
		{
			name: "match all skips a criterion with no accepted values",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{"mfa"}, Match: oidc.MatchAll}),
			amr:  []string{"mfa"}, assert: met,
		},
		{
			name: "configured with nothing accepted never meets assurance",
			opts: corp(oidc.Assurance{AcceptedAMR: []string{}, AcceptedACR: []string{}}),
			amr:  []string{"mfa"}, acr: "gold", assert: notMet,
		},
		{
			name: "match all with nothing accepted never meets assurance",
			opts: corp(oidc.Assurance{Match: oidc.MatchAll}),
			amr:  []string{"mfa"}, acr: "gold", assert: notMet,
		},
		{
			name: "a requested acr the provider ignored is not evidence",
			opts: corp(oidc.Assurance{RequestACR: []string{"urn:corp:loa:2"}, AcceptedACR: []string{"urn:corp:loa:2"}}),
			acr:  "urn:corp:loa:1", assert: notMet,
		},
		{
			name:   "an empty asserted acr never matches",
			opts:   corp(oidc.Assurance{AcceptedACR: []string{"gold"}}),
			assert: notMet,
		},
		{
			name: "another provider's configuration does not apply to corp",
			opts: []oidc.ManagerOption{oidc.WithProviderAssurance("partner", oidc.Assurance{AcceptedAMR: []string{"otp"}})},
			amr:  []string{"otp"}, assert: notMet,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := assuranceManager(t, tc.opts...)
			a, ok := oidc.AssuranceForTest(m, "corp")
			require.True(t, ok, "corp is registered")
			tc.assert(t, oidc.MatchAssuranceForTest(a, tc.amr, tc.acr))
		})
	}
}

// TestManagerAssuranceFor pins how a provider's configuration is resolved:
// the default, a consumer's replacement kept as given, and none for a
// provider the registry does not hold.
func TestManagerAssuranceFor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		opts     func() []oidc.ManagerOption
		provider string
		assert   func(t *testing.T, got oidc.Assurance, ok bool)
	}

	cases := []testCase{
		{
			name: "a provider with no option gets the default", provider: "corp",
			assert: func(t *testing.T, got oidc.Assurance, ok bool) {
				require.True(t, ok)
				assert.Equal(t, oidc.Assurance{AcceptedAMR: []string{"mfa"}, Match: oidc.MatchAny}, got)
			},
		},
		{
			name: "a configured empty set stays empty", provider: "corp",
			opts: func() []oidc.ManagerOption {
				return []oidc.ManagerOption{oidc.WithProviderAssurance("corp", oidc.Assurance{})}
			},
			assert: func(t *testing.T, got oidc.Assurance, ok bool) {
				require.True(t, ok)
				assert.Empty(t, got.AcceptedAMR, "the default must not fill a configured empty set")
				assert.Empty(t, got.AcceptedACR)
				assert.Empty(t, got.RequestACR)
			},
		},
		{
			name: "the configuration is the manager's own copy", provider: "corp",
			opts: func() []oidc.ManagerOption {
				amr, acr, req := []string{"hwk"}, []string{"gold"}, []string{"gold"}
				opt := oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: amr, AcceptedACR: acr, RequestACR: req})
				return []oidc.ManagerOption{opt, func(*oidc.Manager) error {
					amr[0], acr[0], req[0] = "changed", "changed", "changed"
					return nil
				}}
			},
			assert: func(t *testing.T, got oidc.Assurance, ok bool) {
				require.True(t, ok)
				assert.Equal(t, []string{"hwk"}, got.AcceptedAMR)
				assert.Equal(t, []string{"gold"}, got.AcceptedACR)
				assert.Equal(t, []string{"gold"}, got.RequestACR)
			},
		},
		{
			name: "the last option for a provider replaces an earlier one", provider: "corp",
			opts: func() []oidc.ManagerOption {
				return []oidc.ManagerOption{
					oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: []string{"hwk"}}),
					oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedACR: []string{"gold"}, Match: oidc.MatchAll}),
				}
			},
			assert: func(t *testing.T, got oidc.Assurance, ok bool) {
				require.True(t, ok)
				assert.Equal(t, oidc.Assurance{AcceptedACR: []string{"gold"}, Match: oidc.MatchAll}, got)
			},
		},
		{
			name: "an unregistered provider has no configuration", provider: "corpp",
			assert: func(t *testing.T, got oidc.Assurance, ok bool) {
				assert.False(t, ok)
				assert.Equal(t, oidc.Assurance{}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []oidc.ManagerOption
			if tc.opts != nil {
				opts = tc.opts()
			}
			got, ok := oidc.AssuranceForTest(assuranceManager(t, opts...), tc.provider)
			tc.assert(t, got, ok)
		})
	}
}
