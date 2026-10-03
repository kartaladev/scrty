package assurance_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/internal/assurance"
)

func TestProof(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		proof  func() assurance.Proof
		assert func(t *testing.T, p assurance.Proof)
	}

	cases := []testCase{
		{
			name:  "the zero value proves nothing",
			proof: func() assurance.Proof { return assurance.Proof{} },
			assert: func(t *testing.T, p assurance.Proof) {
				assert.False(t, p.Holds())
				assert.Empty(t, p.Kind())
				assert.True(t, p.At().IsZero())
			},
		},
		{
			name:  "an empty kind proves nothing",
			proof: func() assurance.Proof { return assurance.New("", at) },
			assert: func(t *testing.T, p assurance.Proof) {
				assert.False(t, p.Holds())
				assert.Equal(t, assurance.Proof{}, p, "an invalid proof is the zero proof")
			},
		},
		{
			name:  "a zero instant proves nothing",
			proof: func() assurance.Proof { return assurance.New(factor.Passkey, time.Time{}) },
			assert: func(t *testing.T, p assurance.Proof) {
				assert.False(t, p.Holds())
				assert.Equal(t, assurance.Proof{}, p, "an invalid proof is the zero proof")
			},
		},
		{
			name:  "a kind and an instant hold",
			proof: func() assurance.Proof { return assurance.New(factor.Passkey, at) },
			assert: func(t *testing.T, p assurance.Proof) {
				assert.True(t, p.Holds())
				assert.Equal(t, factor.Passkey, p.Kind())
				assert.Equal(t, at, p.At())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.proof())
		})
	}
}

func TestFederated(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		evidence func() assurance.Federated
		assert   func(t *testing.T, f assurance.Federated)
	}

	cases := []testCase{
		{
			name:     "the zero value asserts nothing",
			evidence: func() assurance.Federated { return assurance.Federated{} },
			assert: func(t *testing.T, f assurance.Federated) {
				assert.False(t, f.Asserted())
				assert.Empty(t, f.Provider())
				assert.Empty(t, f.Issuer())
				assert.Empty(t, f.AMR())
				assert.Empty(t, f.ACR())
			},
		},
		{
			name: "an empty provider asserts nothing",
			evidence: func() assurance.Federated {
				return assurance.NewFederated("", "https://idp.example", []string{"mfa"}, "gold")
			},
			assert: func(t *testing.T, f assurance.Federated) {
				assert.False(t, f.Asserted())
				assert.Equal(t, assurance.Federated{}, f, "evidence naming no provider is the zero evidence")
			},
		},
		{
			name: "a provider asserts its issuer, amr and acr",
			evidence: func() assurance.Federated {
				return assurance.NewFederated("corp", "https://idp.example", []string{"pwd", "otp"}, "gold")
			},
			assert: func(t *testing.T, f assurance.Federated) {
				assert.True(t, f.Asserted())
				assert.Equal(t, "corp", f.Provider())
				assert.Equal(t, "https://idp.example", f.Issuer())
				assert.Equal(t, []string{"pwd", "otp"}, f.AMR())
				assert.Equal(t, "gold", f.ACR())
			},
		},
		{
			// A login whose provider asserted nothing is still evidence of which
			// provider it came from, so it can be matched and found wanting.
			name: "a provider that asserted no amr or acr is still evidence",
			evidence: func() assurance.Federated {
				return assurance.NewFederated("corp", "https://idp.example", nil, "")
			},
			assert: func(t *testing.T, f assurance.Federated) {
				assert.True(t, f.Asserted())
				assert.Empty(t, f.AMR())
				assert.Empty(t, f.ACR())
			},
		},
		{
			name: "the caller's amr slice is copied in",
			evidence: func() assurance.Federated {
				amr := []string{"mfa"}
				f := assurance.NewFederated("corp", "https://idp.example", amr, "")
				amr[0] = "pwd"

				return f
			},
			assert: func(t *testing.T, f assurance.Federated) {
				assert.Equal(t, []string{"mfa"}, f.AMR(), "the minted evidence changed with the caller's slice")
			},
		},
		{
			name: "the returned amr slice is a copy",
			evidence: func() assurance.Federated {
				f := assurance.NewFederated("corp", "https://idp.example", []string{"mfa"}, "")
				f.AMR()[0] = "pwd"

				return f
			},
			assert: func(t *testing.T, f assurance.Federated) {
				assert.Equal(t, []string{"mfa"}, f.AMR(), "a reader changed the minted evidence")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.evidence())
		})
	}
}
