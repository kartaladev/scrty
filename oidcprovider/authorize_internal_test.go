// These tests are white-box, in package oidcprovider: namesAlgorithm's equality
// with the key's algorithm is not observable alone through the public path, where
// the JOSE stack's own algorithm match refuses the same hint.
package oidcprovider

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

func TestNamesAlgorithm(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		header func(t *testing.T) jws.Headers
		assert func(t *testing.T, named bool)
	}

	withAlg := func(alg jwa.SignatureAlgorithm) func(t *testing.T) jws.Headers {
		return func(t *testing.T) jws.Headers {
			t.Helper()

			h := jws.NewHeaders()
			require.NoError(t, h.Set(jws.AlgorithmKey, alg))

			return h
		}
	}

	cases := []testCase{
		{
			name:   "an algorithm equal to the key's is named",
			header: withAlg(jwa.RS256()),
			assert: func(t *testing.T, named bool) { t.Helper(); require.True(t, named) },
		},
		{
			name:   "an algorithm differing from the key's is refused",
			header: withAlg(jwa.RS384()),
			assert: func(t *testing.T, named bool) { t.Helper(); require.False(t, named) },
		},
		{
			name:   "a header with no alg is refused",
			header: func(t *testing.T) jws.Headers { t.Helper(); return jws.NewHeaders() },
			assert: func(t *testing.T, named bool) { t.Helper(); require.False(t, named) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, namesAlgorithm(tc.header(t), jwa.RS256()))
		})
	}
}
