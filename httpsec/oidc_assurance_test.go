package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

func TestWithOIDCSignInAssurance_Refusals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []httpsec.OIDCProviderOption
		says string
	}

	fn := func(*session.Session) ([]string, string) { return nil, "" }

	cases := []testCase{
		{
			name: "a nil function is refused",
			opts: []httpsec.OIDCProviderOption{httpsec.WithOIDCSignInAssurance(nil)},
			says: "WithOIDCSignInAssurance",
		},
		{
			name: "given twice is refused",
			opts: []httpsec.OIDCProviderOption{httpsec.WithOIDCSignInAssurance(fn), httpsec.WithOIDCSignInAssurance(fn)},
			says: "WithOIDCSignInAssurance",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := &opFixture{keys: tokenKeys()}
			p := f.provider(t)

			_, err := httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p, tc.opts...))...)
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.ErrorContains(t, err, tc.says)
		})
	}
}
