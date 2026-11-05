package oidcprovider_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

func TestSignInSelector_Validate(t *testing.T) {
	t.Parallel()

	family := id.MustParse("01926a4e-0000-7000-8000-000000000001")
	other := id.MustParse("01926a4e-0000-7000-8000-000000000002")
	const (
		user    = "user-secret-value"
		issuer  = "https://idp.example.com/value"
		session = "session-value"
	)

	valid := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}
	invalid := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrConfig)
		assert.NotContains(t, err.Error(), user, "the text repeats no value")
		assert.NotContains(t, err.Error(), issuer, "the text repeats no value")
		assert.NotContains(t, err.Error(), session, "the text repeats no value")
		assert.NotContains(t, err.Error(), family.String(), "the text repeats no value")
	}

	cases := []struct {
		name   string
		sel    oidcprovider.SignInSelector
		assert func(t *testing.T, err error)
	}{
		{name: "family", sel: oidcprovider.SignInSelector{Family: family}, assert: valid},
		{name: "user", sel: oidcprovider.SignInSelector{User: user}, assert: valid},
		{name: "user except a family", sel: oidcprovider.SignInSelector{User: user, ExceptFamily: other}, assert: valid},
		{name: "upstream issuer and session", sel: oidcprovider.SignInSelector{ExternalIssuer: issuer, ExternalSessionID: session}, assert: valid},
		{name: "user and upstream issuer", sel: oidcprovider.SignInSelector{User: user, ExternalIssuer: issuer}, assert: valid},

		{name: "empty", sel: oidcprovider.SignInSelector{}, assert: invalid},
		{name: "family and user", sel: oidcprovider.SignInSelector{Family: family, User: user}, assert: invalid},
		{name: "family and except", sel: oidcprovider.SignInSelector{Family: family, ExceptFamily: other}, assert: invalid},
		{name: "family and issuer", sel: oidcprovider.SignInSelector{Family: family, ExternalIssuer: issuer}, assert: invalid},
		{name: "family and session", sel: oidcprovider.SignInSelector{Family: family, ExternalSessionID: session}, assert: invalid},
		{name: "except alone", sel: oidcprovider.SignInSelector{ExceptFamily: other}, assert: invalid},
		{name: "issuer alone", sel: oidcprovider.SignInSelector{ExternalIssuer: issuer}, assert: invalid},
		{name: "session alone", sel: oidcprovider.SignInSelector{ExternalSessionID: session}, assert: invalid},
		{name: "user and session", sel: oidcprovider.SignInSelector{User: user, ExternalSessionID: session}, assert: invalid},
		{name: "user, issuer and session", sel: oidcprovider.SignInSelector{User: user, ExternalIssuer: issuer, ExternalSessionID: session}, assert: invalid},
		{name: "user, except and issuer", sel: oidcprovider.SignInSelector{User: user, ExceptFamily: other, ExternalIssuer: issuer}, assert: invalid},
		{name: "user, except and session", sel: oidcprovider.SignInSelector{User: user, ExceptFamily: other, ExternalSessionID: session}, assert: invalid},
		{name: "except, issuer and session", sel: oidcprovider.SignInSelector{ExceptFamily: other, ExternalIssuer: issuer, ExternalSessionID: session}, assert: invalid},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.sel.Validate())
		})
	}
}
