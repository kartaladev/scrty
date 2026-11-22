package oidcprovider_test

import (
	"context"
	"fmt"
	"log"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/token/signingkey"
)

// exampleUsers stands in for the application's user store, which the provider asks only
// when a token is issued. This example issues none.
type exampleUsers struct{ identity.UserLoader }

// ExampleWithDeviceAuthorization enables the device authorization grant (RFC 8628) and
// registers a command-line client for it. The grant is off by default, and a client can
// list GrantDeviceCode only on a provider that enabled it. The option names the page where a
// user types the code the device shows: it is the application's own, on the issuer's origin.
//
// The client is public and native, and has only the device grant, so it needs no redirect
// URI and no secret. It asks for neither verification_uri_complete (DeviceCompleteURI is
// off) nor a grant that outlives its sign-in (DeviceGrantsOutliveSignIn is off).
//
// The provider keeps device authorizations in memory and draws its user-code key at start.
// A provider over a durable store (WithDeviceAuthorizationStore) must also be given a key
// shared by every replica, with WithUserCodeKey.
func ExampleWithDeviceAuthorization() {
	const issuer = "https://id.example.com"

	keys, err := signingkey.New(context.Background(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	if err != nil {
		log.Fatal(err)
	}

	provider, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: issuer,
		Clients: []oidcprovider.Client{{
			ID:              "acme-cli",
			Name:            "Acme CLI",
			Type:            oidcprovider.Public,
			ApplicationType: oidcprovider.Native,
			GrantTypes:      []oidcprovider.GrantType{oidcprovider.GrantDeviceCode},
			Scopes:          []string{"openid"},
		}},
		Keys:         keys,
		Users:        exampleUsers{},
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	}, oidcprovider.WithDeviceAuthorization(issuer+"/activate"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(provider.DeviceEnabled())
	// Output: true
}
