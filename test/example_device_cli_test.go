package test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// Example_deviceCLI is the device grant as a command-line client drives it, with
// golang.org/x/oauth2: Config.DeviceAuth asks the provider for a device code and a user
// code, the program shows the user code, and Config.DeviceAccessToken polls the token
// endpoint until the user has answered on another device. The README's "CLI clients"
// section holds this code, so keep the two in step.
//
// It makes no call when the package's tests run: the example has no output comment, so it
// is compiled and never run.
func Example_deviceCLI() {
	const issuer = "https://id.example.com"

	conf := &oauth2.Config{
		ClientID: "acme-cli", // a public client: no secret
		Scopes:   []string{"openid", "offline_access"},
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: issuer + "/oauth2/device-authorization",
			TokenURL:      issuer + "/oauth2/token",
		},
	}

	// A deadline of its own: polling stops when the authorization expires, and no later
	// than this.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	da, err := conf.DeviceAuth(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Show the page and the code, and ask the user to check that the code matches. Do not
	// open VerificationURIComplete (it is empty unless the client was registered with
	// DeviceCompleteURI) or fill the code in for the user.
	fmt.Printf("Open %s and enter the code %s\n", da.VerificationURI, da.UserCode)

	// DeviceAccessToken polls at da.Interval and obeys slow_down. It returns when the user
	// approves, or with an error when the user denies or the code expires.
	token, err := conf.DeviceAccessToken(ctx, da)
	if err != nil {
		log.Fatal(err)
	}

	// The refresh token (offline_access) keeps the CLI signed in. TokenSource refreshes it.
	client := conf.Client(ctx, token)
	res, err := client.Get(issuer + "/oauth2/userinfo")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	fmt.Println(res.StatusCode == http.StatusOK)
}
