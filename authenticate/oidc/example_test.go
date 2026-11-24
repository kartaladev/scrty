package oidc_test

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
)

// exampleUsers is a user loader that finds nobody. The examples in this file
// build managers and never log anyone in, so it is never asked.
type exampleUsers struct{}

func (exampleUsers) LoadByUsername(context.Context, string) (*identity.Details, error) {
	return nil, identity.ErrUserNotFound
}

func (exampleUsers) LoadByUserID(context.Context, identity.UserID) (*identity.Details, error) {
	return nil, identity.ErrUserNotFound
}

// ExampleWithProviderAssurance states which values a provider's ID token must
// assert for a login to count as having used a second factor at the provider.
// The configuration replaces the default (the amr value "mfa" alone) as a
// whole. RequestACR is sent to the provider as acr_values: a request the
// provider may ignore, never evidence, so only AcceptedACR is ever matched
// against the token.
func ExampleWithProviderAssurance() {
	users := exampleUsers{}

	registry, err := oidc.NewRegistry(oidc.Provider{ //nolint:gosec // G101: a placeholder secret in an example, not a credential
		Name:         "corp",
		Issuer:       "https://idp.example.com",
		ClientID:     "scrty",
		ClientSecret: "corp-client-secret",
		RedirectURL:  "https://app.example.com/sso/callback/corp",
	})
	if err != nil {
		panic(err)
	}

	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), users)
	if err != nil {
		panic(err)
	}

	manager, err := oidc.NewRelyingParty(registry, broker,
		oidc.WithProviderAssurance("corp", oidc.Assurance{
			AcceptedAMR: []string{"mfa", "hwk"},
			AcceptedACR: []string{"gold"},
			RequestACR:  []string{"gold"},
			Match:       oidc.AssuranceMatchAny,
		}),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(manager != nil)

	// A configuration for a provider that is not registered fails at
	// construction, not at the first login.
	_, err = oidc.NewRelyingParty(registry, broker,
		oidc.WithProviderAssurance("elsewhere", oidc.Assurance{AcceptedAMR: []string{"mfa"}}),
	)
	fmt.Println(errors.Is(err, oidc.ErrConfig))

	// Output:
	// true
	// true
}

// adminsNeedAHardwareKey is an oidc.AssuranceEvaluator: a rule the
// per-provider configuration cannot state, because it depends on the user.
type adminsNeedAHardwareKey struct{ admins []identity.UserID }

func (e adminsNeedAHardwareKey) MeetsAssurance(_ context.Context, in oidc.AssuranceInput) (bool, error) {
	if slices.Contains(e.admins, in.User) {
		return slices.Contains(in.AMR, "hwk"), nil
	}

	return slices.Contains(in.AMR, "mfa"), nil
}

// ExampleWithAssuranceEvaluator replaces the matching of asserted values with
// a rule of the application's own. The library still reads the values from
// the verified ID token alone; the evaluator only decides what they are worth.
// It runs on every request of a federated session, so it must be fast and free
// of side effects, and an error it returns denies.
func ExampleWithAssuranceEvaluator() {
	users := exampleUsers{}

	registry, err := oidc.NewRegistry(oidc.Provider{ //nolint:gosec // G101: a placeholder secret in an example, not a credential
		Name:         "corp",
		Issuer:       "https://idp.example.com",
		ClientID:     "scrty",
		ClientSecret: "corp-client-secret",
		RedirectURL:  "https://app.example.com/sso/callback/corp",
	})
	if err != nil {
		panic(err)
	}

	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), users)
	if err != nil {
		panic(err)
	}

	evaluator := adminsNeedAHardwareKey{admins: []identity.UserID{"root"}}

	manager, err := oidc.NewRelyingParty(registry, broker, oidc.WithAssuranceEvaluator(evaluator))
	if err != nil {
		panic(err)
	}

	fmt.Println(manager != nil)

	// The evaluator is an ordinary value, so the rule is testable on its own.
	ctx := context.Background()

	admin, _ := evaluator.MeetsAssurance(ctx, oidc.AssuranceInput{User: "root", AMR: []string{"mfa"}})
	ada, _ := evaluator.MeetsAssurance(ctx, oidc.AssuranceInput{User: "ada", AMR: []string{"mfa"}})
	fmt.Println(admin, ada)

	// Output:
	// true
	// false true
}

// departmentBroker resolves users by the department their provider's UserInfo
// states. It implements oidc.UpstreamBroker and accepts upstream access for
// corp, so a callback through corp hands it the upstream access; a callback
// through any other provider calls Broker.
type departmentBroker struct{}

func (departmentBroker) Broker(context.Context, oidc.ExternalIdentity) (*identity.Principal, error) {
	return nil, oidc.ErrNoLinkedAccount
}

// AcceptsUpstream asks for upstream access on corp's logins only; any other
// provider's are brokered by Broker.
func (departmentBroker) AcceptsUpstream(provider string) bool { return provider == "corp" }

func (departmentBroker) BrokerUpstream(ctx context.Context, ext oidc.ExternalIdentity, up oidc.Upstream) (*identity.Principal, error) {
	members, err := up.UserInfo(ctx)
	if err != nil {
		// ErrUserInfoFailed: no access token, no endpoint, or an unusable
		// answer. Its text holds neither the token nor the answer.
		return nil, fmt.Errorf("department lookup: %w", err)
	}
	dept, _ := members["department"].(string)
	return &identity.Principal{ID: identity.UserID(ext.Subject), Username: dept + "/" + ext.Subject}, nil
}

// ExampleUpstream_UserInfo shows a broker that asks for upstream access and
// fetches UserInfo. The upstream access prints as "[redacted]" under every
// verb, so it is safe in a log line; a token response without an access token
// still logs the user in, and only UserInfo fails.
func ExampleUpstream_UserInfo() {
	var broker oidc.IdentityBroker = departmentBroker{}
	upstream, ok := broker.(oidc.UpstreamBroker)
	fmt.Println("asks for upstream access:", ok)

	// What a callback hands the broker when the token response carried no
	// access token.
	var up oidc.Upstream
	fmt.Println("has access token:", up.HasAccessToken())
	fmt.Printf("printed: %v %+v %#v\n", up, up, up)

	_, err := upstream.BrokerUpstream(context.Background(), oidc.ExternalIdentity{Provider: "corp", Subject: "s-1"}, up)
	fmt.Println("userinfo failed:", errors.Is(err, oidc.ErrUserInfoFailed))
	// Output:
	// asks for upstream access: true
	// has access token: false
	// printed: [redacted] [redacted] [redacted]
	// userinfo failed: true
}

// ExampleWithBrokerSignInHook shows an adoption hook: on a user's first
// sign-in through the corp provider it finds the account imported earlier by
// the email UserInfo reports, and on later sign-ins it keeps the linked user.
// Its writes, here a profile refresh, sit in Apply, which the broker runs only
// once it has accepted the decision and linked the identity.
func ExampleWithBrokerSignInHook() {
	accounts := importedAccounts{"alice@corp.example": "u-7"}

	hook := func(ctx context.Context, ext oidc.ExternalIdentity, up oidc.Upstream, linked identity.UserID) (oidc.SignInDecision, error) {
		user := linked // the identity's link decides, once it has one
		if user == "" {
			// Match by email only when the provider verified it.
			if !ext.EmailVerified {
				return oidc.SignInDecision{}, oidc.ErrNoLinkedAccount
			}
			var ok bool
			if user, ok = accounts[ext.Email]; !ok {
				return oidc.SignInDecision{}, oidc.ErrNoLinkedAccount
			}
		}
		info, err := up.UserInfo(ctx)
		if err != nil {
			return oidc.SignInDecision{}, err // a broker failure; the login fails
		}
		return oidc.SignInDecision{
			User: user,
			// Writes for the decided user only, and safe to repeat.
			Apply: func(ctx context.Context) error {
				return accounts.refreshProfile(ctx, user, info)
			},
		}, nil
	}

	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), accounts,
		oidc.WithBrokerSignInHook("corp", hook))
	if err != nil {
		panic(err)
	}
	_ = broker // given to oidc.NewRelyingParty, which calls BrokerUpstream
}

// importedAccounts is a consumer's user store: user references by email.
type importedAccounts map[string]identity.UserID

func (a importedAccounts) LoadByUserID(_ context.Context, user identity.UserID) (*identity.Details, error) {
	for email, ref := range a {
		if ref == user {
			return &identity.Details{ID: ref, Username: email, Active: true}, nil
		}
	}
	return nil, identity.ErrUserNotFound
}

func (a importedAccounts) LoadByUsername(ctx context.Context, username string) (*identity.Details, error) {
	if ref, ok := a[username]; ok {
		return a.LoadByUserID(ctx, ref)
	}
	return nil, identity.ErrUserNotFound
}

func (a importedAccounts) refreshProfile(context.Context, identity.UserID, map[string]any) error {
	return nil
}
