package oidc_test

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
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
		RedirectURL:  "https://app.example.com/login/oauth2/callback/corp",
	})
	if err != nil {
		panic(err)
	}

	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), users)
	if err != nil {
		panic(err)
	}

	manager, err := oidc.NewManager(registry, broker,
		oidc.WithProviderAssurance("corp", oidc.Assurance{
			AcceptedAMR: []string{"mfa", "hwk"},
			AcceptedACR: []string{"gold"},
			RequestACR:  []string{"gold"},
			Match:       oidc.MatchAny,
		}),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(manager != nil)

	// A configuration for a provider that is not registered fails at
	// construction, not at the first login.
	_, err = oidc.NewManager(registry, broker,
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
		RedirectURL:  "https://app.example.com/login/oauth2/callback/corp",
	})
	if err != nil {
		panic(err)
	}

	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), users)
	if err != nil {
		panic(err)
	}

	evaluator := adminsNeedAHardwareKey{admins: []identity.UserID{"root"}}

	manager, err := oidc.NewManager(registry, broker, oidc.WithAssuranceEvaluator(evaluator))
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
