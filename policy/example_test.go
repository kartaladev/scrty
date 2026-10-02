package policy_test

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/policy"
)

// exampleUsers is a user loader that finds nobody. The examples in this file
// never log anyone in, so it is never asked.
type exampleUsers struct{}

func (exampleUsers) LoadByUsername(context.Context, string) (*identity.Details, error) {
	return nil, identity.ErrUserNotFound
}

func (exampleUsers) LoadByUserID(context.Context, identity.UserID) (*identity.Details, error) {
	return nil, identity.ErrUserNotFound
}

// exampleManager is the OIDC manager the examples use as the source of
// provider assurance. It implements policy.FederatedAssuranceSource.
func exampleManager() *oidc.Manager {
	registry, err := oidc.NewRegistry(oidc.Provider{
		Name:         "corp",
		Issuer:       "https://idp.example.com",
		ClientID:     "scrty",
		ClientSecret: "corp-client-secret",
		RedirectURL:  "https://app.example.com/login/oauth2/callback/corp",
	})
	if err != nil {
		panic(err)
	}

	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), exampleUsers{})
	if err != nil {
		panic(err)
	}

	manager, err := oidc.NewManager(registry, broker)
	if err != nil {
		panic(err)
	}

	return manager
}

// ExampleWithFederatedAssurance chooses what the requirement policy does with
// a required user's OIDC login whose provider did not assert a second factor.
// The default, FederatedAssuranceChallenge, challenges for the library's own
// second factor. FederatedAssuranceRefuse refuses the login. FederatedAssuranceExempt
// lets it in on the provider's word alone, whatever the provider asserted: it
// is a bypass of the requirement for OIDC logins, so choose it only when the
// provider is the sole authority for the second factor and you accept that a
// provider that does not enforce one lets required users in without any.
//
// The policy answers, ahead of any login, whether an OIDC login would be
// admitted without a local second factor. Only Exempt admits it: provider
// assurance is known at a login, never before.
func ExampleWithFederatedAssurance() {
	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Co")
	if err != nil {
		panic(err)
	}

	lookups, err := mfa.LookupsFor(totp)
	if err != nil {
		panic(err)
	}

	manager := exampleManager()
	ctx := context.Background()

	for _, mode := range []policy.FederatedAssuranceMode{
		policy.FederatedAssuranceChallenge,
		policy.FederatedAssuranceRefuse,
		policy.FederatedAssuranceExempt,
	} {
		source := policy.WithFederatedAssuranceSource(manager)

		requirement, err := policy.NewMFARequirementPolicy(nil, lookups,
			policy.WithMFARequiredForAll(),
			policy.WithFederatedAssurance(mode),
			source,
		)
		if err != nil {
			panic(err)
		}

		admits, err := requirement.(policy.LoginAdmission).
			AdmitsWithoutLocalSecondFactor(ctx, "u-1", factor.OIDC)
		if err != nil {
			panic(err)
		}

		fmt.Println(mode, admits)
	}

	// Output:
	// FederatedAssuranceChallenge false
	// FederatedAssuranceRefuse false
	// FederatedAssuranceExempt true
}

// ExampleWithFederatedChallengeWhenUnmet makes the second-factor challenge
// policy challenge an enrolled user's OIDC login when the provider's
// assurance is not met. By default that policy allows OIDC logins, because the
// requirement policy is the one that governs required users. The option needs
// the source of provider assurance and is refused at construction without it.
func ExampleWithFederatedChallengeWhenUnmet() {
	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Co")
	if err != nil {
		panic(err)
	}

	lookups, err := mfa.LookupsFor(totp)
	if err != nil {
		panic(err)
	}

	_, err = policy.NewMFAPolicy(lookups, policy.WithFederatedChallengeWhenUnmet(true))
	fmt.Println(err != nil)

	_, err = policy.NewMFAPolicy(lookups,
		policy.WithFederatedChallengeWhenUnmet(true),
		policy.WithFederatedAssuranceSource(exampleManager()),
	)
	fmt.Println(err)

	// Output:
	// true
	// <nil>
}
