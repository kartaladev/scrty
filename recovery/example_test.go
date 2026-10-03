package recovery_test

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
)

// exampleUsers is the smallest identity.UserLoader the examples in this file
// need: one user, found by username or ID alike.
type exampleUsers struct{ details *identity.Details }

func (u exampleUsers) LoadByUsername(_ context.Context, username string) (*identity.Details, error) {
	if username != u.details.Username {
		return nil, identity.ErrUserNotFound
	}

	return u.details, nil
}

func (u exampleUsers) LoadByUserID(_ context.Context, id identity.UserID) (*identity.Details, error) {
	if id != u.details.ID {
		return nil, identity.ErrUserNotFound
	}

	return u.details, nil
}

// ExampleMFAEnrolments registers TOTP as a recovery's MFA reset kind. A
// completed recovery removes every enrolment MFAEnrolments lists for the
// user, except one the recovery itself proved possession of; the resulting
// AuthenticatorKind is what WithAuthenticatorKinds registers.
func ExampleMFAEnrolments() {
	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Co")
	if err != nil {
		panic(err)
	}

	kind, err := recovery.MFAEnrolments(totp)
	if err != nil {
		panic(err)
	}

	fmt.Println(kind.Kind())

	// Output: mfa
}

// ExampleNewWayBackCheck asks whether a user has another way back into their
// account before letting them go without saved recovery codes, the check
// passkey-authentication calls at registration. Holding a set of saved codes
// is itself a way back in, so the check answers true once the user has
// generated one.
func ExampleNewWayBackCheck() {
	ctx := context.Background()

	users := exampleUsers{details: &identity.Details{
		ID: "u-1", Username: "grace@example.com", Active: true,
	}}

	codes, err := recovery.NewCodes()
	if err != nil {
		panic(err)
	}

	check, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
		Users: users,
		Codes: codes,
	})
	if err != nil {
		panic(err)
	}

	before, err := check.HasWayBack(ctx, users.details.ID)
	if err != nil {
		panic(err)
	}

	if _, err := codes.Generate(ctx, users.details.ID); err != nil {
		panic(err)
	}

	after, err := check.HasWayBack(ctx, users.details.ID)
	if err != nil {
		panic(err)
	}

	fmt.Println(before, after)

	// Output: false true
}

// ExampleWayBackDeps_admits counts a linked OIDC login as a way back into the
// account only when the requirement policy would admit that login without a
// local second factor. Without Admits a linked OIDC identity never counts,
// since an OIDC login is no longer exempt from the second factor by its kind.
// Wiring the policy's own answer keeps the check and the login from
// disagreeing: it says yes in FederatedAssuranceExempt mode, for a kind the
// exemption rule marks, and for a user who is not required to use a second
// factor.
//
// The answer is the requirement policy's alone. A consumer who also sets
// policy.WithFederatedChallengeWhenUnmet(true) on the second-factor challenge
// policy has a policy that can still challenge an enrolled user's OIDC login
// this answer admits, and wires an Admits that answers false for such users.
func ExampleWayBackDeps_admits() {
	ctx := context.Background()

	users := exampleUsers{details: &identity.Details{
		ID: "u-1", Username: "grace@example.com", Active: true,
	}}

	codes, err := recovery.NewCodes()
	if err != nil {
		panic(err)
	}

	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Co")
	if err != nil {
		panic(err)
	}

	lookups, err := mfa.LookupsFor(totp)
	if err != nil {
		panic(err)
	}

	requirement, err := policy.NewMFARequirementPolicy(nil, lookups,
		policy.WithMFARequiredForAll(),
		policy.WithFederatedAssurance(policy.FederatedAssuranceExempt),
	)
	if err != nil {
		panic(err)
	}

	deps := recovery.WayBackDeps{
		Users: users,
		Codes: codes,
		LinkedLogins: func(context.Context, identity.UserID) ([]factor.Kind, error) {
			return []factor.Kind{factor.OIDC}, nil
		},
	}

	without, err := recovery.NewWayBackCheck(deps)
	if err != nil {
		panic(err)
	}

	deps.Admits = requirement.(policy.LoginAdmission).AdmitsWithoutLocalSecondFactor

	with, err := recovery.NewWayBackCheck(deps)
	if err != nil {
		panic(err)
	}

	before, err := without.HasWayBack(ctx, users.details.ID)
	if err != nil {
		panic(err)
	}

	after, err := with.HasWayBack(ctx, users.details.ID)
	if err != nil {
		panic(err)
	}

	fmt.Println(before, after)

	// Output: false true
}
