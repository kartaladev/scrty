package recovery_test

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
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
