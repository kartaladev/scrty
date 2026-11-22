package oidcprovider

import (
	"context"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// unspentUnion is what a grant store reads outstanding families from when the device grant is
// on: the code store's, and the device store's approved and spent records. It is a value, so
// that a second provider built over the same stores joins one equal to the first, as
// GrantStore.UseCodes requires.
type unspentUnion struct {
	codes, devices UnspentCodes
}

var _ UnspentCodes = unspentUnion{}

// UnspentBySignIn implements UnspentCodes: the code store's families, then the device
// store's. Either failing fails the call with no partial answer, so a grant store records
// nothing it would have to report again. A nil device side answers the code side alone.
func (u unspentUnion) UnspentBySignIn(ctx context.Context, sel SignInSelector, includeOffline bool) ([]id.ID, error) {
	return u.join(
		func(c UnspentCodes) ([]id.ID, error) { return c.UnspentBySignIn(ctx, sel, includeOffline) },
	)
}

// UnspentByClient implements UnspentCodes, as UnspentBySignIn does.
func (u unspentUnion) UnspentByClient(ctx context.Context, user identity.UserID, clientID string) ([]id.ID, error) {
	return u.join(
		func(c UnspentCodes) ([]id.ID, error) { return c.UnspentByClient(ctx, user, clientID) },
	)
}

// join asks each side in turn and concatenates the answers.
func (u unspentUnion) join(ask func(UnspentCodes) ([]id.ID, error)) ([]id.ID, error) {
	codes, err := ask(u.codes)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: reading outstanding codes: %w", err)
	}
	if u.devices == nil {
		return slices.Clone(codes), nil
	}
	devices, err := ask(u.devices)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: reading approved device authorizations: %w", err)
	}

	// A new slice, so that no answer a store still holds is written into.
	return slices.Concat(codes, devices), nil
}

// endsWithSignIn is the one rule that decides whether a grant, a code or a device approval
// ends with its sign-in: when tied to it (EndsWithSignIn), or when it holds neither
// offline_access (Offline) nor the device grant's SurvivesSignInEnd. Tied wins over both. A
// code's grant never has SurvivesSignInEnd, so for it this is !Offline || EndsWithSignIn.
func endsWithSignIn(offline, tied, survives bool) bool {
	return tied || (!offline && !survives)
}
