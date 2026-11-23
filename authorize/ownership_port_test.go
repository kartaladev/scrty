package authorize_test

import (
	"context"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// ownershipPort is the pair of functions an OwnershipAttributes carries, as an
// interface, so a test can hand them a typed gomock double and assert exactly
// which were called. It lives in a test file because the production API takes
// plain functions: a consumer's ownership check is two closures, not a type.
//
//go:generate mockgen -source=ownership_port_test.go -destination=ownership_mock_test.go -package=authorize_test -typed -mock_names=ownershipPort=MockOwnership
type ownershipPort interface {
	ResolveID(ctx context.Context) (string, error)
	OwnedBy(ctx context.Context, subject *identity.Principal, id string) (bool, error)
}

// ownedBy returns ownership attributes for crm/lead whose functions are port's.
func ownedBy(port ownershipPort) authorize.OwnershipAttributes {
	return authorize.OwnershipAttributes{
		Group:     "crm",
		Resource:  "lead",
		ResolveID: port.ResolveID,
		OwnedBy:   port.OwnedBy,
	}
}
