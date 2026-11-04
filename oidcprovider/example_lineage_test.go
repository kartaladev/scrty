//go:build oplineage_negative

package oidcprovider_test

import (
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

// This file exists to fail to compile. It is kept out of the build by its tag, and
// TestRefreshTokenStore_CannotBeBuiltOutsideScrty runs go vet with the tag on and reads
// the refusal: the one way a caller could try to fill a RefreshTokenStore from a
// session.Store is a field the compiler does not let it name.
var _ = func(s session.Store) oidcprovider.RefreshTokenStore {
	return oidcprovider.RefreshTokenStore{sessions: s}
}
