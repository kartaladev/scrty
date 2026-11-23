package authorize_test

import (
	"context"

	"github.com/kartaladev/scrty/authorize"
)

// inspectingAuthorizer is a consumer's authorizer that also implements
// authorize.PrivilegeInspector, as one that answers or declines bulk checks in
// a FirstOf does. It lives in a test file because the production API names the
// two interfaces separately; the methods are spelled out so mockgen's source
// mode can write them. Their types are local aliases: mockgen's source mode
// reads this file as the authorize package itself and would otherwise drop the
// authorize qualifier.
//
//go:generate mockgen -source=inspect_ports_test.go -destination=inspector_mock_test.go -package=authorize_test -typed -mock_names=inspectingAuthorizer=MockInspectingAuthorizer
type inspectingAuthorizer interface {
	Authorize(ctx context.Context, attrs attributes) error
	InspectPrivileges(ctx context.Context, group, resource string, names []string) (holdings, error)
}

type (
	attributes = authorize.Attributes
	holdings   = authorize.Holdings
)

var (
	_ authorize.Authorizer         = inspectingAuthorizer(nil)
	_ authorize.PrivilegeInspector = inspectingAuthorizer(nil)
)
