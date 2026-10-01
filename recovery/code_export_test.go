package recovery

import (
	"context"

	"github.com/kartaladev/scrty/identity"
)

// This file exposes what the package's tests need and consumers must not have.
// It is a test file, so nothing here reaches a production build.

// CodeBytes is the entropy a saved code carries, pinned by the tests.
const CodeBytes = codeBytes

// NewCode exposes the saved-code generator.
var NewCode = newCode

// ParseCode exposes the saved-code parser.
var ParseCode = parseCode

// Check exposes the throttled, write-free check the recovery flow runs before
// anything is spent.
func (c *Codes) Check(ctx context.Context, user identity.UserID, presented string) ([32]byte, error) {
	return c.check(ctx, user, presented)
}

// Spend exposes the conditional spend the recovery flow runs last.
func (c *Codes) Spend(ctx context.Context, user identity.UserID, hash [32]byte) error {
	return c.spend(ctx, user, hash)
}
