package authenticate_test

import (
	"errors"
	"testing"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// principal returns the resolved caller a delegate reports on success.
func principal(t *testing.T) *identity.Principal {
	t.Helper()

	return &identity.Principal{ID: identity.UserID("u1"), Username: "ada"}
}

// errBackendDown stands for a failure of something a delegate depends on,
// rather than a decision about the caller. The manager must pass it through
// unchanged so a caller can tell an outage from a refusal.
var errBackendDown = errors.New("the user store is unreachable")

// presentedToken stands for a compact JWS a caller presents. Nothing here
// parses it: the verifier is the only thing that reads a token.
const presentedToken = "header.payload.signature"

// tokenID is the identifier a verified token carries as jti, in the canonical
// layout a consumer's own records would key on.
var tokenID = id.MustParse("0192f3a4-5b6c-7d8e-9f01-fedcba987654")

// storedPassword is the password the known users in these cases actually have.
const storedPassword = "correct-horse-battery-staple"

// errNoIdentifier stands for a generator that cannot mint an identifier, such
// as one backed by a counter service that is unreachable.
var errNoIdentifier = errors.New("the identifier generator is unavailable")
