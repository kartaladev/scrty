package authenticate

import (
	"context"

	"github.com/kartaladev/scrty/identity"
)

// DecoyVerifier spends the password work a real verification would, on a
// refusal made before any password was checked. It reports nothing about the
// outcome; handled says only whether creds are of a kind it verifies, so a
// Manager can find the right delegate without calling Authenticate.
//
// It is optional: an Authenticator that does not implement it simply cannot
// spend a decoy, and a caller that needs the work to be indistinguishable from
// a real verification may warn that its authenticator offers none.
type DecoyVerifier interface {
	VerifyDecoy(ctx context.Context, creds identity.Credentials) (handled bool)
}
