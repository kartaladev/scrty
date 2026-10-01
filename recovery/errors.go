package recovery

import (
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/ratelimit"
)

// ErrConfig is wrapped by every error this package's constructors return for a
// wiring mistake, so a consumer can tell a contradictory configuration from a
// runtime failure without matching on message text.
var ErrConfig = errors.New("recovery: invalid configuration")

// ErrRefused is the refusal of a presented proof: a code that is malformed,
// unknown, already spent or another user's. The causes are deliberately one
// error, so a caller learns that the proof is not good and nothing more.
//
// It wraps authenticate.ErrAuthenticationFailed, so every caller that already
// answers a failed authentication answers a refused recovery the same way.
var ErrRefused = fmt.Errorf("recovery: refused: %w", authenticate.ErrAuthenticationFailed)

// ErrCodeThrottled is the refusal of a saved-code presentation for a user at
// the presentation limit, or when the limiter could not say whether the user
// is. The code is not looked up.
//
// It wraps ratelimit.ErrThrottled, so a caller that already answers a
// throttled source answers it the same way.
var ErrCodeThrottled = fmt.Errorf("recovery: saved-code presentations throttled: %w", ratelimit.ErrThrottled)

// ErrMalformed is the refusal of a recovery request that cannot be acted on as
// sent: a proof of the wrong shape, a kind that is not enabled, or a reported
// loss of an authenticator the user does not hold. It is also what
// ParseAuthenticatorRef returns for text that is not a "kind:id" reference.
//
// It is the caller's mistake rather than a failed proof, so it is answered as a
// bad request, and nothing is spent before it is returned.
var ErrMalformed = errors.New("recovery: malformed recovery")

// ErrNotYetCompletable is the refusal of a finish presented before the hold
// on its recovery has ended. Nothing is spent: the completion token stays
// usable, and the same finish succeeds once the hold is over.
var ErrNotYetCompletable = errors.New("recovery: not yet completable")

// ErrCooldown is the refusal of a request to a route the consumer marked as
// sensitive, from a session whose user completed an account recovery within
// the cool-down window. The caller is authenticated and is refused an action,
// not a credential, so it is answered as forbidden.
var ErrCooldown = errors.New("recovery: refused during the recovery cool-down")

// ErrReauthenticationRequired is the refusal of a saved-code regeneration from
// a session whose latest authentication is older than the freshness window.
// The caller must authenticate again before a new set is issued; the existing
// set is left unchanged.
var ErrReauthenticationRequired = errors.New("recovery: reauthentication required")
