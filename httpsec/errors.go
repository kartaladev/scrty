package httpsec

import (
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// The refusals this package defines itself. Every other refusal a consumer
// sees comes from the core that decided it — authenticate, authorize, policy
// or session — and this package neither restates nor renames those.
var (
	// ErrAuthenticationRequired refuses a request that presented nothing to
	// authenticate with, or whose session no longer exists, expired, or could
	// not be read. It is deliberately the same refusal in all of those cases:
	// telling them apart would say whether a session ever existed.
	//
	// authorize exports a refusal of the same name for an anonymous request
	// that matched a rule requiring authentication. The authorization stage
	// wraps that one with this, so a consumer matching either identity reaches
	// both and does not have to know which stage refused.
	ErrAuthenticationRequired = errors.New("httpsec: authentication required")

	// ErrCredentialsMissing refuses a login that carried no credentials, or a
	// JSON body that could not be decoded. It is the client's mistake, so it
	// maps to 400, and it says nothing about the account.
	ErrCredentialsMissing = errors.New("httpsec: missing or unreadable login credentials")

	// ErrRequestTooLarge refuses a body over the configured bound before it is
	// parsed.
	ErrRequestTooLarge = errors.New("httpsec: request too large")
)

// ChallengeError refuses a request that must satisfy a challenge before it
// goes further.
//
// It carries what the consumer's error handling needs to prompt for: the kind
// asked for, the pending session when one was established, and the token
// issued alongside it when the challenge was raised at login. Its text names
// only the kind — a challenge is reported to a client, and a token or a
// session handle written into an error string reaches every log that records
// one.
type ChallengeError struct {
	// Kind is what the caller is being asked for.
	Kind policy.ChallengeKind

	// Session is the pending session the caller answers the challenge on, and
	// is nil for a stateless first factor that established none.
	Session *session.Session

	// Token is the access token issued alongside the pending session, and is
	// empty unless one was issued when the challenge was raised.
	Token string
}

// Error names the challenge kind and nothing else. The session handle and the
// token are fields, not text.
func (e *ChallengeError) Error() string {
	return fmt.Sprintf("httpsec: challenge required: %s", e.Kind)
}
