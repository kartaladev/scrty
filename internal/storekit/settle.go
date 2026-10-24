package storekit

import (
	"errors"

	"github.com/kartaladev/scrty/session"
)

// MaxDeletePasses bounds the passes of a user-wide session delete, as
// pgschema.StreakAddMaxRuns bounds a streak write's runs. A pass that removes
// something is followed by another only to reach the successor an in-flight
// supersession inserted, which one more pass does; sessions created as fast
// as the passes remove them would otherwise keep the delete running until its
// context ends, and the library's callers pass contexts that do not end.
const MaxDeletePasses = 64

// UntilSettled runs pass, a user-wide delete of sessions for op, until it
// removes nothing, at most MaxDeletePasses times, and returns what every pass
// removed, those before an error included. A pass's error is returned as it
// is. When every pass removed something, the error is
// session.ErrDeleteDidNotSettle wrapped by wrap with op, the adapter's own
// wrapping of a failure.
func UntilSettled(op string, pass func() (int, error), wrap func(op string, err error) error) (int, error) {
	total := 0
	for range MaxDeletePasses {
		n, err := pass()
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
		total += n
	}

	return total, wrap(op, session.ErrDeleteDidNotSettle)
}

// ErrIdentifierInUse is why a bounded insert (OneTimeStore.InsertWithin) of
// an identifier already stored fails. It carries no adapter prefix; the
// adapter wraps it with its own and the operation's name.
var ErrIdentifierInUse = errors.New("the identifier is already in use")
