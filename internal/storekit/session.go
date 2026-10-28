package storekit

import (
	"encoding/json"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/session"
)

// OptionalDigest is a successor digest as stored in its nullable column, or
// compared with it: nil, NULL, for none, an empty one included, since the
// session contract reads an empty digest as none.
func OptionalDigest(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}

	return b
}

// OptionalDigestArg is OptionalDigest as a statement argument: an untyped nil
// for none, so every driver sends NULL, and the digest otherwise.
func OptionalDigestArg(b []byte) any {
	if d := OptionalDigest(b); d != nil {
		return d
	}

	return nil
}

// NotFoundUnless is the outcome of a conditional session write that changed
// no row, given whether the session is stored: err when reading that failed,
// nil when the session is stored, and session.ErrNotFound when not.
func NotFoundUnless(exists bool, err error) error {
	if err != nil {
		return err
	}
	if !exists {
		return session.ErrNotFound
	}

	return nil
}

// SupersedeRefusal is the outcome of a supersession whose conditional update
// of the old session changed no row, given the cause pgschema's
// SessionSupersedeRefusal read: session.ErrNotFound when the session
// is not stored, noFamily when it is stored in no family, and
// session.ErrRenewalConflict otherwise. noFamily is the adapter's own
// error, returned as it is.
func SupersedeRefusal(cause int, noFamily error) error {
	switch cause {
	case pgschema.SupersedeRefusalMissing:
		return session.ErrNotFound
	case pgschema.SupersedeRefusalNoFamily:
		return noFamily
	default:
		return session.ErrRenewalConflict
	}
}

// PresentationRefusal is the outcome of a first-presentation mark that
// changed no row: err when reading why failed, session.ErrNotFound
// when the session is not stored, session.ErrSuperseded when it is
// superseded, and nil when its first presentation is recorded already.
func PresentationRefusal(exists, superseded bool, err error) error {
	switch {
	case err != nil:
		return err
	case !exists:
		return session.ErrNotFound
	case superseded:
		return session.ErrSuperseded
	default:
		return nil
	}
}

// EncodeSessionData is a session's data as the JSON object text its jsonb
// column holds, "{}" for none, so the column never holds null. The error is
// encoding/json's.
func EncodeSessionData(data map[string]string) (string, error) {
	if data == nil {
		data = map[string]string{}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(encoded), nil
}

// DecodeSessionData is the data a session's jsonb column holds. A null or
// empty object reads back as an empty, non-nil map, the "none" every store
// returns. The error is encoding/json's.
func DecodeSessionData(raw []byte) (map[string]string, error) {
	var data map[string]string
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	if data == nil {
		data = map[string]string{}
	}

	return data, nil
}

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
