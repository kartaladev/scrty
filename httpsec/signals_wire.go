package httpsec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/session"
)

// This file is the stream's wire format and its narrowing: everything that decides which
// bytes a client receives.

// appSignalPrefix is what every consumer's signal name starts with (Chain.PublishSignal).
const appSignalPrefix = "app."

// signalFilter is what one stream may send of what its chain allows. The session event
// and session_ended are never asked about: they are always sent.
type signalFilter struct {
	// chain is the chain's set. A library signal outside it is never wanted, whatever
	// names says, so a client can narrow and never widen. It is the endpoint's own map,
	// shared by every stream and only read.
	chain map[Signal]bool

	// narrowed is false with no signals parameter: every signal of chain and every
	// consumer signal. It is true with one, and names is then what the parameter left,
	// so an empty names wants nothing.
	narrowed bool
	names    map[string]bool
}

// wants reports whether a stream with this filter sends the signal name. It judges
// interest and not validity: a consumer's name is checked when it is published and again
// when a bus hands it back (validAppSignalName), and a name that is neither a library
// signal in chain nor a consumer's is never wanted.
//
// The session event and session_ended are always wanted, whatever chain and the narrowing
// say, because a stream cannot go on without them. Otherwise the zero filter wants no library
// signal, because its chain is empty, and every consumer's.
func (f signalFilter) wants(name string) bool {
	if name == "session" || name == string(SignalSessionEnded) {
		return true
	}

	if !strings.HasPrefix(name, appSignalPrefix) && !f.chain[Signal(name)] {
		return false
	}

	return !f.narrowed || f.names[name]
}

const (
	// maxSignalData is the most bytes of data a consumer's signal may carry.
	maxSignalData = 8 << 10

	// maxAppSignalName is the longest consumer signal name, its prefix included.
	maxAppSignalName = len(appSignalPrefix) + 63

	// maxNarrowNames and maxNarrowBytes bound the signals query parameter, all
	// occurrences together.
	maxNarrowNames = 16
	maxNarrowBytes = 256
)

// errUnsafeEvent is why writeEvent refused an event: a field that would break the
// event-stream framing.
var errUnsafeEvent = errors.New("httpsec: signal event holds a line break or NUL")

// validAppSignalName reports whether name is a consumer's signal name of the fixed shape,
// ^app\.[a-z0-9][a-z0-9._-]{0,62}$, which excludes CR, LF, ":" and NUL. It is written out
// by hand so that no end-of-line rule of a pattern can let a trailing line break through.
func validAppSignalName(name string) bool {
	if len(name) <= len(appSignalPrefix) || len(name) > maxAppSignalName ||
		!strings.HasPrefix(name, appSignalPrefix) {
		return false
	}

	for i := len(appSignalPrefix); i < len(name); i++ {
		c := name[i]

		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > len(appSignalPrefix) && (c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}

	return true
}

// validSignalData reports whether data can go out as one data line unchanged: at most
// 8 KiB, valid JSON, valid UTF-8, and holding no raw line break between its tokens, as
// json.MarshalIndent output does. Empty data is not JSON and is refused. Duplicate keys
// are accepted: their meaning is the consumer's.
func validSignalData(data json.RawMessage) bool {
	// A raw CR or LF inside a JSON string is already invalid JSON, so any that is left in
	// valid JSON sits between tokens. json.Valid does not check the UTF-8 of strings.
	return len(data) <= maxSignalData &&
		!bytes.ContainsAny(data, "\r\n") &&
		utf8.Valid(data) &&
		json.Valid(data)
}

// writeEvent writes one event: "event: <name>\ndata: <json>\n\n", with no id. It refuses,
// writing nothing, a name or encoded data holding a raw CR, LF or NUL. data is encoded as
// JSON, and a json.RawMessage is written unchanged. The event goes out in a single Write,
// so a failed write leaves no half of one behind.
func writeEvent(w io.Writer, name string, data any) error {
	if strings.ContainsAny(name, "\r\n\x00") {
		return fmt.Errorf("%w: in the event name", errUnsafeEvent)
	}

	var encoded []byte

	if raw, ok := data.(json.RawMessage); ok {
		if len(raw) == 0 {
			return errors.New("httpsec: signal event has empty data")
		}

		encoded = raw
	} else {
		var err error

		if encoded, err = json.Marshal(data); err != nil {
			return fmt.Errorf("httpsec: encode signal event data: %w", err)
		}
	}

	if bytes.ContainsAny(encoded, "\r\n\x00") {
		return fmt.Errorf("%w: in the event data", errUnsafeEvent)
	}

	event := make([]byte, 0, len("event: \ndata: \n\n")+len(name)+len(encoded))
	event = append(event, "event: "...)
	event = append(event, name...)
	event = append(event, "\ndata: "...)
	event = append(event, encoded...)
	event = append(event, "\n\n"...)

	_, err := w.Write(event)

	return err
}

// writeRetry writes the retry field, in whole milliseconds. It never writes "retry: 0":
// construction refuses a delay under 1 ms, and the caller's jitter can take 1 ms below
// that, so a delay that rounds to nothing is written as 1. A fraction of a millisecond
// rounds up. The caller chooses the delay, its jitter included.
func writeRetry(w io.Writer, delay time.Duration) error {
	ms := delay / time.Millisecond
	if delay%time.Millisecond > 0 {
		ms++
	}

	ms = max(ms, 1)

	_, err := io.WriteString(w, "retry: "+strconv.FormatInt(int64(ms), 10)+"\n\n")

	return err
}

// writeHeartbeat writes a heartbeat, the comment ":\n\n".
func writeHeartbeat(w io.Writer) error {
	_, err := io.WriteString(w, ":\n\n")

	return err
}

// sessionData is the data of a session event.
type sessionData struct {
	IdleDeadline     string  `json:"idle_deadline"`
	AbsoluteDeadline string  `json:"absolute_deadline"`
	AuthenticatedAt  *string `json:"authenticated_at"`
}

// sessionEventData is the data of a session event: the two deadlines and authenticated_at
// in RFC 3339, UTC, and null for an AuthenticatedAt that is zero. It is the only encoder of
// that event, and it omits the upstream fields of s, which a reload hands back raw: no
// identifier, the issuer's or the upstream session's, reaches the client.
func sessionEventData(s session.SignInState) any {
	d := sessionData{
		IdleDeadline:     s.IdleDeadline.UTC().Format(time.RFC3339Nano),
		AbsoluteDeadline: s.AbsoluteDeadline.UTC().Format(time.RFC3339Nano),
	}

	if !s.AuthenticatedAt.IsZero() {
		at := s.AuthenticatedAt.UTC().Format(time.RFC3339Nano)
		d.AuthenticatedAt = &at
	}

	return d
}

// narrowed reads every occurrence of the signals query parameter, the argument being
// Request.QueryValues("signals"), nil when absent. It refuses with ErrMalformedRequest
// (400) more than 16 names or 256 bytes, counted over all occurrences together and before
// anything is dropped. A name outside the chain's set, or an app. name of the wrong shape,
// is dropped, and an empty parameter keeps none, so only what is always sent goes out.
//
// It always sets chain to e.set, the map settle built, so what it returns can never
// widen the chain's set.
func (e *sessionSignals) narrowed(values []string) (signalFilter, error) {
	f := signalFilter{chain: e.set}
	if len(values) == 0 {
		return f, nil
	}

	f.narrowed = true
	f.names = map[string]bool{}

	var bytesSeen, namesSeen int

	for _, v := range values {
		if bytesSeen += len(v); bytesSeen > maxNarrowBytes {
			return signalFilter{}, ErrMalformedRequest
		}

		for name := range strings.SplitSeq(v, ",") {
			if name == "" {
				continue
			}

			if namesSeen++; namesSeen > maxNarrowNames {
				return signalFilter{}, ErrMalformedRequest
			}

			if strings.HasPrefix(name, appSignalPrefix) {
				if validAppSignalName(name) {
					f.names[name] = true
				}
			} else if e.set[Signal(name)] {
				f.names[name] = true
			}
		}
	}

	return f, nil
}
