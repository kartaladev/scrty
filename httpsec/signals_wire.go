package httpsec

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/kartaladev/scrty/session"
)

// This file is the stream's wire format and its narrowing: everything that decides which
// bytes a client receives. Dispatch C2a owns it. Only signalFilter.wants is implemented
// so far; every other function here is a stub saying what it must do.

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

// validAppSignalName reports whether name is a consumer's signal name of the fixed shape,
// ^app\.[a-z0-9][a-z0-9._-]{0,62}$, which excludes CR, LF, ":" and NUL. The stub refuses
// every name.
func validAppSignalName(string) bool { return false }

// validSignalData reports whether data can go out as one data line unchanged: at most
// 8 KiB, valid JSON, valid UTF-8, and holding no raw line break between its tokens, as
// json.MarshalIndent output does. The stub refuses all data.
func validSignalData(json.RawMessage) bool { return false }

// writeEvent writes one event: "event: <name>\ndata: <json>\n\n", with no id. It refuses,
// writing nothing, a name or encoded data holding a raw CR or LF. data is encoded as JSON,
// and a json.RawMessage is written unchanged. The stub writes nothing.
func writeEvent(io.Writer, string, any) error { return nil }

// writeRetry writes the retry field, in whole milliseconds. It never writes "retry: 0":
// construction refuses a delay under 1 ms, and the caller's jitter can take 1 ms below
// that, so a positive delay that truncates to nothing is written as 1. The caller chooses
// the delay, its jitter included. The stub writes nothing.
func writeRetry(io.Writer, time.Duration) error { return nil }

// writeHeartbeat writes a heartbeat, the comment ":\n\n". The stub writes nothing.
func writeHeartbeat(io.Writer) error { return nil }

// sessionEventData is the data of a session event: the two deadlines and authenticated_at
// in RFC 3339, UTC, and null for an AuthenticatedAt that is zero. It is the only encoder of
// that event, and it omits the upstream fields of s, which a reload hands back raw. The
// stub returns nil.
func sessionEventData(session.SignInState) any { return nil }

// narrowed reads every occurrence of the signals query parameter, the argument being
// Request.QueryValues("signals"), nil when absent. It refuses with ErrMalformedRequest
// (400) more than 16 names or 256 bytes. A name outside the chain's set, or an app. name
// of the wrong shape, is dropped.
//
// It always sets chain to e.set, the map settle built, so what it returns can never
// widen the chain's set. The stub narrows nothing.
func (e *sessionSignals) narrowed([]string) (signalFilter, error) {
	return signalFilter{chain: e.set}, nil
}
