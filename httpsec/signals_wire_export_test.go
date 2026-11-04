package httpsec

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/kartaladev/scrty/session"
)

// SignalFilterWants is signalFilter.wants of name, for a filter over the chain's set chain,
// narrowed to names when narrowed is true.
func SignalFilterWants(chain []Signal, narrowed bool, names []string, name string) bool {
	f := signalFilter{narrowed: narrowed, names: map[string]bool{}}

	if chain != nil {
		f.chain = make(map[Signal]bool, len(chain))
		for _, s := range chain {
			f.chain[s] = true
		}
	}

	for _, n := range names {
		f.names[n] = true
	}

	return f.wants(name)
}

// ValidAppSignalName is validAppSignalName.
func ValidAppSignalName(name string) bool { return validAppSignalName(name) }

// ValidSignalData is validSignalData.
func ValidSignalData(data json.RawMessage) bool { return validSignalData(data) }

// WriteEvent is writeEvent.
func WriteEvent(w io.Writer, name string, data any) error { return writeEvent(w, name, data) }

// WriteRetry is writeRetry.
func WriteRetry(w io.Writer, delay time.Duration) error { return writeRetry(w, delay) }

// WriteHeartbeat is writeHeartbeat.
func WriteHeartbeat(w io.Writer) error { return writeHeartbeat(w) }

// SessionEventData is sessionEventData.
func SessionEventData(s session.SignInState) any { return sessionEventData(s) }

// Narrowed is sessionSignals.narrowed over an endpoint whose chain's set is chain. It
// returns the filter's wants, narrowed and the names it kept, sorted.
func Narrowed(chain []Signal, values []string) (wants func(string) bool, narrowed bool, names []string, err error) {
	e := &sessionSignals{set: make(map[Signal]bool, len(chain))}
	for _, s := range chain {
		e.set[s] = true
	}

	f, err := e.narrowed(values)
	if err != nil {
		return nil, false, nil, err
	}

	for n := range f.names {
		names = append(names, n)
	}

	sort.Strings(names)

	return f.wants, f.narrowed, names, nil
}
