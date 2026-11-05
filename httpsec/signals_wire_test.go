package httpsec_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

func TestSessionSignals_Narrowing_Wants(t *testing.T) {
	t.Parallel()

	expiring := string(httpsec.SignalSessionExpiring)
	credential := string(httpsec.SignalCredentialChanged)
	chain := []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalSessionExpiring}

	type testCase struct {
		name     string
		chain    []httpsec.Signal
		narrowed bool
		names    []string
		signal   string
		assert   func(t *testing.T, wanted bool)
	}

	wanted := func(t *testing.T, got bool) {
		t.Helper()
		assert.True(t, got)
	}
	unwanted := func(t *testing.T, got bool) {
		t.Helper()
		assert.False(t, got)
	}

	cases := []testCase{
		{name: "the zero filter wants no library signal", signal: expiring, assert: unwanted},
		{name: "the zero filter wants a consumer's", signal: "app.roles", assert: wanted},
		{name: "not narrowed, a signal of the chain's set", chain: chain, signal: expiring, assert: wanted},
		{name: "not narrowed, a library signal outside the chain's set", chain: chain, signal: credential, assert: unwanted},
		{name: "not narrowed, every consumer's", chain: chain, signal: "app.roles", assert: wanted},
		{name: "not narrowed, a name that is neither", chain: chain, signal: "other", assert: unwanted},
		{
			name:  "a name that is neither is unwanted even when named",
			chain: chain, narrowed: true, names: []string{"other"}, signal: "other", assert: unwanted,
		},
		{
			name:  "session_ended is wanted even when narrowed away",
			chain: chain, narrowed: true, names: []string{expiring}, signal: "session_ended", assert: wanted,
		},
		{
			name:   "session_ended is wanted outside the chain's set",
			signal: "session_ended", assert: wanted,
		},
		{
			name:  "session is wanted even when narrowed away",
			chain: chain, narrowed: true, names: []string{expiring}, signal: "session", assert: wanted,
		},
		{
			name:  "narrowed to a signal of the chain's set",
			chain: chain, narrowed: true, names: []string{expiring}, signal: expiring, assert: wanted,
		},
		{
			name:  "narrowing cannot widen the chain's set",
			chain: chain, narrowed: true, names: []string{credential}, signal: credential, assert: unwanted,
		},
		{
			name:  "a signal of the chain's set the client left out",
			chain: chain, narrowed: true, names: []string{"app.roles"}, signal: expiring, assert: unwanted,
		},
		{
			name:  "narrowed to a consumer's",
			chain: chain, narrowed: true, names: []string{"app.roles"}, signal: "app.roles", assert: wanted,
		},
		{
			name:  "a consumer's the client left out",
			chain: chain, narrowed: true, names: []string{expiring}, signal: "app.roles", assert: unwanted,
		},
		{name: "narrowed to nothing, no library signal", chain: chain, narrowed: true, signal: expiring, assert: unwanted},
		{name: "narrowed to nothing, no consumer's", chain: chain, narrowed: true, signal: "app.roles", assert: unwanted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, httpsec.SignalFilterWants(tc.chain, tc.narrowed, tc.names, tc.signal))
		})
	}
}

// wireWriter counts its Write calls and can fail them.
type wireWriter struct {
	buf   bytes.Buffer
	calls int
	err   error
}

func (w *wireWriter) Write(p []byte) (int, error) {
	w.calls++

	if w.err != nil {
		return 0, w.err
	}

	return w.buf.Write(p)
}

func TestSessionSignals_WireFormat_Event(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		event  string
		data   any
		failed error
		assert func(t *testing.T, w *wireWriter, err error)
	}

	written := func(want string) func(t *testing.T, w *wireWriter, err error) {
		return func(t *testing.T, w *wireWriter, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, want, w.buf.String())
			assert.Equal(t, 1, w.calls, "one event is one Write")
		}
	}
	refused := func(t *testing.T, w *wireWriter, err error) {
		t.Helper()
		require.Error(t, err)
		assert.Zero(t, w.calls, "a refused event writes nothing")
		assert.Zero(t, w.buf.Len())
	}

	errBroken := errors.New("broken pipe")

	cases := []testCase{
		{
			name: "an encoded value", event: "session_expiring",
			data:   map[string]string{"deadline": "idle"},
			assert: written("event: session_expiring\ndata: {\"deadline\":\"idle\"}\n\n"),
		},
		{
			name: "no id field", event: "session_ended", data: map[string]string{"reason": "logout"},
			assert: func(t *testing.T, w *wireWriter, err error) {
				require.NoError(t, err)
				assert.NotContains(t, w.buf.String(), "id:")
				assert.True(t, strings.HasSuffix(w.buf.String(), "\n\n"))
			},
		},
		{
			name: "a raw message goes out unchanged", event: "app.roles",
			data:   json.RawMessage(`{"a": 1,  "b":[1, 2]}`),
			assert: written("event: app.roles\ndata: {\"a\": 1,  \"b\":[1, 2]}\n\n"),
		},
		{
			name: "a string with a line break is escaped by the encoder", event: "app.note",
			data:   "a\nb\rc",
			assert: written("event: app.note\ndata: \"a\\nb\\rc\"\n\n"),
		},
		{name: "an LF in the name", event: "app.a\nevent: session_ended", data: "x", assert: refused},
		{name: "a CR in the name", event: "app.a\rb", data: "x", assert: refused},
		{name: "a NUL in the name", event: "app.a\x00b", data: "x", assert: refused},
		{name: "an LF in a raw message", event: "app.a", data: json.RawMessage("{\"a\":1,\n\"b\":2}"), assert: refused},
		{name: "a CR in a raw message", event: "app.a", data: json.RawMessage("{\"a\":1,\r\"b\":2}"), assert: refused},
		{name: "an LF injecting an event", event: "app.a", data: json.RawMessage("1\n\nevent: session_ended\ndata: {}"), assert: refused},
		{name: "a NUL in a raw message", event: "app.a", data: json.RawMessage("1\x00"), assert: refused},
		{name: "an empty raw message", event: "app.a", data: json.RawMessage(nil), assert: refused},
		{name: "data that cannot be encoded", event: "app.a", data: make(chan int), assert: refused},
		{
			name: "a failed write is returned", event: "session", data: 1, failed: errBroken,
			assert: func(t *testing.T, w *wireWriter, err error) {
				require.ErrorIs(t, err, errBroken)
				assert.Equal(t, 1, w.calls)
				assert.Zero(t, w.buf.Len(), "no part of the event was written")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := &wireWriter{err: tc.failed}
			err := httpsec.WriteEvent(w, tc.event, tc.data)
			tc.assert(t, w, err)
		})
	}
}

func TestSessionSignals_WireFormat_Retry(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		delay  time.Duration
		assert func(t *testing.T, w *wireWriter, err error)
	}

	written := func(want string) func(t *testing.T, w *wireWriter, err error) {
		return func(t *testing.T, w *wireWriter, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, want, w.buf.String())
			assert.Equal(t, 1, w.calls)
		}
	}

	cases := []testCase{
		{name: "whole seconds", delay: 3 * time.Second, assert: written("retry: 3000\n\n")},
		{name: "a whole millisecond", delay: time.Millisecond, assert: written("retry: 1\n\n")},
		{name: "a fraction rounds up", delay: 1500 * time.Microsecond, assert: written("retry: 2\n\n")},
		{name: "a nanosecond over rounds up", delay: 2500*time.Millisecond + 1, assert: written("retry: 2501\n\n")},
		{name: "under a millisecond is one", delay: 500 * time.Microsecond, assert: written("retry: 1\n\n")},
		{name: "a nanosecond is one", delay: 1, assert: written("retry: 1\n\n")},
		{name: "the largest delay does not overflow to one", delay: math.MaxInt64, assert: written("retry: 9223372036855\n\n")},
		{name: "zero is never retry 0", delay: 0, assert: written("retry: 1\n\n")},
		{name: "negative is never retry 0", delay: -time.Second, assert: written("retry: 1\n\n")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := &wireWriter{}
			err := httpsec.WriteRetry(w, tc.delay)
			tc.assert(t, w, err)
		})
	}
}

func TestSessionSignals_WireFormat_Heartbeat(t *testing.T) {
	t.Parallel()

	w := &wireWriter{}
	require.NoError(t, httpsec.WriteHeartbeat(w))
	assert.Equal(t, ":\n\n", w.buf.String())
	assert.Equal(t, 1, w.calls)

	errBroken := errors.New("broken pipe")
	require.ErrorIs(t, httpsec.WriteHeartbeat(&wireWriter{err: errBroken}), errBroken)
}

func TestSessionSignals_WireFormat_SessionEventData(t *testing.T) {
	t.Parallel()

	idle := time.Date(2026, 11, 4, 12, 30, 0, 0, time.FixedZone("WIB", 7*3600))
	absolute := time.Date(2026, 11, 5, 8, 0, 0, 500_000_000, time.UTC)
	at := time.Date(2026, 11, 4, 11, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		state  session.SignInState
		assert func(t *testing.T, got map[string]any)
	}

	cases := []testCase{
		{
			name: "deadlines and authenticated_at in RFC 3339, UTC",
			state: session.SignInState{
				IdleDeadline: idle, AbsoluteDeadline: absolute, AuthenticatedAt: at,
			},
			assert: func(t *testing.T, got map[string]any) {
				assert.Equal(t, "2026-11-04T05:30:00Z", got["idle_deadline"])
				assert.Equal(t, "2026-11-05T08:00:00.5Z", got["absolute_deadline"])
				assert.Equal(t, "2026-11-04T11:00:00Z", got["authenticated_at"])
			},
		},
		{
			name:  "a zero authenticated_at is null",
			state: session.SignInState{IdleDeadline: idle, AbsoluteDeadline: absolute},
			assert: func(t *testing.T, got map[string]any) {
				v, present := got["authenticated_at"]
				assert.True(t, present, "the key is present")
				assert.Nil(t, v)
			},
		},
		{
			name: "no upstream identifier is ever carried",
			state: session.SignInState{
				IdleDeadline: idle, AbsoluteDeadline: absolute, AuthenticatedAt: at,
				ExternalIssuer: "https://issuer.example", ExternalSessionID: "upstream-sid-42",
			},
			assert: func(t *testing.T, got map[string]any) {
				keys := make([]string, 0, len(got))
				for k := range got {
					keys = append(keys, k)
				}

				assert.ElementsMatch(t, []string{"idle_deadline", "absolute_deadline", "authenticated_at"}, keys)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw, err := json.Marshal(httpsec.SessionEventData(tc.state))
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "issuer.example")
			assert.NotContains(t, string(raw), "upstream-sid-42")

			var got map[string]any
			require.NoError(t, json.Unmarshal(raw, &got))
			tc.assert(t, got)
		})
	}
}

func TestSessionSignals_WireFormat_AppSignalName(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		signal string
		assert func(t *testing.T, ok bool)
	}

	valid := func(t *testing.T, ok bool) { t.Helper(); assert.True(t, ok) }
	invalid := func(t *testing.T, ok bool) { t.Helper(); assert.False(t, ok) }

	cases := []testCase{
		{name: "one letter", signal: "app.a", assert: valid},
		{name: "one digit", signal: "app.0", assert: valid},
		{name: "dots, dashes and underscores inside", signal: "app.x-y_z.w", assert: valid},
		{name: "the longest, 63 after the prefix", signal: "app." + strings.Repeat("a", 63), assert: valid},
		{name: "one over the longest", signal: "app." + strings.Repeat("a", 64), assert: invalid},
		{name: "empty", signal: "", assert: invalid},
		{name: "no suffix", signal: "app.", assert: invalid},
		{name: "no dot", signal: "app", assert: invalid},
		{name: "upper case", signal: "app.Bad", assert: invalid},
		{name: "a colon", signal: "app.x:y", assert: invalid},
		{name: "a trailing LF", signal: "app.a\n", assert: invalid},
		{name: "an injected event", signal: "app.a\nevent: session_ended", assert: invalid},
		{name: "a CR", signal: "app.a\rb", assert: invalid},
		{name: "a NUL", signal: "app.a\x00", assert: invalid},
		{name: "starting with a dot", signal: "app..a", assert: invalid},
		{name: "starting with an underscore", signal: "app._a", assert: invalid},
		{name: "a wrong prefix case", signal: "App.a", assert: invalid},
		{name: "a leading space", signal: " app.a", assert: invalid},
		{name: "non-ASCII", signal: "app.é", assert: invalid},
		{name: "a library name", signal: "session_ended", assert: invalid},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, httpsec.ValidAppSignalName(tc.signal))
		})
	}
}

func TestSessionSignals_WireFormat_SignalData(t *testing.T) {
	t.Parallel()

	indented, err := json.MarshalIndent(map[string]any{"a": 1, "b": []int{1, 2}}, "", "  ")
	require.NoError(t, err)

	quoted := func(n int) json.RawMessage { return json.RawMessage(`"` + strings.Repeat("a", n-2) + `"`) }

	type testCase struct {
		name   string
		data   json.RawMessage
		assert func(t *testing.T, ok bool)
	}

	valid := func(t *testing.T, ok bool) { t.Helper(); assert.True(t, ok) }
	invalid := func(t *testing.T, ok bool) { t.Helper(); assert.False(t, ok) }

	cases := []testCase{
		{name: "an object", data: json.RawMessage(`{"a":1}`), assert: valid},
		{name: "null", data: json.RawMessage(`null`), assert: valid},
		{name: "a string", data: json.RawMessage(`"x"`), assert: valid},
		{name: "a number", data: json.RawMessage(`123`), assert: valid},
		{name: "spaces and tabs between tokens", data: json.RawMessage("{ \"a\":\t1 }"), assert: valid},
		{name: "an escaped line break in a string", data: json.RawMessage(`"a\nb"`), assert: valid},
		{name: "multi-byte UTF-8", data: json.RawMessage(`"héllo ✓"`), assert: valid},
		{name: "duplicate keys are the consumer's", data: json.RawMessage(`{"a":1,"a":2}`), assert: valid},
		{name: "exactly 8192 bytes", data: quoted(8192), assert: valid},
		{name: "8193 bytes", data: quoted(8193), assert: invalid},
		{name: "MarshalIndent output", data: indented, assert: invalid},
		{name: "a CR between tokens", data: json.RawMessage("{\"a\":1,\r\"b\":2}"), assert: invalid},
		{name: "a CRLF between tokens", data: json.RawMessage("{\"a\":1,\r\n\"b\":2}"), assert: invalid},
		{name: "a leading LF", data: json.RawMessage("\n{}"), assert: invalid},
		{name: "a trailing LF", data: json.RawMessage("{}\n"), assert: invalid},
		{name: "invalid UTF-8 inside a string", data: json.RawMessage("\"a\xffb\""), assert: invalid},
		{name: "a truncated sequence inside a string", data: json.RawMessage("\"a\xe2\x82\""), assert: invalid},
		{name: "not JSON", data: json.RawMessage(`abc`), assert: invalid},
		{name: "an unclosed object", data: json.RawMessage(`{`), assert: invalid},
		{name: "two values", data: json.RawMessage(`{} {}`), assert: invalid},
		{name: "empty", data: json.RawMessage(""), assert: invalid},
		{name: "nil", data: nil, assert: invalid},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, httpsec.ValidSignalData(tc.data))
		})
	}
}

func TestSessionSignals_Narrowing(t *testing.T) {
	t.Parallel()

	expiring := string(httpsec.SignalSessionExpiring)
	credential := string(httpsec.SignalCredentialChanged)
	chain := []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalSessionExpiring}

	type testCase struct {
		name   string
		values []string
		assert func(t *testing.T, wants func(string) bool, narrowed bool, names []string, err error)
	}

	kept := func(want ...string) func(t *testing.T, wants func(string) bool, narrowed bool, names []string, err error) {
		return func(t *testing.T, _ func(string) bool, narrowed bool, names []string, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.True(t, narrowed)
			assert.Equal(t, want, append([]string(nil), names...))
		}
	}
	refused := func(t *testing.T, _ func(string) bool, _ bool, _ []string, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrMalformedRequest)
	}
	names := func(n int, prefix string) string {
		out := make([]string, n)
		for i := range out {
			out[i] = prefix + string(rune('a'+i%26)) + string(rune('a'+i/26))
		}

		return strings.Join(out, ",")
	}

	cases := []testCase{
		{
			name: "no parameter is not narrowed", values: nil,
			assert: func(t *testing.T, wants func(string) bool, narrowed bool, names []string, err error) {
				require.NoError(t, err)
				assert.False(t, narrowed)
				assert.Empty(t, names)
				assert.True(t, wants(expiring), "the chain's set")
				assert.True(t, wants("app.roles"), "every consumer's")
				assert.False(t, wants(credential), "outside the chain's set")
			},
		},
		{
			name: "an empty slice is no parameter", values: []string{},
			assert: func(t *testing.T, _ func(string) bool, narrowed bool, _ []string, err error) {
				require.NoError(t, err)
				assert.False(t, narrowed)
			},
		},
		{
			name: "an empty parameter sends only what is always sent", values: []string{""},
			assert: func(t *testing.T, wants func(string) bool, narrowed bool, names []string, err error) {
				require.NoError(t, err)
				assert.True(t, narrowed)
				assert.Empty(t, names)
				assert.False(t, wants(expiring))
				assert.False(t, wants("app.roles"))
				assert.True(t, wants("session"))
				assert.True(t, wants("session_ended"))
			},
		},
		{name: "commas alone", values: []string{",,,,"}, assert: kept()},
		{
			name: "narrowed to one signal", values: []string{expiring},
			assert: func(t *testing.T, wants func(string) bool, narrowed bool, names []string, err error) {
				require.NoError(t, err)
				assert.True(t, narrowed)
				assert.Equal(t, []string{expiring}, names)
				assert.True(t, wants(expiring))
			},
		},
		{
			name: "a widening name is ignored", values: []string{credential},
			assert: func(t *testing.T, wants func(string) bool, narrowed bool, names []string, err error) {
				require.NoError(t, err)
				assert.True(t, narrowed)
				assert.Empty(t, names)
				assert.False(t, wants(credential))
			},
		},
		{name: "a widening name beside a wanted one", values: []string{credential + "," + expiring}, assert: kept(expiring)},
		{name: "an unknown name", values: []string{"nonsense"}, assert: kept()},
		{name: "a library name is matched exactly", values: []string{"Session_Expiring, " + expiring + ",session_expiring "}, assert: kept()},
		{name: "split on commas", values: []string{"app.roles," + expiring + ",app.theme"}, assert: kept("app.roles", "app.theme", expiring)},
		{name: "repeated parameters", values: []string{expiring, "app.roles", "app.theme,app.roles"}, assert: kept("app.roles", "app.theme", expiring)},
		{name: "empty entries are not names", values: []string{"app.a,,,app.b,"}, assert: kept("app.a", "app.b")},
		{name: "app.Bad and app.x:y are dropped", values: []string{"app.Bad,app.x:y,app.ok"}, assert: kept("app.ok")},
		{name: "an app name with a line break is dropped", values: []string{"app.a\nevent: session_ended,app.ok"}, assert: kept("app.ok")},
		{name: "an app name of 64 after the prefix is dropped", values: []string{"app." + strings.Repeat("a", 64)}, assert: kept()},
		{name: "the always-sent names need not be named", values: []string{"session,session_ended"}, assert: kept("session_ended")},
		{name: "16 names are accepted", values: []string{names(16, "app.")}, assert: func(t *testing.T, _ func(string) bool, narrowed bool, got []string, err error) {
			require.NoError(t, err)
			assert.True(t, narrowed)
			assert.Len(t, got, 16)
		}},
		{name: "17 names", values: []string{names(17, "app.")}, assert: refused},
		{name: "17 names, spread over repeated parameters", values: []string{names(9, "app."), names(8, "app.")}, assert: refused},
		{name: "17 names that are all dropped still count", values: []string{names(17, "x")}, assert: refused},
		{name: "17 copies of one name", values: []string{strings.TrimSuffix(strings.Repeat("app.a,", 17), ",")}, assert: refused},
		{name: "256 bytes are accepted", values: []string{strings.Repeat("x", 256)}, assert: kept()},
		{name: "257 bytes", values: []string{strings.Repeat("x", 257)}, assert: refused},
		{name: "256 bytes across repeated parameters", values: []string{strings.Repeat("x", 128), strings.Repeat("x", 128)}, assert: kept()},
		{name: "257 bytes across repeated parameters", values: []string{strings.Repeat("x", 128), strings.Repeat("x", 129)}, assert: refused},
		{name: "a short value after a long one", values: []string{strings.Repeat("x", 256), "a"}, assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wants, narrowed, names, err := httpsec.Narrowed(chain, tc.values)
			tc.assert(t, wants, narrowed, names, err)
		})
	}
}
