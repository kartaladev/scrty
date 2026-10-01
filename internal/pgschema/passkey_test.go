package pgschema_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pgschema"
)

func TestPasskeyTransports(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		transports []string
		assert     func(t *testing.T, text string, err error)
	}

	roundTrips := func(want string, back []string) func(t *testing.T, text string, err error) {
		return func(t *testing.T, text string, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, want, text)
			assert.Equal(t, back, pgschema.ParsePasskeyTransports(text))
		}
	}
	refused := func(t *testing.T, text string, err error) {
		t.Helper()
		require.ErrorIs(t, err, pgschema.ErrPasskeyTransportUnstorable)
		assert.Empty(t, text)
	}

	cases := []testCase{
		{name: "transports are one per line, in order", transports: []string{"usb", "nfc", "hybrid"},
			assert: roundTrips("usb\nnfc\nhybrid", []string{"usb", "nfc", "hybrid"})},
		{name: "one transport is its own text", transports: []string{"internal"},
			assert: roundTrips("internal", []string{"internal"})},
		{name: "no transports are the empty text, read back as none", transports: nil, assert: roundTrips("", nil)},
		{name: "an empty list reads back as none", transports: []string{}, assert: roundTrips("", nil)},
		{name: "a transport holding a newline is refused", transports: []string{"usb\nnfc"}, assert: refused},
		{name: "a transport holding a carriage return is refused", transports: []string{"usb\r"}, assert: refused},
		{name: "an empty transport is refused", transports: []string{"usb", ""}, assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			text, err := pgschema.PasskeyTransportsText(tc.transports)
			tc.assert(t, text, err)
		})
	}
}
