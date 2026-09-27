package storetest

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/seal"
)

// fullSealed returns probes with every input present. They are never called:
// the input check looks only at whether they are there.
func fullSealed() Sealed[struct{}] {
	return Sealed[struct{}]{
		Encoding:       SealedBase64URL,
		Rotation:       ResealOnRead,
		NewWithKeyring: func(*testing.T, seal.Keyring) struct{} { return struct{}{} },
		Put:            func(context.Context, struct{}, string, []byte) error { return nil },
		Get: func(context.Context, struct{}, string) ([]byte, bool, error) {
			return nil, false, nil
		},
		RawColumn:  func(*testing.T, *sql.DB, string) []byte { return nil },
		CopySealed: func(*testing.T, *sql.DB, string, string) {},
	}
}

func TestSealedInputs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		harness func(h *DurableHarness[struct{}])
		sealed  func(s *Sealed[struct{}])
		assert  func(t *testing.T, failures []string)
	}

	noChange := func(*DurableHarness[struct{}]) {}
	failsWith := func(want string) func(t *testing.T, failures []string) {
		return func(t *testing.T, failures []string) {
			require.Equal(t, []string{want}, failures)
		}
	}
	missing := func(field string, drop func(s *Sealed[struct{}])) testCase {
		return testCase{
			name:    "a missing " + field + " fails naming it",
			harness: noChange,
			sealed:  drop,
			assert:  failsWith("storetest: " + field + " is required"),
		}
	}

	cases := []testCase{
		{
			name:    "complete probes pass, for either encoding and rotation",
			harness: noChange,
			sealed:  func(s *Sealed[struct{}]) { s.Encoding, s.Rotation = SealedBytes, UnchangedOnRead },
			assert: func(t *testing.T, failures []string) {
				assert.Empty(t, failures)
			},
		},
		{
			name:    "missing out-of-band access fails naming it",
			harness: func(h *DurableHarness[struct{}]) { h.Raw = nil },
			sealed:  func(*Sealed[struct{}]) {},
			assert:  failsWith("storetest: DurableHarness.Raw is required"),
		},
		missing("Sealed.Encoding", func(s *Sealed[struct{}]) { s.Encoding = 0 }),
		missing("Sealed.Rotation", func(s *Sealed[struct{}]) { s.Rotation = 0 }),
		missing("Sealed.NewWithKeyring", func(s *Sealed[struct{}]) { s.NewWithKeyring = nil }),
		missing("Sealed.Put", func(s *Sealed[struct{}]) { s.Put = nil }),
		missing("Sealed.Get", func(s *Sealed[struct{}]) { s.Get = nil }),
		missing("Sealed.RawColumn", func(s *Sealed[struct{}]) { s.RawColumn = nil }),
		missing("Sealed.CopySealed", func(s *Sealed[struct{}]) { s.CopySealed = nil }),
		{
			name:    "an encoding that is not one of the constants fails naming it",
			harness: noChange,
			sealed:  func(s *Sealed[struct{}]) { s.Encoding = 7 },
			assert:  failsWith("storetest: Sealed.Encoding is required"),
		},
		{
			name:    "a rotation that is not one of the constants fails naming it",
			harness: noChange,
			sealed:  func(s *Sealed[struct{}]) { s.Rotation = -1 },
			assert:  failsWith("storetest: Sealed.Rotation is required"),
		},
		{
			name:    "missing harness and suite inputs fail once, naming every one",
			harness: func(h *DurableHarness[struct{}]) { h.Raw = nil },
			sealed:  func(s *Sealed[struct{}]) { s.CopySealed = nil },
			assert:  failsWith("storetest: DurableHarness.Raw, Sealed.CopySealed are required"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, s := fullHarness(), fullSealed()
			tc.harness(&h)
			tc.sealed(&s)

			tc.assert(t, runRecorded(t, func(tb testing.TB) { requireSealed(tb, h, s) }))
		})
	}
}
