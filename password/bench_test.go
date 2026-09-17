package password_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/password"
)

// benchEncoder builds the encoder every benchmark below shares.
//
// The parameters are the cheapest the floor accepts — mib19 with two iterations,
// the pair TestArgon2idParameters proves is acceptable — which keeps the run
// quick while still performing the whole derivation: the property under test is
// the ratio between two benchmarks, not the absolute cost of either.
func benchEncoder(tb testing.TB) password.Encoder {
	tb.Helper()

	enc, err := password.NewArgon2idEncoder(
		password.WithArgon2idMemory(mib19),
		password.WithArgon2idIterations(2),
	)
	require.NoError(tb, err)

	return enc
}

// BenchmarkMatchStoredHashWrongPassword is the reference cost: a real user typed
// the wrong password, so the record exists and the derivation runs in full.
func BenchmarkMatchStoredHashWrongPassword(b *testing.B) {
	enc := benchEncoder(b)

	stored, err := enc.Encode("hunter2")
	require.NoError(b, err)

	b.ResetTimer()

	for b.Loop() {
		_ = enc.Match("wrong-password", stored)
	}
}

// BenchmarkMatchDecoyWrongPassword is the unknown-user cost. The decoy is what a
// caller encodes once at construction and matches against whenever the user
// lookup misses; it must cost the same as the row above, or the difference tells
// an attacker which usernames exist.
func BenchmarkMatchDecoyWrongPassword(b *testing.B) {
	enc := benchEncoder(b)

	decoy, err := enc.Encode("decoy")
	require.NoError(b, err)

	b.ResetTimer()

	for b.Loop() {
		_ = enc.Match("wrong-password", decoy)
	}
}

// BenchmarkMatchDecoyLongPassword pins that the cost does not follow the
// password's length: a length check that short-circuits would leak through
// timing what the input was, and would make the decoy path cheap for anyone who
// sends a long enough password.
func BenchmarkMatchDecoyLongPassword(b *testing.B) {
	enc := benchEncoder(b)

	decoy, err := enc.Encode("decoy")
	require.NoError(b, err)

	long := string(make([]byte, 4096))

	b.ResetTimer()

	for b.Loop() {
		_ = enc.Match(long, decoy)
	}
}
