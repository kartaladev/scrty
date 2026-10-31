package password_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"

	"github.com/kartaladev/scrty/authenticate/password"
)

func TestArgon2idEncode(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, enc password.Encoder)
	}

	cases := []testCase{
		{
			name: "the default encoding names its algorithm and parameters",
			assert: func(t *testing.T, enc password.Encoder) {
				encoded, err := enc.Encode("hunter2")
				require.NoError(t, err)

				assert.True(t, strings.HasPrefix(string(encoded), "argon2id$65536$1$4$"),
					"the stored form carries what verification needs — 64 MiB, 1 iteration, "+
						"4 threads — so a hash made today still verifies after the defaults "+
						"change; got %q", encoded)
				assert.True(t, enc.Match("hunter2", encoded),
					"the default encoder must verify what it just produced")
			},
		},
		{
			name: "every encoding is salted, so one password never yields one hash",
			assert: func(t *testing.T, enc password.Encoder) {
				first, err := enc.Encode("hunter2")
				require.NoError(t, err)

				second, err := enc.Encode("hunter2")
				require.NoError(t, err)

				assert.NotEqual(t, first, second,
					"two users who choose the same password must not share a stored hash: "+
						"identical hashes reveal that they match, and cracking one cracks both")

				assert.True(t, enc.Match("hunter2", first),
					"a fresh salt must not cost the encoder the ability to verify")
				assert.True(t, enc.Match("hunter2", second))
			},
		},
		{
			name: "a wrong password does not match",
			assert: func(t *testing.T, enc password.Encoder) {
				encoded, err := enc.Encode("hunter2")
				require.NoError(t, err)

				assert.False(t, enc.Match("hunter3", encoded))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewArgon2idEncoder()
			require.NoError(t, err, "the default encoder takes no configuration")
			require.NotNil(t, enc)

			tc.assert(t, enc)
		})
	}
}

func TestArgon2idMatch(t *testing.T) {
	t.Parallel()

	encodeWith := func(t *testing.T, opts []password.Argon2idOption, pw string) []byte {
		t.Helper()

		enc, err := password.NewArgon2idEncoder(opts...)
		require.NoError(t, err)

		encoded, err := enc.Encode(pw)
		require.NoError(t, err)

		return encoded
	}

	type testCase struct {
		name   string
		opts   []password.Argon2idOption
		stored func(t *testing.T) []byte
		input  string
		assert func(t *testing.T, matched bool)
	}

	// zeroField rewrites one cost field of a real record to zero, so only the
	// field under test is unusual. The parser accepts "0" for iterations and for
	// threads, and argon2.IDKey panics on either.
	zeroField := func(field int) func(t *testing.T) []byte {
		return func(t *testing.T) []byte {
			real1 := encodeWith(t, nil, "hunter2")

			parts := strings.Split(string(real1), "$")
			require.Len(t, parts, 6)

			parts[field] = "0"

			return []byte(strings.Join(parts, "$"))
		}
	}

	noZeroCostMatch := func(t *testing.T, matched bool) {
		assert.False(t, matched,
			"a record the parser accepted but the derivation cannot honour must "+
				"report no match, not take the process down")
	}

	const kib = 1024 // small, so the ceiling cases that do derive stay fast

	// atCost builds a record whose key is genuinely derived at the parameters it
	// claims, so only a ceiling can make Match refuse it.
	atCost := func(iterations uint32, threads uint8, saltLen int, keyLen uint32) func(t *testing.T) []byte {
		return func(_ *testing.T) []byte {
			salt := make([]byte, saltLen)
			for i := range salt {
				salt[i] = byte(i + 1)
			}

			key := argon2.IDKey([]byte("hunter2"), salt, iterations, kib, threads, keyLen)

			return fmt.Appendf(nil, "argon2id$%d$%d$%d$%s$%s", kib, iterations, threads,
				base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
		}
	}

	refused := func(t *testing.T, matched bool) {
		t.Helper()
		assert.False(t, matched, "a record above a ceiling is refused even when its key is right")
	}

	cases := []testCase{
		{
			name: "a hash made with the old cost still verifies under a raised one",
			opts: []password.Argon2idOption{password.WithArgon2idMemory(mib128)},
			stored: func(t *testing.T) []byte {
				// Written at the 64 MiB default, verified by a 128 MiB encoder.
				return encodeWith(t, nil, "hunter2")
			},
			input: "hunter2",
			assert: func(t *testing.T, matched bool) {
				assert.True(t, matched,
					"the parameters come from the stored hash; reading them from the encoder "+
						"would lock every user out the day an operator raises the cost")
			},
		},
		{
			name:   "a wrong password does not match",
			stored: func(t *testing.T) []byte { return encodeWith(t, nil, "hunter2") },
			input:  "hunter3",
			assert: func(t *testing.T, matched bool) { assert.False(t, matched) },
		},
		{
			// Only the algorithm label is rewritten, so the parameters, salt and
			// derived key all still belong to this encoder. If Match ignored the
			// label it would derive the identical key and report a match, so this
			// row fails exactly when the check is removed. A hand-written foreign
			// hash would not do: its key would fail to match whether the label was
			// checked or not, and the row would prove nothing.
			name: "a record labelled with another algorithm does not match",
			stored: func(t *testing.T) []byte {
				valid := encodeWith(t, nil, "hunter2")

				return append([]byte("scrypt"), bytes.TrimPrefix(valid, []byte("argon2id"))...)
			},
			input: "hunter2",
			assert: func(t *testing.T, matched bool) {
				assert.False(t, matched,
					"the algorithm label is part of the record: ignoring it would let a hash "+
						"stored for one algorithm satisfy another algorithm's encoder")
			},
		},
		// The three rows below are robustness assertions rather than proofs. No
		// plausible mutation makes them fail — a record this broken yields a
		// non-matching key however the parser mishandles it — so they exist to
		// pin that Match answers false rather than panicking or erroring on input
		// a corrupted or hand-edited store might hold. The guards they walk past
		// are proven instead by the no-salt row below and by
		// TestArgon2idRejectsARecordWithNoDerivedKey, by rewriting one field of a
		// real record so that ignoring the guard would produce a match.
		{
			name: "a record whose salt is not base64 does not match",
			stored: func(_ *testing.T) []byte {
				return []byte("argon2id$65536$1$4$!!!$AAAA")
			},
			input:  "hunter2",
			assert: func(t *testing.T, matched bool) { assert.False(t, matched) },
		},
		{
			name: "a truncated record does not match",
			stored: func(_ *testing.T) []byte {
				return []byte("argon2id$65536$1$4")
			},
			input:  "hunter2",
			assert: func(t *testing.T, matched bool) { assert.False(t, matched) },
		},
		{
			name:   "an empty record does not match",
			stored: func(_ *testing.T) []byte { return nil },
			input:  "hunter2",
			assert: func(t *testing.T, matched bool) { assert.False(t, matched) },
		},
		// A stored record with a zero cost field must report no match, as the
		// Encoder contract says of a malformed record, rather than panic.
		{name: "zero iterations", stored: zeroField(2), input: "hunter2", assert: noZeroCostMatch},
		{name: "zero threads", stored: zeroField(3), input: "hunter2", assert: noZeroCostMatch},
		{
			name: "rejects a record with no salt",
			opts: []password.Argon2idOption{
				password.WithArgon2idMemory(mib19),
				password.WithArgon2idIterations(2),
			},
			stored: func(_ *testing.T) []byte {
				// The key this record carries is genuinely derived with an empty salt, so a
				// parser that accepted the empty salt field would derive the same bytes and
				// report a match. That is what makes this row fail when the guard is removed,
				// rather than failing for some incidental reason.
				key := argon2.IDKey([]byte("hunter2"), nil, 2, mib19, 4, 32)

				return fmt.Appendf(nil, "argon2id$%d$%d$%d$$%s",
					mib19, 2, 4, base64.RawStdEncoding.EncodeToString(key))
			},
			input: "hunter2",
			assert: func(t *testing.T, matched bool) {
				assert.False(t, matched,
					"a salt is what stops two users who chose the same password sharing a "+
						"hash, so a record that carries none is not a record this encoder "+
						"produced and must never verify")
			},
		},
		{name: "threads above the ceiling", stored: atCost(1, 64, 16, 32), input: "hunter2", assert: refused},
		{name: "threads one above the ceiling", stored: atCost(1, 17, 16, 32), input: "hunter2", assert: refused},
		{name: "iterations above the ceiling", stored: atCost(17, 1, 16, 32), input: "hunter2", assert: refused},
		{name: "salt above the ceiling", stored: atCost(1, 1, 65, 32), input: "hunter2", assert: refused},
		{name: "key above the ceiling", stored: atCost(1, 1, 16, 65), input: "hunter2", assert: refused},
		{
			name: "every parameter at its ceiling", stored: atCost(16, 16, 64, 64), input: "hunter2",
			assert: func(t *testing.T, matched bool) { assert.True(t, matched) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewArgon2idEncoder(tc.opts...)
			require.NoError(t, err)

			tc.assert(t, enc.Match(tc.input, tc.stored(t)))
		})
	}
}

// The parser's salt and key guards.
//
// Both are reachable only through a record this package did not write, and both
// were previously uncovered: three separate mutations of them compiled and left
// the whole suite green. A row that merely feeds in a broken record cannot pin
// them, because a broken record yields a non-matching key whether the guard runs
// or not. So each row below is built so that IGNORING the guard would produce a
// match, or a panic, rather than the same false.

// Standalone: it asserts no panic around the Match call itself, which
// TestArgon2idMatch's loop makes outside its assert closure.
func TestArgon2idRejectsARecordWithNoDerivedKey(t *testing.T) {
	t.Parallel()

	enc, err := password.NewArgon2idEncoder(
		password.WithArgon2idMemory(mib19),
		password.WithArgon2idIterations(2),
	)
	require.NoError(t, err)

	honest, err := enc.Encode("hunter2")
	require.NoError(t, err)

	parts := strings.Split(string(honest), "$")
	require.Len(t, parts, 6)

	type testCase struct {
		name string
		key  string
	}

	// Both shapes leave the parser with nothing to compare against. Without the
	// guard the derivation is asked for a zero-length key, which panics inside
	// argon2 rather than returning anything, so asserting a plain false here is
	// enough to make the guard load-bearing.
	cases := []testCase{
		{name: "the derived key field is empty", key: ""},
		{name: "the derived key field is not base64", key: "!!!"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			record := strings.Join(
				[]string{parts[0], parts[1], parts[2], parts[3], parts[4], tc.key}, "$")

			assert.NotPanics(t, func() {
				assert.False(t, enc.Match("hunter2", []byte(record)),
					"a record with no derived key reports no match, and reports it "+
						"rather than crashing the process that asked")
			})
		})
	}
}

// The record must not dictate unbounded work in Match.
//
// parseArgon2id bounds memory and iterations only by their field widths, so one
// record can make every verification against it cost arbitrarily more than the
// encoder that is configured to run it. Measured here with a modest multiplier;
// the field admits 4294967295.
// Standalone: it times two Match calls against each other instead of asserting one.
func TestArgon2idMatchDoesNotLetTheRecordDictateUnboundedWork(t *testing.T) {
	t.Parallel()

	enc, err := password.NewArgon2idEncoder(
		password.WithArgon2idMemory(mib19),
		password.WithArgon2idIterations(2),
	)
	require.NoError(t, err)

	honest, err := enc.Encode("hunter2")
	require.NoError(t, err)

	parts := strings.Split(string(honest), "$")
	require.Len(t, parts, 6)

	// Same record, one field rewritten: 4096 iterations instead of 2.
	hostile := strings.Join([]string{parts[0], parts[1], "4096", parts[3], parts[4], parts[5]}, "$")

	baseline := timeMatch(t, enc, honest)
	inflated := timeMatch(t, enc, []byte(hostile))

	t.Logf("baseline %v, record-dictated %v, ratio %.0fx", baseline, inflated, float64(inflated)/float64(baseline))

	assert.Less(t, float64(inflated)/float64(baseline), 10.0,
		"a single record must not be able to multiply the cost of verifying against "+
			"it without limit: this is the login path")
}

func timeMatch(t *testing.T, enc password.Encoder, record []byte) time.Duration {
	t.Helper()

	start := time.Now()
	_ = enc.Match("wrong-password", record)

	return time.Since(start)
}

func TestArgon2idParameters(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []password.Argon2idOption
		assert func(t *testing.T, enc password.Encoder, err error)
	}

	requireWeak := func(t *testing.T, err error, named ...string) {
		t.Helper()

		require.ErrorIs(t, err, password.ErrWeakParameters)

		for _, n := range named {
			assert.Contains(t, err.Error(), n,
				"the error has to say which parameter is too low, or the operator cannot fix it")
		}
	}

	cases := []testCase{
		{
			name: "19 MiB with one iteration is below the floor",
			opts: []password.Argon2idOption{
				password.WithArgon2idMemory(mib19),
				password.WithArgon2idIterations(1),
			},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				requireWeak(t, err, "memory", "iteration")
				assert.Nil(t, enc, "a refused configuration must not yield a usable encoder")
			},
		},
		{
			name: "19 MiB is acceptable once iterations make up for it",
			opts: []password.Argon2idOption{
				password.WithArgon2idMemory(mib19),
				password.WithArgon2idIterations(2),
			},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.NoError(t, err, "the floor trades memory against iterations, it is not a single number")
				assert.NotNil(t, enc)
			},
		},
		{
			name: "46 MiB is acceptable at one iteration",
			opts: []password.Argon2idOption{
				password.WithArgon2idMemory(mib46),
				password.WithArgon2idIterations(1),
			},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.NoError(t, err)
				assert.NotNil(t, enc)
			},
		},
		{
			name: "no threads is refused",
			opts: []password.Argon2idOption{password.WithArgon2idThreads(0)},
			assert: func(t *testing.T, _ password.Encoder, err error) {
				requireWeak(t, err, "thread")
			},
		},
		{
			name: "a salt shorter than 16 bytes is refused",
			opts: []password.Argon2idOption{password.WithArgon2idSaltLength(15)},
			assert: func(t *testing.T, _ password.Encoder, err error) {
				requireWeak(t, err, "salt")
			},
		},
		{
			name: "a derived key shorter than 32 bytes is refused",
			opts: []password.Argon2idOption{password.WithArgon2idKeyLength(31)},
			assert: func(t *testing.T, _ password.Encoder, err error) {
				requireWeak(t, err, "key")
			},
		},
		{
			name: "a consumer raising the cost gets it recorded in the hash",
			opts: []password.Argon2idOption{
				password.WithArgon2idMemory(mib128),
				password.WithArgon2idIterations(3),
			},
			assert: func(t *testing.T, enc password.Encoder, err error) {
				require.NoError(t, err)
				require.NotNil(t, enc)

				encoded, encErr := enc.Encode("hunter2")
				require.NoError(t, encErr)
				assert.True(t, strings.HasPrefix(string(encoded), "argon2id$131072$3$"),
					"the raised cost must reach the stored form, or verification would "+
						"silently use the old one; got %q", encoded)
				assert.True(t, enc.Match("hunter2", encoded))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := password.NewArgon2idEncoder(tc.opts...)
			tc.assert(t, enc, err)
		})
	}
}

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
