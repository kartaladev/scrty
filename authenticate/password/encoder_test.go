package password_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/password"
)

// encoderCase names one of the encoders the package ships. Every rule that must
// hold for "an encoder" rather than for one algorithm is asserted against all of
// them, so a new encoder cannot quietly arrive with its own opinion about the
// bytes it is handed.
type encoderCase struct {
	name string
	new  func() (password.Encoder, error)
}

func shippedEncoders() []encoderCase {
	return []encoderCase{
		// Argon2id at the cheapest parameters its floor accepts, which halves what
		// these cases cost: every rule asserted against them holds at any legal
		// cost, and the shipped defaults are covered by TestArgon2idEncode. bcrypt
		// and scrypt are constructed bare because neither has a cheaper legal
		// point — for both, the default is the floor.
		{name: "argon2id", new: func() (password.Encoder, error) {
			return password.NewArgon2idEncoder(
				password.WithArgon2idMemory(mib19),
				password.WithArgon2idIterations(2),
			)
		}},
		{name: "bcrypt", new: func() (password.Encoder, error) { return password.NewBcryptEncoder() }},
		{name: "scrypt", new: func() (password.Encoder, error) { return password.NewScryptEncoder() }},
	}
}

func TestPasswordsAreHashedExactlyAsGiven(t *testing.T) {
	t.Parallel()

	// é written as one code point, U+00E9, and as "e" followed by U+0301, the
	// combining acute accent. The two render identically and a user may type
	// either, depending on their keyboard and operating system, but they are
	// different byte sequences and therefore different passwords.
	const (
		precomposed = "café"
		decomposed  = "café"
	)

	type testCase struct {
		name string
		// stored is encoded; presented is then matched against that hash.
		stored    string
		presented string
		assert    func(t *testing.T, matched bool)
	}

	cases := []testCase{
		{
			name:      "the exact bytes match",
			stored:    decomposed,
			presented: decomposed,
			assert: func(t *testing.T, matched bool) {
				assert.True(t, matched,
					"the control: whatever the bytes are, a password matches itself. "+
						"Without this row the mismatch rows below would also pass against "+
						"a Match that never matches anything")
			},
		},
		{
			name:      "a different normalization form is a different password",
			stored:    precomposed,
			presented: decomposed,
			assert: func(t *testing.T, matched bool) {
				assert.False(t, matched,
					"normalizing would make two distinct byte sequences one credential. "+
						"The bytes are hashed as given, so a user who enrolled with one form "+
						"must present that form")
			},
		},
		{
			name:      "the reverse normalization direction is also a different password",
			stored:    decomposed,
			presented: precomposed,
			assert: func(t *testing.T, matched bool) {
				assert.False(t, matched,
					"normalization to either form is still normalization")
			},
		},
		{
			name:      "surrounding whitespace is part of the password",
			stored:    "hunter2",
			presented: " hunter2 ",
			assert: func(t *testing.T, matched bool) {
				assert.False(t, matched,
					"trimming the presented password would admit a value the user never "+
						"enrolled, and would silently shrink the space of passwords a user "+
						"may choose")
			},
		},
		{
			name:      "two different all-whitespace passwords are different passwords",
			stored:    " \t ",
			presented: "  ",
			assert: func(t *testing.T, matched bool) {
				assert.False(t, matched,
					"trimming would reduce both of these to the empty string and so make "+
						"them one credential. Both sides are whitespace on purpose: if only "+
						"one were, trimming would still leave them unequal and this row "+
						"could not fail")
			},
		},
		{
			name:      "case is part of the password",
			stored:    "hunter2",
			presented: "Hunter2",
			assert: func(t *testing.T, matched bool) {
				assert.False(t, matched,
					"case folding would collapse distinct passwords into one credential")
			},
		},
	}

	// One subtest per encoder-and-case pair. The joined name gives the same
	// "…/argon2id/case" path a nested t.Run would, without the extra layer.
	for _, enc := range shippedEncoders() {
		for _, tc := range cases {
			t.Run(enc.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				encoder, err := enc.new()
				require.NoError(t, err)

				encoded, err := encoder.Encode(tc.stored)
				require.NoError(t, err)

				tc.assert(t, encoder.Match(tc.presented, encoded))
			})
		}
	}
}

// Only Argon2id and scrypt are covered: bcrypt derives its own salt inside
// golang.org/x/crypto and exposes no source to replace.
func TestEncodeReportsASaltThatCannotBeRead(t *testing.T) {
	t.Parallel()

	boom := errors.New("entropy source offline")

	// Identical across the rows on purpose: the rule under test is the same for
	// every encoder, and it is the salt source that varies, not the expectation.
	assertReported := func(t *testing.T, encoded []byte, err error) {
		require.ErrorIs(t, err, boom,
			"the cause reaches the caller, because only the caller can tell a dead "+
				"entropy source from a mistyped password and the two deserve different "+
				"responses")
		assert.Nil(t, encoded,
			"no hash is returned: a record derived over a salt that was never read "+
				"would be a record over zeros, identical for every user who chose the "+
				"same password")
	}

	type testCase struct {
		name   string
		new    func(random io.Reader) (password.Encoder, error)
		assert func(t *testing.T, encoded []byte, err error)
	}

	cases := []testCase{
		{
			name: "argon2id",
			new: func(random io.Reader) (password.Encoder, error) {
				return password.NewArgon2idEncoder(password.WithArgon2idRandom(random))
			},
			assert: assertReported,
		},
		{
			name: "scrypt",
			new: func(random io.Reader) (password.Encoder, error) {
				return password.NewScryptEncoder(password.WithScryptRandom(random))
			},
			assert: assertReported,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			random := NewMockReader(gomock.NewController(t))
			// Exactly once, and the controller verifies it: an encoder that never
			// reached for a salt would fail here rather than pass quietly.
			random.EXPECT().Read(gomock.Any()).Return(0, boom).Times(1)

			enc, err := tc.new(random)
			require.NoError(t, err,
				"replacing the salt source is configuration, not a weak parameter")

			encoded, err := enc.Encode("hunter2")
			tc.assert(t, encoded, err)
		})
	}
}

// TestDecoyFollowsConsumerParameters pins the other half of the decoy pattern:
// equal cost is only useful if the decoy is as expensive as the real records.
// A decoy encoded by a differently configured encoder would be cheaper or dearer
// than the hashes it stands in for, which is the leak it exists to close.
func TestDecoyFollowsConsumerParameters(t *testing.T) {
	t.Parallel()

	// mib128 is declared in helpers_test.go, in this same test package.
	enc, err := password.NewArgon2idEncoder(password.WithArgon2idMemory(mib128))
	require.NoError(t, err)

	decoy, err := enc.Encode("decoy")
	require.NoError(t, err)

	assert.Contains(t, string(decoy), "argon2id$131072$",
		"the decoy records the consumer's parameters, so matching against it derives "+
			"with their 128 MiB rather than the library's default 64 MiB")
	assert.False(t, enc.Match("anything", decoy),
		"the decoy is a hash of a password no user knows, so nothing presented "+
			"matches it")
}

func TestEncoderConstruction(t *testing.T) {
	t.Parallel()

	const twoGiBInKiB = 2 * 1024 * 1024

	assertRefused := func(t *testing.T, enc password.Encoder, err error) {
		require.ErrorIs(t, err, password.ErrNoRandomSource)
		assert.Nil(t, enc, "no encoder is returned from a refused configuration")
	}

	// aboveCeiling refuses a parameter above its ceiling, naming it in the error.
	aboveCeiling := func(param string) func(t *testing.T, enc password.Encoder, err error) {
		return func(t *testing.T, enc password.Encoder, err error) {
			require.ErrorIs(t, err, password.ErrInvalidParameters)
			assert.True(t, strings.Contains(err.Error(), param), "the error must name the parameter: %v", err)
			assert.Nil(t, enc)
		}
	}

	atCeiling := func(t *testing.T, enc password.Encoder, err error) {
		require.NoError(t, err)
		assert.NotNil(t, enc)
	}

	// encodesIfAccepted holds when construction refuses the configuration, or
	// when the encoder it built can encode.
	encodesIfAccepted := func(t *testing.T, enc password.Encoder, err error) {
		if err != nil {
			return // refused at construction, which is the rule
		}

		_, encErr := enc.Encode("hunter2")
		require.NoError(t, encErr,
			"a configuration the constructor accepted must not fail at the first "+
				"login: a wiring mistake is a construction error")
	}

	type testCase struct {
		name   string
		new    func() (password.Encoder, error)
		assert func(t *testing.T, enc password.Encoder, err error)
	}

	cases := []testCase{
		// A nil salt source is meaningless configuration, not a weak parameter: it
		// cannot produce a salt at all. It is refused by the constructor, because the
		// alternative is a panic inside io.ReadFull at the first login, long after
		// whoever wired it has stopped watching.
		{
			name: "argon2id",
			new: func() (password.Encoder, error) {
				return password.NewArgon2idEncoder(password.WithArgon2idRandom(nil))
			},
			assert: assertRefused,
		},
		{
			name: "scrypt",
			new: func() (password.Encoder, error) {
				return password.NewScryptEncoder(password.WithScryptRandom(nil))
			},
			assert: assertRefused,
		},
		{
			name:   "scrypt p above the ceiling",
			new:    func() (password.Encoder, error) { return password.NewScryptEncoder(password.WithScryptP(32)) },
			assert: aboveCeiling("p=32"),
		},
		{
			name:   "scrypt working memory above the ceiling",
			new:    func() (password.Encoder, error) { return password.NewScryptEncoder(password.WithScryptN(1 << 20)) },
			assert: aboveCeiling("N="),
		},
		{
			name:   "bcrypt cost above the ceiling",
			new:    func() (password.Encoder, error) { return password.NewBcryptEncoder(password.WithBcryptCost(17)) },
			assert: aboveCeiling("cost 17"),
		},
		{
			name: "Argon2id memory above the ceiling",
			new: func() (password.Encoder, error) {
				return password.NewArgon2idEncoder(password.WithArgon2idMemory(twoGiBInKiB))
			},
			assert: aboveCeiling("memory"),
		},
		{
			name: "Argon2id iterations above the ceiling",
			new: func() (password.Encoder, error) {
				return password.NewArgon2idEncoder(password.WithArgon2idIterations(17))
			},
			assert: aboveCeiling("iterations"),
		},
		{
			name:   "Argon2id threads above the ceiling",
			new:    func() (password.Encoder, error) { return password.NewArgon2idEncoder(password.WithArgon2idThreads(17)) },
			assert: aboveCeiling("threads"),
		},
		{
			name: "Argon2id salt above the ceiling",
			new: func() (password.Encoder, error) {
				return password.NewArgon2idEncoder(password.WithArgon2idSaltLength(65))
			},
			assert: aboveCeiling("salt"),
		},
		{
			name: "Argon2id key above the ceiling",
			new: func() (password.Encoder, error) {
				return password.NewArgon2idEncoder(password.WithArgon2idKeyLength(65))
			},
			assert: aboveCeiling("derived key"),
		},
		{
			name:   "scrypt p=16",
			new:    func() (password.Encoder, error) { return password.NewScryptEncoder(password.WithScryptP(16)) },
			assert: atCeiling,
		},
		{
			name: "bcrypt cost 16",
			new: func() (password.Encoder, error) {
				return password.NewBcryptEncoder(password.WithBcryptCost(16))
			},
			assert: atCeiling,
		},
		{
			name: "Argon2id at every ceiling",
			new: func() (password.Encoder, error) {
				return password.NewArgon2idEncoder(
					password.WithArgon2idMemory(1024*1024), password.WithArgon2idIterations(16),
					password.WithArgon2idThreads(16), password.WithArgon2idSaltLength(64),
					password.WithArgon2idKeyLength(64))
			},
			assert: atCeiling,
		},
		// The constructors must refuse what the algorithm itself rejects, so a
		// configuration that would fail at the first login fails at construction
		// instead.
		{
			name: "scrypt N above the floor but not a power of two",
			new: func() (password.Encoder, error) {
				return password.NewScryptEncoder(password.WithScryptN(40000))
			},
			assert: encodesIfAccepted,
		},
		{
			name: "bcrypt cost above what bcrypt accepts",
			new: func() (password.Encoder, error) {
				return password.NewBcryptEncoder(password.WithBcryptCost(32))
			},
			assert: encodesIfAccepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := tc.new()
			tc.assert(t, enc, err)
		})
	}
}

// ErrNoRandomSource must not be bypassed by a typed nil.
//
// validate checks `e.random == nil`, which is false for an interface holding a
// nil *bytes.Reader. Construction succeeds and the first Encode panics, which is
// exactly what ErrNoRandomSource's godoc promises cannot happen.
// Standalone: its rows are named argon2id and scrypt, as TestEncoderConstruction's nil-source rows are.
func TestConstructionRefusesATypedNilRandomSource(t *testing.T) {
	t.Parallel()

	var typedNil *bytes.Reader // nil pointer in a non-nil io.Reader

	type testCase struct {
		name string
		new  func(io.Reader) (password.Encoder, error)
	}

	cases := []testCase{
		{name: "argon2id", new: func(r io.Reader) (password.Encoder, error) {
			return password.NewArgon2idEncoder(password.WithArgon2idRandom(r))
		}},
		{name: "scrypt", new: func(r io.Reader) (password.Encoder, error) {
			return password.NewScryptEncoder(password.WithScryptRandom(r))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := tc.new(typedNil)
			require.ErrorIs(t, err, password.ErrNoRandomSource,
				"a salt source that cannot deliver is meaningless configuration and is "+
					"refused at construction, whether the nil is typed or not")
			assert.Nil(t, enc)
		})
	}
}

func TestRecognizer_BuiltInEncodersRecognizeOnlyWhatTheyWouldVerify(t *testing.T) {
	t.Parallel()

	encoders := map[string]func() (password.Encoder, error){
		"argon2id": func() (password.Encoder, error) { return password.NewArgon2idEncoder() },
		"bcrypt":   func() (password.Encoder, error) { return password.NewBcryptEncoder() },
		"scrypt":   func() (password.Encoder, error) { return password.NewScryptEncoder() },
	}

	// One hash of each algorithm, produced by the real encoders, so each
	// encoder can be shown the others' formats.
	hashes := map[string][]byte{}
	for name, build := range encoders {
		enc, err := build()
		require.NoError(t, err)

		hashes[name], err = enc.Encode("hunter2")
		require.NoError(t, err)
	}

	b64 := base64.RawStdEncoding
	salt := b64.EncodeToString(make([]byte, 16))
	key := b64.EncodeToString(make([]byte, 32))

	type testCase struct {
		name    string
		encoder string
		encoded []byte
		assert  func(t *testing.T, recognized bool)
	}

	recognized := func(t *testing.T, got bool) {
		t.Helper()
		assert.True(t, got, "a hash the encoder verifies was reported unrecognised")
	}
	unrecognized := func(t *testing.T, got bool) {
		t.Helper()
		assert.False(t, got, "a hash Match refuses unread was reported recognised")
	}

	var cases []testCase
	for name := range encoders {
		cases = append(cases,
			testCase{name: name + " recognises its own hash", encoder: name, encoded: hashes[name], assert: recognized},
			testCase{name: name + " does not recognise an empty hash", encoder: name, encoded: []byte{}, assert: unrecognized},
			testCase{name: name + " does not recognise a nil hash", encoder: name, encoded: nil, assert: unrecognized},
			testCase{name: name + " does not recognise garbage", encoder: name, encoded: []byte("not a hash"), assert: unrecognized},
		)
		for other := range encoders {
			if other != name {
				cases = append(cases, testCase{
					name: name + " does not recognise a " + other + " hash", encoder: name,
					encoded: hashes[other], assert: unrecognized,
				})
			}
		}
	}

	cases = append(cases,
		testCase{
			name: "argon2id does not recognise a record demanding memory above the ceiling", encoder: "argon2id",
			encoded: fmt.Appendf(nil, "argon2id$%d$3$1$%s$%s", 1<<30, salt, key), assert: unrecognized,
		},
		testCase{
			name: "scrypt does not recognise a record demanding parallelism above the ceiling", encoder: "scrypt",
			encoded: fmt.Appendf(nil, "scrypt$32768$8$128$%s$%s", salt, key), assert: unrecognized,
		},
		testCase{
			name: "bcrypt does not recognise a record whose cost is above the ceiling", encoder: "bcrypt",
			encoded: []byte("$2a$20$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"), assert: unrecognized,
		},
		testCase{
			name: "bcrypt does not recognise a record whose salt is outside bcrypt's alphabet", encoder: "bcrypt",
			encoded: []byte("$2a$10$!bcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[:60]), assert: unrecognized,
		},
		testCase{
			name: "scrypt does not recognise a record whose N is not a power of two", encoder: "scrypt",
			encoded: fmt.Appendf(nil, "scrypt$3$8$1$%s$%s", salt, key), assert: unrecognized,
		},
		testCase{
			name: "scrypt does not recognise a record whose N is one", encoder: "scrypt",
			encoded: fmt.Appendf(nil, "scrypt$1$8$1$%s$%s", salt, key), assert: unrecognized,
		},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := encoders[tc.encoder]()
			require.NoError(t, err)

			rec, ok := enc.(password.Recognizer)
			require.True(t, ok, "the built-in %s encoder does not implement Recognizer", tc.encoder)

			tc.assert(t, rec.Recognizes(tc.encoded))
		})
	}
}
