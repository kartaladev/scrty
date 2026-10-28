package authenticate_test

// The three tests below share one table runner: each is a table over the same
// Authenticate call, split by the guarantee it pins so each can be run by name.

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

// recognizingRecorder is a recordingEncoder that also forwards recognition to
// the real encoder behind it, as a built-in encoder would offer it.
type recognizingRecorder struct {
	*recordingEncoder

	inner password.Recognizer
}

func (r recognizingRecorder) Recognizes(encoded []byte) bool { return r.inner.Recognizes(encoded) }

type unusableHashCase struct {
	name string
	// stored returns the hash the known user "ada" has; inner is the real
	// encoder behind the recorder.
	stored func(t *testing.T, inner password.Encoder) []byte
	// recognizing wires an encoder that implements password.Recognizer; false
	// wires one that, like a consumer's own encoder, does not.
	recognizing bool
	presented   string
	// reason and level, when set, are the refusal record the case must leave:
	// its reason, and its slog level name.
	reason, level string
	assert        func(t *testing.T, err error, enc *recordingEncoder)
}

func runUnusableHashCases(t *testing.T, cases []unusableHashCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			inner := cheapEncoder(t)
			rec := newRecordingEncoder(t, ctrl, inner)

			var enc password.Encoder = rec
			if tc.recognizing {
				r, ok := inner.(password.Recognizer)
				require.True(t, ok)
				enc = recognizingRecorder{recordingEncoder: rec, inner: r}
			}

			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(&identity.Details{
				Username: "ada",
				Password: tc.stored(t, inner),
				Active:   true,
			}, nil)

			buf := &bytes.Buffer{}
			auth, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(enc), authenticate.WithPasswordLogger(debugLogger(buf)))
			require.NoError(t, err)

			presented := tc.presented
			if presented == "" {
				presented = presentedPassword
			}

			_, err = auth.Authenticate(t.Context(), identity.NewUsernamePassword("ada", []byte(presented)))
			tc.assert(t, err, rec)

			if tc.reason != "" {
				records := refusalRecords(t, buf)
				require.Len(t, records, 1)
				assert.Equal(t, tc.reason, records[0]["reason"])
				assert.Equal(t, tc.level, records[0]["level"])
			}
		})
	}
}

// refusedAfterOneReferenceVerification asserts the refusal cost exactly what an
// unknown username costs: one verification, against the reference hash.
func refusedAfterOneReferenceVerification(t *testing.T, err error, enc *recordingEncoder) {
	t.Helper()

	assert.Equal(t, authenticate.ErrAuthenticationFailed, err)

	matches, matchedTo := enc.calls()
	require.Equal(t, 1, matches,
		"an unusable hash must cost one verification, as an unknown user does, and never two")
	assert.Equal(t, enc.reference(t), matchedTo[0],
		"the one verification was not against the reference hash, so it derived nothing")
}

func noHash(t *testing.T, _ password.Encoder) []byte {
	t.Helper()

	return nil
}

func bcryptHash(t *testing.T, _ password.Encoder) []byte {
	t.Helper()

	enc, err := password.NewBcryptEncoder()
	require.NoError(t, err)

	h, err := enc.Encode(presentedPassword)
	require.NoError(t, err)

	return h
}

func TestPasswordProvider_PasswordlessUserCostsSameAsUnknownUser(t *testing.T) {
	t.Parallel()

	runUnusableHashCases(t, []unusableHashCase{
		{
			name:   "a nil hash, through an encoder without recognition",
			stored: noHash,
			reason: "no-password-hash", level: "DEBUG",
			assert: refusedAfterOneReferenceVerification,
		},
		{
			name: "an empty hash, through an encoder without recognition",
			stored: func(t *testing.T, _ password.Encoder) []byte {
				t.Helper()

				return []byte{}
			},
			assert: refusedAfterOneReferenceVerification,
		},
		{
			name:        "a nil hash, through an encoder with recognition",
			stored:      noHash,
			recognizing: true,
			reason:      "no-password-hash", level: "DEBUG",
			assert: refusedAfterOneReferenceVerification,
		},
	})
}

func TestPasswordProvider_UnrecognisedHashCostsOneVerification(t *testing.T) {
	t.Parallel()

	runUnusableHashCases(t, []unusableHashCase{
		{
			name:        "a hash in another algorithm's format, through an encoder that recognises its own",
			stored:      bcryptHash,
			recognizing: true,
			reason:      "unrecognised-hash", level: "WARN",
			assert: refusedAfterOneReferenceVerification,
		},
		{
			name: "a usable hash and a wrong password cost one verification, against the stored hash",
			stored: func(t *testing.T, inner password.Encoder) []byte {
				t.Helper()

				h, err := inner.Encode(storedPassword)
				require.NoError(t, err)

				return h
			},
			recognizing: true,
			assert: func(t *testing.T, err error, enc *recordingEncoder) {
				t.Helper()

				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)

				matches, matchedTo := enc.calls()
				require.Equal(t, 1, matches, "a wrong password must not cost two derivations")
				assert.NotEqual(t, enc.reference(t), matchedTo[0])
			},
		},
		{
			name:   "by default, an encoder without recognition is trusted with any non-empty hash",
			stored: bcryptHash,
			assert: func(t *testing.T, err error, enc *recordingEncoder) {
				t.Helper()

				assert.Equal(t, authenticate.ErrAuthenticationFailed, err)

				matches, matchedTo := enc.calls()
				require.Equal(t, 1, matches)
				assert.NotEqual(t, enc.reference(t), matchedTo[0],
					"an encoder that cannot report recognition was second-guessed")
			},
		},
	})
}

func TestPasswordProvider_ReferencePasswordNeverAdmits(t *testing.T) {
	t.Parallel()

	runUnusableHashCases(t, []unusableHashCase{
		{
			name:      "a user without a hash presents the reference password",
			stored:    noHash,
			presented: authenticate.ReferencePassword,
			assert:    refusedAfterOneReferenceVerification,
		},
		{
			name:        "a user with an unrecognised hash presents the reference password",
			stored:      bcryptHash,
			recognizing: true,
			presented:   authenticate.ReferencePassword,
			assert:      refusedAfterOneReferenceVerification,
		},
	})
}
