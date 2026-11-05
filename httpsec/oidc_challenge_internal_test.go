package httpsec

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/store/seal"
)

// challengeRecorder keeps what a challenge sets.
type challengeRecorder struct{ header http.Header }

func (w *challengeRecorder) SetHeader(name, value string) { w.header.Set(name, value) }
func (w *challengeRecorder) AddHeader(name, value string) { w.header.Add(name, value) }

// dpopAnswersChallenge stands for the set of errors dpopVerifier.challenge answers, so that a sign-in
// endpoint leaves them to it. This holds the two to one set by what the challenge does, over every error
// the status table knows, bare, wrapped and joined.
func TestDPoPAnswersChallenge_AgreesWithTheChallenge(t *testing.T) {
	t.Parallel()

	kr := must.Must(seal.NewKeyring(seal.WithKeyringEncryptionKey("k1", make([]byte, 32))))
	v, err := newDPoPVerifier(DPoP{
		PublicURL:   "https://op.example.com",
		Nonce:       true,
		NonceCipher: seal.SessionCipher(must.Must(seal.NewAEADCipher(kr))),
	}, time.Now)
	require.NoError(t, err)

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, predicate, answered bool)
	}

	agree := func(t *testing.T, predicate, answered bool) {
		t.Helper()
		assert.Equal(t, answered, predicate, "the challenge answered %t, the predicate said %t", answered, predicate)
	}

	cases := []testCase{
		{name: "an error of no row", err: errors.New("of no row"), assert: agree},
		{name: "a challenge owed", err: &ChallengeError{}, assert: agree},
	}
	for _, row := range statusTable {
		cases = append(cases,
			testCase{name: "bare: " + row.err.Error(), err: row.err, assert: agree},
			testCase{name: "wrapped: " + row.err.Error(), err: fmt.Errorf("wrapped: %w", row.err), assert: agree},
			testCase{name: "joined: " + row.err.Error(), err: errors.Join(errors.New("beside it"), row.err), assert: agree},
		)
	}

	var answers int

	for _, tc := range cases {
		w := &challengeRecorder{header: http.Header{}}
		require.ErrorIs(t, v.challenge(t.Context(), w, tc.err), tc.err, tc.name)

		answered := len(w.header.Values(headerWWWAuthenticate)) > 0
		if answered {
			answers++
		}

		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, dpopAnswersChallenge(tc.err), answered)
		})
	}

	// Four errors, in three forms each: a table that stopped reaching them would agree with anything.
	assert.Equal(t, 12, answers)
}
