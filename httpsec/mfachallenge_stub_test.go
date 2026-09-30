package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
)

// testDeviceChannel is the channel the scripted challenge method reports. It
// is a test-only value, the channel of no first-factor kind, so a challenge
// method is never refused as same-channel unless a case asks for it.
const testDeviceChannel factor.Channel = "authenticator-device"

// challengeStub is a scripted mfa.ChallengeMethod, named "passkey" unless a
// case names it otherwise.
//
// It is hand-written rather than generated because its behaviour, not only
// its calls, is what the cases rely on: BeginChallenge builds the document a
// client would answer from the challenge it is given, and PresentedChallenge
// reads that challenge back out of the client's answer, so a round trip through
// the chain behaves as a real challenge protocol does. What it answers at
// Enrolled and Verify is scripted, and every Verify is counted, because "the
// method was never asked" is the guarantee most of the cases pin.
//
// It is safe for concurrent use, as the port requires.
type challengeStub struct {
	// name is what Name reports: "passkey" when empty.
	name string

	// channel is what Channel reports: testDeviceChannel unless a case needs
	// the method on a first factor's channel.
	channel factor.Channel

	// enrolled and enrolledErr are what Enrolled answers.
	enrolled    bool
	enrolledErr error

	// verifyErr is what Verify answers, for every call, and beginErr what
	// BeginChallenge answers.
	verifyErr error
	beginErr  error

	// verifyCalls counts Verify calls.
	verifyCalls atomic.Int32

	// onVerify, when set, runs at the start of every Verify with the response
	// being verified, so a case can observe what the chain had done by then.
	onVerify func(ctx context.Context, response []byte)

	mu sync.Mutex
	// issued are the challenges BeginChallenge was handed, in order.
	issued []string
}

var _ mfa.ChallengeMethod = (*challengeStub)(nil)

// newChallengeStub is a passkey the user is enrolled on and that accepts
// every response it is asked to verify.
func newChallengeStub() *challengeStub {
	return &challengeStub{channel: testDeviceChannel, enrolled: true}
}

func (c *challengeStub) Name() string {
	if c.name == "" {
		return "passkey"
	}

	return c.name
}

func (c *challengeStub) Channel() factor.Channel { return c.channel }

func (c *challengeStub) Enrolled(context.Context, identity.UserID) (bool, error) {
	return c.enrolled, c.enrolledErr
}

func (*challengeStub) Response() mfa.ResponseFormat { return mfa.JSONBody(16 << 10) }

func (c *challengeStub) Verify(ctx context.Context, _ identity.UserID, response []byte) error {
	c.verifyCalls.Add(1)

	if c.onVerify != nil {
		c.onVerify(ctx, response)
	}

	return c.verifyErr
}

// stubChallengeDocument is the document BeginChallenge sends and a client
// answers with: the challenge, carried back as it was received.
type stubChallengeDocument struct {
	Challenge string `json:"challenge"`
}

func (c *challengeStub) BeginChallenge(
	_ context.Context,
	_ identity.UserID,
	challenge string,
) (json.RawMessage, error) {
	if c.beginErr != nil {
		return nil, c.beginErr
	}

	c.mu.Lock()
	c.issued = append(c.issued, challenge)
	c.mu.Unlock()

	return json.Marshal(stubChallengeDocument{Challenge: challenge})
}

// errStubUnreadableAnswer is what PresentedChallenge refuses an answer whose
// challenge member is not a string with.
var errStubUnreadableAnswer = errors.New("mfachallenge_stub_test: the answer's challenge is unreadable")

// PresentedChallenge reads the challenge member of a JSON answer. An answer
// without one presents the empty challenge, and one whose member is not a
// string cannot be read at all.
func (*challengeStub) PresentedChallenge(response []byte) (string, error) {
	var doc stubChallengeDocument
	if err := json.Unmarshal(response, &doc); err != nil {
		return "", errors.Join(errStubUnreadableAnswer, err)
	}

	return doc.Challenge, nil
}

// lastIssued is the challenge the most recent begin was handed, and empty when
// no begin reached the method.
func (c *challengeStub) lastIssued() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.issued) == 0 {
		return ""
	}

	return c.issued[len(c.issued)-1]
}

// answer is a response to challenge, as a client of this method would post it.
func answer(challenge string) string {
	b, err := json.Marshal(stubChallengeDocument{Challenge: challenge})
	if err != nil {
		panic(err) // a string always marshals
	}

	return string(b)
}

// issuedAll is every challenge a begin handed the method, in order.
func (c *challengeStub) issuedAll() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]string(nil), c.issued...)
}
