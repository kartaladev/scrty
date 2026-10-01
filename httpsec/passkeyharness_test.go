package httpsec_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/session"
)

// The registration endpoints' paths under the default prefix.
const (
	passkeyBeginPath        = httpsec.DefaultPasskeyRegistrationPrefix + "/begin"
	passkeyFinishPath       = httpsec.DefaultPasskeyRegistrationPrefix + "/finish"
	passkeyConfirmPath      = httpsec.DefaultPasskeyRegistrationPrefix + "/confirm"
	passkeyConfirmEmailPath = httpsec.DefaultPasskeyRegistrationPrefix + "/confirm-email"
)

// passkeyRP is the relying party the stub verifier reports.
var passkeyRP = passkey.RelyingParty{ID: "example.com", Name: "Example", Origins: []string{"https://example.com"}}

// passkeyVerifierStub drives a generated passkey.Verifier mock with a few
// rules, so the chain's passkey endpoints can be exercised without the
// WebAuthn adapter, which the core module must not depend on.
//
// A registration response is {"challenge","id","name"} and an assertion
// {"challenge","id","handle"}, the challenge base64url-encoded as clientDataJSON
// carries it. Every registration verifies as a user-verified, backup-eligible
// passkey, and every assertion whose challenge is the expected one verifies,
// user-verified, with a zero counter.
type passkeyVerifierStub struct {
	mock *MockPasskeyVerifier

	mu         sync.Mutex
	creations  []string // challenges rendered into creation options
	requests   []string // challenges rendered into request options
	allowed    [][]passkey.Descriptor
	parseCalls int

	// notUserVerified makes every assertion verify with user presence only,
	// refuseAssertions makes every assertion fail to verify, as a bad
	// signature does, and signCount is the counter every verified assertion
	// reports.
	notUserVerified  atomic.Bool
	refuseAssertions atomic.Bool
	signCount        atomic.Uint32
}

func newPasskeyVerifierStub(t *testing.T) *passkeyVerifierStub {
	t.Helper()

	ctrl := gomock.NewController(t)
	v := &passkeyVerifierStub{mock: NewMockPasskeyVerifier(ctrl)}

	v.mock.EXPECT().RelyingParty().Return(passkeyRP).AnyTimes()
	v.mock.EXPECT().CreationOptions(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, in passkey.CreationInput) (json.RawMessage, error) {
			v.mu.Lock()
			defer v.mu.Unlock()

			v.creations = append(v.creations, in.Challenge)

			return json.Marshal(map[string]string{"challenge": encodeChallenge(in.Challenge)})
		})
	v.mock.EXPECT().RequestOptions(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, in passkey.RequestInput) (json.RawMessage, error) {
			v.mu.Lock()
			defer v.mu.Unlock()

			v.requests = append(v.requests, in.Challenge)
			v.allowed = append(v.allowed, in.Allow)

			return json.Marshal(map[string]any{"challenge": encodeChallenge(in.Challenge), "allow": len(in.Allow)})
		})
	v.mock.EXPECT().ParseRegistration(gomock.Any()).AnyTimes().
		DoAndReturn(func(body []byte) (passkey.ParsedRegistration, error) {
			v.mu.Lock()
			v.parseCalls++
			v.mu.Unlock()

			var r struct{ Challenge, ID, Name string }
			if err := json.Unmarshal(body, &r); err != nil || r.ID == "" {
				return nil, errors.New("stub: unreadable registration")
			}

			p := NewMockParsedRegistration(ctrl)
			p.EXPECT().Challenge().Return(r.Challenge).AnyTimes()
			p.EXPECT().CredentialID().Return([]byte(r.ID)).AnyTimes()
			p.EXPECT().Name().Return(r.Name).AnyTimes()

			return p, nil
		})
	v.mock.EXPECT().VerifyRegistration(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, p passkey.ParsedRegistration, exp passkey.RegistrationExpectation) (*passkey.NewCredential, error) {
			if p.Challenge() != encodeChallenge(exp.Challenge) {
				return nil, errors.New("stub: challenge mismatch")
			}

			return &passkey.NewCredential{
				CredentialID:   p.CredentialID(),
				PublicKey:      append([]byte("cose-"), p.CredentialID()...),
				UserVerified:   true,
				BackupEligible: true,
				BackupState:    true,
				Transports:     []string{"internal"},
			}, nil
		})
	v.mock.EXPECT().ParseAssertion(gomock.Any()).AnyTimes().
		DoAndReturn(func(body []byte) (passkey.ParsedAssertion, error) {
			var a struct {
				Challenge, ID string
				Handle        []byte
			}
			if err := json.Unmarshal(body, &a); err != nil || a.ID == "" {
				return nil, errors.New("stub: unreadable assertion")
			}

			p := NewMockParsedAssertion(ctrl)
			p.EXPECT().Challenge().Return(a.Challenge).AnyTimes()
			p.EXPECT().CredentialID().Return([]byte(a.ID)).AnyTimes()
			p.EXPECT().UserHandle().Return(a.Handle).AnyTimes()

			return p, nil
		})
	v.mock.EXPECT().VerifyAssertion(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, p passkey.ParsedAssertion, c *passkey.Credential, exp passkey.AssertionExpectation) (*passkey.AssertionResult, error) {
			if v.refuseAssertions.Load() || p.Challenge() != encodeChallenge(exp.Challenge) ||
				!bytes.Equal(p.CredentialID(), c.CredentialID) {
				return nil, errors.New("stub: assertion does not verify")
			}

			return &passkey.AssertionResult{
				SignCount:    v.signCount.Load(),
				UserVerified: !v.notUserVerified.Load(), BackupEligible: c.BackupEligible, BackupState: c.BackupState,
			}, nil
		})

	return v
}

// encodeChallenge is a token string as clientDataJSON carries it.
func encodeChallenge(token string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(token))
}

// lastCreation is the challenge the latest registration begin rendered.
func (v *passkeyVerifierStub) lastCreation(t *testing.T) string {
	t.Helper()

	v.mu.Lock()
	defer v.mu.Unlock()

	require.NotEmpty(t, v.creations, "no registration was begun")

	return v.creations[len(v.creations)-1]
}

// lastRequest is the challenge the latest assertion begin rendered.
func (v *passkeyVerifierStub) lastRequest(t *testing.T) string {
	t.Helper()

	v.mu.Lock()
	defer v.mu.Unlock()

	require.NotEmpty(t, v.requests, "no assertion was begun")

	return v.requests[len(v.requests)-1]
}

// registrationBody is a registration response answering challenge with
// credential credID.
func registrationBody(challenge, credID string) string {
	b, _ := json.Marshal(map[string]string{"challenge": encodeChallenge(challenge), "id": credID, "name": "Laptop"})

	return string(b)
}

// handleAssertionBody is an assertion answering challenge from credential
// credID, carrying the user handle handle, as a passwordless login's does.
func handleAssertionBody(challenge, credID string, handle []byte) string {
	b, _ := json.Marshal(map[string]any{"challenge": encodeChallenge(challenge), "id": credID, "handle": handle})

	return string(b)
}

// assertionBody is an assertion answering challenge from credential credID.
func assertionBody(challenge, credID string) string {
	b, _ := json.Marshal(map[string]string{"challenge": encodeChallenge(challenge), "id": credID})

	return string(b)
}

// jsonPost is a JSON POST of body to path.
func jsonPost(ctx context.Context, path, body string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	return req
}

// passkeyHarness is the enrolment harness with passkeys added: a real
// passkey.Manager over the in-memory stores and the stub verifier, sending
// its notices and emailed codes to a capturing sender, enabled on the chain.
type passkeyHarness struct {
	*enrolHarness

	verifier *passkeyVerifierStub
	creds    *passkey.MemoryCredentialStore
	notices  *capturingSender
	recovery *passkey.RecoveryDeps

	// pkOpts are further manager options, and passkeyOpts further
	// EnablePasskeys options.
	pkOpts      []passkey.Option
	passkeyOpts []httpsec.PasskeyOption

	// passkeyMethod puts the passkey MFA method on EnableMFA after TOTP, so
	// the enrolment path counts it among its enrolling methods.
	passkeyMethod bool

	// withoutEnrolment builds the chain with no enrolment path, and
	// withRecoveryGate with the recovery gate.
	withoutEnrolment bool
	withRecoveryGate bool

	manager *passkey.Manager
}

func newPasskeyHarness(t *testing.T) *passkeyHarness {
	t.Helper()

	return &passkeyHarness{
		enrolHarness: newEnrolHarness(t),
		verifier:     newPasskeyVerifierStub(t),
		creds:        passkey.NewMemoryCredentialStore(),
		notices:      &capturingSender{},
	}
}

// build builds the passkey manager and the chain carrying s.
func (h *passkeyHarness) build(t *testing.T, s *session.Session) *httpsec.Chain {
	t.Helper()

	c, err := httpsec.New(h.chainOptions(t, s)...)
	require.NoError(t, err)

	return c
}

// chainOptions are the options build assembles the chain from.
func (h *passkeyHarness) chainOptions(t *testing.T, s *session.Session) []httpsec.Option {
	t.Helper()

	m, err := passkey.New(passkey.Deps{
		Verifier:    h.verifier.mock,
		Credentials: h.creds,
		Users:       h.users,
		Sender:      h.notices,
		Recovery:    h.recovery,
	}, append([]passkey.Option{passkey.WithRepudiationContact("help@example.com")}, h.pkOpts...)...)
	require.NoError(t, err)

	h.manager = m

	if h.passkeyMethod {
		h.extraMethods = append(h.extraMethods, m.MFAMethod())
	}

	h.extra = append(h.extra, httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: m, Sessions: h.sessions}, h.passkeyOpts...))
	if h.withRecoveryGate {
		h.extra = append(h.extra, httpsec.EnableRecoveryGateForTest())
	}

	opts := h.options(t, s)
	if h.withoutEnrolment {
		opts = withoutEnrolmentPath(t, h, s)
	}

	return opts
}

// withoutEnrolmentPath is the harness's options with no enrolment path and no
// policy engine.
func withoutEnrolmentPath(t *testing.T, h *passkeyHarness, s *session.Session) []httpsec.Option {
	t.Helper()

	return append([]httpsec.Option{
		h.carries(s),
		httpsec.EnableMFA(append([]mfa.Method{h.method}, h.extraMethods...),
			append([]httpsec.MFAOption{httpsec.WithMFATokens(h.tokens)}, h.mfaOpts...)...),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}, h.logoutOpts...),
	}, h.extra...)
}

// register begins and finishes a registration through chain, returning the
// finish's outcome.
func (h *passkeyHarness) register(t *testing.T, chain *httpsec.Chain, credID string) served {
	t.Helper()

	begun := serve(t, chain, post(t.Context(), passkeyBeginPath, ""))
	require.NoError(t, begun.err)

	return serve(t, chain, jsonPost(t.Context(), passkeyFinishPath, registrationBody(h.verifier.lastCreation(t), credID)))
}

// credential is the user's one stored passkey.
func (h *passkeyHarness) credential(t *testing.T) *passkey.Credential {
	t.Helper()

	list, err := h.creds.List(t.Context(), testMFAUser)
	require.NoError(t, err)
	require.Len(t, list, 1)

	return list[0]
}
