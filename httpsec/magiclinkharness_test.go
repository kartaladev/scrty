package httpsec_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// The addresses these tests submit. One has an account and one has none, and
// the whole point of the request endpoint is that a client cannot tell which
// is which.
const (
	magicLinkKnown   = "ada@example.com"
	magicLinkUnknown = "nobody@example.com"
)

// magicLinkUserID is the reference a link records, and the one redemption
// loads by.
const magicLinkUserID identity.UserID = "u-1"

// magicLinkTTL is how long a link lives in these tests, and therefore what the
// binding cookie's lifetime must be.
const magicLinkTTL = 15 * time.Minute

// magicLinkSource is the client address most of these requests come from. It
// is a documentation-range address, so nothing here can reach a real host.
const magicLinkSource = "203.0.113.7"

func magicLinkUser() *identity.Details {
	return &identity.Details{
		ID:       magicLinkUserID,
		Name:     "Ada Lovelace",
		Username: magicLinkKnown,
		Active:   true,
	}
}

// capturingSender is the notify.Sender the magic-link manager sends through.
// It reports itself non-blocking, which is what the manager requires, and it
// keeps every message so a test can read the link a user would have received.
type capturingSender struct {
	mu   sync.Mutex
	sent []notify.Message
}

func (s *capturingSender) Send(_ context.Context, m notify.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sent = append(s.sent, m)

	return nil
}

// NonBlocking reports that Send does not wait for delivery, which is the
// promise the magic-link manager refuses to be built without.
func (s *capturingSender) NonBlocking() bool { return true }

func (s *capturingSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.sent)
}

// lastLink is the URL of the most recent message, which is what a recipient
// would click.
func (s *capturingSender) lastLink(t *testing.T) string {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	require.NotEmpty(t, s.sent, "no message was sent")

	found := linkPattern.FindString(s.sent[len(s.sent)-1].TextBody)
	require.NotEmpty(t, found, "the message carries no link")

	return found
}

var linkPattern = regexp.MustCompile(`https?://\S+`)

// lastToken is the token the most recent link carries.
func (s *capturingSender) lastToken(t *testing.T) string {
	t.Helper()

	u, err := url.Parse(s.lastLink(t))
	require.NoError(t, err)

	tok := u.Query().Get("token")
	require.NotEmpty(t, tok, "the link carries no token")

	return tok
}

// lastNext is the redirect target the most recent link carries, which is what
// the flow settled on after the allowlist had its say.
func (s *capturingSender) lastNext(t *testing.T) string {
	t.Helper()

	u, err := url.Parse(s.lastLink(t))
	require.NoError(t, err)

	return u.Query().Get("next")
}

// magicLinkHarness is what a magic-link chain is wired to: a real one-time
// token manager and a real magic-link manager, so a link that is issued can
// actually be redeemed, with doubles only where a test has to say what the
// store answered.
type magicLinkHarness struct {
	sessions *session.Manager
	users    *MockUserLoader
	tokens   *MockGenerator
	sender   *capturingSender
	manager  *magiclink.Manager

	// issued counts the access tokens the login tail asked for, which is how a
	// test pins that a refused redemption issues none, and sessionID is the
	// handle the last of them was issued for.
	issued    atomic.Int64
	sessionID atomic.Value

	// linkOpts and engine are what a case wants configured differently.
	linkOpts []httpsec.MagicLinkOption
	engine   *policy.Engine
}

func newMagicLinkHarness(t *testing.T, managerOpts ...magiclink.Option) *magicLinkHarness {
	t.Helper()

	ctrl := gomock.NewController(t)

	sessions, err := session.NewManager()
	require.NoError(t, err)

	h := &magicLinkHarness{
		sessions: sessions,
		users:    NewMockUserLoader(ctrl),
		tokens:   NewMockGenerator(ctrl),
		sender:   &capturingSender{},
	}

	h.users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, username string) (*identity.Details, error) {
			if username == magicLinkKnown {
				return magicLinkUser(), nil
			}

			return nil, identity.ErrUserNotFound
		})

	h.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id identity.UserID) (*identity.Details, error) {
			if id == magicLinkUserID {
				return magicLinkUser(), nil
			}

			return nil, identity.ErrUserNotFound
		})

	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			h.issued.Add(1)
			h.sessionID.Store(id)

			return "issued-token", nil
		})

	onetimes, err := onetime.NewManager("magic-link", onetime.WithTTL(magicLinkTTL))
	require.NoError(t, err)

	h.manager, err = magiclink.NewManager(
		onetimes, h.users, h.sender, "https://app.example.com", managerOpts...)
	require.NoError(t, err)

	return h
}

// options are the magic-link options every chain in these tests is built with:
// the collaborators the endpoints need, plus whatever the case configured.
func (h *magicLinkHarness) options() []httpsec.MagicLinkOption {
	var opts []httpsec.MagicLinkOption

	// Left out entirely when the harness has none, so a case can pin what
	// happens to a chain that was never given one.
	if h.sessions != nil {
		opts = append(opts, httpsec.WithMagicLinkSessions(h.sessions))
	}

	if h.tokens != nil {
		opts = append(opts, httpsec.WithMagicLinkTokens(h.tokens))
	}

	return append(opts, h.linkOpts...)
}

// chain assembles the chain under test.
func (h *magicLinkHarness) chain(t *testing.T) *httpsec.Chain {
	t.Helper()

	c, err := h.build()
	require.NoError(t, err)

	return c
}

// build is chain without the assertion, for the cases that are about the
// construction error itself.
func (h *magicLinkHarness) build() (*httpsec.Chain, error) {
	opts := []httpsec.Option{httpsec.EnableMagicLink(h.manager, h.options()...)}
	if h.engine != nil {
		opts = append(opts, httpsec.WithPolicyEngine(h.engine))
	}

	return httpsec.New(opts...)
}

// activeSessions counts the sessions the flow established for the user a link
// authenticates.
func (h *magicLinkHarness) activeSessions(t *testing.T) int {
	t.Helper()

	n, err := h.sessions.CountActiveByUser(t.Context(), magicLinkUserID)
	require.NoError(t, err)

	return n
}

// requestLink drives one link request through the chain and returns what the
// response said.
func (h *magicLinkHarness) requestLink(t *testing.T, c *httpsec.Chain, address string) served {
	t.Helper()

	return serve(t, c, formRequest(t.Context(), DefaultMagicLinkRequestPathForTest,
		url.Values{"email": {address}}.Encode()))
}

// The paths these tests use. They are the library's documented defaults, named
// here so a test reads like the client it stands in for.
const (
	DefaultMagicLinkRequestPathForTest = httpsec.DefaultMagicLinkRequestPath
	DefaultMagicLinkConsumePathForTest = httpsec.DefaultMagicLinkConsumePath
)

// postBody posts an arbitrary body to path, which is how the malformed-body
// cases reach the endpoint.
func postBody(ctx context.Context, path, contentType string, body io.Reader) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, body)
	req.Header.Set("Content-Type", contentType)
	req.RemoteAddr = magicLinkSource + ":51000"

	return req
}

// postValues posts a URL-encoded form from a named source address.
func postValues(ctx context.Context, path, source string, values url.Values) *http.Request {
	req := postBody(ctx, path, "application/x-www-form-urlencoded",
		strings.NewReader(values.Encode()))
	req.RemoteAddr = source + ":51000"

	return req
}

// getFrom is a GET from a named source address, which is what a mail scanner's
// prefetch looks like.
func getFrom(ctx context.Context, path, source string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	req.RemoteAddr = source + ":51000"

	return req
}

// cookieNamed returns the cookie the response set under name, or nil.
func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() { //nolint:bodyclose // the recorder's result has no body to close
		if c.Name == name {
			return c
		}
	}

	return nil
}

// link asks for a link as a browser would, and returns the token the message
// carried and the binding value that browser now holds.
func (h *magicLinkHarness) link(t *testing.T, c *httpsec.Chain) (token, nonce string) {
	t.Helper()

	out := h.requestLink(t, c, magicLinkKnown)
	require.NoError(t, out.err)

	if cookie := cookieNamed(out.rec, httpsec.DefaultBindingCookieName); cookie != nil {
		nonce = cookie.Value
	}

	return h.sender.lastToken(t), nonce
}

// redeem posts a token back as the confirmation page would, from the usual
// source, carrying the binding cookie when there is one.
func (h *magicLinkHarness) redeem(t *testing.T, c *httpsec.Chain, token, nonce string) served {
	t.Helper()

	return h.redeemFrom(t, c, magicLinkSource, token, nonce)
}

// redeemFrom is redeem from a named client address, which is what the
// rate-limit accounting is keyed on.
func (h *magicLinkHarness) redeemFrom(
	t *testing.T,
	c *httpsec.Chain,
	source, token, nonce string,
) served {
	t.Helper()

	req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, source,
		url.Values{"token": {token}})
	if nonce != "" {
		req.AddCookie(bindingCookie(nonce))
	}

	return serve(t, c, req)
}

// consumeWithNext posts a token back along with the redirect target the
// confirmation page carried.
func consumeWithNext(t *testing.T, token, nonce, next string) *http.Request {
	t.Helper()

	req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, magicLinkSource,
		url.Values{"token": {token}, "next": {next}})
	if nonce != "" {
		req.AddCookie(bindingCookie(nonce))
	}

	return req
}

// openedSession is the session the login tail created, read back from the
// store by the identifier the access token was issued for. That identifier is
// the session handle, which is how a later bearer request finds it.
func (h *magicLinkHarness) openedSession(t *testing.T) *session.Session {
	t.Helper()

	id, _ := h.sessionID.Load().(string)
	require.NotEmpty(t, id, "no access token was issued, so no session was opened")

	s, err := h.sessions.Load(t.Context(), id)
	require.NoError(t, err)

	return s
}

// urlValues builds a form body from alternating names and values, so a case
// reads as the submission it stands for.
func urlValues(pairs ...string) url.Values {
	values := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		values.Set(pairs[i], pairs[i+1])
	}

	return values
}

// bindingCookie is the cookie a browser sends back. The attributes a response
// sets are the library's business and are asserted where they are set; a
// request carries only a name and a value.
func bindingCookie(nonce string) *http.Cookie {
	//nolint:gosec // G124: this is a request cookie, which carries no attributes at all
	return &http.Cookie{Name: httpsec.DefaultBindingCookieName, Value: nonce}
}

// redeemerFunc adapts a function to httpsec.Redeemer, so a test can stand in a
// redemption that behaves as badly as it likes.
type redeemerFunc func(
	ctx context.Context,
	token, nonce string,
	checks ...magiclink.Check,
) (magiclink.Redemption, error)

func (f redeemerFunc) Redeem(
	ctx context.Context,
	token, nonce string,
	checks ...magiclink.Check,
) (magiclink.Redemption, error) {
	return f(ctx, token, nonce, checks...)
}
