package oidcprovider_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	// exchangeSecret is every confidential client's secret in authzClients.
	exchangeSecret = "0123456789abcdef0123456789abcdef"
	// authzVerifier is the verifier of authzChallenge, from RFC 7636 appendix B.
	authzVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	tiedClient     = "tied-app"
	tiedRedirect   = "https://tied.example.com/cb"
	nativeClient   = "native-refresh"
	nativeRedirect = "https://native.example.com/cb"
	weekClient     = "week-app"
	weekRedirect   = "https://week.example.com/cb"
	nonceRedirect  = "https://nonce.example.com/cb"

	// tunedClient signs ES256, with an ID token of 10 minutes and an access token of 15.
	tunedClient   = "tuned-app"
	tunedRedirect = "https://tuned.example.com/cb"
	// opaqueClient gets opaque access tokens.
	opaqueClient   = "opaque-app"
	opaqueRedirect = "https://opaque.example.com/cb"
	// audienceClient has a default audience, and resources it may ask for.
	audienceClient   = "audience-app"
	audienceRedirect = "https://audience.example.com/cb"
	// issuerAudienceClient's default audience already names the issuer.
	issuerAudienceClient   = "issuer-audience-app"
	issuerAudienceRedirect = "https://issuer-audience.example.com/cb"

	defaultAudience = "https://api.example.com"
	ordersResource  = "https://orders.example.com"
	invoiceResource = "https://invoices.example.com"
	otherResource   = "https://other.example.com"
)

// exchangeUsers is who a fixture's user loader knows, which a row changes.
type exchangeUsers struct {
	mu       sync.Mutex
	disabled map[identity.UserID]bool
	missing  map[identity.UserID]bool
	failing  bool
	// impostor makes every load answer with another user's details.
	impostor bool
	// answersNothing makes every load answer with neither details nor an error.
	answersNothing bool
	// onLoad runs at each load: the moment between a code's check and its spend.
	onLoad func()
	// username is what every load names the user by, as a chain reading usernames does.
	username string
}

func (u *exchangeUsers) load(user identity.UserID) (*identity.Details, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.onLoad != nil {
		u.onLoad()
	}
	if u.failing {
		return nil, errOutage
	}
	if u.answersNothing {
		return nil, nil //nolint:nilnil // a loader that says nothing has not said the user is live
	}
	if u.impostor {
		return activeUser("someone-else")
	}
	if u.missing[user] {
		return nil, identity.ErrUserNotFound
	}
	details, err := activeUser(user)
	if err != nil {
		return nil, err
	}
	details.Active = !u.disabled[user]
	details.Username = u.username

	return details, nil
}

func (u *exchangeUsers) set(change func(*exchangeUsers)) {
	u.mu.Lock()
	defer u.mu.Unlock()

	change(u)
}

// exchangeKeys signs with the test's fixed keys, under a generated mock, and fails or hangs
// up on request.
type exchangeKeys struct {
	*MockKeySource

	mu sync.Mutex
	// onSign and onVerify, when set, run first at each use, and an error they return is
	// the source's answer.
	onSign, onVerify func(context.Context) error
}

func newExchangeKeys(t *testing.T) *exchangeKeys {
	t.Helper()

	k := &exchangeKeys{MockKeySource: NewMockKeySource(gomock.NewController(t))}
	k.EXPECT().Signer(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, alg signingkey.Alg) (string, crypto.Signer, error) {
			if err := k.run(ctx, func() func(context.Context) error { return k.onSign }); err != nil {
				return "", nil, err
			}
			if alg == signingkey.ES256 {
				return esKid, testECKey(), nil
			}

			return rsKid, testRSAKey(), nil
		},
	).AnyTimes()
	k.EXPECT().VerificationKeys(gomock.Any()).DoAndReturn(
		func(ctx context.Context) ([]signingkey.PublicKey, error) {
			if err := k.run(ctx, func() func(context.Context) error { return k.onVerify }); err != nil {
				return nil, err
			}

			return []signingkey.PublicKey{
				{Kid: rsKid, Alg: signingkey.RS256, Key: testRSAKey().Public()},
				{Kid: esKid, Alg: signingkey.ES256, Key: testECKey().Public()},
			}, nil
		},
	).AnyTimes()

	return k
}

func (k *exchangeKeys) run(ctx context.Context, hook func() func(context.Context) error) error {
	k.mu.Lock()
	run := hook()
	k.mu.Unlock()
	if run == nil {
		return nil
	}

	return run(ctx)
}

// SupportedAlgs reports the algorithms the provider may build issuers for.
func (*exchangeKeys) SupportedAlgs() []signingkey.Alg {
	return []signingkey.Alg{signingkey.RS256, signingkey.ES256}
}

func (k *exchangeKeys) failSigning(run func(context.Context) error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.onSign = run
}

func (k *exchangeKeys) failVerifying(run func(context.Context) error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.onVerify = run
}

// exchangeFixture is a parkFixture whose users and keys a row can change, with the clients
// the exchange's own rows need besides authzClients.
type exchangeFixture struct {
	*parkFixture
	users *exchangeUsers
	keys  *exchangeKeys
}

// exchangeFixtureStart is the time a fixture's clock starts at.
var exchangeFixtureStart = time.Date(2026, 11, 4, 10, 4, 0, 0, time.UTC)

func newExchangeFixture(t *testing.T, opts ...oidcprovider.Option) *exchangeFixture {
	t.Helper()

	return newExchangeFixtureOn(t, clockwork.NewFakeClockAt(exchangeFixtureStart), opts...)
}

// newExchangeFixtureOn is newExchangeFixture on a clock the row already holds, for a store it
// builds on the same clock.
func newExchangeFixtureOn(t *testing.T, clk *clockwork.FakeClock, opts ...oidcprovider.Option) *exchangeFixture {
	t.Helper()

	store, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	consents, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)

	secret := []byte(exchangeSecret)
	both := []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken}
	scopes := []string{"openid", "profile", "offline_access"}
	clients := append(authzClients(),
		oidcprovider.Client{
			ID: tiedClient, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{tiedRedirect},
			Scopes: scopes, GrantTypes: both, EndGrantsWithSignIn: true,
		},
		oidcprovider.Client{
			ID: nativeClient, Type: oidcprovider.Public, ApplicationType: oidcprovider.Native,
			RedirectURIs: []string{nativeRedirect}, Scopes: scopes, GrantTypes: both,
		},
		oidcprovider.Client{
			ID: weekClient, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{weekRedirect},
			Scopes: scopes, GrantTypes: both, GrantAbsoluteLifetime: 7 * 24 * time.Hour,
		},
		oidcprovider.Client{
			ID: tunedClient, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{tunedRedirect},
			Scopes: scopes, IDTokenAlg: signingkey.ES256, IDTokenLifetime: 10 * time.Minute, AccessTokenLifetime: 15 * time.Minute,
		},
		oidcprovider.Client{
			ID: opaqueClient, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{opaqueRedirect},
			Scopes: scopes, OpaqueAccessTokens: true, GrantTypes: both,
		},
		oidcprovider.Client{
			ID: audienceClient, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{audienceRedirect},
			Scopes: []string{"openid", "api.read"}, DefaultAudience: []string{defaultAudience},
			Resources: []string{ordersResource, invoiceResource, otherResource},
		},
		oidcprovider.Client{
			ID: issuerAudienceClient, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{issuerAudienceRedirect},
			Scopes: []string{"openid"}, DefaultAudience: []string{issuer, defaultAudience},
		},
	)
	registry, err := oidcprovider.NewMemoryRegistry(clients)
	require.NoError(t, err)

	users := &exchangeUsers{disabled: map[identity.UserID]bool{}, missing: map[identity.UserID]bool{}}
	loader := NewMockUserLoader(gomock.NewController(t))
	loader.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) { return users.load(user) },
	).AnyTimes()

	logs := &bytes.Buffer{}
	keys := newExchangeKeys(t)
	base := []oidcprovider.Option{
		oidcprovider.WithClock(clk),
		oidcprovider.WithPendingRequestStore(store),
		oidcprovider.WithConsentStore(consents),
		oidcprovider.WithLogger(slog.New(slog.NewTextHandler(logs, nil))),
	}
	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         keys,
		Users:        loader,
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	}, append(base, opts...)...)
	require.NoError(t, err)

	return &exchangeFixture{
		parkFixture: &parkFixture{p: p, store: store, consents: consents, registry: registry, clk: clk, logs: logs},
		users:       users,
		keys:        keys,
	}
}

// issue is a code for billing-web, for openid and profile, from a fresh sign-in of u-1.
func (x *exchangeFixture) issue(t *testing.T) issuedCode {
	t.Helper()

	return issueCodeFor(t, x.parkFixture, "billing-web", nil, testSignIn(x.parkFixture, "u-1"), "openid", "profile")
}

// issueOffline is issue, also holding offline_access.
func (x *exchangeFixture) issueOffline(t *testing.T) issuedCode {
	t.Helper()

	return issueCodeFor(t, x.parkFixture, "billing-web", func(v url.Values) {
		v.Set("scope", "openid profile offline_access")
	}, testSignIn(x.parkFixture, "u-1"), "openid", "profile", "offline_access")
}

// issueTied is a code holding offline_access, for a client tied to its sign-in.
func (x *exchangeFixture) issueTied(t *testing.T) issuedCode {
	t.Helper()

	return issueCodeFor(t, x.parkFixture, tiedClient, func(v url.Values) {
		asClient(v, tiedClient, tiedRedirect)
		v.Set("scope", "openid offline_access")
	}, testSignIn(x.parkFixture, "u-1"), "openid", "offline_access")
}

// issueNonceOnly is a code with no challenge, which a PKCEOrNonce client's nonce stands in
// for.
func (x *exchangeFixture) issueNonceOnly(t *testing.T) issuedCode {
	t.Helper()

	return issueCodeFor(t, x.parkFixture, "nonce-web", func(v url.Values) {
		asClient(v, "nonce-web", nonceRedirect)
		v.Set("scope", "openid")
		v.Set("nonce", "n-1")
		v.Del("code_challenge")
		v.Del("code_challenge_method")
	}, testSignIn(x.parkFixture, "u-1"), "openid")
}

// issueRecord writes a code straight to the stores, for a state no authorization request
// can reach: a billing-web code for openid unless change says otherwise.
func (x *exchangeFixture) issueRecord(t *testing.T, change func(*oidcprovider.CodeRecord)) issuedCode {
	t.Helper()

	tokens, err := x.p.CodeManagerForTest()
	require.NoError(t, err)
	code, tok, err := tokens.Issue(t.Context(), "u-1")
	require.NoError(t, err)
	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	record := &oidcprovider.CodeRecord{
		TokenID:     tok.ID,
		ClientID:    "billing-web",
		RedirectURI: authzRedirect,
		Challenge:   authzChallenge,
		Scopes:      []string{"openid"},
		SignIn:      testSignIn(x.parkFixture, "u-1"),
		GrantFamily: family,
		ExpiresAt:   tok.ExpiresAt,
	}
	change(record)
	require.NoError(t, x.p.CodesForTest().Create(t.Context(), record))

	return issuedCode{code: code, signIn: record.SignIn}
}

// lineageOf is the stored record a refresh token names, once its shape is checked.
func lineageOf(t *testing.T, x *exchangeFixture, grant *oidcprovider.Grant, refreshToken string) *session.Session {
	t.Helper()

	secret, found := strings.CutPrefix(refreshToken, "rt."+grant.Family.String()+".")
	require.True(t, found, "a refresh token is rt.<family>.<secret>")
	lineage, err := x.p.LineageForTest().Load(t.Context(), secret)
	require.NoError(t, err)

	return lineage
}

// exchangeForm is what a client's exchange of c sends, for change to alter.
func exchangeForm(c issuedCode, redirectURI string, change func(url.Values)) url.Values {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {c.code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {authzVerifier},
	}
	if change != nil {
		change(form)
	}

	return form
}

// confidentialExchange is c's exchange by a client using its secret.
func confidentialExchange(clientID, redirectURI string, c issuedCode, change func(url.Values)) oidcprovider.TokenRequest {
	return oidcprovider.TokenRequest{
		Credentials: oidcprovider.ClientCredentials{Authorization: basic(clientID, exchangeSecret)},
		Form:        exchangeForm(c, redirectURI, change),
	}
}

// billingExchange is c's exchange by billing-web, the client most rows ask as.
func billingExchange(c issuedCode, change func(url.Values)) oidcprovider.TokenRequest {
	return confidentialExchange("billing-web", authzRedirect, c, change)
}

// assertDependencyFailure checks fixed text wrapping the cause, repeating none of it.
func assertDependencyFailure(t *testing.T, err error) {
	t.Helper()

	require.ErrorIs(t, err, oidcprovider.ErrDependency)
	assert.NotContains(t, err.Error(), errOutage.Error())
}

// consumedAt is when c's token was spent, and zero while it is unspent.
func consumedAt(t *testing.T, x *exchangeFixture, c issuedCode) time.Time {
	t.Helper()

	stored, err := x.p.CodeTokensForTest().FindByID(t.Context(), tokenIDOf(t, c.code))
	require.NoError(t, err)

	return stored.ConsumedAt
}

func assertUnspent(t *testing.T, x *exchangeFixture, c issuedCode) {
	t.Helper()

	assert.True(t, consumedAt(t, x, c).IsZero(), "the code is left unspent")
}

func assertSpent(t *testing.T, x *exchangeFixture, c issuedCode) {
	t.Helper()

	assert.False(t, consumedAt(t, x, c).IsZero(), "the code is spent")
}

// assertRefused checks the protocol's code, and that nothing else is said.
func assertRefused(t *testing.T, err error, code string) {
	t.Helper()

	var refusal *oidcprovider.Error
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, code, refusal.Code)
	assert.Equal(t, "oidcprovider: "+code, err.Error(), "a refusal says nothing of which check failed")
}

// grantOf is the grant c's exchange writes.
func grantOf(t *testing.T, x *exchangeFixture, c issuedCode) *oidcprovider.Grant {
	t.Helper()

	grant, err := x.p.GrantsForTest().Load(t.Context(), recordOf(t, x.parkFixture, c.code).GrantFamily)
	require.NoError(t, err)

	return grant
}

// mockedCodeTokens is a generated mock holding its codes in a memory store, whose reads and
// spends a row sets up itself.
func mockedCodeTokens(t *testing.T) (*MockCodeTokenStore, *onetime.MemoryStore) {
	t.Helper()

	memory, err := onetime.NewMemoryStore()
	require.NoError(t, err)
	tokens := NewMockCodeTokenStore(gomock.NewController(t))
	tokens.EXPECT().Insert(gomock.Any(), gomock.Any()).DoAndReturn(memory.Insert).AnyTimes()

	return tokens, memory
}

// byOwner and byAnotherClient are the two who can present a billing-web code.
func byOwner(c issuedCode) oidcprovider.TokenRequest { return billingExchange(c, nil) }

func byAnotherClient(c issuedCode) oidcprovider.TokenRequest {
	return confidentialExchange("code-only", "https://code-only.example.com/cb", c, nil)
}

func TestProvider_ExchangeCode(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    func(*testing.T) []oidcprovider.Option
		ctx     func(context.Context) context.Context
		arrange func(*testing.T, *exchangeFixture) (issuedCode, oidcprovider.TokenRequest)
		assert  func(*testing.T, *exchangeFixture, issuedCode, *oidcprovider.TokenResponse, error)
	}

	// endOf ends the sign-in c came from, as Provider.EndSignIn will through this operation.
	endOf := func(t *testing.T, x *exchangeFixture, c issuedCode) {
		t.Helper()
		_, err := x.p.GrantsForTest().EndSignIns(t.Context(), oidcprovider.SignInSelector{Family: c.signIn.Family}, x.clk.Now())
		require.NoError(t, err)
	}
	revokeUser := func(t *testing.T, x *exchangeFixture) {
		t.Helper()
		_, err := x.p.GrantsForTest().RevokeByUser(t.Context(), "u-1", oidcprovider.CauseRecovery, x.clk.Now())
		require.NoError(t, err)
	}
	refused := func(t *testing.T, _ *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
		t.Helper()
		assertRefused(t, err, oidcprovider.CodeInvalidGrant)
		assert.Nil(t, res)
	}

	refusedAndUnspent := func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
		t.Helper()
		refused(t, x, c, res, err)
		assertUnspent(t, x, c)
	}
	dependencyFailedAndUnspent := func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
		t.Helper()
		assertDependencyFailure(t, err)
		assert.Nil(t, res)
		assertUnspent(t, x, c)
	}
	// refusedUnspent is a billing-web exchange change spoils: it is refused, and the same
	// code then exchanges.
	refusedUnspent := func(name string, change func(url.Values)) testCase {
		return testCase{
			name: name + " is refused, unspent",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, change)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refused(t, x, c, res, err)
				_, err = x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err, "the refusal left the code unspent")
			},
		}
	}
	// verifierOfBadSyntax is a code whose challenge is the verifier's own hash, so only the
	// verifier's syntax can refuse it.
	verifierOfBadSyntax := func(name, verifier string) testCase {
		return testCase{
			name: name + " is refused, unspent",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				sum := sha256.Sum256([]byte(verifier))
				c := issueCodeFor(t, x.parkFixture, "billing-web", func(v url.Values) {
					v.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
				}, testSignIn(x.parkFixture, "u-1"), "openid", "profile")

				return c, billingExchange(c, func(v url.Values) { v.Set("code_verifier", verifier) })
			},
			assert: refusedAndUnspent,
		}
	}
	// dpopRow is a code bound to a key by its request's dpop_jkt, exchanged by a request
	// proving binding.
	dpopRow := func(name string, binding oidcprovider.Binding, exchanges bool) testCase {
		return testCase{
			name: name,
			opts: func(*testing.T) []oidcprovider.Option { return []oidcprovider.Option{oidcprovider.WithDPoP()} },
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueCodeFor(t, x.parkFixture, "billing-web", func(v url.Values) {
					v.Set("dpop_jkt", authzChallenge)
				}, testSignIn(x.parkFixture, "u-1"), "openid", "profile")
				req := billingExchange(c, nil)
				req.Binding = binding

				return c, req
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				if exchanges {
					require.NoError(t, err)

					return
				}
				refusedAndUnspent(t, x, c, res, err)
			},
		}
	}
	// outage is a request answered as a failing store, which an ERROR line records because
	// the token manager keeps the store's own error to itself.
	outage := func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
		t.Helper()
		dependencyFailedAndUnspent(t, x, c, res, err)
		assert.Contains(t, x.logs.String(), "level=ERROR")
	}
	// spendFails is a store that answers its reads, and cannot record the spend.
	spendFails := func(name string, request func(issuedCode) oidcprovider.TokenRequest) testCase {
		return testCase{
			name: name,
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				tokens, memory := mockedCodeTokens(t)
				tokens.EXPECT().FindByID(gomock.Any(), gomock.Any()).DoAndReturn(memory.FindByID).AnyTimes()
				tokens.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).Return(errOutage)

				return []oidcprovider.Option{oidcprovider.WithCodeTokenStore(tokens)}
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, request(c)
			},
			assert: outage,
		}
	}
	// readFailsOnce is an outage that ended between the check and the second look.
	readFailsOnce := func(name string, request func(issuedCode) oidcprovider.TokenRequest) testCase {
		return testCase{
			name: name,
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				tokens, memory := mockedCodeTokens(t)
				gomock.InOrder(
					tokens.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, errOutage),
					tokens.EXPECT().FindByID(gomock.Any(), gomock.Any()).DoAndReturn(memory.FindByID).AnyTimes(),
				)

				return []oidcprovider.Option{oidcprovider.WithCodeTokenStore(tokens)}
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, request(c)
			},
			assert: outage,
		}
	}
	// hungUp is a caller who left: its own context's error, no outage, and no ERROR line.
	hungUp := func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
		t.Helper()
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, oidcprovider.ErrDependency)
		assert.Nil(t, res)
		assertUnspent(t, x, c)
		assert.NotContains(t, x.logs.String(), "level=ERROR")
	}
	// hungUpAtSpend is a caller leaving at the very moment of the spend.
	hungUpAtSpend := func() testCase {
		var leaving context.Context

		return testCase{
			name: "a caller hanging up at the spend matches its own context's error, with no ERROR line",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				var leave context.CancelFunc
				leaving, leave = context.WithCancel(t.Context())
				t.Cleanup(leave)
				tokens, memory := mockedCodeTokens(t)
				tokens.EXPECT().FindByID(gomock.Any(), gomock.Any()).DoAndReturn(memory.FindByID).AnyTimes()
				tokens.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, _ id.ID, _ time.Time) error {
						leave()

						return ctx.Err()
					})

				return []oidcprovider.Option{oidcprovider.WithCodeTokenStore(tokens)}
			},
			ctx: func(context.Context) context.Context { return leaving },
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, byOwner(c)
			},
			assert: hungUp,
		}
	}
	// requestRow is a request that never reaches the code, which stays unspent.
	requestRow := func(name, code string, change func(url.Values)) testCase {
		return testCase{
			name: name,
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, change)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, code)
				assert.Nil(t, res)
				assertUnspent(t, x, c)
			},
		}
	}

	cases := []testCase{
		{
			name: "auth_time is the sign-in's",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				signIn := testSignIn(x.parkFixture, "u-1")
				signIn.AuthenticatedAt = x.clk.Now().Add(-4 * time.Minute)
				c := issueCodeFor(t, x.parkFixture, "billing-web", nil, signIn, "openid", "profile")

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				grant := grantOf(t, x, c)
				assert.True(t, grant.AuthTime.Equal(time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)),
					"the sign-in authenticated at 10:00 and the exchange ran at 10:04, got %s", grant.AuthTime)
				assert.True(t, lineageOf(t, x, grant, res.RefreshToken).AuthenticatedAt.Equal(grant.AuthTime),
					"the lineage states the sign-in's time too")
				assert.Equal(t, c.signIn.AMR, grant.AMR)
				assert.Equal(t, c.signIn.ACR, grant.ACR)
				assert.Equal(t, c.signIn.Family, grant.SignInFamily)
			},
		},
		{
			name: "a code outstanding when its sign-in ends is refused",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				endOf(t, x, c)

				return c, billingExchange(c, nil)
			},
			assert: refused,
		},
		{
			name: "a code holding offline_access survives its sign-in's end",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issueOffline(t)
				endOf(t, x, c)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, _ *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, grantOf(t, x, c).Revoked)
			},
		},
		{
			name: "a tied client's offline code ends with its sign-in",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issueTied(t)
				endOf(t, x, c)

				return c, confidentialExchange(tiedClient, tiedRedirect, c, nil)
			},
			assert: refused,
		},
		{
			name: "a code outstanding when its user's grants are revoked is refused",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				revokeUser(t, x)

				return c, billingExchange(c, nil)
			},
			assert: refused,
		},
		{
			name: "an offline code does not survive its user's grants being revoked",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issueOffline(t)
				revokeUser(t, x)

				return c, billingExchange(c, nil)
			},
			assert: refused,
		},
		{
			name: "a user disabled since the code was issued is refused",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				x.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })

				return c, billingExchange(c, nil)
			},
			assert: refused,
		},
		{
			name: "a user gone since the code was issued is refused",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				x.users.set(func(u *exchangeUsers) { u.missing["u-1"] = true })

				return c, billingExchange(c, nil)
			},
			assert: refused,
		},
		{
			name: "a wrong client secret leaves the code unspent",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				req := billingExchange(c, nil)
				req.Credentials.Authorization = basic("billing-web", "another-secret-of-thirty-two-bytes")

				return c, req
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidClient)
				assert.Nil(t, res)
				_, err = x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err, "the same code exchanges with the right secret")
			},
		},
		{
			name: "another client's code is consumed, then refused",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, confidentialExchange("code-only", "https://code-only.example.com/cb", c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refused(t, x, c, res, err)
				assertSpent(t, x, c)
				res, err = x.p.Token(t.Context(), billingExchange(c, nil))
				refused(t, x, c, res, err)
			},
		},
		refusedUnspent("a wrong verifier", func(v url.Values) { v.Set("code_verifier", strings.Repeat("a", 43)) }),
		refusedUnspent("a missing verifier", func(v url.Values) { v.Del("code_verifier") }),
		refusedUnspent("another redirect URI", func(v url.Values) { v.Set("redirect_uri", authzRedirect+"/") }),
		refusedUnspent("a missing redirect URI", func(v url.Values) { v.Del("redirect_uri") }),
		verifierOfBadSyntax("a verifier of 16 characters whose hash matches", strings.Repeat("v", 16)),
		verifierOfBadSyntax("a verifier of 129 characters whose hash matches", strings.Repeat("v", 129)),
		verifierOfBadSyntax("a verifier with a reserved character whose hash matches", strings.Repeat("v", 42)+"!"),
		{
			name: "a verifier for a code with no challenge is refused, unspent",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issueNonceOnly(t)

				return c, confidentialExchange("nonce-web", nonceRedirect, c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refused(t, x, c, res, err)
				_, err = x.p.Token(t.Context(), confidentialExchange("nonce-web", nonceRedirect, c, func(v url.Values) { v.Del("code_verifier") }))
				require.NoError(t, err, "the code with no challenge exchanges without a verifier")
			},
		},
		{
			name: "a code holding neither a challenge nor a nonce is refused",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issueRecord(t, func(r *oidcprovider.CodeRecord) {
					r.ClientID, r.RedirectURI, r.Challenge, r.Nonce = "nonce-web", nonceRedirect, "", ""
				})

				return c, confidentialExchange("nonce-web", nonceRedirect, c, func(v url.Values) { v.Del("code_verifier") })
			},
			assert: refusedAndUnspent,
		},
		{
			name: "a code with no challenge is refused once its client requires PKCE",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issueNonceOnly(t)
				client := authzClients()[2]
				client.PKCE = oidcprovider.PKCERequired
				require.NoError(t, x.registry.Put(t.Context(), client))

				return c, confidentialExchange("nonce-web", nonceRedirect, c, func(v url.Values) { v.Del("code_verifier") })
			},
			assert: refusedAndUnspent,
		},
		{
			name: "a code 61 seconds old is refused",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				x.clk.Advance(61 * time.Second)

				return c, billingExchange(c, nil)
			},
			assert: refused,
		},
		{
			name: "a code is refused at the very instant it expires",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				x.clk.Advance(60 * time.Second)

				return c, billingExchange(c, nil)
			},
			assert: refused,
		},
		{
			name: "a code record past its expiry is judged by the provider's clock",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issueRecord(t, func(r *oidcprovider.CodeRecord) { r.ExpiresAt = x.clk.Now().Add(-time.Second) })

				return c, billingExchange(c, nil)
			},
			assert: refusedAndUnspent,
		},
		{
			name: "a token with no record behind it is refused",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				tokens, err := x.p.CodeManagerForTest()
				require.NoError(t, err)
				code, _, err := tokens.Issue(t.Context(), "u-1")
				require.NoError(t, err)
				c := issuedCode{code: code}

				return c, billingExchange(c, nil)
			},
			assert: refused,
		},
		{
			name: "success writes the grant from the code, and a lineage of its family",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueCodeFor(t, x.parkFixture, "billing-web", func(v url.Values) {
					v.Set("resource", "https://api.example.com")
				}, testSignIn(x.parkFixture, "u-1"), "openid", "profile")

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "openid profile", res.Scope)
				assert.Equal(t, "Bearer", res.TokenType)
				assert.Equal(t, 300, res.ExpiresIn)
				assert.NotEmpty(t, res.AccessToken)
				assert.NotEmpty(t, res.IDToken)
				assert.NotEmpty(t, res.RefreshToken)
				assertSpent(t, x, c)

				record := recordOf(t, x.parkFixture, c.code)
				grant := grantOf(t, x, c)
				assert.Equal(t, oidcprovider.Grant{
					Family:            record.GrantFamily,
					User:              "u-1",
					ClientID:          "billing-web",
					Scopes:            []string{"openid", "profile"},
					Resources:         []string{"https://api.example.com"},
					AuthTime:          c.signIn.AuthenticatedAt,
					AMR:               c.signIn.AMR,
					ACR:               c.signIn.ACR,
					CodeID:            record.TokenID,
					SignInFamily:      c.signIn.Family,
					ExternalIssuer:    c.signIn.ExternalIssuer,
					ExternalSessionID: c.signIn.ExternalSessionID,
					HoldsLineage:      true,
					CreatedAt:         x.clk.Now(),
					ExpiresAt:         c.signIn.AbsoluteExpiresAt,
				}, *grant)

				lineage := lineageOf(t, x, grant, res.RefreshToken)
				assert.Equal(t, record.GrantFamily, lineage.FamilyID)
				assert.Equal(t, identity.UserID("u-1"), lineage.UserID)
				assert.True(t, lineage.AuthenticatedAt.Equal(c.signIn.AuthenticatedAt), "a lineage states the sign-in's time too")
				assert.True(t, lineage.AbsoluteExpiresAt.Equal(grant.ExpiresAt))
				assert.True(t, lineage.IdleExpiresAt.Equal(grant.ExpiresAt), "30 days idle is past this grant's deadline")
			},
		},
		{
			name: "an online grant ends at the sign-in's absolute deadline",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				signIn := testSignIn(x.parkFixture, "u-1")
				signIn.AbsoluteExpiresAt = x.clk.Now().Add(12 * time.Hour)
				c := issueCodeFor(t, x.parkFixture, "billing-web", nil, signIn, "openid", "profile")

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				grant := grantOf(t, x, c)
				assert.True(t, grant.ExpiresAt.Equal(x.clk.Now().Add(12*time.Hour)), "got %s", grant.ExpiresAt)
				assert.True(t, lineageOf(t, x, grant, res.RefreshToken).AbsoluteExpiresAt.Equal(grant.ExpiresAt))
			},
		},
		{
			name: "an offline grant outlives its sign-in's deadline, for 90 days by default",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issueOffline(t)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				grant := grantOf(t, x, c)
				assert.True(t, grant.Offline)
				assert.False(t, grant.EndsWithSignIn)
				assert.True(t, grant.HoldsLineage)
				assert.True(t, grant.ExpiresAt.Equal(x.clk.Now().Add(90*24*time.Hour)), "got %s", grant.ExpiresAt)
				lineage := lineageOf(t, x, grant, res.RefreshToken)
				assert.True(t, lineage.AbsoluteExpiresAt.Equal(grant.ExpiresAt))
				assert.True(t, lineage.IdleExpiresAt.Equal(x.clk.Now().Add(30*24*time.Hour)), "got %s", lineage.IdleExpiresAt)
			},
		},
		{
			name: "a client's own absolute lifetime replaces the 90 days",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueCodeFor(t, x.parkFixture, weekClient, func(v url.Values) {
					asClient(v, weekClient, weekRedirect)
					v.Set("scope", "openid offline_access")
				}, testSignIn(x.parkFixture, "u-1"), "openid", "offline_access")

				return c, confidentialExchange(weekClient, weekRedirect, c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, _ *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, grantOf(t, x, c).ExpiresAt.Equal(x.clk.Now().Add(7*24*time.Hour)))
			},
		},
		{
			name: "a tied client's offline grant is marked so, and ends at the sign-in's deadline",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issueTied(t)

				return c, confidentialExchange(tiedClient, tiedRedirect, c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				grant := grantOf(t, x, c)
				assert.True(t, grant.Offline)
				assert.True(t, grant.EndsWithSignIn)
				assert.True(t, grant.HoldsLineage)
				assert.NotEmpty(t, res.RefreshToken)
				assert.True(t, grant.ExpiresAt.Equal(c.signIn.AbsoluteExpiresAt), "got %s", grant.ExpiresAt)
			},
		},
		{
			name: "an online code is refused once its sign-in's deadline has passed",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				signIn := testSignIn(x.parkFixture, "u-1")
				signIn.AbsoluteExpiresAt = x.clk.Now().Add(30 * time.Second)
				c := issueCodeFor(t, x.parkFixture, "billing-web", nil, signIn, "openid", "profile")
				x.clk.Advance(30 * time.Second)

				return c, billingExchange(c, nil)
			},
			assert: refusedAndUnspent,
		},
		{
			name: "an offline code does not need its sign-in's deadline to be ahead",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				signIn := testSignIn(x.parkFixture, "u-1")
				signIn.AbsoluteExpiresAt = x.clk.Now().Add(30 * time.Second)
				c := issueCodeFor(t, x.parkFixture, "billing-web", func(v url.Values) {
					v.Set("scope", "openid offline_access")
				}, signIn, "openid", "offline_access")
				x.clk.Advance(30 * time.Second)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, _ *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, grantOf(t, x, c).Revoked)
			},
		},
		{
			name: "a client with no refresh grant gets a row holding no lineage, to the sign-in's deadline",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueCodeFor(t, x.parkFixture, "code-only", func(v url.Values) {
					asClient(v, "code-only", "https://code-only.example.com/cb")
				}, testSignIn(x.parkFixture, "u-1"), "openid", "profile")

				return c, confidentialExchange("code-only", "https://code-only.example.com/cb", c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, res.RefreshToken)
				grant := grantOf(t, x, c)
				assert.False(t, grant.HoldsLineage)
				assert.True(t, grant.ExpiresAt.Equal(c.signIn.AbsoluteExpiresAt), "got %s", grant.ExpiresAt)
				assert.Equal(t, 0, x.p.LineageHeldForTest(), "no lineage was written")
			},
		},
		{
			name: "a no-lineage grant ends at the sign-in's deadline even past the client's absolute lifetime",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				client := authzClients()[1]
				client.GrantAbsoluteLifetime = time.Hour
				require.NoError(t, x.registry.Put(t.Context(), client))
				c := issueCodeFor(t, x.parkFixture, "code-only", func(v url.Values) {
					asClient(v, "code-only", "https://code-only.example.com/cb")
				}, testSignIn(x.parkFixture, "u-1"), "openid", "profile")

				return c, confidentialExchange("code-only", "https://code-only.example.com/cb", c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, _ *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, grantOf(t, x, c).ExpiresAt.Equal(c.signIn.AbsoluteExpiresAt))
			},
		},
		dpopRow("a dpop_jkt another key proves is refused, unspent", oidcprovider.Binding{JKT: "another-key"}, false),
		dpopRow("a dpop_jkt no key proves is refused, unspent", oidcprovider.Binding{}, false),
		dpopRow("a dpop_jkt the proof's key matches exchanges", oidcprovider.Binding{JKT: authzChallenge}, true),
		{
			name: "a public client's grant is bound to the key of its proof",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueCodeFor(t, x.parkFixture, nativeClient, func(v url.Values) {
					asClient(v, nativeClient, nativeRedirect)
					v.Set("scope", "openid offline_access")
				}, testSignIn(x.parkFixture, "u-1"), "openid", "offline_access")

				return c, oidcprovider.TokenRequest{
					Form:    exchangeForm(c, nativeRedirect, func(v url.Values) { v.Set("client_id", nativeClient) }),
					Binding: oidcprovider.Binding{JKT: boundJKT},
				}
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				grant := grantOf(t, x, c)
				assert.Equal(t, boundJKT, grant.KeyBinding)
				assert.Equal(t, session.KeyBinding{JKT: boundJKT}, lineageOf(t, x, grant, res.RefreshToken).KeyBinding)
			},
		},
		{
			name: "a confidential client's grant is not bound to its proof's key",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				req := billingExchange(c, nil)
				req.Binding = oidcprovider.Binding{JKT: boundJKT}

				return c, req
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				grant := grantOf(t, x, c)
				assert.Empty(t, grant.KeyBinding)
				assert.Equal(t, session.KeyBinding{}, lineageOf(t, x, grant, res.RefreshToken).KeyBinding)
			},
		},
		{
			name: "the grant row is written before the lineage",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				ctrl := gomock.NewController(t)
				grants := NewMockGrantStore(ctrl)
				grants.EXPECT().UseCodes(gomock.Any()).Return(nil)
				lineages := NewMockLineageSessionStore(ctrl)
				gomock.InOrder(
					grants.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, oidcprovider.ErrNotFound),
					grants.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, g *oidcprovider.Grant) error {
						assert.True(t, g.HoldsLineage, "the row says a lineage follows it")

						return nil
					}),
					lineages.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil),
				)

				return []oidcprovider.Option{
					oidcprovider.WithGrantStore(grants),
					oidcprovider.WithRefreshTokenStore(oplineage.New(lineages)),
				}
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, _ *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEmpty(t, res.RefreshToken)
			},
		},
		{
			name: "a lineage that cannot be written answers an error with no token, and the grant row is kept",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				lineages := NewMockLineageSessionStore(gomock.NewController(t))
				lineages.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errOutage)

				return []oidcprovider.Option{oidcprovider.WithRefreshTokenStore(oplineage.New(lineages))}
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assertSpent(t, x, c)
				grant := grantOf(t, x, c)
				assert.False(t, grant.Revoked)
				assert.True(t, grant.HoldsLineage)
			},
		},
		{
			name: "a grant that cannot be written writes no lineage",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				ctrl := gomock.NewController(t)
				grants := NewMockGrantStore(ctrl)
				grants.EXPECT().UseCodes(gomock.Any()).Return(nil)
				grants.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, oidcprovider.ErrNotFound)
				grants.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errOutage)

				return []oidcprovider.Option{
					oidcprovider.WithGrantStore(grants),
					oidcprovider.WithRefreshTokenStore(oplineage.New(NewMockLineageSessionStore(ctrl))),
				}
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assertSpent(t, x, c)
			},
		},
		{
			name: "a tombstone that cannot be read fails, unspent",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				grants := NewMockGrantStore(gomock.NewController(t))
				grants.EXPECT().UseCodes(gomock.Any()).Return(nil)
				grants.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, errOutage)

				return []oidcprovider.Option{oidcprovider.WithGrantStore(grants)}
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: dependencyFailedAndUnspent,
		},
		{
			name: "a caller who left matches its own context's error, and is no outage",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				grants := NewMockGrantStore(gomock.NewController(t))
				grants.EXPECT().UseCodes(gomock.Any()).Return(nil)
				grants.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, _ id.ID) (*oidcprovider.Grant, error) {
					return nil, ctx.Err()
				})

				return []oidcprovider.Option{oidcprovider.WithGrantStore(grants)}
			},
			ctx: func(ctx context.Context) context.Context {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()

				return cancelled
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Nil(t, res)
				assertUnspent(t, x, c)
			},
		},
		{
			name: "a user that cannot be loaded fails, unspent",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				x.users.set(func(u *exchangeUsers) { u.failing = true })

				return c, billingExchange(c, nil)
			},
			assert: dependencyFailedAndUnspent,
		},
		{
			name: "a code record that cannot be read fails, unspent",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				memory, err := oidcprovider.NewMemoryCodeStore()
				require.NoError(t, err)
				codes := NewMockCodeStore(gomock.NewController(t))
				codes.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(memory.Create)
				codes.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, errOutage)

				return []oidcprovider.Option{oidcprovider.WithCodeStore(codes)}
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: dependencyFailedAndUnspent,
		},
		{
			name: "a code-token store that cannot answer fails, rather than calling the code bad",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				tokens := NewMockCodeTokenStore(gomock.NewController(t))
				tokens.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(nil)
				tokens.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, errOutage).AnyTimes()

				return []oidcprovider.Option{oidcprovider.WithCodeTokenStore(tokens)}
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, _ *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
			},
		},
		spendFails("a store failing at the spend fails for the code's own client, rather than calling the code bad", byOwner),
		spendFails("a store failing at the spend fails for another client too", byAnotherClient),
		readFailsOnce("a read failing once fails for the code's own client, rather than calling the code bad", byOwner),
		readFailsOnce("a read failing once fails for another client too", byAnotherClient),
		{
			name: "a caller hanging up at the check matches its own context's error, with no ERROR line",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				memory, err := onetime.NewMemoryStore()
				require.NoError(t, err)

				return []oidcprovider.Option{oidcprovider.WithCodeTokenStore(&contextTokens{Store: memory})}
			},
			ctx: func(ctx context.Context) context.Context {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()

				return cancelled
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, byOwner(c)
			},
			assert: hungUp,
		},
		hungUpAtSpend(),
		{
			name: "a code expiring between its check and its spend is refused, and no failure",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				x.users.set(func(u *exchangeUsers) {
					u.onLoad = func() { x.clk.Advance(61 * time.Second) }
				})

				return c, byOwner(c)
			},
			assert: refusedAndUnspent,
		},
		{
			name: "a live code's identifier with another secret is refused, and no failure",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				tokenID, _, _ := strings.Cut(c.code, ".")

				return c, byOwner(issuedCode{code: tokenID + ".never-issued"})
			},
			assert: refusedAndUnspent,
		},
		{
			name: "a live token of another purpose is refused, and no failure",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				const secret = "another-purposes-secret"
				tokenID := tokenIDText(t)
				sum := sha256.Sum256([]byte(secret))
				require.NoError(t, x.p.CodeTokensForTest().Insert(t.Context(), onetime.Token{
					ID: id.MustParse(tokenID), Purpose: "another-purpose", Subject: "u-1", SecretHash: sum[:],
					IssuedAt: x.clk.Now(), ExpiresAt: x.clk.Now().Add(time.Minute),
				}))

				return issuedCode{}, byOwner(issuedCode{code: tokenID + "." + secret})
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refused(t, x, c, res, err)
			},
		},
		{
			name: "a user loaded under another identifier is refused, unspent",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				x.users.set(func(u *exchangeUsers) { u.impostor = true })

				return c, byOwner(c)
			},
			assert: refusedAndUnspent,
		},
		{
			name: "a loader answering with neither details nor an error is refused, unspent",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				x.users.set(func(u *exchangeUsers) { u.answersNothing = true })

				return c, byOwner(c)
			},
			assert: refusedAndUnspent,
		},
		{
			name: "an offline code of a client with no refresh grant is refused past its sign-in's deadline",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issueRecord(t, func(r *oidcprovider.CodeRecord) {
					r.ClientID, r.RedirectURI = "code-only", "https://code-only.example.com/cb"
					r.Offline = true
					r.SignIn.AbsoluteExpiresAt = x.clk.Now()
				})

				return c, byAnotherClient(c)
			},
			assert: refusedAndUnspent,
		},
		requestRow("no grant_type is invalid_request", oidcprovider.CodeInvalidRequest, func(v url.Values) { v.Del("grant_type") }),
		requestRow("a grant type no one may use is unsupported", oidcprovider.CodeUnsupportedGrantType, func(v url.Values) { v.Set("grant_type", "password") }),
		requestRow("no code is invalid_request", oidcprovider.CodeInvalidRequest, func(v url.Values) { v.Del("code") }),
		requestRow("an empty code counts as none", oidcprovider.CodeInvalidRequest, func(v url.Values) { v.Set("code", "") }),
		requestRow("a repeated code is invalid_request", oidcprovider.CodeInvalidRequest, func(v url.Values) { v.Add("code", "another") }),
		requestRow("a repeated verifier is invalid_request", oidcprovider.CodeInvalidRequest, func(v url.Values) { v.Add("code_verifier", authzVerifier) }),
		{
			name: "a credential in the query is invalid_request, unspent",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				req := billingExchange(c, nil)
				req.Query = url.Values{"client_secret": {exchangeSecret}}

				return c, req
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidRequest)
				assert.Nil(t, res)
				assertUnspent(t, x, c)
			},
		},
		{
			name: "a client not registered for refreshing is unauthorized for it",
			arrange: func(t *testing.T, _ *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()

				return issuedCode{}, oidcprovider.TokenRequest{
					Credentials: oidcprovider.ClientCredentials{Authorization: basic("code-only", exchangeSecret)},
					Form:        url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt.a.b"}},
				}
			},
			assert: func(t *testing.T, _ *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeUnauthorizedClient)
				assert.Nil(t, res)
			},
		},
		{
			name: "a client not registered for codes is unauthorized for them, unspent",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				client := authzClients()[0]
				client.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantRefreshToken}
				require.NoError(t, x.registry.Put(t.Context(), client))

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeUnauthorizedClient)
				assert.Nil(t, res)
				assertUnspent(t, x, c)
			},
		},
		{
			name: "a request and a response print and log redacted",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, _ *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				req := billingExchange(c, nil)
				for _, text := range []string{fmt.Sprintf("%v %+v", req, *res), fmt.Sprintf("%s %#v", req, res)} {
					assert.NotContains(t, text, c.code)
					assert.NotContains(t, text, authzVerifier)
					assert.NotContains(t, text, res.RefreshToken)
				}
				assert.Equal(t, "[REDACTED]", req.LogValue().String())
				assert.Equal(t, "[REDACTED]", res.LogValue().String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []oidcprovider.Option
			if tc.opts != nil {
				opts = tc.opts(t)
			}
			x := newExchangeFixture(t, opts...)
			c, req := tc.arrange(t, x)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			res, err := x.p.Token(ctx, req)
			tc.assert(t, x, c, res, err)
			if c.code != "" {
				assert.NotContains(t, x.logs.String(), c.code, "no log line carries the code")
				if err != nil {
					assert.NotContains(t, err.Error(), c.code)
				}
			}
		})
	}
}

// barrierGrants holds each grant's Create at a barrier a row releases, so that what a row
// runs meanwhile has landed between the code's spend and the grant's commit.
type barrierGrants struct {
	oidcprovider.GrantStore

	entered, release chan struct{}
}

func newBarrierGrants(t *testing.T) *barrierGrants {
	t.Helper()

	memory, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)

	return &barrierGrants{GrantStore: memory, entered: make(chan struct{}), release: make(chan struct{})}
}

// Create implements oidcprovider.GrantStore.
func (b *barrierGrants) Create(ctx context.Context, g *oidcprovider.Grant) error {
	close(b.entered)
	select {
	case <-b.release:
		return b.GrantStore.Create(ctx, g)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// watchedGrants fails a revocation on request, and refuses one made on a context that has
// ended, as a store reaching a database would.
type watchedGrants struct {
	oidcprovider.GrantStore

	failing atomic.Bool
}

// Revoke implements oidcprovider.GrantStore.
func (w *watchedGrants) Revoke(ctx context.Context, family id.ID, cause oidcprovider.RevocationCause, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.failing.Load() {
		return errOutage
	}

	return w.GrantStore.Revoke(ctx, family, cause, at)
}

// meetingTokens holds the first spend until the second arrives, so both have passed their
// check, and exactly one of the two spends can win.
type meetingTokens struct {
	onetime.Store

	arrived atomic.Int32
	met     chan struct{}
}

// Consume implements onetime.Store.
func (m *meetingTokens) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	if m.arrived.Add(1) == 2 {
		close(m.met)
	}
	select {
	case <-m.met:
		return m.Store.Consume(ctx, tokenID, at)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// contextTokens refuses a read made on a context that has ended, as a store reaching a
// database would.
type contextTokens struct {
	onetime.Store
}

// FindByID implements onetime.Store.
func (c *contextTokens) FindByID(ctx context.Context, tokenID id.ID) (*onetime.Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return c.Store.FindByID(ctx, tokenID)
}

// exchanged is one request's answer.
type exchanged struct {
	res *oidcprovider.TokenResponse
	err error
}

// exchangeAsync runs a request on its own goroutine, whose answer the channel gives.
func exchangeAsync(ctx context.Context, x *exchangeFixture, req oidcprovider.TokenRequest) <-chan exchanged {
	answer := make(chan exchanged, 1)
	go func() {
		res, err := x.p.Token(ctx, req)
		answer <- exchanged{res: res, err: err}
	}()

	return answer
}

// spendAsAnotherClient leaves c spent with no grant stored behind it.
func spendAsAnotherClient(t *testing.T, x *exchangeFixture, c issuedCode) {
	t.Helper()

	_, err := x.p.Token(t.Context(), confidentialExchange("code-only", "https://code-only.example.com/cb", c, nil))
	assertRefused(t, err, oidcprovider.CodeInvalidGrant)
	assertSpent(t, x, c)
}

func TestProvider_CodeReplay(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		barrier bool
		opts    func(*testing.T) []oidcprovider.Option
		run     func(*testing.T, *exchangeFixture, *barrierGrants)
	}

	// raceCommit runs during between the first exchange's spend and its commit, and returns
	// the first exchange's answer once it has been let go. The barrier makes the order the
	// only one possible, so no sleep is involved.
	raceCommit := func(t *testing.T, x *exchangeFixture, barrier *barrierGrants, c issuedCode, during func()) exchanged {
		t.Helper()

		first := exchangeAsync(t.Context(), x, billingExchange(c, nil))
		<-barrier.entered
		during()
		close(barrier.release)

		return <-first
	}
	// issueNative is a code for a public client, which proves nothing but the verifier.
	issueNative := func(t *testing.T, x *exchangeFixture) issuedCode {
		t.Helper()

		return issueCodeFor(t, x.parkFixture, nativeClient, func(v url.Values) {
			asClient(v, nativeClient, nativeRedirect)
			v.Set("scope", "openid offline_access")
		}, testSignIn(x.parkFixture, "u-1"), "openid", "offline_access")
	}
	nativeExchange := func(c issuedCode, change func(url.Values)) oidcprovider.TokenRequest {
		return oidcprovider.TokenRequest{Form: exchangeForm(c, nativeRedirect, func(v url.Values) {
			v.Set("client_id", nativeClient)
			if change != nil {
				change(v)
			}
		})}
	}
	wrongVerifier := func(v url.Values) { v.Set("code_verifier", strings.Repeat("a", 43)) }
	noVerifier := func(v url.Values) { v.Del("code_verifier") }
	// issueBound is a billing-web code bound to a key by its request's dpop_jkt.
	issueBound := func(t *testing.T, x *exchangeFixture) issuedCode {
		t.Helper()

		return issueCodeFor(t, x.parkFixture, "billing-web", func(v url.Values) {
			v.Set("dpop_jkt", authzChallenge)
		}, testSignIn(x.parkFixture, "u-1"), "openid", "profile")
	}
	withBinding := func(c issuedCode, jkt string) oidcprovider.TokenRequest {
		req := billingExchange(c, nil)
		req.Binding = oidcprovider.Binding{JKT: jkt}

		return req
	}
	// replayArrange is a code's first exchange and its replay.
	type replayArrange = func(*testing.T, *exchangeFixture) (first, replay oidcprovider.TokenRequest, c issuedCode)
	// invalidReplay exchanges a code, then presents it again in a way that fails what the code
	// was issued for. Whoever holds only a leaked code ends nothing.
	invalidReplay := func(
		name string,
		opts func(*testing.T) []oidcprovider.Option,
		arrange replayArrange,
	) testCase {
		return testCase{
			name: "invalid_replay " + name,
			opts: opts,
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				first, replay, c := arrange(t, x)
				res, err := x.p.Token(t.Context(), first)
				require.NoError(t, err)

				_, err = x.p.Token(t.Context(), replay)
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)

				grant := grantOf(t, x, c)
				assert.False(t, grant.Revoked, "an invalid replay ended the user's grant")
				if res.RefreshToken != "" {
					lineageOf(t, x, grant, res.RefreshToken)
				}
			},
		}
	}
	confidential := func(change func(url.Values)) replayArrange {
		return func(t *testing.T, x *exchangeFixture) (oidcprovider.TokenRequest, oidcprovider.TokenRequest, issuedCode) {
			t.Helper()
			c := x.issue(t)

			return billingExchange(c, nil), billingExchange(c, change), c
		}
	}
	public := func(change func(url.Values)) replayArrange {
		return func(t *testing.T, x *exchangeFixture) (oidcprovider.TokenRequest, oidcprovider.TokenRequest, issuedCode) {
			t.Helper()
			c := issueNative(t, x)

			return nativeExchange(c, nil), nativeExchange(c, change), c
		}
	}
	bound := func(replayJKT string) replayArrange {
		return func(t *testing.T, x *exchangeFixture) (oidcprovider.TokenRequest, oidcprovider.TokenRequest, issuedCode) {
			t.Helper()
			c := issueBound(t, x)

			return withBinding(c, authzChallenge), withBinding(c, replayJKT), c
		}
	}
	dpop := func(*testing.T) []oidcprovider.Option { return []oidcprovider.Option{oidcprovider.WithDPoP()} }
	// validReplayAfter exchanges a code, lets the clock run past its expiry, lets another
	// issue run the default stores' sweeps, and presents the code again as its client.
	validReplayAfter := func(name string, pastExpiry time.Duration, revoked bool) testCase {
		return testCase{
			name: name,
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				_, err := x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				family := grantOf(t, x, c).Family

				x.clk.Advance(60*time.Second + pastExpiry)
				x.issue(t)

				res, err := x.p.Token(t.Context(), billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.Nil(t, res)

				grant, err := x.p.GrantsForTest().Load(t.Context(), family)
				require.NoError(t, err)
				assert.Equal(t, revoked, grant.Revoked)
			},
		}
	}
	// loseSpendToOwner has another client pass its check, then the code's own client spend the
	// code before that client's spend lands.
	loseSpendToOwner := func() testCase {
		var beforeSpend func()

		return testCase{
			name: "another client losing the spend to the code's own client revokes nothing",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				tokens, memory := mockedCodeTokens(t)
				tokens.EXPECT().FindByID(gomock.Any(), gomock.Any()).DoAndReturn(memory.FindByID).AnyTimes()
				tokens.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, tokenID id.ID, at time.Time) error {
						if run := beforeSpend; run != nil {
							beforeSpend = nil
							run()
						}

						return memory.Consume(ctx, tokenID, at)
					}).AnyTimes()

				return []oidcprovider.Option{oidcprovider.WithCodeTokenStore(tokens)}
			},
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				beforeSpend = func() {
					_, err := x.p.Token(t.Context(), byOwner(c))
					require.NoError(t, err)
				}

				_, err := x.p.Token(t.Context(), byAnotherClient(c))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.False(t, grantOf(t, x, c).Revoked)
			},
		}
	}
	// replayBudget sees the context a replay's last write runs on.
	replayBudget := func() testCase {
		var (
			deadline time.Time
			bounded  bool
		)

		return testCase{
			name: "a replay's revocation that stopped listening to its caller is still bounded",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				lineages := NewMockLineageSessionStore(gomock.NewController(t))
				lineages.EXPECT().DeleteFamily(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, _ id.ID) (int, error) {
					deadline, bounded = ctx.Deadline()

					return 0, nil
				})

				return []oidcprovider.Option{oidcprovider.WithRefreshTokenStore(oplineage.New(lineages))}
			},
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				spendAsAnotherClient(t, x, c)

				asked := time.Now()
				_, err := x.p.Token(t.Context(), billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)

				require.True(t, bounded, "a hung store would hold the replay for ever")
				assert.False(t, deadline.After(asked.Add(11*time.Second)), "got %s from %s", deadline, asked)
			},
		}
	}

	// recordUnreadable is a replay whose record the store cannot read on the second look, the
	// first exchange having been made while it could.
	recordUnreadable := func() testCase {
		var failing atomic.Bool

		return testCase{
			name: "a replay whose record cannot be read fails, and revokes nothing",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				memory, err := oidcprovider.NewMemoryCodeStore()
				require.NoError(t, err)
				codes := NewMockCodeStore(gomock.NewController(t))
				codes.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(memory.Create)
				codes.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, tokenID id.ID) (*oidcprovider.CodeRecord, error) {
					if failing.Load() {
						return nil, errOutage
					}

					return memory.Load(ctx, tokenID)
				}).AnyTimes()

				return []oidcprovider.Option{oidcprovider.WithCodeStore(codes)}
			},
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				spendAsAnotherClient(t, x, c)
				family := recordOf(t, x.parkFixture, c.code).GrantFamily
				failing.Store(true)

				_, err := x.p.Token(t.Context(), billingExchange(c, nil))
				assertDependencyFailure(t, err)

				_, err = x.p.GrantsForTest().Load(t.Context(), family)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "a failed read still revoked")
			},
		}
	}
	// vanishingToken is a replay whose token store answers nothing at all on the second look,
	// neither a token nor an error.
	vanishingToken := func() testCase {
		var armed atomic.Bool
		var looks atomic.Int32

		return testCase{
			name: "a replay whose token store answers nothing on the second look is refused",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				tokens, memory := mockedCodeTokens(t)
				tokens.EXPECT().FindByID(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, tokenID id.ID) (*onetime.Token, error) {
						if armed.Load() && looks.Add(1) > 1 {
							return nil, nil
						}

						return memory.FindByID(ctx, tokenID)
					}).AnyTimes()
				tokens.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Consume).AnyTimes()

				return []oidcprovider.Option{oidcprovider.WithCodeTokenStore(tokens)}
			},
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				spendAsAnotherClient(t, x, c)
				family := recordOf(t, x.parkFixture, c.code).GrantFamily
				armed.Store(true)

				var err error
				require.NotPanics(t, func() { _, err = x.p.Token(t.Context(), billingExchange(c, nil)) })
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)

				_, err = x.p.GrantsForTest().Load(t.Context(), family)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		}
	}

	cases := []testCase{
		recordUnreadable(),
		vanishingToken(),
		invalidReplay("a wrong verifier", nil, confidential(wrongVerifier)),
		invalidReplay("no verifier", nil, confidential(noVerifier)),
		invalidReplay("another redirect URI", nil, confidential(func(v url.Values) { v.Set("redirect_uri", authzRedirect+"/") })),
		invalidReplay("another client", nil, func(t *testing.T, x *exchangeFixture) (oidcprovider.TokenRequest, oidcprovider.TokenRequest, issuedCode) {
			t.Helper()
			c := x.issue(t)

			return byOwner(c), byAnotherClient(c), c
		}),
		invalidReplay("another client holding the code's redirect URI and verifier", nil, func(t *testing.T, x *exchangeFixture) (oidcprovider.TokenRequest, oidcprovider.TokenRequest, issuedCode) {
			t.Helper()
			c := x.issue(t)

			return byOwner(c), confidentialExchange("code-only", authzRedirect, c, nil), c
		}),
		invalidReplay("a public client's wrong verifier", nil, public(wrongVerifier)),
		invalidReplay("a public client's missing verifier", nil, public(noVerifier)),
		invalidReplay("no proof of a bound code's key", dpop, bound("")),
		invalidReplay("another key than a bound code's", dpop, bound("another-key")),
		{
			name: "a public client's valid replay revokes",
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := issueNative(t, x)
				_, err := x.p.Token(t.Context(), nativeExchange(c, nil))
				require.NoError(t, err)

				_, err = x.p.Token(t.Context(), nativeExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.True(t, grantOf(t, x, c).Revoked)
			},
		},
		validReplayAfter("valid_within_the_minute", 30*time.Second, true),
		validReplayAfter("valid_past_the_minute", 2*time.Minute, false),
		{
			name: "consumer_store_retains",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				tokens, err := onetime.NewMemoryStore()
				require.NoError(t, err)
				// A clock that never reaches any code's expiry: a store that keeps what it holds.
				codes, err := oidcprovider.NewMemoryCodeStore(oidcprovider.WithMemoryStoreClock(
					clockwork.NewFakeClockAt(time.Date(2026, 11, 4, 10, 4, 0, 0, time.UTC))))
				require.NoError(t, err)

				return []oidcprovider.Option{oidcprovider.WithCodeTokenStore(tokens), oidcprovider.WithCodeStore(codes)}
			},
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				_, err := x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)

				x.clk.Advance(time.Hour)
				x.issue(t)

				_, err = x.p.Token(t.Context(), billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.True(t, grantOf(t, x, c).Revoked)
			},
		},
		{
			name:    "end_reaches_exchange_in_flight",
			barrier: true,
			run: func(t *testing.T, x *exchangeFixture, barrier *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				family := recordOf(t, x.parkFixture, c.code).GrantFamily
				first := raceCommit(t, x, barrier, c, func() {
					x.clk.Advance(61 * time.Second)
					x.issue(t)
					_, err := x.p.GrantsForTest().EndSignIns(t.Context(), oidcprovider.SignInSelector{Family: c.signIn.Family}, x.clk.Now())
					require.NoError(t, err)
				})
				require.NoError(t, first.err)

				grant, err := x.p.GrantsForTest().Load(t.Context(), family)
				require.NoError(t, err)
				assert.True(t, grant.Revoked, "a live grant survived the end of the sign-in it came from")
			},
		},
		loseSpendToOwner(),
		replayBudget(),
		{
			name: "a hung-up replay reads its record whatever became of the caller",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				memory, err := oidcprovider.NewMemoryCodeStore(oidcprovider.WithMemoryStoreClock(
					clockwork.NewFakeClockAt(time.Date(2026, 11, 4, 10, 4, 0, 0, time.UTC))))
				require.NoError(t, err)
				codes := NewMockCodeStore(gomock.NewController(t))
				codes.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(memory.Create)
				codes.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, tokenID id.ID) (*oidcprovider.CodeRecord, error) {
					if err := ctx.Err(); err != nil {
						return nil, err
					}

					return memory.Load(ctx, tokenID)
				}).AnyTimes()
				tokens, err := onetime.NewMemoryStore()
				require.NoError(t, err)

				return []oidcprovider.Option{
					oidcprovider.WithCodeStore(codes),
					oidcprovider.WithCodeTokenStore(&contextTokens{Store: tokens}),
				}
			},
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				spendAsAnotherClient(t, x, c)

				leaving, leave := context.WithCancel(t.Context())
				leave()
				_, err := x.p.Token(leaving, billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.True(t, grantOf(t, x, c).Revoked)
			},
		},
		{
			name:    "racing_commit",
			barrier: true,
			run: func(t *testing.T, x *exchangeFixture, barrier *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				first := raceCommit(t, x, barrier, c, func() {
					_, err := x.p.Token(t.Context(), billingExchange(c, nil))
					assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				})
				require.NoError(t, first.err, "the one request that spent the code is the one answered with tokens")
				require.NotEmpty(t, first.res.IDToken)
				require.NotEmpty(t, first.res.AccessToken)
				_, err := x.p.VerifyAccessToken(t.Context(), first.res.AccessToken)
				assertRefused(t, err, oidcprovider.CodeInvalidToken)

				grant := grantOf(t, x, c)
				assert.True(t, grant.Revoked, "a live grant survived the replay that should have revoked it")
				assert.Equal(t, oidcprovider.CauseCodeReplay, grant.RevokeCause)
				assert.Equal(t, "billing-web", grant.ClientID, "the commit filled in the record the replay left")

				require.NotEmpty(t, first.res.RefreshToken)
				_, err = x.p.Token(t.Context(), refreshRequest("billing-web", first.res.RefreshToken, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
			},
		},
		{
			name: "after_exchange",
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				res, err := x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				live := grantOf(t, x, c)
				require.False(t, live.Revoked)
				secret := strings.TrimPrefix(res.RefreshToken, "rt."+live.Family.String()+".")
				_, err = x.p.VerifyAccessToken(t.Context(), res.AccessToken)
				require.NoError(t, err, "its access token is good until the replay")

				_, err = x.p.Token(t.Context(), billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				_, err = x.p.VerifyAccessToken(t.Context(), res.AccessToken)
				assertRefused(t, err, oidcprovider.CodeInvalidToken)

				grant := grantOf(t, x, c)
				assert.True(t, grant.Revoked)
				assert.Equal(t, oidcprovider.CauseCodeReplay, grant.RevokeCause)
				assert.True(t, grant.RevokedAt.Equal(x.clk.Now()))
				_, err = x.p.LineageForTest().Load(t.Context(), secret)
				require.ErrorIs(t, err, session.ErrNotFound, "its refresh token is gone with the family")

				_, err = x.p.Token(t.Context(), refreshRequest("billing-web", res.RefreshToken, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
			},
		},
		{
			name: "a valid replay asking for a resource outside the grant still revokes",
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				_, err := x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)

				_, err = x.p.Token(t.Context(), billingExchange(c, func(v url.Values) {
					v.Set("resource", "https://nowhere.example.com")
				}))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.True(t, grantOf(t, x, c).Revoked, "resource is no part of what makes a replay valid")
			},
		},
		{
			name: "concurrent",
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				start := make(chan struct{})
				answers := make(chan exchanged, 16)
				var wg sync.WaitGroup
				for range 16 {
					wg.Go(func() {
						<-start
						res, err := x.p.Token(t.Context(), billingExchange(c, nil))
						answers <- exchanged{res: res, err: err}
					})
				}
				close(start)
				wg.Wait()
				close(answers)

				succeeded := 0
				for answer := range answers {
					if answer.err == nil {
						succeeded++
						assert.NotEmpty(t, answer.res.AccessToken)
						assert.NotEmpty(t, answer.res.IDToken)

						continue
					}
					assertRefused(t, answer.err, oidcprovider.CodeInvalidGrant)
				}
				assert.Equal(t, 1, succeeded, "exactly one receives tokens")
				assert.True(t, grantOf(t, x, c).Revoked, "the fifteen others were replays")
			},
		},
		{
			name: "the loser of the spend itself is a replay",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				memory, err := onetime.NewMemoryStore()
				require.NoError(t, err)

				return []oidcprovider.Option{
					oidcprovider.WithCodeTokenStore(&meetingTokens{Store: memory, met: make(chan struct{})}),
				}
			},
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				one, two := exchangeAsync(t.Context(), x, billingExchange(c, nil)), exchangeAsync(t.Context(), x, billingExchange(c, nil))
				first, second := <-one, <-two
				if first.err != nil {
					first, second = second, first
				}
				require.NoError(t, first.err)
				assertRefused(t, second.err, oidcprovider.CodeInvalidGrant)
				assert.True(t, grantOf(t, x, c).Revoked)
			},
		},
		{
			name: "a valid replay at exactly a minute past the code's expiry still revokes, after a sweep",
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				_, err := x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				family := grantOf(t, x, c).Family
				x.clk.Advance(2 * time.Minute) // the code lived a minute: now it is a minute past
				x.issue(t)                     // a write that brings a sweep of each default store

				_, err = x.p.Token(t.Context(), billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)

				grant, err := x.p.GrantsForTest().Load(t.Context(), family)
				require.NoError(t, err)
				assert.True(t, grant.Revoked, "a valid replay at the boundary revoked nothing")
			},
		},
		{
			name: "a replay past the code's expiry revokes while the code is still held",
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				_, err := x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				x.clk.Advance(61 * time.Second)

				_, err = x.p.Token(t.Context(), billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.True(t, grantOf(t, x, c).Revoked)
			},
		},
		{
			name: "a spent code's identifier with another secret is no replay, and revokes nothing",
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				res, err := x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				tokenID, _, _ := strings.Cut(c.code, ".")

				_, err = x.p.Token(t.Context(), billingExchange(issuedCode{code: tokenID + ".never-issued"}, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)

				grant := grantOf(t, x, c)
				assert.False(t, grant.Revoked)
				lineageOf(t, x, grant, res.RefreshToken)
			},
		},
		{
			name: "what is no code at all revokes nothing",
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				for _, code := range []string{"not-a-code", "not-an-id.secret", tokenIDText(t) + ".", tokenIDText(t) + ".never-issued"} {
					_, err := x.p.Token(t.Context(), billingExchange(issuedCode{code: code}, nil))
					assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				}
			},
		},
		{
			name: "an unspent code's failed check revokes nothing",
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				x.clk.Advance(61 * time.Second)

				_, err := x.p.Token(t.Context(), billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)

				_, err = x.p.GrantsForTest().Load(t.Context(), recordOf(t, x.parkFixture, c.code).GrantFamily)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "a replay whose record has gone is refused, with nothing to reach",
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				_, err := x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				live := grantOf(t, x, c)
				_, err = x.p.CodesForTest().DeleteExpired(t.Context(), x.clk.Now().Add(time.Hour))
				require.NoError(t, err)

				_, err = x.p.Token(t.Context(), billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)

				grant, err := x.p.GrantsForTest().Load(t.Context(), live.Family)
				require.NoError(t, err)
				assert.False(t, grant.Revoked)
			},
		},
		{
			name: "a replay that hangs up still revokes",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				memory, err := oidcprovider.NewMemoryGrantStore()
				require.NoError(t, err)
				lineages := NewMockLineageSessionStore(gomock.NewController(t))
				lineages.EXPECT().DeleteFamily(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, _ id.ID) (int, error) {
					return 1, ctx.Err()
				})

				tokens, err := onetime.NewMemoryStore()
				require.NoError(t, err)

				return []oidcprovider.Option{
					oidcprovider.WithGrantStore(&watchedGrants{GrantStore: memory}),
					oidcprovider.WithRefreshTokenStore(oplineage.New(lineages)),
					oidcprovider.WithCodeTokenStore(&contextTokens{Store: tokens}),
				}
			},
			run: func(t *testing.T, x *exchangeFixture, _ *barrierGrants) {
				t.Helper()
				c := x.issue(t)
				spendAsAnotherClient(t, x, c)

				hungUp, cancel := context.WithCancel(t.Context())
				cancel()
				_, err := x.p.Token(hungUp, billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.True(t, grantOf(t, x, c).Revoked)
			},
		},
	}
	cases = append(cases, testCase{
		name:    "end_racing_commit keeps the end's revocation and its mark",
		barrier: true,
		run: func(t *testing.T, x *exchangeFixture, barrier *barrierGrants) {
			t.Helper()
			c := x.issue(t)
			first := raceCommit(t, x, barrier, c, func() {
				_, err := x.p.GrantsForTest().EndSignIns(t.Context(), oidcprovider.SignInSelector{Family: c.signIn.Family}, x.clk.Now())
				require.NoError(t, err)
			})
			require.NoError(t, first.err)

			grant := grantOf(t, x, c)
			assert.True(t, grant.Revoked)
			assert.Equal(t, oidcprovider.CauseSignInEnded, grant.RevokeCause)
			assert.False(t, grant.SignInEndedAt.IsZero(), "the end marked it, so it is not told twice")
			assert.Equal(t, "billing-web", grant.ClientID)

			again, err := x.p.GrantsForTest().EndSignIns(t.Context(), oidcprovider.SignInSelector{Family: c.signIn.Family}, x.clk.Now())
			require.NoError(t, err)
			assert.Empty(t, again)
		},
	}, testCase{
		name:    "revoke_racing_commit keeps the revocation",
		barrier: true,
		run: func(t *testing.T, x *exchangeFixture, barrier *barrierGrants) {
			t.Helper()
			c := x.issue(t)
			first := raceCommit(t, x, barrier, c, func() {
				_, err := x.p.GrantsForTest().RevokeByUser(t.Context(), "u-1", oidcprovider.CauseRecovery, x.clk.Now())
				require.NoError(t, err)
			})
			require.NoError(t, first.err)

			grant := grantOf(t, x, c)
			assert.True(t, grant.Revoked)
			assert.Equal(t, oidcprovider.CauseRecovery, grant.RevokeCause)
			assert.True(t, grant.SignInEndedAt.IsZero())
		},
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []oidcprovider.Option
			if tc.opts != nil {
				opts = tc.opts(t)
			}
			var barrier *barrierGrants
			if tc.barrier {
				barrier = newBarrierGrants(t)
				opts = append(opts, oidcprovider.WithGrantStore(barrier))
			}
			tc.run(t, newExchangeFixture(t, opts...), barrier)
		})
	}
}

// TestProvider_CodeReplay_BudgetEnds is apart because it runs in synctest bubbles, where the
// replay's real ten-second budget passes in no time; no row of TestProvider_CodeReplay can share
// that setup. The work runs on a context detached from the caller, who stays and is the one to
// judge each failure: a budget running out is a dependency failure, not the caller's own ending.
func TestProvider_CodeReplay_BudgetEnds(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// opts returns the options and arm, which makes the named step hang until its context ends.
		opts   func(*testing.T) ([]oidcprovider.Option, func())
		assert func(t *testing.T, err error)
	}

	assertBudgetEnded := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, t.Context().Err(), "the caller never left")
		assertDependencyFailure(t, err)
	}

	cases := []testCase{
		{
			name: "a code record read hanging past the budget fails the dependency",
			opts: func(t *testing.T) ([]oidcprovider.Option, func()) {
				t.Helper()
				memory, err := oidcprovider.NewMemoryCodeStore()
				require.NoError(t, err)
				var hang atomic.Bool
				codes := NewMockCodeStore(gomock.NewController(t))
				codes.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(memory.Create).AnyTimes()
				codes.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, tokenID id.ID) (*oidcprovider.CodeRecord, error) {
						if hang.Load() {
							<-ctx.Done()

							return nil, ctx.Err()
						}

						return memory.Load(ctx, tokenID)
					}).AnyTimes()

				return []oidcprovider.Option{oidcprovider.WithCodeStore(codes)}, func() { hang.Store(true) }
			},
			assert: assertBudgetEnded,
		},
		{
			name: "a token read hanging past the budget fails the dependency",
			opts: func(t *testing.T) ([]oidcprovider.Option, func()) {
				t.Helper()
				memory, err := onetime.NewMemoryStore()
				require.NoError(t, err)
				tokens := &hangSecondRead{Store: memory}

				return []oidcprovider.Option{oidcprovider.WithCodeTokenStore(tokens)}, func() { tokens.armed.Store(true) }
			},
			assert: assertBudgetEnded,
		},
		{
			name: "a grant revocation hanging past the budget fails the dependency",
			opts: func(t *testing.T) ([]oidcprovider.Option, func()) {
				t.Helper()
				memory, err := oidcprovider.NewMemoryGrantStore()
				require.NoError(t, err)
				grants := &hangingGrants{GrantStore: memory}

				return []oidcprovider.Option{oidcprovider.WithGrantStore(grants)}, func() { grants.armed.Store(true) }
			},
			assert: assertBudgetEnded,
		},
		{
			name: "a lineage revocation hanging past the budget fails the dependency",
			opts: func(t *testing.T) ([]oidcprovider.Option, func()) {
				t.Helper()
				var hang atomic.Bool
				lineages := NewMockLineageSessionStore(gomock.NewController(t))
				lineages.EXPECT().DeleteFamily(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, _ id.ID) (int, error) {
						if hang.Load() {
							<-ctx.Done()

							return 0, ctx.Err()
						}

						return 0, nil
					}).AnyTimes()

				return []oidcprovider.Option{oidcprovider.WithRefreshTokenStore(oplineage.New(lineages))}, func() { hang.Store(true) }
			},
			assert: assertBudgetEnded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				opts, arm := tc.opts(t)
				x := newExchangeFixture(t, opts...)
				c := x.issue(t)
				spendAsAnotherClient(t, x, c)
				arm()

				_, err := x.p.Token(t.Context(), billingExchange(c, nil))
				tc.assert(t, err)
			})
		})
	}
}

// hangSecondRead hangs every token read after the first once armed. The first is the check's own,
// and the later one is the replay's.
type hangSecondRead struct {
	onetime.Store

	armed atomic.Bool
	calls atomic.Int32
}

// FindByID implements onetime.Store.
func (h *hangSecondRead) FindByID(ctx context.Context, tokenID id.ID) (*onetime.Token, error) {
	if h.armed.Load() && h.calls.Add(1) >= 2 {
		<-ctx.Done()

		return nil, ctx.Err()
	}

	return h.Store.FindByID(ctx, tokenID)
}

// hangingGrants holds a revocation until its context ends, once armed.
type hangingGrants struct {
	oidcprovider.GrantStore

	armed atomic.Bool
}

// Revoke implements oidcprovider.GrantStore.
func (h *hangingGrants) Revoke(ctx context.Context, family id.ID, cause oidcprovider.RevocationCause, at time.Time) error {
	if h.armed.Load() {
		<-ctx.Done()

		return ctx.Err()
	}

	return h.GrantStore.Revoke(ctx, family, cause, at)
}

// TestProvider_CodeReplay_PartWay is apart because each row's stores are held for its own
// body to break and mend.
func TestProvider_CodeReplay_PartWay(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		breakStore func(*watchedGrants, *atomic.Bool)
		assert     func(*testing.T, *oidcprovider.Grant)
	}

	cases := []testCase{
		{
			name:       "a tombstone that cannot be written still revokes the lineage, and can be tried again",
			breakStore: func(g *watchedGrants, _ *atomic.Bool) { g.failing.Store(true) },
			assert: func(t *testing.T, grant *oidcprovider.Grant) {
				t.Helper()
				assert.Nil(t, grant, "no revocation could be recorded")
			},
		},
		{
			name:       "a lineage that cannot be revoked still leaves the tombstone, and can be tried again",
			breakStore: func(_ *watchedGrants, lineage *atomic.Bool) { lineage.Store(true) },
			assert: func(t *testing.T, grant *oidcprovider.Grant) {
				t.Helper()
				require.NotNil(t, grant)
				assert.True(t, grant.Revoked)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			memory, err := oidcprovider.NewMemoryGrantStore()
			require.NoError(t, err)
			grants := &watchedGrants{GrantStore: memory}
			var lineageFailing atomic.Bool
			lineageCalls := atomic.Int32{}
			lineages := NewMockLineageSessionStore(gomock.NewController(t))
			lineages.EXPECT().DeleteFamily(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, id.ID) (int, error) {
				lineageCalls.Add(1)
				if lineageFailing.Load() {
					return 0, errOutage
				}

				return 0, nil
			}).AnyTimes()
			x := newExchangeFixture(t,
				oidcprovider.WithGrantStore(grants),
				oidcprovider.WithRefreshTokenStore(oplineage.New(lineages)),
			)

			c := x.issue(t)
			spendAsAnotherClient(t, x, c)
			tc.breakStore(grants, &lineageFailing)

			_, err = x.p.Token(t.Context(), billingExchange(c, nil))
			assertDependencyFailure(t, err)
			assert.Equal(t, int32(1), lineageCalls.Load(), "the lineage was tried whatever became of the row")

			family := recordOf(t, x.parkFixture, c.code).GrantFamily
			grant, err := memory.Load(t.Context(), family)
			if err != nil {
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				grant = nil
			}
			tc.assert(t, grant)

			grants.failing.Store(false)
			lineageFailing.Store(false)
			_, err = x.p.Token(t.Context(), billingExchange(c, nil))
			assertRefused(t, err, oidcprovider.CodeInvalidGrant)
			assert.True(t, grantOf(t, x, c).Revoked, "the code stays spent, so presenting it again finishes the job")
		})
	}
}

// tokenIDText is a valid identifier, for a code with nothing after it.
func tokenIDText(t *testing.T) string {
	t.Helper()

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	return family.String()
}
