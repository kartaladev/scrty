package test_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/store/migrate"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/store/seal"
	"github.com/kartaladev/scrty/store/sqlstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/token/signingkey"
)

// The cases of TestOIDCProvider_Durable are whole scenarios, each with its own setup, so they
// share a table by name and an assert closure over one environment, not a single call.

// durSuccessorKey is the key every provider these tests build shares, as replicas over one store must.
var durSuccessorKey = []byte("durable tests successor key, 32+")

const (
	durOpaqueSecret = "fedcba9876543210fedcba9876543210"
	durScope        = "openid email"
	durUser         = identity.UserID("u-1")
	durUsername     = "ada@example.com"
)

// durClient is a client of the provider under test, with the secret it authenticates by.
type durClient struct{ id, secret string }

var (
	durWeb    = durClient{id: opClient, secret: opSecret}
	durOpaque = durClient{id: "billing-opaque", secret: durOpaqueSecret}
)

func (c durClient) creds() oidcprovider.ClientCredentials {
	return oidcprovider.ClientCredentials{
		Authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte(c.id+":"+c.secret)),
	}
}

// durUsers answers every lookup with an active user whose username is an email address, which
// the default claim source releases as email.
type durUsers struct{ identity.UserLoader }

func (durUsers) LoadByUserID(_ context.Context, user identity.UserID) (*identity.Details, error) {
	return &identity.Details{ID: user, Username: durUsername, Active: true}, nil
}

// hookedLineage is a lineage store that calls back before a load and before a supersession,
// which is how a case lands another request's write at an exact point of this one.
type hookedLineage struct {
	session.Store
	beforeLoad      func(ctx context.Context, secret string)
	beforeSupersede func(ctx context.Context, op session.Supersession)
}

func (h hookedLineage) Load(ctx context.Context, secret string) (*session.Session, error) {
	if h.beforeLoad != nil {
		h.beforeLoad(ctx, secret)
	}

	return h.Store.Load(ctx, secret)
}

func (h hookedLineage) Supersede(ctx context.Context, op session.Supersession) error {
	if h.beforeSupersede != nil {
		h.beforeSupersede(ctx, op)
	}

	return h.Store.Supersede(ctx, op)
}

// durAdmin builds an adapter's consent and client stores over a database: the tables that
// the consumer's own administration writes and the provider reads, beside the ones opStores holds.
type durAdmin func(t *testing.T, conn test.PostgresConn) (oidcprovider.ConsentStore, oidcprovider.ClientStore)

// durAdmins is each adapter's durAdmin, by the adapter's name in opAdapters.
var durAdmins = map[string]durAdmin{
	"sqlstore": func(_ *testing.T, conn test.PostgresConn) (oidcprovider.ConsentStore, oidcprovider.ClientStore) {
		return mustStore(sqlstore.NewConsentStore(conn.DB)), mustStore(sqlstore.NewClientStore(conn.DB))
	},
	"pgx": func(t *testing.T, conn test.PostgresConn) (oidcprovider.ConsentStore, oidcprovider.ClientStore) {
		cfg, err := pgxpool.ParseConfig(conn.DSN)
		require.NoError(t, err)
		pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
		require.NoError(t, err)
		t.Cleanup(pool.Close)

		return mustStore(pgxstore.NewConsentStore(pool)), mustStore(pgxstore.NewClientStore(pool))
	},
	"gorm": func(t *testing.T, conn test.PostgresConn) (oidcprovider.ConsentStore, oidcprovider.ClientStore) {
		db, err := gormdb.Open(postgres.Open(conn.DSN), &gormdb.Config{DisableAutomaticPing: true})
		require.NoError(t, err)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { _ = sqlDB.Close() })

		return mustStore(gormstore.NewConsentStore(db)), mustStore(gormstore.NewClientStore(db))
	},
}

// durClientConfig is c as the provider is configured with it.
func durClientConfig(c durClient, opaque bool) oidcprovider.Client {
	return oidcprovider.Client{
		ID: c.id, Type: oidcprovider.Confidential, Secret: []byte(c.secret),
		RedirectURIs: []string{opRedirect}, Scopes: []string{"openid", "email"},
		GrantTypes:         []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
		IDTokenAlg:         signingkey.ES256,
		OpaqueAccessTokens: opaque,
	}
}

// durEnv is one adapter's migrated database, with the signing keys and clock every provider
// built over it shares, as a deployment and its restarts do.
type durEnv struct {
	conn     test.PostgresConn
	cipher   seal.Cipher
	clk      *clockwork.FakeClock
	open     func(*testing.T, test.PostgresConn, seal.Cipher, clock.Clock) opStores
	admin    durAdmin
	keys     *signingkey.Keys
	consents oidcprovider.ConsentStore
}

func newDurEnv(
	t *testing.T, name string, open func(*testing.T, test.PostgresConn, seal.Cipher, clock.Clock) opStores,
) *durEnv {
	t.Helper()

	set := migrate.SecurityState()
	conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))
	clk := clockwork.NewFakeClockAt(time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC))
	keys, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
		signingkey.WithAlgs(signingkey.ES256), signingkey.WithClock(clk))
	require.NoError(t, err)

	admin, ok := durAdmins[name]
	require.True(t, ok, "an admin store builder for adapter %s", name)
	consents, clients := admin(t, conn)
	// The clients are registered once, as a consumer's administration does, and every provider
	// built over the database reads them from its rows.
	for _, c := range []struct {
		client durClient
		opaque bool
	}{{durWeb, false}, {durOpaque, true}} {
		require.NoError(t, clients.Put(t.Context(), durClientConfig(c.client, c.opaque)))
	}

	return &durEnv{
		conn: conn, cipher: storefix.TestCipher(t), clk: clk, open: open, admin: admin, keys: keys,
		consents: consents,
	}
}

// build is a provider over fresh stores on the env's database: the first build is the
// deployment, and each later one a restart. wrap, when given, stands between the provider and
// its lineage.
func (e *durEnv) build(
	t *testing.T, wrap func(session.Store) session.Store, opts ...oidcprovider.Option,
) *oidcprovider.Provider {
	t.Helper()

	st := e.open(t, e.conn, e.cipher, e.clk)
	if wrap != nil {
		st.lineage = oplineage.New(wrap(oplineage.Sessions(st.lineage)))
	}
	consents, clients := e.admin(t, e.conn)
	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       opIssuer,
		Registry:     clients,
		Keys:         e.keys,
		Users:        durUsers{},
		LoginURL:     opIssuer + "/login",
		ConsentURL:   opIssuer + "/consent",
		LogoutURL:    opIssuer + "/logout",
		LoggedOutURL: opIssuer + "/bye",
	}, append([]oidcprovider.Option{
		oidcprovider.WithClock(e.clk),
		oidcprovider.WithPendingRequestStore(st.pending),
		oidcprovider.WithCodeStore(st.codes),
		oidcprovider.WithGrantStore(st.grants),
		oidcprovider.WithCodeTokenStore(st.tokens),
		oidcprovider.WithAccessTokenStore(st.access),
		oidcprovider.WithAssertionIDStore(st.assertions),
		oidcprovider.WithBrowserSessionStore(st.browser),
		oidcprovider.WithRefreshTokenStore(st.lineage),
		oidcprovider.WithRefreshSuccessorKey(durSuccessorKey),
		oidcprovider.WithConsentStore(consents),
	}, opts...)...)
	require.NoError(t, err)

	return p
}

// durIssued is what one real authorization and exchange handed out.
type durIssued struct {
	handle, flow, code string
	tokens             *oidcprovider.TokenResponse
}

// issue authorizes, resumes with a signed-in user and exchanges the code, through p's real paths.
func (e *durEnv) issue(t *testing.T, p *oidcprovider.Provider, c durClient) durIssued {
	t.Helper()

	ctx := t.Context()
	now := e.clk.Now()
	require.NoError(t, e.consents.Give(ctx, durUser, c.id, []string{"openid", "email"}, false, now))

	auth, err := p.Authorize(ctx, oidcprovider.AuthorizeInput{Params: url.Values{
		"client_id": {c.id}, "redirect_uri": {opRedirect}, "response_type": {"code"},
		"scope": {durScope}, "state": {"s"}, "code_challenge": {opChallenge}, "code_challenge_method": {"S256"},
	}})
	require.NoError(t, err)
	loc, err := url.Parse(auth.Location)
	require.NoError(t, err)
	handle := loc.Query().Get("req")
	require.NotEmpty(t, handle)

	signIn := oidcprovider.SignIn{
		User: durUser, Family: newID(), AuthenticatedAt: now, AMR: []string{"pwd"}, ACR: "urn:example:acr",
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}
	resumed, err := p.Resume(ctx, oidcprovider.ResumeInput{
		Handle: handle, FlowSecret: auth.FlowSecret, SignIn: &signIn, IdleTimeout: 15 * time.Minute,
	})
	require.NoError(t, err)
	back, err := url.Parse(resumed.RedirectTo)
	require.NoError(t, err)
	code := back.Query().Get("code")
	require.NotEmpty(t, code, resumed.RedirectTo)

	tokens, err := p.Token(ctx, oidcprovider.TokenRequest{
		Credentials: c.creds(),
		Form: url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {opRedirect},
			"code_verifier": {opVerifier},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.IDToken)
	require.NotEmpty(t, tokens.RefreshToken)

	return durIssued{handle: handle, flow: auth.FlowSecret, code: code, tokens: tokens}
}

func (e *durEnv) refresh(ctx context.Context, p *oidcprovider.Provider, c durClient, refreshToken string) (*oidcprovider.TokenResponse, error) {
	return p.Token(ctx, oidcprovider.TokenRequest{
		Credentials: c.creds(),
		Form:        url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}},
	})
}

func (e *durEnv) mustRefresh(t *testing.T, p *oidcprovider.Provider, c durClient, refreshToken string) *oidcprovider.TokenResponse {
	t.Helper()

	res, err := e.refresh(t.Context(), p, c, refreshToken)
	require.NoError(t, err)
	require.NotEmpty(t, res.RefreshToken)

	return res
}

func requireRefusal(t *testing.T, err error, code string) {
	t.Helper()

	var refusal *oidcprovider.Error
	require.ErrorAs(t, err, &refusal, "want a refusal")
	require.Equal(t, code, refusal.Code)
}

func (e *durEnv) requireRefreshRefused(t *testing.T, p *oidcprovider.Provider, c durClient, refreshToken string) {
	t.Helper()

	_, err := e.refresh(t.Context(), p, c, refreshToken)
	requireRefusal(t, err, oidcprovider.CodeInvalidGrant)
}

func (e *durEnv) requireTokenRefused(t *testing.T, p *oidcprovider.Provider, accessToken string) {
	t.Helper()

	_, err := p.VerifyAccessToken(t.Context(), accessToken)
	requireRefusal(t, err, oidcprovider.CodeInvalidToken)
}

func (e *durEnv) introspect(t *testing.T, p *oidcprovider.Provider, c durClient, token string) map[string]any {
	t.Helper()

	got, err := p.Introspect(t.Context(), c.creds(), url.Values{"token": {token}})
	require.NoError(t, err)

	return got
}

// familyOf is the family a refresh token names.
func familyOf(t *testing.T, refreshToken string) id.ID {
	t.Helper()

	parts := strings.Split(refreshToken, ".")
	require.Len(t, parts, 3, "a refresh token is rt.<family>.<secret>")
	family, err := id.Parse(parts[1])
	require.NoError(t, err)

	return family
}

// heads counts the family's refresh tokens that have not been superseded.
func (e *durEnv) heads(t *testing.T, family id.ID) int {
	t.Helper()

	return countRows(t, e.conn.DB, "op_refresh_tokens", "family_id = '"+family.String()+"' AND superseded_at IS NULL")
}

func (e *durEnv) lineageRows(t *testing.T, family id.ID) int {
	t.Helper()

	return countRows(t, e.conn.DB, "op_refresh_tokens", "family_id = '"+family.String()+"'")
}

// dumpDatabase is every row of every table as text, bytea columns in hex, by table name.
func dumpDatabase(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()

	rows, err := db.QueryContext(t.Context(),
		`SELECT table_name FROM information_schema.tables
		 WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'`)
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		tables = append(tables, name)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.NotEmpty(t, tables)

	dump := make(map[string]string, len(tables))
	for _, table := range tables {
		var text string
		// table is a name the database itself just reported, quoted as an identifier.
		q := `SELECT coalesce(string_agg(row_to_json(x)::text, E'\n'), '') FROM "` + table + `" x`
		require.NoError(t, db.QueryRowContext(t.Context(), q).Scan(&text), table)
		dump[table] = text
	}

	return dump
}

// spellings are the forms a credential could be stored in without being sealed or hashed.
func spellings(credential string) []string {
	raw := []byte(credential)

	return []string{
		credential,
		hex.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
	}
}

// credentialHit is one place a credential was found: the table, which credential, and the
// spelling it was found in.
type credentialHit struct{ table, label, spelling string }

// findCredentials is every table of dump that holds any spelling of any of the credentials, by label.
func findCredentials(dump map[string]string, credentials map[string]string) []credentialHit {
	var hits []credentialHit
	for table, text := range dump {
		for label, credential := range credentials {
			for _, spelling := range spellings(credential) {
				if strings.Contains(text, spelling) {
					hits = append(hits, credentialHit{table: table, label: label, spelling: spelling})
				}
			}
		}
	}

	return hits
}

// requireScanSeesCredentials proves the scan can find what it looks for: a credential planted in
// a scratch table of the database, once in each spelling, must be found in every one of them. A
// scan that read nothing would otherwise pass for a database that holds nothing in clear.
func (e *durEnv) requireScanSeesCredentials(t *testing.T) {
	t.Helper()

	const scratch = "scan_control"
	// Its bytes are chosen so the standard and URL alphabets differ, and the length so that padded
	// and unpadded forms differ: all six spellings below are distinct.
	planted := "planted-known-credential-?>>?>>012345678"
	_, err := e.conn.DB.ExecContext(t.Context(), "CREATE TABLE "+scratch+" (v text NOT NULL)")
	require.NoError(t, err)
	for _, spelling := range spellings(planted) {
		_, err = e.conn.DB.ExecContext(t.Context(), "INSERT INTO "+scratch+" (v) VALUES ($1)", spelling)
		require.NoError(t, err)
	}

	hits := findCredentials(dumpDatabase(t, e.conn.DB), map[string]string{"planted": planted})

	// The scratch table goes before the scan that matters reads the database.
	_, err = e.conn.DB.ExecContext(t.Context(), "DROP TABLE "+scratch)
	require.NoError(t, err)

	var found []string
	for _, hit := range hits {
		assert.Equal(t, scratch, hit.table, "only the scratch table holds the planted credential")
		found = append(found, hit.spelling)
	}
	// The spellings are listed literally, not taken from spellings(), so that a spelling dropped
	// from spellings() is noticed rather than agreed with.
	want := []string{
		planted,
		"706c616e7465642d6b6e6f776e2d63726564656e7469616c2d3f3e3e3f3e3e303132333435363738",
		"cGxhbnRlZC1rbm93bi1jcmVkZW50aWFsLT8+Pj8+PjAxMjM0NTY3OA==",
		"cGxhbnRlZC1rbm93bi1jcmVkZW50aWFsLT8+Pj8+PjAxMjM0NTY3OA",
		"cGxhbnRlZC1rbm93bi1jcmVkZW50aWFsLT8-Pj8-PjAxMjM0NTY3OA==",
		"cGxhbnRlZC1rbm93bi1jcmVkZW50aWFsLT8-Pj8-PjAxMjM0NTY3OA",
	}
	require.ElementsMatch(t, want, found, "the scan finds the credential in every spelling")
}

// lastSegment is a token's secret: the part after its final dot.
func lastSegment(token string) string {
	return token[strings.LastIndex(token, ".")+1:]
}

// landing is the point in tabA's refresh at which the other tab's whole refresh lands.
type landing int

const (
	// landBeforeFourthLoad lands it before the fourth read of the token.
	landBeforeFourthLoad landing = iota
	// landBeforeSupersede lands it after the last read and before the rotation's write.
	landBeforeSupersede
)

// raceTrace is what a race's hooks saw in tabA's lineage, counted from the database and from
// the calls, so a case proves where the other tab landed and not just that it did.
type raceTrace struct {
	// rowsBeforeLanding and rowsAfterLanding are the family's rows around the other tab's refresh.
	rowsBeforeLanding, rowsAfterLanding int
	// loadsAtLanding and loads are the reads of the token tabA had made when the other tab landed,
	// and by the end.
	loadsAtLanding, loads int
	// supersedes are tabA's rotation writes, and supersedesAfterLanding those made after the landing.
	supersedes, supersedesAfterLanding int
}

// raceOtherTab runs a refresh of one token on tabA, and the whole refresh of the same token on
// tabB at the point named, under a shared successor key. It checks what holds wherever the
// landing is: neither refresh fails, both answer one successor, and the family keeps one head and
// two rows and stays live. It returns what the hooks saw.
func (e *durEnv) raceOtherTab(t *testing.T, key []byte, at landing) raceTrace {
	t.Helper()

	issuer := e.build(t, nil, oidcprovider.WithRefreshSuccessorKey(key))
	issued := e.issue(t, issuer, durWeb)
	rt0 := issued.tokens.RefreshToken
	family := familyOf(t, rt0)
	secret := lastSegment(rt0)

	// tabB is the other tab.
	tabB := e.build(t, nil, oidcprovider.WithRefreshSuccessorKey(key))
	var (
		tr      raceTrace
		landed  bool
		bResult *oidcprovider.TokenResponse
		bErr    error
	)
	rows := func() int { return e.lineageRows(t, family) }
	land := func(ctx context.Context) {
		landed = true
		tr.loadsAtLanding = tr.loads
		tr.rowsBeforeLanding = rows()
		bResult, bErr = e.refresh(ctx, tabB, durWeb, rt0)
		tr.rowsAfterLanding = rows()
	}
	hooks := func(wrapped session.Store) session.Store {
		return hookedLineage{Store: wrapped,
			beforeLoad: func(ctx context.Context, got string) {
				if got != secret {
					return
				}
				tr.loads++
				if at == landBeforeFourthLoad && tr.loads == 4 {
					land(ctx)
				}
			},
			beforeSupersede: func(ctx context.Context, _ session.Supersession) {
				tr.supersedes++
				if at == landBeforeSupersede && !landed {
					land(ctx)
				}
				if landed {
					tr.supersedesAfterLanding++
				}
			},
		}
	}
	tabA := e.build(t, hooks, oidcprovider.WithRefreshSuccessorKey(key))

	res, err := e.refresh(t.Context(), tabA, durWeb, rt0)
	require.True(t, landed, "the other tab's write landed mid-refresh")
	require.NoError(t, bErr)
	require.NoError(t, err, "no dependency failure from an identifier in use")
	assert.Equal(t, bResult.RefreshToken, res.RefreshToken, "the same successor")
	assert.Equal(t, 1, e.heads(t, family))
	assert.Equal(t, 2, e.lineageRows(t, family))
	e.mustRefresh(t, issuer, durWeb, res.RefreshToken)

	return tr
}

// TestOIDCProvider_Durable runs a provider over each durable adapter on PostgreSQL: an
// authorization, an exchange, a refresh after a restart and a revocation, and what memory stores
// could only reason about: the refresh races, and the columns the provider's tables keep.
func TestOIDCProvider_Durable(t *testing.T) {
	t.Parallel()

	sharedKey := []byte("a-shared-successor-key-of-32-bytes!!")

	type testCase struct {
		name   string
		assert func(t *testing.T, e *durEnv)
	}

	cases := []testCase{
		{
			name: "a restarted provider under a changed key refreshes the first's token and the old one re-rotates",
			assert: func(t *testing.T, e *durEnv) {
				first := e.build(t, nil)
				issued := e.issue(t, first, durWeb)
				rt0 := issued.tokens.RefreshToken

				rt1 := e.mustRefresh(t, first, durWeb, rt0).RefreshToken

				// A restart under another key cannot derive the successor the first provider
				// answered: the token inside its grace rotates again, and the first answer is
				// knocked out (R20, the limit stated).
				second := e.build(t, nil, oidcprovider.WithRefreshSuccessorKey([]byte("a-changed-successor-key-of-32-bytes!")))
				res := e.mustRefresh(t, second, durWeb, rt0)
				assert.NotEqual(t, rt1, res.RefreshToken, "a fresh key re-rotates")
				assert.Equal(t, 1, e.heads(t, familyOf(t, rt0)), "one head remains")

				// The grant is live and the new head works on the restarted provider.
				e.mustRefresh(t, second, durWeb, res.RefreshToken)
				_, err := second.VerifyAccessToken(t.Context(), res.AccessToken)
				assert.NoError(t, err)
			},
		},
		{
			name: "a restarted provider sharing the key answers the same successor",
			assert: func(t *testing.T, e *durEnv) {
				first := e.build(t, nil, oidcprovider.WithRefreshSuccessorKey(sharedKey))
				issued := e.issue(t, first, durWeb)
				rt0 := issued.tokens.RefreshToken

				rt1 := e.mustRefresh(t, first, durWeb, rt0).RefreshToken

				second := e.build(t, nil, oidcprovider.WithRefreshSuccessorKey(sharedKey))
				res := e.mustRefresh(t, second, durWeb, rt0)
				assert.Equal(t, rt1, res.RefreshToken, "the same key derives the same successor")
				assert.Equal(t, 1, e.heads(t, familyOf(t, rt0)), "one head remains")
				assert.Equal(t, 2, e.lineageRows(t, familyOf(t, rt0)), "the answer wrote nothing")

				e.mustRefresh(t, second, durWeb, rt1)
			},
		},
		{
			name: "revoking ends every token of the grant, after a restart",
			assert: func(t *testing.T, e *durEnv) {
				first := e.build(t, nil)
				web := e.issue(t, first, durWeb)
				opaque := e.issue(t, first, durOpaque)
				require.True(t, strings.HasPrefix(opaque.tokens.AccessToken, "at."), "an opaque access token")
				webRefreshed := e.mustRefresh(t, first, durWeb, web.tokens.RefreshToken)
				opaqueRefreshed := e.mustRefresh(t, first, durOpaque, opaque.tokens.RefreshToken)

				second := e.build(t, nil)
				for _, at := range []string{web.tokens.AccessToken, webRefreshed.AccessToken, opaque.tokens.AccessToken, opaqueRefreshed.AccessToken} {
					_, err := second.VerifyAccessToken(t.Context(), at)
					require.NoError(t, err, "live before the revocation")
				}

				require.NoError(t, second.Revoke(t.Context(), durWeb.creds(), url.Values{"token": {webRefreshed.RefreshToken}}))
				require.NoError(t, second.Revoke(t.Context(), durOpaque.creds(), url.Values{"token": {opaqueRefreshed.RefreshToken}}))

				// Presented to the provider that was never told, too.
				third := e.build(t, nil)
				for _, p := range []*oidcprovider.Provider{second, third} {
					e.requireRefreshRefused(t, p, durWeb, webRefreshed.RefreshToken)
					e.requireRefreshRefused(t, p, durWeb, web.tokens.RefreshToken)
					e.requireRefreshRefused(t, p, durOpaque, opaqueRefreshed.RefreshToken)
					for _, at := range []string{
						web.tokens.AccessToken, webRefreshed.AccessToken, opaque.tokens.AccessToken, opaqueRefreshed.AccessToken,
					} {
						e.requireTokenRefused(t, p, at)
					}
				}
				for _, issued := range []durIssued{web, opaque} {
					family := familyOf(t, issued.tokens.RefreshToken)
					assert.Zero(t, e.lineageRows(t, family), "the family is deleted")
					assert.Equal(t, 1, countRows(t, e.conn.DB, "op_grants", "family = '"+family.String()+"' AND revoked"),
						"the grant row is marked revoked")
				}
			},
		},
		{
			name: "revoking an opaque access token ends it alone",
			assert: func(t *testing.T, e *durEnv) {
				first := e.build(t, nil)
				opaque := e.issue(t, first, durOpaque)

				second := e.build(t, nil)
				require.NoError(t, second.Revoke(t.Context(), durOpaque.creds(), url.Values{"token": {opaque.tokens.AccessToken}}))
				e.requireTokenRefused(t, second, opaque.tokens.AccessToken)
				e.mustRefresh(t, second, durOpaque, opaque.tokens.RefreshToken)
			},
		},
		{
			name: "introspection and UserInfo answer before the revocation and after it",
			assert: func(t *testing.T, e *durEnv) {
				first := e.build(t, nil)
				web := e.issue(t, first, durWeb)
				opaque := e.issue(t, first, durOpaque)

				p := e.build(t, nil)
				for _, tc := range []struct {
					c      durClient
					issued durIssued
				}{{durWeb, web}, {durOpaque, opaque}} {
					got := e.introspect(t, p, tc.c, tc.issued.tokens.AccessToken)
					assert.Equal(t, true, got["active"], tc.c.id)
					assert.Equal(t, tc.c.id, got["client_id"])
					assert.Equal(t, string(durUser), got["sub"])
					assert.Equal(t, durScope, got["scope"])
					assert.Equal(t, "Bearer", got["token_type"])
					assert.Equal(t, opIssuer, got["iss"])

					got = e.introspect(t, p, tc.c, tc.issued.tokens.RefreshToken)
					assert.Equal(t, true, got["active"], tc.c.id)
					assert.Equal(t, "refresh_token", got["token_type"])
					assert.Equal(t, string(durUser), got["sub"])
				}

				verified := make(map[string]*oidcprovider.AccessToken)
				for _, issued := range []durIssued{web, opaque} {
					at, err := p.VerifyAccessToken(t.Context(), issued.tokens.AccessToken)
					require.NoError(t, err)
					verified[at.ClientID] = at
					claims, err := p.UserInfo(t.Context(), at)
					require.NoError(t, err)
					assert.Equal(t, string(durUser), claims["sub"])
					assert.Equal(t, durUsername, claims["email"], "the username that is an address is released")
					assert.Equal(t, false, claims["email_verified"])
				}

				require.NoError(t, p.Revoke(t.Context(), durWeb.creds(), url.Values{"token": {web.tokens.RefreshToken}}))
				require.NoError(t, p.Revoke(t.Context(), durOpaque.creds(), url.Values{"token": {opaque.tokens.RefreshToken}}))

				after := e.build(t, nil)
				for _, tc := range []struct {
					c      durClient
					issued durIssued
				}{{durWeb, web}, {durOpaque, opaque}} {
					assert.Equal(t, map[string]any{"active": false}, e.introspect(t, after, tc.c, tc.issued.tokens.AccessToken), tc.c.id)
					assert.Equal(t, map[string]any{"active": false}, e.introspect(t, after, tc.c, tc.issued.tokens.RefreshToken), tc.c.id)
					_, err := after.UserInfo(t.Context(), verified[tc.c.id])
					requireRefusal(t, err, oidcprovider.CodeInvalidToken)
				}
			},
		},
		{
			name: "two concurrent refreshes within the window share a key and both get the same successor",
			assert: func(t *testing.T, e *durEnv) {
				// Both refreshes reach their rotation's write before either makes it, so they
				// really race for the one conditional update.
				var arrived atomic.Int32
				ready := make(chan struct{})
				barrier := func(wrapped session.Store) session.Store {
					return hookedLineage{Store: wrapped, beforeSupersede: func(ctx context.Context, _ session.Supersession) {
						if arrived.Add(1) == 2 {
							close(ready)
						}
						select {
						case <-ready:
						case <-ctx.Done():
						case <-time.After(30 * time.Second):
						}
					}}
				}
				issuer := e.build(t, nil, oidcprovider.WithRefreshSuccessorKey(sharedKey))
				issued := e.issue(t, issuer, durWeb)
				rt0 := issued.tokens.RefreshToken
				family := familyOf(t, rt0)

				tabA := e.build(t, barrier, oidcprovider.WithRefreshSuccessorKey(sharedKey))
				tabB := e.build(t, barrier, oidcprovider.WithRefreshSuccessorKey(sharedKey))

				var wg sync.WaitGroup
				results := make([]*oidcprovider.TokenResponse, 2)
				errs := make([]error, 2)
				for i, p := range []*oidcprovider.Provider{tabA, tabB} {
					wg.Add(1)
					go func() {
						defer wg.Done()
						results[i], errs[i] = e.refresh(t.Context(), p, durWeb, rt0)
					}()
				}
				wg.Wait()

				require.NoError(t, errs[0])
				require.NoError(t, errs[1])
				require.GreaterOrEqual(t, arrived.Load(), int32(2), "both reached the write")
				assert.Equal(t, results[0].RefreshToken, results[1].RefreshToken, "one successor")
				assert.NotEqual(t, rt0, results[0].RefreshToken)
				assert.Equal(t, 1, e.heads(t, family), "one head remains")
				assert.Equal(t, 2, e.lineageRows(t, family))

				// The grant stays live: the head refreshes, and both tabs' access tokens verify.
				e.mustRefresh(t, issuer, durWeb, results[0].RefreshToken)
				for _, res := range results {
					_, err := issuer.VerifyAccessToken(t.Context(), res.AccessToken)
					assert.NoError(t, err)
				}
			},
		},
		{
			name: "a superseded token past its grace revokes the whole grant",
			assert: func(t *testing.T, e *durEnv) {
				first := e.build(t, nil)
				issued := e.issue(t, first, durWeb)
				rt0 := issued.tokens.RefreshToken
				family := familyOf(t, rt0)
				refreshed := e.mustRefresh(t, first, durWeb, rt0)

				// The default grace is 30 seconds.
				e.clk.Advance(31 * time.Second)

				second := e.build(t, nil)
				e.requireRefreshRefused(t, second, durWeb, rt0)

				at, err := second.VerifyAccessToken(t.Context(), refreshed.AccessToken)
				require.Nil(t, at)
				requireRefusal(t, err, oidcprovider.CodeInvalidToken)
				e.requireRefreshRefused(t, second, durWeb, refreshed.RefreshToken)
				assert.Zero(t, e.lineageRows(t, family), "the family is deleted")
				assert.Equal(t, 1, countRows(t, e.conn.DB, "op_grants", "family = '"+family.String()+"' AND revoked"),
					"the grant row is marked revoked")
			},
		},
		{
			name: "the other tab landing between the rotation's read and its write ends in the same successor",
			assert: func(t *testing.T, e *durEnv) {
				tr := e.raceOtherTab(t, sharedKey, landBeforeSupersede)

				// The rotation judged by a read that was already stale: the family was one row
				// when it read, and the other tab's successor was there when it wrote, so its
				// write met a successor it had not observed.
				assert.Equal(t, 1, tr.rowsBeforeLanding, "the token was live when the other tab landed")
				assert.Equal(t, 2, tr.rowsAfterLanding, "the other tab's successor is stored")
				require.Equal(t, 1, tr.supersedes, "tabA's rotation wrote once")
				assert.Equal(t, 1, tr.supersedesAfterLanding, "tabA's write came after the other tab's")
				// The four reads before a rotation's write are the family check, the manager's read,
				// the read that guards a slow user load, and the rotation's own: the landing came
				// after all of them, and the one read after it is the refusal's reload.
				assert.Equal(t, 4, tr.loadsAtLanding, "the landing came after the rotation's own read")
				assert.Equal(t, 5, tr.loads, "the lost write reloads the token once")
			},
		},
		{
			name: "a second read that finds the other tab's write answers the same successor",
			assert: func(t *testing.T, e *durEnv) {
				tr := e.raceOtherTab(t, sharedKey, landBeforeFourthLoad)

				// The loads of the token in one refresh: its family check, the manager's read, the
				// read that guards a slow user load, and the rotation's own. The other tab lands
				// before the fourth, so the rotation reads the superseded token, and a read follows.
				assert.Equal(t, 1, tr.rowsBeforeLanding, "the token was live when the other tab landed")
				assert.Equal(t, 2, tr.rowsAfterLanding, "the other tab's successor is stored")
				assert.Equal(t, 4, tr.loadsAtLanding, "the other tab landed at the rotation's own read")
				assert.Greater(t, tr.loads, tr.loadsAtLanding, "a read of the token followed the landing")
				assert.Zero(t, tr.supersedes, "the rotation found the successor and wrote nothing")
			},
		},
		{
			name: "no credential is in any column after a real exchange and refresh",
			assert: func(t *testing.T, e *durEnv) {
				e.requireScanSeesCredentials(t)

				p := e.build(t, nil)
				credentials := make(map[string]string)
				families := make(map[string]string)
				for _, c := range []durClient{durWeb, durOpaque} {
					issued := e.issue(t, p, c)
					refreshed := e.mustRefresh(t, p, c, issued.tokens.RefreshToken)

					// The scan sees the rows: the grant's family, which is no secret, is found.
					family := familyOf(t, issued.tokens.RefreshToken)
					families[c.id] = family.String()
					require.NotEmpty(t, findCredentials(dumpDatabase(t, e.conn.DB), map[string]string{"family": family.String()}),
						"the scan finds the grant's rows")

					for label, secret := range map[string]string{
						"pending handle": issued.handle, "flow secret": issued.flow,
						"code": issued.code, "code secret": lastSegment(issued.code),
						"access token": issued.tokens.AccessToken, "access token secret": lastSegment(issued.tokens.AccessToken),
						"ID token":      issued.tokens.IDToken,
						"refresh token": issued.tokens.RefreshToken, "refresh secret": lastSegment(issued.tokens.RefreshToken),
						"refreshed access token": refreshed.AccessToken, "refreshed access secret": lastSegment(refreshed.AccessToken),
						"refreshed ID token":      refreshed.IDToken,
						"refreshed refresh token": refreshed.RefreshToken, "refreshed refresh secret": lastSegment(refreshed.RefreshToken),
					} {
						require.NotEmpty(t, secret, label)
						credentials[c.id+" "+label] = secret
					}
				}

				// The consents and clients are in rows the scan reads: it finds their keys, which
				// are no secrets, in their tables.
				dump := dumpDatabase(t, e.conn.DB)
				assert.Positive(t, countRows(t, e.conn.DB, "op_consents", ""), "op_consents holds rows")
				assert.Positive(t, countRows(t, e.conn.DB, "op_clients", ""), "op_clients holds rows")
				assert.Contains(t, dump["op_consents"], string(durUser), "the scan reads the consents")
				for _, c := range []durClient{durWeb, durOpaque} {
					assert.Contains(t, dump["op_clients"], c.id, "the scan reads the clients")
					// A client's secret is kept as a digest, so the secret itself is a credential too.
					credentials[c.id+" client secret"] = c.secret
				}

				// Every table that holds a credential is read, too: each is found to hold a row, by a
				// key that is no secret. The opaque client's access token is the only one stored.
				for table, key := range map[string]string{
					"op_refresh_tokens":      families[durWeb.id],
					"op_access_tokens":       families[durOpaque.id],
					"op_authorization_codes": families[durWeb.id],
					"op_grants":              families[durOpaque.id],
					"op_pending_requests":    string(durUser),
					"op_browser_sessions":    string(durUser),
				} {
					assert.Contains(t, dump[table], key, "the scan reads %s", table)
				}
				// No client here authenticates by assertion, so this table is empty at scan time.
				// The scan still names it, which a scan that skipped it would not.
				assert.Contains(t, dump, "op_client_assertions", "the scan reads the assertion identifiers")

				for _, hit := range findCredentials(dump, credentials) {
					assert.Failf(t, "a credential is kept in clear", "table %s holds the %s", hit.table, hit.label)
				}
			},
		},
	}

	for _, adapter := range opAdapters {
		t.Run(adapter.name, func(t *testing.T) {
			t.Parallel()

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()

					tc.assert(t, newDurEnv(t, adapter.name, adapter.open))
				})
			}
		})
	}
}
