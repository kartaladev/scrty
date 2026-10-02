package httpsecconformance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/migrate"
	"github.com/kartaladev/scrty/onetime"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// recoveryResolvePath is the consumer's password-change resolve endpoint the
// recovery scenarios bind a recovered session with. It is distinct from every
// login, logout and recovery path the chain registers of its own.
const recoveryResolvePath = "/account/password/resolve"

// recoveryHoldDelay is the fixed delay a held-recovery scenario configures.
const recoveryHoldDelay = time.Hour

// recoveryRepudiationContact is the text every recovery notice ends with.
const recoveryRepudiationContact = "Write to security@example.com if this was not you."

// RecoveryFixture is the account-recovery path's wiring for one run, over its
// own PostgreSQL-backed stores: a durable session store, saved-code store and
// recovery-record store, each on the migrated security-state schema.
//
// It is built once per scenario, so no framework is judged on state another
// left in the database, and it is not shared with the base Effects' Sessions
// field's usual in-memory Store: a recovery scenario reads sessions back
// through SessionStore instead.
type RecoveryFixture struct {
	// Pool is the migrated database every store of the fixture runs on, so a
	// scenario can put further stores of its own on the same one.
	Pool *pgxpool.Pool

	// SessionStore is the durable store behind the session manager every
	// recovery scenario's chain is wired with.
	SessionStore session.Store

	// Codes manages saved recovery codes over the durable code store.
	Codes *recovery.Codes

	// Records is the durable recovery-record store.
	Records recovery.RecordStore

	// TOTP is the second factor a completed recovery can bind, and the kind
	// its authenticators are reset through.
	TOTP *mfa.TOTP
	Kind recovery.AuthenticatorKind

	// Clock is shared by the session manager, TOTP and the recovery core, so
	// a scenario moves time for all three at once.
	Clock *clockwork.FakeClock

	// Outbox is every message the recovery core queued: issued codes and
	// notices.
	Outbox *Outbox

	// OneTime is the durable issued-code and hold-token store. A scenario that
	// sends an HTTP request to a recovery endpoint builds its own standalone
	// Recoverer over the same RecoveryFixture and passes it the same
	// coreOpts (see recoveryCoreOptions) as the chain's own, internally-built
	// one; sharing this store is what lets a code or a token either one
	// mints be honoured by the other.
	OneTime onetime.Store
}

// LoadSession reads a session back out of the durable store, so a scenario can
// assert what the recovery core or the chain marked on it.
func (fx *RecoveryFixture) LoadSession(t *testing.T, id string) *session.Session {
	t.Helper()

	s, err := fx.SessionStore.Load(t.Context(), id)
	require.NoError(t, err)

	return s
}

// lastMessage is the most recent message the fixture's sender was given, such
// as the issued code Start queued.
func (fx *RecoveryFixture) lastMessage(t *testing.T) string {
	t.Helper()

	sent := fx.Outbox.Messages()
	require.NotEmpty(t, sent, "nothing was sent")

	return sent[len(sent)-1].TextBody
}

// conformanceRecoveryMessages is the fixture's message builder: the issued
// code, and the held recovery's cancel link, are each a message's whole body,
// so a scenario reads either back without parsing prose.
type conformanceRecoveryMessages struct{}

func (conformanceRecoveryMessages) IssuedCode(code string, _ time.Time) (string, string) {
	return "issued-code", code
}

func (conformanceRecoveryMessages) Recovered(recovery.Notice) (string, string) {
	return "recovered", "recovered"
}

func (conformanceRecoveryMessages) Held(_ recovery.Notice, link string, _ time.Time) (string, string) {
	return "held", link
}

func (conformanceRecoveryMessages) Cancelled(recovery.Notice) (string, string) {
	return "cancelled", "cancelled"
}

func (conformanceRecoveryMessages) Regenerated(time.Time) (string, string) {
	return "regenerated", "regenerated"
}

// newRecoveryPostgresPool starts a migrated PostgreSQL database for one
// scenario run and opens a small pool on it, closed at cleanup.
func newRecoveryPostgresPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	set := migrate.SecurityState()
	conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))

	cfg, err := pgxpool.ParseConfig(conn.DSN)
	require.NoError(t, err)
	cfg.MaxConns = 8

	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	return pool
}

// newRecoveryFixture builds a RecoveryFixture over a freshly migrated
// database, and the session manager every recovery scenario's chain shares
// with it.
func newRecoveryFixture(t *testing.T) (*RecoveryFixture, *session.Manager) {
	t.Helper()

	pool := newRecoveryPostgresPool(t)
	cipher := storefix.TestCipher(t)
	clk := clockwork.NewFakeClockAt(time.Now())

	sessionStore, err := pgxstore.NewSessionStore(pool, cipher, pgxstore.WithClock(clk))
	require.NoError(t, err)

	sessions, err := session.NewManager(session.WithClock(clk), session.WithStore(sessionStore))
	require.NoError(t, err)

	codeStore, err := pgxstore.NewRecoveryCodeStore(pool)
	require.NoError(t, err)

	codes, err := recovery.NewCodes(recovery.WithCodeStore(codeStore), recovery.WithCodesClock(clk))
	require.NoError(t, err)

	records, err := pgxstore.NewRecoveryRecordStore(pool)
	require.NoError(t, err)

	totpMethod, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example", mfa.WithClock(clk))
	require.NoError(t, err)

	kind, err := recovery.MFAEnrolments(totpMethod)
	require.NoError(t, err)

	oneTime, err := pgxstore.NewOneTimeStore(pool, pgxstore.WithClock(clk))
	require.NoError(t, err)

	fx := &RecoveryFixture{
		Pool:         pool,
		SessionStore: sessionStore,
		Codes:        codes,
		Records:      records,
		TOTP:         totpMethod,
		Kind:         kind,
		Clock:        clk,
		Outbox:       &Outbox{},
		OneTime:      oneTime,
	}

	return fx, sessions
}

// recoveryCoreOptions are the recovery core's own options every scenario
// shares: the proof kinds enabled, the reset kind, the message builder that
// makes a message's body legible, and the fixture's shared clock.
//
// A scenario that builds both a standalone Recoverer and, through
// httpsec.WithRecoveryCore, the chain's own recoverer passes this same slice
// to both on purpose: the durable issued-code and hold-token store
// (fx.OneTime) they name here is what lets a code or a token minted by
// either be checked or spent by the other, which is what an HTTP-level
// recovery scenario needs — the request goes to the chain's recoverer, and
// the fixture has to hand it something the standalone one already issued.
func recoveryCoreOptions(fx *RecoveryFixture, proofs ...recovery.ProofKind) []recovery.Option {
	return []recovery.Option{
		recovery.WithProofs(proofs...),
		recovery.WithRepudiationContact(recoveryRepudiationContact),
		recovery.WithAuthenticatorKinds(fx.Kind),
		recovery.WithMessages(conformanceRecoveryMessages{}),
		recovery.WithClock(fx.Clock),
		recovery.WithIssuedCodeStore(fx.OneTime),
		recovery.WithHoldTokenStore(fx.OneTime),
	}
}

// noopChangePassword is a password-change resolve function that only reports
// success. Its behaviour is not the subject of a recovery scenario: what a
// completed resolve leaves the session in is.
var noopChangePassword httpsec.ChangePasswordFunc = func(*httpsec.Exchange) error { return nil }

// recoveryScenarios is every account-recovery behaviour that must be
// identical on every adapter, run over the pgx durable backend: sessions,
// saved codes and recovery records all persist to real PostgreSQL tables.
func recoveryScenarios() []Scenario {
	return []Scenario{
		recoverySavedAndIssuedCodesReachRecoveryPending(),
		recoveryEnrolmentThenVerifyReachesFullSession(),
		recoveryPasswordRouteReachesFullSession(),
		recoveryHeldRecoveryCancelledByLogin(),
		recoveryCooldownRefusesAfterReLogin(),
		recoveryCompleteEndpointIssuesACredential(),
		recoveryStartEndpointIssuesACode(),
		recoveryCompleteRefusesAWrongSavedCode(),
		recoveryFinishEndpointCompletesAHeldRecovery(),
		recoveryCancelEndpointCancelsAHeldRecovery(),
		recoveryCodesEndpointRegeneratesForAFreshSession(),
		recoveryCodesEndpointReportsTheRemainingCount(),
		recoveryCodesEndpointRefusesAStaleSession(),
	}
}

// cancelTokenFromLink reads the cancel token a held recovery's notice linked
// to, exactly as the consumer's own page would: by parsing the link and
// reading recovery.CancelLinkParam out of its query.
func cancelTokenFromLink(t *testing.T, link string) string {
	t.Helper()

	u, err := url.Parse(link)
	require.NoError(t, err, "link: %q", link)

	token := u.Query().Get(recovery.CancelLinkParam)
	require.NotEmpty(t, token, "link carries no cancel token: %q", link)

	return token
}

// mangleSavedCode returns a saved code of the same shape as code, with its
// first non-dash character flipped to another character of the Crockford
// base32 alphabet: well-formed, so it is checked rather than rejected as
// malformed, and always wrong.
func mangleSavedCode(code string) string {
	b := []byte(code)

	for i, c := range b {
		if c == '-' {
			continue
		}

		if c == '0' {
			b[i] = '1'
		} else {
			b[i] = '0'
		}

		break
	}

	return string(b)
}

// recoverySavedAndIssuedCodesReachRecoveryPending pins spec account-recovery
// "A recovery produces a confined session, never a full one" and http-security
// -chain's recovery gate: a saved code and an issued code, checked and spent
// through the durable stores, produce a recovery-pending session, and that
// session is refused a protected route with the account-recovery challenge.
func recoverySavedAndIssuedCodesReachRecoveryPending() Scenario {
	return Scenario{
		Name: "a saved code and an issued code lead to a recovery-pending session, refused a protected route",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofIssued)

			standalone, err := recovery.NewRecoverer(deps, coreOpts...)
			require.NoError(t, err)

			saved, err := fx.Codes.Generate(ctx, UserID)
			require.NoError(t, err)

			standalone.Start(ctx, Username)
			issued := fx.lastMessage(t)

			result, err := standalone.Recover(ctx, recovery.Request{
				Username: Username, Saved: saved[0], Issued: issued, Source: ClientAddress,
			})
			require.NoError(t, err)
			require.NotNil(t, result.Session)
			require.Equal(t, session.MFARecoveryPending, result.Session.MFA,
				"a saved code and an issued code produce a recovery-pending session")

			effects := &Effects{Sessions: sessions, Recovery: fx, SessionID: result.Session.ID}

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: fixtureTokens{}, Sessions: sessions, Users: fixtureUsers{},
					}),
					httpsec.EnableAccountRecovery(httpsec.RecoveryDeps(deps),
						httpsec.WithRecoveryCore(coreOpts...),
						httpsec.WithRecoveryTokens(fixtureTokens{}),
					),
					httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithChangePasswordEndpoint(recoveryResolvePath, noopChangePassword)),
				},
				Effects: effects,
				Routes:  plainRoute(),
			}
		},
		Request: authenticatedRequest(http.MethodGet, RoutePath),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusForbidden, res.Status)
			assert.Empty(t, res.Body, "a refusal carries no error text")
			assert.False(t, res.RouteRan, "the route behind the gate did not run")

			var challenge *httpsec.ChallengeError
			require.ErrorAs(t, res.Refusal, &challenge)
			assert.Equal(t, policy.ChallengeAccountRecovery, challenge.Kind)
			assert.Empty(t, challenge.Token, "a gate issues nothing")
			require.NotNil(t, challenge.Session)
			assert.Equal(t, session.MFARecoveryPending, challenge.Session.MFA)
		},
	}
}

// recoveryEnrolmentThenVerifyReachesFullSession pins spec account-recovery "A
// recovery produces a confined session, never a full one": from a
// recovery-pending session, the MFA enrolment path followed by verification
// binds a new authenticator, and the resulting session reaches a protected
// route while keeping the recovery's own record: the first factor and the
// time it was recovered.
func recoveryEnrolmentThenVerifyReachesFullSession() Scenario {
	return Scenario{
		Name: "the MFA enrolment path followed by verification reaches a full session",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			s, err := sessions.Create(ctx, UserID, session.WithFirstFactor(factor.Recovery))
			require.NoError(t, err)

			sessions.MarkRecoveryPending(s, 15*time.Minute, fx.Clock.Now())

			provisioning, gen, err := fx.TOTP.BeginEnrolmentGeneration(ctx, UserID, Username)
			require.NoError(t, err)
			s.EnrolmentGeneration = gen

			proveCode, err := totp.GenerateCode(provisioning.Secret, fx.Clock.Now())
			require.NoError(t, err)

			emailed, err := fx.TOTP.ProveDevice(ctx, UserID, gen, proveCode, true, 10*time.Minute)
			require.NoError(t, err)

			require.NoError(t, fx.TOTP.RedeemEmailCode(ctx, UserID, gen, emailed))
			s.MFA = session.MFAPending

			// The proof spent this step's code; verification presents the next one.
			fx.Clock.Advance(fx.TOTP.Period())

			verifyCode, err := totp.GenerateCode(provisioning.Secret, fx.Clock.Now())
			require.NoError(t, err)

			require.NoError(t, fx.TOTP.Verify(ctx, UserID, []byte(verifyCode)))
			s.MFA = session.MFASatisfied
			s.MFASatisfiedAt = fx.Clock.Now()

			// What the verify endpoint itself does next: give the deadlines back
			// and clear the marker, so the session this scenario sends carries
			// none.
			require.NoError(t, sessions.RestoreEnrolmentDeadlines(s))
			require.NoError(t, sessions.Save(ctx, s))

			effects := &Effects{Sessions: sessions, Recovery: fx, SessionID: s.ID}

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: fixtureTokens{}, Sessions: sessions, Users: fixtureUsers{},
					}),
				},
				Effects: effects,
				Routes:  []Route{{Method: http.MethodGet, Path: RoutePath, Status: http.StatusOK, Body: RouteBody}},
			}
		},
		Request: authenticatedRequest(http.MethodGet, RoutePath),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, RouteBody, res.Body)
			assert.True(t, res.RouteRan, "the bound session reaches the route behind the gate")

			s := res.Effects.Recovery.LoadSession(t, res.Effects.SessionID)
			assert.Equal(t, session.MFASatisfied, s.MFA)
			assert.Equal(t, factor.Recovery, s.FirstFactor, "the session still records how it began")
			assert.False(t, s.RecoveredAt.IsZero(), "the recovery time is kept")
			assert.True(t, s.EnrolmentOriginDeadline.IsZero(), "the confinement marker is cleared")
		},
	}
}

// recoveryPasswordRouteReachesFullSession pins spec account-recovery "A
// recovery produces a confined session, never a full one": a successful
// password change at the consumer's resolve endpoint binds a recovery-pending
// session for a user who is not required to use a second factor, restoring
// its deadlines and clearing its recovery-pending state without rotating the
// handle.
func recoveryPasswordRouteReachesFullSession() Scenario {
	return Scenario{
		Name: "the password-change resolve endpoint completes a recovery for a user not required to use MFA",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			s, err := sessions.Create(ctx, UserID, session.WithFirstFactor(factor.Recovery))
			require.NoError(t, err)

			sessions.MarkRecoveryPending(s, 15*time.Minute, fx.Clock.Now())
			require.NoError(t, sessions.Save(ctx, s))

			effects := &Effects{Sessions: sessions, Recovery: fx, SessionID: s.ID}

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: fixtureTokens{}, Sessions: sessions, Users: fixtureUsers{},
					}),
					httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithChangePasswordEndpoint(recoveryResolvePath, noopChangePassword)),
				},
				Effects: effects,
			}
		},
		Request: func(spec ChainSpec) RequestSpec {
			r := authenticatedRequest(http.MethodPost, recoveryResolvePath)(spec)
			r.Header["Content-Type"] = "application/x-www-form-urlencoded"
			r.Body = url.Values{"password": {"a new one"}}.Encode()

			return r
		},
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)

			s := res.Effects.Recovery.LoadSession(t, res.Effects.SessionID)
			assert.Equal(t, session.MFANone, s.MFA,
				"the resolve completes the recovery for a user not required to use MFA")
			assert.False(t, s.PasswordChangePending)
			assert.True(t, s.EnrolmentOriginDeadline.IsZero(), "the confinement marker is cleared")
			assert.True(t, s.AbsoluteExpiresAt.After(time.Now().Add(time.Hour)),
				"the deadline a login would have had is restored")
		},
	}
}

// recoveryHeldRecoveryCancelledByLogin pins spec account-recovery "A held
// recovery is cancelled by the user": with a delay configured, a login of the
// same user cancels the pending recovery, and the finish presented afterwards
// is refused as a recovery-refused error.
func recoveryHeldRecoveryCancelledByLogin() Scenario {
	return Scenario{
		Name: "a held recovery is cancelled by a login, and the finish is later refused",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := append(recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofIssued),
				recovery.WithDelay(recoveryHoldDelay),
				recovery.WithCancelLink("https://app.example.com/cancel"),
			)

			standalone, err := recovery.NewRecoverer(deps, coreOpts...)
			require.NoError(t, err)

			saved, err := fx.Codes.Generate(ctx, UserID)
			require.NoError(t, err)

			standalone.Start(ctx, Username)
			issued := fx.lastMessage(t)

			result, err := standalone.Recover(ctx, recovery.Request{
				Username: Username, Saved: saved[0], Issued: issued, Source: ClientAddress,
			})
			require.NoError(t, err)
			require.NotNil(t, result.Held, "the configured delay holds the recovery")

			effects := &Effects{Sessions: sessions, Recovery: fx}
			effects.recoveryStandalone = standalone
			effects.recoveryCompletion = result.Held.CompletionToken

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: &fixtureAuthenticator{calls: &effects.authCalls},
						Sessions:      sessions,
						Tokens:        fixtureTokens{},
						Attempts:      policy.NewMemoryAttemptStore(),
					}),
					httpsec.EnableAccountRecovery(httpsec.RecoveryDeps(deps),
						httpsec.WithRecoveryCore(coreOpts...),
					),
					httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithChangePasswordEndpoint(recoveryResolvePath, noopChangePassword)),
				},
				Effects: effects,
			}
		},
		Request: sending(RequestSpec{
			Method: http.MethodPost,
			Path:   httpsec.DefaultLoginPath,
			Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body: url.Values{
				httpsec.DefaultLoginUsernameParam: {Username},
				httpsec.DefaultLoginPasswordParam: {Password},
			}.Encode(),
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusOK, res.Status, "the login this scenario is about still succeeds")

			_, err := res.Effects.recoveryStandalone.Finish(t.Context(), res.Effects.recoveryCompletion)
			require.ErrorIs(t, err, recovery.ErrRefused, "the login cancelled the held recovery")
			assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err))
		},
	}
}

// recoveryCooldownRefusesAfterReLogin pins spec account-recovery "An opt-in
// cool-down refuses sensitive routes after a recovery": EnableRecoveryCooldown
// marks a route, and a session opened well after the recovery — as a logout
// and a fresh login would leave one — is still refused on it, because the
// cool-down is read from the recovery record and not from the session.
func recoveryCooldownRefusesAfterReLogin() Scenario {
	sensitive := httpsec.Route{Method: http.MethodPost, Path: "/account/email"}

	return Scenario{
		Name: "the recovery cool-down still refuses a marked route after a logout and a re-login",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			rid, err := id.NewV7Generator().NewID()
			require.NoError(t, err)

			completedAt := fx.Clock.Now().Add(-3 * time.Hour)
			require.NoError(t, fx.Records.Insert(ctx, recovery.Record{
				ID: rid, User: UserID, StartedAt: completedAt, NotBefore: completedAt, CompletedAt: completedAt,
			}))

			// A session opened well after the recovery, independent of whatever
			// session the recovery itself produced: what a logout and a fresh
			// login would leave behind.
			s, err := sessions.Create(ctx, UserID, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			effects := &Effects{Sessions: sessions, Recovery: fx, SessionID: s.ID}

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: fixtureTokens{}, Sessions: sessions, Users: fixtureUsers{},
					}),
					httpsec.EnableRecoveryCooldown(fx.Records, 48*time.Hour, sensitive),
				},
				Effects: effects,
				Routes:  []Route{{Method: sensitive.Method, Path: sensitive.Path, Status: http.StatusOK, Body: RouteBody}},
			}
		},
		Request: authenticatedRequest(sensitive.Method, sensitive.Path),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusForbidden, res.Status)
			assert.Empty(t, res.Body)
			assert.False(t, res.RouteRan, "the marked route did not run during the cool-down")
			require.ErrorIs(t, res.Refusal, recovery.ErrCooldown)
		},
	}
}

// recoveryCompleteEndpointIssuesACredential pins spec account-recovery "A
// recovery needs two proofs of different kinds" and "A recovery produces a
// confined session, never a full one": a POST to the complete endpoint itself
// — the one request every adapter must handle identically — with a saved code
// and an issued code answers with a credential for a recovery-pending session
// and a fresh set of saved codes.
//
// The issued code is minted by a standalone Recoverer built from the same
// core options (coreOpts) as the chain's own, so the two share every
// durable store, the issued-code and hold-token store included: this is the
// one way an HTTP-level scenario can present a code the chain's own
// internally-built Recoverer will recognise.
func recoveryCompleteEndpointIssuesACredential() Scenario {
	return Scenario{
		Name: "POST /recovery/complete answers a credential for a recovery-pending session",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofIssued)

			standalone, err := recovery.NewRecoverer(deps, coreOpts...)
			require.NoError(t, err)

			saved, err := fx.Codes.Generate(ctx, UserID)
			require.NoError(t, err)

			standalone.Start(ctx, Username)
			issued := fx.lastMessage(t)

			effects := &Effects{Sessions: sessions, Recovery: fx}
			effects.recoverySavedCode = saved[0]
			effects.recoveryIssuedCode = issued

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableAccountRecovery(httpsec.RecoveryDeps(deps),
						httpsec.WithRecoveryCore(coreOpts...),
						httpsec.WithRecoveryTokens(fixtureTokens{}),
					),
					httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithChangePasswordEndpoint(recoveryResolvePath, noopChangePassword)),
				},
				Effects: effects,
			}
		},
		Request: func(spec ChainSpec) RequestSpec {
			return RequestSpec{
				Method: http.MethodPost,
				Path:   httpsec.DefaultRecoveryCompletePath,
				Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body: url.Values{
					httpsec.RecoveryUsernameParam:   {Username},
					httpsec.RecoverySavedCodeParam:  {spec.Effects.recoverySavedCode},
					httpsec.RecoveryIssuedCodeParam: {spec.Effects.recoveryIssuedCode},
				}.Encode(),
				ClientAddress: ClientAddress,
			}
		},
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))

			var body struct {
				AccessToken   string   `json:"access_token"`
				RecoveryCodes []string `json:"recovery_codes"`
				Remaining     int      `json:"remaining"`
			}
			require.NoError(t, json.Unmarshal([]byte(res.Body), &body), "body: %q", res.Body)
			assert.NotEmpty(t, body.AccessToken)
			assert.Len(t, body.RecoveryCodes, 10, "a spent saved code is replaced with a fresh set")
			assert.Equal(t, 10, body.Remaining)

			claims, err := fixtureTokens{}.Verify(t.Context(), body.AccessToken)
			require.NoError(t, err)

			s := res.Effects.Recovery.LoadSession(t, claims.ID())
			assert.Equal(t, session.MFARecoveryPending, s.MFA)
			assert.Equal(t, factor.Recovery, s.FirstFactor)
		},
	}
}

// recoveryStartEndpointIssuesACode pins spec account-recovery "An issued
// recovery code is sent by email and is checked before it is consumed": a
// POST to the start endpoint itself always answers 202 with an empty body,
// and — the one thing this HTTP-level scenario adds over the core's own
// tests — actually queues one issued-code message through the sender the
// chain was wired with.
func recoveryStartEndpointIssuesACode() Scenario {
	return Scenario{
		Name: "POST /recovery/start answers 202 and queues one issued code",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofIssued)

			effects := &Effects{Sessions: sessions, Recovery: fx}

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableAccountRecovery(httpsec.RecoveryDeps(deps),
						httpsec.WithRecoveryCore(coreOpts...),
						httpsec.WithRecoveryTokens(fixtureTokens{}),
					),
					httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithChangePasswordEndpoint(recoveryResolvePath, noopChangePassword)),
				},
				Effects: effects,
			}
		},
		Request: sending(RequestSpec{
			Method: http.MethodPost,
			Path:   httpsec.DefaultRecoveryStartPath,
			Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body: url.Values{
				httpsec.RecoveryUsernameParam: {Username},
			}.Encode(),
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusAccepted, res.Status)
			assert.Empty(t, res.Body)

			assert.Len(t, res.Effects.Recovery.Outbox.Messages(), 1, "exactly one issued code was queued")
			assert.NotEmpty(t, res.Effects.Recovery.lastMessage(t), "the message carries the issued code")
		},
	}
}

// recoveryCompleteRefusesAWrongSavedCode pins spec account-recovery "Every
// proof is checked before any is spent": a wrong saved code posted alongside
// a valid issued code is refused, and neither proof is spent — the issued
// code still checks, and the saved set's remaining count is unchanged. The
// standalone Recoverer built alongside the chain's own, sharing every durable
// store (see recoveryCoreOptions), is what lets the assertion check that
// directly rather than trust the refusal alone.
func recoveryCompleteRefusesAWrongSavedCode() Scenario {
	return Scenario{
		Name: "POST /recovery/complete with a wrong saved code spends neither proof",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofIssued)

			standalone, err := recovery.NewRecoverer(deps, coreOpts...)
			require.NoError(t, err)

			saved, err := fx.Codes.Generate(ctx, UserID)
			require.NoError(t, err)

			standalone.Start(ctx, Username)
			issued := fx.lastMessage(t)

			effects := &Effects{Sessions: sessions, Recovery: fx}
			effects.recoveryStandalone = standalone
			effects.recoverySavedCode = saved[0]
			effects.recoveryIssuedCode = issued

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableAccountRecovery(httpsec.RecoveryDeps(deps),
						httpsec.WithRecoveryCore(coreOpts...),
						httpsec.WithRecoveryTokens(fixtureTokens{}),
					),
					httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithChangePasswordEndpoint(recoveryResolvePath, noopChangePassword)),
				},
				Effects: effects,
			}
		},
		Request: func(spec ChainSpec) RequestSpec {
			return RequestSpec{
				Method: http.MethodPost,
				Path:   httpsec.DefaultRecoveryCompletePath,
				Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body: url.Values{
					httpsec.RecoveryUsernameParam:   {Username},
					httpsec.RecoverySavedCodeParam:  {mangleSavedCode(spec.Effects.recoverySavedCode)},
					httpsec.RecoveryIssuedCodeParam: {spec.Effects.recoveryIssuedCode},
				}.Encode(),
				ClientAddress: ClientAddress,
			}
		},
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.Empty(t, res.Body, "a refusal carries no error text")
			require.ErrorIs(t, res.Refusal, recovery.ErrRefused)

			remaining, err := res.Effects.Recovery.Codes.Remaining(t.Context(), UserID)
			require.NoError(t, err)
			assert.Equal(t, 10, remaining.N, "the saved set was not spent")

			// The issued code still checks: a second recovery presenting it
			// with the real saved code succeeds, which it could not if the
			// refused attempt above had already spent it.
			result, err := res.Effects.recoveryStandalone.Recover(t.Context(), recovery.Request{
				Username: Username,
				Saved:    res.Effects.recoverySavedCode,
				Issued:   res.Effects.recoveryIssuedCode,
				Source:   ClientAddress,
			})
			require.NoError(t, err, "the refused attempt spent neither proof")
			require.NotNil(t, result.Session)
		},
	}
}

// recoveryFinishEndpointCompletesAHeldRecovery pins spec account-recovery
// "Recovery completes at once by default, with opt-in holds": once the hold
// is over, a POST to the finish endpoint itself completes the recovery held
// by a standalone Recoverer sharing the chain's own durable stores, and
// answers exactly as an unheld completion would.
func recoveryFinishEndpointCompletesAHeldRecovery() Scenario {
	return Scenario{
		Name: "POST /recovery/finish completes a held recovery once the hold is over",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := append(recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofIssued),
				recovery.WithDelay(recoveryHoldDelay),
				recovery.WithCancelLink("https://app.example.com/cancel"),
			)

			standalone, err := recovery.NewRecoverer(deps, coreOpts...)
			require.NoError(t, err)

			saved, err := fx.Codes.Generate(ctx, UserID)
			require.NoError(t, err)

			standalone.Start(ctx, Username)
			issued := fx.lastMessage(t)

			result, err := standalone.Recover(ctx, recovery.Request{
				Username: Username, Saved: saved[0], Issued: issued, Source: ClientAddress,
			})
			require.NoError(t, err)
			require.NotNil(t, result.Held, "the configured delay holds the recovery")

			fx.Clock.Advance(recoveryHoldDelay + time.Second)

			effects := &Effects{Sessions: sessions, Recovery: fx}
			effects.recoveryCompletion = result.Held.CompletionToken

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableAccountRecovery(httpsec.RecoveryDeps(deps),
						httpsec.WithRecoveryCore(coreOpts...),
						httpsec.WithRecoveryTokens(fixtureTokens{}),
					),
					httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithChangePasswordEndpoint(recoveryResolvePath, noopChangePassword)),
				},
				Effects: effects,
			}
		},
		Request: func(spec ChainSpec) RequestSpec {
			return RequestSpec{
				Method: http.MethodPost,
				Path:   httpsec.DefaultRecoveryFinishPath,
				Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body: url.Values{
					httpsec.RecoveryCompletionTokenParam: {spec.Effects.recoveryCompletion},
				}.Encode(),
				ClientAddress: ClientAddress,
			}
		},
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))

			var body struct {
				AccessToken   string   `json:"access_token"`
				RecoveryCodes []string `json:"recovery_codes"`
			}
			require.NoError(t, json.Unmarshal([]byte(res.Body), &body), "body: %q", res.Body)
			assert.NotEmpty(t, body.AccessToken)
			assert.Len(t, body.RecoveryCodes, 10, "the saved code spent at Recover is replaced once finished")

			claims, err := fixtureTokens{}.Verify(t.Context(), body.AccessToken)
			require.NoError(t, err)

			s := res.Effects.Recovery.LoadSession(t, claims.ID())
			assert.Equal(t, session.MFARecoveryPending, s.MFA)
			assert.Equal(t, factor.Recovery, s.FirstFactor)
		},
	}
}

// recoveryCancelEndpointCancelsAHeldRecovery pins spec account-recovery "A
// held recovery is cancelled by the user": a POST to the cancel endpoint
// itself, carrying the token read from the held notice's cancel link,
// answers 204 with an empty body and leaves the recovery refused to finish.
func recoveryCancelEndpointCancelsAHeldRecovery() Scenario {
	return Scenario{
		Name: "POST /recovery/cancel cancels a held recovery, and the finish is later refused",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := append(recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofIssued),
				recovery.WithDelay(recoveryHoldDelay),
				recovery.WithCancelLink("https://app.example.com/cancel"),
			)

			standalone, err := recovery.NewRecoverer(deps, coreOpts...)
			require.NoError(t, err)

			saved, err := fx.Codes.Generate(ctx, UserID)
			require.NoError(t, err)

			standalone.Start(ctx, Username)
			issued := fx.lastMessage(t)

			result, err := standalone.Recover(ctx, recovery.Request{
				Username: Username, Saved: saved[0], Issued: issued, Source: ClientAddress,
			})
			require.NoError(t, err)
			require.NotNil(t, result.Held, "the configured delay holds the recovery")

			link := fx.lastMessage(t)

			effects := &Effects{Sessions: sessions, Recovery: fx}
			effects.recoveryStandalone = standalone
			effects.recoveryCompletion = result.Held.CompletionToken
			effects.recoveryCancelToken = cancelTokenFromLink(t, link)

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableAccountRecovery(httpsec.RecoveryDeps(deps),
						httpsec.WithRecoveryCore(coreOpts...),
						httpsec.WithRecoveryTokens(fixtureTokens{}),
					),
					httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithChangePasswordEndpoint(recoveryResolvePath, noopChangePassword)),
				},
				Effects: effects,
			}
		},
		Request: func(spec ChainSpec) RequestSpec {
			return RequestSpec{
				Method: http.MethodPost,
				Path:   httpsec.DefaultRecoveryCancelPath,
				Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body: url.Values{
					httpsec.RecoveryCancelTokenParam: {spec.Effects.recoveryCancelToken},
				}.Encode(),
				ClientAddress: ClientAddress,
			}
		},
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusNoContent, res.Status)
			assert.Empty(t, res.Body)

			_, err := res.Effects.recoveryStandalone.Finish(t.Context(), res.Effects.recoveryCompletion)
			require.ErrorIs(t, err, recovery.ErrRefused, "the cancel endpoint cancelled the held recovery")
		},
	}
}

// recoveryCodesOptions is the chain wiring every saved-code endpoint scenario
// shares: a bearer-authenticated caller, saved codes enabled on the core, and
// a password-change resolve endpoint to satisfy EnableAccountRecovery's
// binding requirement, which the saved-code endpoints themselves never use.
func recoveryCodesOptions(sessions *session.Manager, deps recovery.Deps, coreOpts []recovery.Option) []httpsec.Option {
	return []httpsec.Option{
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: fixtureTokens{}, Sessions: sessions, Users: fixtureUsers{},
		}),
		httpsec.EnableAccountRecovery(httpsec.RecoveryDeps(deps),
			httpsec.WithRecoveryCore(coreOpts...),
			httpsec.WithRecoveryTokens(fixtureTokens{}),
		),
		httpsec.EnablePasswordChangeGate(sessions,
			httpsec.WithChangePasswordEndpoint(recoveryResolvePath, noopChangePassword)),
	}
}

// recoveryCodesEndpointRegeneratesForAFreshSession pins spec account-recovery
// "Regenerating codes needs a recent authentication and notifies the user",
// its "Fresh session regenerates" scenario: a POST to the saved-code endpoint
// from a session whose latest authentication falls inside the freshness
// window answers with a fresh set of ten codes, voids the previous set in the
// shared saved-code store, and queues exactly one regeneration notice that
// names no code.
func recoveryCodesEndpointRegeneratesForAFreshSession() Scenario {
	return Scenario{
		Name: "POST /recovery/codes regenerates the set for a fresh session, and notifies the user",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			old, err := fx.Codes.Generate(ctx, UserID)
			require.NoError(t, err)

			s, err := sessions.Create(ctx, UserID, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofIssued)

			effects := &Effects{Sessions: sessions, Recovery: fx, SessionID: s.ID}
			effects.recoverySavedCode = old[0]

			return ChainSpec{
				Options: recoveryCodesOptions(sessions, deps, coreOpts),
				Effects: effects,
			}
		},
		Request: authenticatedRequest(http.MethodPost, httpsec.DefaultRecoveryCodesPath),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))

			var body struct {
				RecoveryCodes []string `json:"recovery_codes"`
			}
			require.NoError(t, json.Unmarshal([]byte(res.Body), &body), "body: %q", res.Body)
			assert.Len(t, body.RecoveryCodes, 10, "a fresh set of ten codes is returned")

			fx := res.Effects.Recovery

			err := fx.Codes.Confirm(t.Context(), UserID, res.Effects.recoverySavedCode)
			require.ErrorIs(t, err, recovery.ErrRefused, "the previous set was voided")

			remaining, err := fx.Codes.Remaining(t.Context(), UserID)
			require.NoError(t, err)
			assert.Equal(t, 10, remaining.N)

			msgs := fx.Outbox.Messages()
			require.Len(t, msgs, 1, "exactly one regeneration notice was queued")
			for _, code := range body.RecoveryCodes {
				assert.NotContains(t, msgs[0].TextBody, code, "the notice names no code")
			}
		},
	}
}

// recoveryCodesEndpointReportsTheRemainingCount pins spec account-recovery
// "Regenerating codes needs a recent authentication and notifies the user",
// its "Count without codes" scenario: a GET to the saved-code endpoint from a
// full session answers with the remaining count and whether it is low, and
// carries no code.
func recoveryCodesEndpointReportsTheRemainingCount() Scenario {
	return Scenario{
		Name: "GET /recovery/codes reports the remaining count, and carries no code",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			_, err := fx.Codes.Generate(ctx, UserID)
			require.NoError(t, err)

			s, err := sessions.Create(ctx, UserID, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofIssued)

			effects := &Effects{Sessions: sessions, Recovery: fx, SessionID: s.ID}

			return ChainSpec{
				Options: recoveryCodesOptions(sessions, deps, coreOpts),
				Effects: effects,
			}
		},
		Request: authenticatedRequest(http.MethodGet, httpsec.DefaultRecoveryCodesPath),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusOK, res.Status)

			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal([]byte(res.Body), &fields), "body: %q", res.Body)

			keys := make([]string, 0, len(fields))
			for k := range fields {
				keys = append(keys, k)
			}
			assert.ElementsMatch(t, []string{"remaining", "low"}, keys,
				"the body carries the count and nothing else, no code included")

			var body struct {
				Remaining int  `json:"remaining"`
				Low       bool `json:"low"`
			}
			require.NoError(t, json.Unmarshal([]byte(res.Body), &body))

			remaining, err := res.Effects.Recovery.Codes.Remaining(t.Context(), UserID)
			require.NoError(t, err)
			assert.Equal(t, remaining.N, body.Remaining)
			assert.Equal(t, remaining.Low, body.Low)
		},
	}
}

// recoveryCodesEndpointRefusesAStaleSession pins spec account-recovery
// "Regenerating codes needs a recent authentication and notifies the user",
// its "Stale session" scenario: a POST from a session whose latest
// authentication falls outside the freshness window is refused, and the
// user's saved-code set stands unchanged.
//
// The freshness check reads wall-clock time, never the fixture's shared fake
// clock: httpsec's recovery interceptor defaults its own clock to time.Now,
// and the only seam that replaces it is a test-only hook internal to the
// httpsec package, unreachable from this module. The session this scenario
// sends is instead backdated at its source: the fixture's session manager is
// built on the same fake clock as everything else the fixture wires, so
// rewinding that clock before this one session is created leaves the
// session's CreatedAt behind the endpoint's own wall-clock reading, which is
// all the freshness check compares against. Nothing else in this run reads
// the clock again before the request is sent, so rewinding it here disturbs
// nothing else the fixture depends on.
func recoveryCodesEndpointRefusesAStaleSession() Scenario {
	return Scenario{
		Name: "POST /recovery/codes refuses a stale session, and the set is unchanged",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			old, err := fx.Codes.Generate(ctx, UserID)
			require.NoError(t, err)

			// Past the endpoint's 15-minute default freshness window (see
			// recoveryCodesEndpointRegeneratesForAFreshSession for the fresh
			// case), and well clear of it against real elapsed test time.
			fx.Clock.Advance(-20 * time.Minute)

			s, err := sessions.Create(ctx, UserID, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofIssued)

			effects := &Effects{Sessions: sessions, Recovery: fx, SessionID: s.ID}
			effects.recoverySavedCode = old[0]

			return ChainSpec{
				Options: recoveryCodesOptions(sessions, deps, coreOpts),
				Effects: effects,
			}
		},
		Request: authenticatedRequest(http.MethodPost, httpsec.DefaultRecoveryCodesPath),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusForbidden, res.Status)
			assert.Empty(t, res.Body, "a refusal carries no error text")
			require.ErrorIs(t, res.Refusal, recovery.ErrReauthenticationRequired)

			fx := res.Effects.Recovery

			require.NoError(t, fx.Codes.Confirm(t.Context(), UserID, res.Effects.recoverySavedCode),
				"the refused request spent nothing")

			remaining, err := fx.Codes.Remaining(t.Context(), UserID)
			require.NoError(t, err)
			assert.Equal(t, 10, remaining.N, "the set is unchanged")
		},
	}
}
