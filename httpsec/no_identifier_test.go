package httpsec_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/onetime"
	"github.com/kartaladev/scrty/token/signingkey"
)

// noIdentifierFailure asserts err is how a login whose principal has no user
// identifier fails: a failure of the consumer's wiring, answered 500 as an
// issuing failure is, whose cause is token.ErrNoSubject in every mode. It is no
// refusal, so a client is not sent back to authenticate.
func noIdentifierFailure(t *testing.T, err error) {
	t.Helper()

	require.ErrorIs(t, err, token.ErrNoSubject)
	assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(err))
	assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
	assert.NotErrorIs(t, err, httpsec.ErrAuthenticationRequired)
	assert.Contains(t, err.Error(), "no user identifier")

	var challenge *httpsec.ChallengeError
	assert.NotErrorAs(t, err, &challenge, "no challenge carries a credential")
}

// noCredential asserts out handed nothing out and reached no handler.
func noCredential(t *testing.T, out served) {
	t.Helper()

	assert.False(t, out.handlerRan)

	body := out.rec.Body.String()
	assert.NotContains(t, body, "access_token", "no credential is handed out")
	assert.Empty(t, out.rec.Header().Values("Set-Cookie"), "no credential is handed out")
}

// oneNoIdentifierRecord asserts logs holds one ERROR record of fixed text for a
// login refused for want of an identifier, and that it names no one: not the
// username the candidate carried, nor any identifier.
func oneNoIdentifierRecord(t *testing.T, logs string, unwanted ...string) {
	t.Helper()

	var records []string

	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "level=ERROR") {
			records = append(records, line)
		}
	}

	require.Len(t, records, 1, "logs: %q", logs)
	assert.Contains(t, records[0], "no user identifier")

	for _, name := range unwanted {
		assert.NotContains(t, records[0], name)
	}
}

// nothingStored asserts sessions holds nothing for the empty user reference.
func nothingStored(t *testing.T, sessions *session.Sessions) {
	t.Helper()

	stored, err := sessions.CountActiveByUser(t.Context(), "")
	require.NoError(t, err)
	assert.Zero(t, stored, "no session is stored for a principal with no identifier")
}

// subjectMode is one of the three ways a chain's credential can be read.
type subjectMode struct {
	name string

	// generator is the mode's token generator, nil with session references.
	generator func(keys signingkey.KeySource) token.Generator

	// bearer enables the mode's bearer.
	bearer func(g token.Generator, s *session.Sessions, u identity.UserLoader) httpsec.Option
}

// signedBearerWith enables a signed bearer verifying through its generator.
func signedBearerWith(opts ...httpsec.BearerTokenOption) func(token.Generator, *session.Sessions, identity.UserLoader) httpsec.Option {
	return func(g token.Generator, s *session.Sessions, u identity.UserLoader) httpsec.Option {
		return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: g.(token.Verifier), Sessions: s, Users: u}, opts...)
	}
}

// Each way a chain's credential can be read: a default chain, one configured to
// use usernames, and one with session references.
var (
	defaultSubjectMode = subjectMode{
		name: "default",
		generator: func(keys signingkey.KeySource) token.Generator {
			return must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience()))
		},
		bearer: signedBearerWith(),
	}
	usernameSubjectMode = subjectMode{
		name: "usernames",
		generator: func(keys signingkey.KeySource) token.Generator {
			return must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience(), token.WithUsernameSubject()))
		},
		bearer: signedBearerWith(httpsec.WithBearerUsernameSubject()),
	}
	referenceSubjectMode = subjectMode{
		name:      "session references",
		generator: func(signingkey.KeySource) token.Generator { return nil },
		bearer: func(_ token.Generator, s *session.Sessions, u identity.UserLoader) httpsec.Option {
			return httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: s, Users: u})
		},
	}
)

// subjectModes are all three.
func subjectModes() []subjectMode {
	return []subjectMode{defaultSubjectMode, usernameSubjectMode, referenceSubjectMode}
}

// unidentifiedProvider is a consumer's authentication provider resolving every
// credential to principal.
type unidentifiedProvider struct{ principal *identity.Principal }

func (p unidentifiedProvider) Authenticate(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
	return &authenticate.Authentication{Principal: p.principal, Time: time.Now()}, nil
}

// noAuthentication is a consumer's authentication provider that returns neither
// an authentication nor an error.
type noAuthentication struct{}

func (noAuthentication) Authenticate(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
	return nil, nil //nolint:nilnil // the fault under test: a provider answering nothing
}

// TestLogin_PrincipalWithNoIdentifier pins spec http-security-chain "Login with
// a principal that has no identifier": in every mode, the login fails, no session
// is stored and no credential is handed out. A provider returning a username
// alone fails loudly at login, not with a session that belongs to no one.
func TestLogin_PrincipalWithNoIdentifier(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		mode      subjectMode
		principal *identity.Principal

		// authenticator, when set, is the provider instead of one resolving every
		// credential to principal.
		authenticator authenticate.Authenticator
		assert        func(t *testing.T, sessions *session.Sessions, out served)
	}

	failed := func(t *testing.T, sessions *session.Sessions, out served) {
		t.Helper()

		noIdentifierFailure(t, out.err)
		noCredential(t, out)
		nothingStored(t, sessions)
	}

	var cases []testCase
	for _, mode := range subjectModes() {
		cases = append(cases,
			testCase{name: mode.name + ": a username and no identifier", mode: mode, principal: &identity.Principal{Username: "alice"}, assert: failed},
			testCase{name: mode.name + ": no username and no identifier", mode: mode, principal: &identity.Principal{}, assert: failed},
			testCase{name: mode.name + ": no principal", mode: mode, principal: nil, assert: failed},
		)
	}

	// A provider answering neither an authentication nor an error is no principal
	// either, and must not panic the login.
	for _, mode := range subjectModes() {
		cases = append(cases, testCase{
			name: mode.name + ": no authentication", mode: mode, authenticator: noAuthentication{}, assert: failed,
		})
	}

	// The generator's own refusal, which the identifier check leaves it to make:
	// under usernames, an identifier and no username is no subject either.
	cases = append(cases, testCase{
		name:      "usernames: an identifier and no username",
		mode:      usernameSubjectMode,
		principal: &identity.Principal{ID: "u-1"},
		assert: func(t *testing.T, sessions *session.Sessions, out served) {
			t.Helper()

			require.ErrorIs(t, out.err, token.ErrNoSubject)
			assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
			noCredential(t, out)

			stored, err := sessions.CountActiveByUser(t.Context(), "u-1")
			require.NoError(t, err)
			assert.Zero(t, stored, "a credential that cannot be issued stores nothing")
		},
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
			sessions := must.Must(session.New(session.WithStore(must.Must(session.NewMemoryStore()))))
			gen := tc.mode.generator(keys)

			var provider authenticate.Authenticator = unidentifiedProvider{principal: tc.principal}
			if tc.authenticator != nil {
				provider = tc.authenticator
			}

			// No user load is expected: a login that fails here loads nobody.
			users := NewMockUserLoader(gomock.NewController(t))

			chain, err := httpsec.New(
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: provider,
					Sessions:      sessions,
					Tokens:        gen,
					Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
				}),
				tc.mode.bearer(gen, sessions, users),
			)
			require.NoError(t, err)

			out := serve(t, chain, postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
				httpsec.DefaultLoginUsernameParam: {"alice"},
				httpsec.DefaultLoginPasswordParam: {"pw"},
			}))

			tc.assert(t, sessions, out)
		})
	}
}

// TestLogin_NoIdentifierLeavesARecord pins that the login tail's refusal of a
// principal with no identifier writes an ERROR record: it is a wiring fault the
// default error handler answers with a status alone, so without the record the
// consumer would never learn of it. The record is sampled like the chain's other
// refusal logs, so a misconfigured provider cannot flood the log, its text is
// fixed, and it names neither the submitted username nor the provider's.
func TestLogin_NoIdentifierLeavesARecord(t *testing.T) {
	t.Parallel()

	const (
		submitted = "submitted-name"
		resolved  = "resolved-name"
	)

	type testCase struct {
		name     string
		opts     []httpsec.Option
		requests int
		assert   func(t *testing.T, logs string)
	}

	errorRecords := func(logs string) []string {
		var records []string

		for _, line := range strings.Split(logs, "\n") {
			if strings.Contains(line, "level=ERROR") {
				records = append(records, line)
			}
		}

		return records
	}

	cases := []testCase{
		{
			name:     "one ERROR record of fixed text, naming no one",
			requests: 1,
			assert: func(t *testing.T, logs string) {
				t.Helper()

				records := errorRecords(logs)
				require.Len(t, records, 1, "logs: %q", logs)
				assert.Contains(t, records[0], "no user identifier")
				assert.NotContains(t, records[0], submitted)
				assert.NotContains(t, records[0], resolved)
				assert.NotContains(t, records[0], "unidentifiedProvider")
			},
		},
		{
			name:     "a repeat inside the window is sampled away",
			requests: 3,
			assert: func(t *testing.T, logs string) {
				t.Helper()

				assert.Len(t, errorRecords(logs), 1, "logs: %q", logs)
			},
		},
		{
			name:     "an interval of zero writes every record",
			opts:     []httpsec.Option{httpsec.WithRefusalLogInterval(0)},
			requests: 3,
			assert: func(t *testing.T, logs string) {
				t.Helper()

				assert.Len(t, errorRecords(logs), 3, "logs: %q", logs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logs syncBuffer

			keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
			sessions := must.Must(session.New(session.WithStore(must.Must(session.NewMemoryStore()))))
			gen := usernameSubjectMode.generator(keys)

			opts := append([]httpsec.Option{
				httpsec.WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: unidentifiedProvider{principal: &identity.Principal{Username: resolved}},
					Sessions:      sessions,
					Tokens:        gen,
					Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
				}),
				usernameSubjectMode.bearer(gen, sessions, NewMockUserLoader(gomock.NewController(t))),
			}, tc.opts...)

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			for range tc.requests {
				out := serve(t, chain, postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
					httpsec.DefaultLoginUsernameParam: {submitted},
					httpsec.DefaultLoginPasswordParam: {"pw"},
				}))
				noIdentifierFailure(t, out.err)
			}

			tc.assert(t, logs.String())
		})
	}
}

// TestCompleteLogin_NoIdentifier pins where the login tail refuses a principal
// with no identifier: ahead of everything it does, so no held recovery is
// cancelled, no policy runs, nothing is issued and nothing is stored. The spies
// fail the test on any call to the generator or the store. A redemption makes the
// same check for itself, inside its checks (TestMagicLink_NoIdentifier and
// TestOIDCHandoff_NoIdentifierRefusedInsideTheChecks).
func TestCompleteLogin_NoIdentifier(t *testing.T) {
	t.Parallel()

	spies := newLoginSpies(t)

	phase := NewMockPolicy(gomock.NewController(t))
	phase.EXPECT().Name().Return("test: no evaluation expected").AnyTimes()
	phase.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()

	var cancelled atomic.Int32

	ex := newExchange(t)
	in := httpsec.PostAuthenticationInputForTest(
		&identity.Principal{Username: "ada"}, factor.Password, "ada", time.Time{}, time.Now())

	deps := httpsec.LoginTailDepsCancellingForTest(
		httpsec.LoginTailDepsForTest(engineOf(t, phase), spies.sessions, spies.tokens),
		func(context.Context, identity.UserID) error {
			cancelled.Add(1)

			return nil
		})

	tok, err := httpsec.CompleteLoginForTest(ex, deps, in)

	noIdentifierFailure(t, err)
	assert.Empty(t, tok)
	assert.Nil(t, ex.Session, "no session is published")
	assert.Zero(t, cancelled.Load(), "no held recovery of an empty user is cancelled")
}

// switchableIdentifier is a loader whose one user's identifier a row can change
// between requests, answering by username and by reference alike.
type switchableIdentifier struct {
	id atomic.Value
}

func (s *switchableIdentifier) loader(t *testing.T, details func() *identity.Details) *MockUserLoader {
	t.Helper()

	current := func() *identity.Details {
		d := details()
		d.ID = s.id.Load().(identity.UserID) //nolint:forcetypeassert // only this type is stored

		return d
	}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) { return current(), nil })
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) { return current(), nil })

	return users
}

// TestMagicLink_NoIdentifier pins what a magic link with no identifier meets, in
// every mode. The library's own manager sends no link for such a user, and refuses
// a link whose user has lost the identifier with its uniform refusal. A consumer's
// redeemer, which can hand the chain's checks anything, is refused inside them,
// before it spends. Either way nothing is stored and nothing is handed out.
func TestMagicLink_NoIdentifier(t *testing.T) {
	t.Parallel()

	// world is one row's harness. The row's act leaves what its assert needs in
	// the fields below it.
	type world struct {
		h  *magicLinkHarness
		id *switchableIdentifier

		logs  syncBuffer
		chain *httpsec.Chain
		sent  int
		link  string
		nonce string
		spent atomic.Bool
	}

	newWorld := func(t *testing.T, mode subjectMode) *world {
		t.Helper()

		h := newMagicLinkHarness(t)
		keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
		gen := mode.generator(keys)

		id := &switchableIdentifier{}
		id.id.Store(magicLinkUserID)

		users := id.loader(t, magicLinkUser)
		h.users = users
		h.manager = must.Must(magiclink.New(must.Must(onetime.New("magic-link", onetime.WithTokenTTL(magicLinkTTL))),
			users, h.sender, "https://app.example.com"))
		h.tokens = nil
		if gen != nil {
			h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkTokens(gen))
		}
		w := &world{h: h, id: id}
		h.chainOpts = append(h.chainOpts,
			httpsec.WithLogger(slog.New(slog.NewTextHandler(&w.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
			mode.bearer(gen, h.sessions, users))

		return w
	}

	type testCase struct {
		name   string
		act    func(t *testing.T, w *world) served
		assert func(t *testing.T, w *world, out served)
	}

	rows := []testCase{
		{
			name: "the manager sends no link for a user with no identifier",
			act: func(t *testing.T, w *world) served {
				t.Helper()

				w.id.id.Store(identity.UserID(""))

				w.sent = w.h.sender.count()

				return w.h.requestLink(t, w.h.chain(t), magicLinkKnown)
			},
			assert: func(t *testing.T, w *world, out served) {
				t.Helper()

				require.NoError(t, out.err, "the request is answered as for any address")
				assert.Equal(t, w.sent, w.h.sender.count(), "no link is sent")
			},
		},
		{
			name: "the manager refuses a link whose user has lost the identifier, and leaves it unspent",
			act: func(t *testing.T, w *world) served {
				t.Helper()

				w.chain = w.h.chain(t)
				w.link, w.nonce = w.h.link(t, w.chain)

				w.id.id.Store(identity.UserID(""))

				return w.h.redeem(t, w.chain, w.link, w.nonce)
			},
			assert: func(t *testing.T, w *world, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, magiclink.ErrInvalidLink)
				noCredential(t, out)
				nothingStored(t, w.h.sessions)

				w.id.id.Store(magicLinkUserID)

				again := w.h.redeem(t, w.chain, w.link, w.nonce)
				require.NoError(t, again.err, "the refused redemption left the link unspent")
				assert.Equal(t, http.StatusOK, again.rec.Code)
			},
		},
		{
			name: "a consumer's redeemer is refused inside the checks, before it spends",
			act: func(t *testing.T, w *world) served {
				t.Helper()

				w.h.linkOpts = append(w.h.linkOpts, httpsec.WithMagicLinkRedeemer(redeemerFunc(func(
					ctx context.Context, _, _ string, checks ...magiclink.Check,
				) (magiclink.Redemption, error) {
					p := identity.Principal{Username: magicLinkKnown}
					for _, check := range checks {
						if err := check(ctx, p, time.Time{}); err != nil {
							return magiclink.Redemption{}, err
						}
					}

					w.spent.Store(true)

					return magiclink.Redemption{Principal: p}, nil
				})))

				return w.h.redeem(t, w.h.chain(t), "any-token", "")
			},
			assert: func(t *testing.T, w *world, out served) {
				t.Helper()

				noIdentifierFailure(t, out.err)
				noCredential(t, out)
				nothingStored(t, w.h.sessions)
				assert.False(t, w.spent.Load(), "the checks refused before the redeemer spent the link")
				oneNoIdentifierRecord(t, w.logs.String(), magicLinkKnown)
			},
		},
	}

	for _, mode := range subjectModes() {
		for _, row := range rows {
			t.Run(mode.name+": "+row.name, func(t *testing.T) {
				t.Parallel()

				w := newWorld(t, mode)

				row.assert(t, w, row.act(t, w))
			})
		}
	}
}

// TestOIDCHandoff_NoIdentifierRefusedInsideTheChecks pins that a consumer's
// redeemer handing the chain's check a candidate with no identifier is answered
// before it spends: the library's own redeemer cannot get there, since it issues
// no code for a principal with no identifier, and refuses a loader's mismatch.
func TestOIDCHandoff_NoIdentifierRefusedInsideTheChecks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mode   subjectMode
		assert func(t *testing.T, h *oidcHarness, spent bool, out served)
	}

	refusedBeforeSpending := func(t *testing.T, h *oidcHarness, spent bool, out served) {
		t.Helper()

		noIdentifierFailure(t, out.err)
		noCredential(t, out)
		nothingStored(t, h.sessions)
		assert.False(t, spent, "the checks refused before the redeemer spent the code")
		oneNoIdentifierRecord(t, h.logs.String(), "ada@example.com")
	}

	var cases []testCase
	for _, mode := range subjectModes() {
		cases = append(cases, testCase{name: mode.name, mode: mode, assert: refusedBeforeSpending})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
			gen := tc.mode.generator(keys)

			var spent atomic.Bool

			redeemer := NewMockHandoffRedeemer(gomock.NewController(t))
			redeemer.EXPECT().Redeem(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, _ string, checks ...oidc.RedeemCheck) (oidc.HandoffResult, error) {
					candidate := oidc.RedeemCandidate{Principal: identity.Principal{Username: "ada@example.com"}}
					for _, check := range checks {
						if err := check(ctx, candidate); err != nil {
							return oidc.HandoffResult{}, err
						}
					}

					spent.Store(true)

					return oidc.HandoffResult{Principal: candidate.Principal}, nil
				})

			opts := []httpsec.OIDCOption{httpsec.WithOIDCSessions(h.sessions), httpsec.WithOIDCHandoffRedeemer(redeemer)}
			if gen != nil {
				opts = append(opts, httpsec.WithOIDCTokens(gen))
			}

			h.chainOpts = append(h.chainOpts, tc.mode.bearer(gen, h.sessions, NewMockUserLoader(gomock.NewController(t))))
			chain := h.build(t, h.handoffs, opts...)

			out := serve(t, chain, handoffRequest(t.Context(), oidcTestSource, "any-code"))

			tc.assert(t, h, spent.Load(), out)
		})
	}
}

// TestPasskeyLogin_NoIdentifier pins what a passkey login with no identifier
// meets: a credential of a real user whose record lost its identifier is the
// uniform refusal the loader's mismatch earns, and a credential recording no user
// reaches the login tail. Neither stores a session or hands anything out. The
// ceremony's challenge is spent by then, by the assertion that came first.
func TestPasskeyLogin_NoIdentifier(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		owner  identity.UserID
		assert func(t *testing.T, err error, logs string)
	}

	cases := []testCase{
		{
			name:  "a credential of a user whose record has no identifier",
			owner: e2eUser,
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			},
		},
		{
			name:  "a credential that records no user",
			owner: "",
			assert: func(t *testing.T, err error, logs string) {
				t.Helper()

				noIdentifierFailure(t, err)
				oneNoIdentifierRecord(t, logs, "cred-1")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dep := newPwlDeployment(t)
			dep.required.on.Store(false)
			dep.jwt = issuingGenerator(t)
			dep.loaderNoIdentifier.Store(true)

			var logs syncBuffer

			dep.extra = append(dep.extra,
				httpsec.WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))))
			dep.build(t)

			handle := dep.seed(t, tc.owner, "cred-1", passkey.StateActive)
			cookie, challenge := dep.begun(t)

			req := jsonPost(t.Context(), passwordlessFinishPath, handleAssertionBody(challenge, "cred-1", handle))
			req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie

			out := serve(t, dep.chain, req)

			tc.assert(t, out.err, logs.String())
			assert.False(t, out.handlerRan)
			assert.NotContains(t, out.rec.Body.String(), "access_token")
			nothingStored(t, dep.sessions)
		})
	}
}

// TestRecovery_NoIdentifierSpendsNothing pins that a recovery whose user has lost
// its identifier by the time it completes is refused as an unknown user, before
// any proof is spent: the same codes recover once the user has one again.
func TestRecovery_NoIdentifierSpendsNothing(t *testing.T) {
	t.Parallel()

	h := newRecoveryHarness(t)
	gen := issuingGenerator(t)

	var id switchableIdentifier
	id.id.Store(e2eUser)

	h.users = id.loader(t, func() *identity.Details {
		return &identity.Details{Name: "Grace Hopper", Username: e2eAddress, Active: true}
	})
	h.noFormLogin = true
	h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}
	h.recOpts = append(h.recOpts, httpsec.WithRecoveryTokens(gen))
	h.chainOpts = append(h.chainOpts,
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: gen, Sessions: h.sessions, Users: h.users}))
	h.build(t)

	form := recoveryForm(httpsec.RecoverySavedCodeParam, h.saved(t), httpsec.RecoveryIssuedCodeParam, h.issued(t))

	id.id.Store(identity.UserID(""))

	out := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource, form))
	require.ErrorIs(t, out.err, recovery.ErrRefused)
	noCredential(t, out)
	nothingStored(t, h.sessions)

	id.id.Store(e2eUser)

	again := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource, form))
	require.NoError(t, again.err, "the refused recovery spent no proof")
	assert.Equal(t, http.StatusOK, again.rec.Code)
}

// noIdentifierChain is a chain, in one bearer mode, holding a session that
// records no user reference, over a loader that answers with a user with no
// identifier, and a renewal endpoint.
type noIdentifierChain struct {
	clk      *clockwork.FakeClock
	sessions *session.Sessions
	gen      token.Generator
	chain    *httpsec.Chain
	sid      string
}

func newNoIdentifierChain(t *testing.T, mode subjectMode) *noIdentifierChain {
	t.Helper()

	clk := clockwork.NewFakeClockAt(dpopNow)
	sessions := must.Must(session.New(session.WithClock(clk), session.WithUnusedSuccessorRecovery(),
		session.WithStore(must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))))

	keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
	gen := mode.generator(keys)

	var id switchableIdentifier
	id.id.Store(identity.UserID(""))

	users := id.loader(t, func() *identity.Details {
		return &identity.Details{Username: "alice", Active: true}
	})

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		mode.bearer(gen, sessions, users),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: users, Tokens: gen}),
	)
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	return &noIdentifierChain{clk: clk, sessions: sessions, gen: gen, chain: chain, sid: s.ID}
}

// TestBearer_EmptyUserReferenceMatchesNoUser pins spec http-security-chain
// "Session and user with no identifier": a session recording no user reference
// is refused on every path a session is resolved on, whatever the loader
// answers.
//
// Under usernames and session references the empty reference is what refuses,
// and the rows mutation-test the guard. In the default mode the credential
// names a user the session does not record, so the subject comparison refuses
// before the empty reference is reached: those three rows pin the outcome (the
// refusal, nothing handed out) and not the guard.
func TestBearer_EmptyUserReferenceMatchesNoUser(t *testing.T) {
	t.Parallel()

	// credential is what f's mode presents for its session: a token naming
	// someone, since a token with no subject is refused for that alone, or the
	// session's own reference.
	credential := func(t *testing.T, f *noIdentifierChain) string {
		t.Helper()

		if f.gen == nil {
			return f.sid
		}

		tok, err := f.gen.Generate(t.Context(), f.sid, &identity.Principal{ID: "u-1", Username: "alice"})
		require.NoError(t, err)

		return tok
	}

	type testCase struct {
		name   string
		mode   subjectMode
		act    func(t *testing.T, f *noIdentifierChain, credential string) served
		assert func(t *testing.T, out served)
	}

	refused := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
		assert.False(t, out.handlerRan)
		assert.NotContains(t, out.rec.Body.String(), "access_token", "no successor's credential is handed out")
	}

	onARoute := func(t *testing.T, f *noIdentifierChain, credential string) served {
		t.Helper()

		return serve(t, f.chain, bearerRequest(t.Context(), "Bearer "+credential))
	}
	onRenewal := func(t *testing.T, f *noIdentifierChain, credential string) served {
		t.Helper()

		req := postValues(t.Context(), httpsec.DefaultSessionRenewalPath, e2eSource, nil)
		req.Header.Set("Authorization", "Bearer "+credential)

		return serve(t, f.chain, req)
	}
	// late moves the session to where only a late renewal may recover it.
	late := func(t *testing.T, f *noIdentifierChain, credential string) served {
		t.Helper()

		s, err := f.sessions.Load(t.Context(), f.sid)
		require.NoError(t, err)

		_, _, err = f.sessions.RotateWithGrace(t.Context(), s, session.DefaultRenewalGrace)
		require.NoError(t, err)

		f.clk.Advance(session.DefaultRenewalGrace + time.Second)

		return onRenewal(t, f, credential)
	}

	var cases []testCase
	for _, mode := range subjectModes() {
		cases = append(cases,
			testCase{name: mode.name + ": on a route", mode: mode, act: onARoute, assert: refused},
			testCase{name: mode.name + ": on the renewal endpoint", mode: mode, act: onRenewal, assert: refused},
			testCase{name: mode.name + ": on a late renewal", mode: mode, act: late, assert: refused},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newNoIdentifierChain(t, tc.mode)

			tc.assert(t, tc.act(t, f, credential(t, f)))
		})
	}
}

// emptyAuthentication is a consumer's authentication provider that returns an
// authentication carrying no principal.
type emptyAuthentication struct{}

func (emptyAuthentication) Authenticate(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
	return &authenticate.Authentication{}, nil
}

// failuresOf seeds four failures for ada and returns the store with a reader of
// how many remain.
func failuresOf(t *testing.T) (policy.AttemptStore, func() int) {
	t.Helper()

	store := must.Must(lockout.NewMemoryAttemptStore())
	for range 4 {
		require.NoError(t, store.RecordFailure(t.Context(), "ada", time.Now()))
	}

	return store, func() int {
		n, err := store.FailureCount(t.Context(), "ada", time.Now().Add(-time.Hour))
		require.NoError(t, err)

		return n
	}
}

// TestBasic_ProviderReturningNoAuthentication pins spec http-security-chain
// "Provider returning no authentication to Basic": a provider answering no
// principal fails the request as a wiring fault, a 500 with no challenge, and
// the account's failures stay.
func TestBasic_ProviderReturningNoAuthentication(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		provider authenticate.Authenticator
		assert   func(t *testing.T, out served, logs string, failures int)
	}

	wiringFault := func(t *testing.T, out served, logs string, failures int) {
		t.Helper()

		require.ErrorIs(t, out.err, token.ErrNoSubject)
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		assert.Empty(t, out.rec.Header().Values("WWW-Authenticate"), "a 500 carries no challenge")
		assert.Equal(t, 4, failures, "nothing is cleared")
		oneNoIdentifierRecord(t, logs, "ada", "s3cret")
	}

	cases := []testCase{
		{name: "nil and no error", provider: noAuthentication{}, assert: wiringFault},
		{name: "an authentication with no principal", provider: emptyAuthentication{}, assert: wiringFault},
		{
			name:     "a principal with no user identifier is allowed",
			provider: unidentifiedProvider{principal: &identity.Principal{Username: "ada"}},
			assert: func(t *testing.T, out served, _ string, failures int) {
				t.Helper()

				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
				assert.Zero(t, failures, "a proven password clears the account's failures")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logs syncBuffer

			attempts, failures := failuresOf(t)

			chain, err := httpsec.New(
				httpsec.WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: tc.provider, Attempts: attempts}),
			)
			require.NoError(t, err)

			out := serve(t, chain, basicRequest(t.Context(), "ada", "s3cret"))

			tc.assert(t, out, logs.String(), failures())
		})
	}
}

// TestLogin_ProviderReturningNoAuthentication pins spec http-security-chain
// "Provider returning no authentication": the login fails as for any principal
// with no identifier, and the account's failures stay.
func TestLogin_ProviderReturningNoAuthentication(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		provider authenticate.Authenticator
		assert   func(t *testing.T, out served, failures int)
	}

	failsAsNoIdentifier := func(t *testing.T, out served, failures int) {
		t.Helper()

		noIdentifierFailure(t, out.err)
		noCredential(t, out)
		assert.Equal(t, 4, failures, "nothing is cleared")
	}

	cases := []testCase{
		{name: "nil and no error", provider: noAuthentication{}, assert: failsAsNoIdentifier},
		{name: "an authentication with no principal", provider: emptyAuthentication{}, assert: failsAsNoIdentifier},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
			sessions := must.Must(session.New(session.WithStore(must.Must(session.NewMemoryStore()))))
			gen := defaultSubjectMode.generator(keys)
			attempts, failures := failuresOf(t)

			chain, err := httpsec.New(
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: tc.provider,
					Sessions:      sessions,
					Tokens:        gen,
					Attempts:      attempts,
				}),
				defaultSubjectMode.bearer(gen, sessions, NewMockUserLoader(gomock.NewController(t))),
			)
			require.NoError(t, err)

			out := serve(t, chain, postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
				httpsec.DefaultLoginUsernameParam: {"ada"},
				httpsec.DefaultLoginPasswordParam: {"pw"},
			}))

			tc.assert(t, out, failures())
		})
	}
}
