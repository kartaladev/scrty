package httpsec_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// testReference is a well-formed session identifier: 32 bytes, unpadded
// base64url, as the session manager issues them.
var testReference = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))

// referencedSession is a live session the store hands back for testReference.
func referencedSession() *session.Session {
	s := liveSession()
	s.ID = testReference

	return s
}

// referenceUsers is a user loader that knows the one user the OIDC harness
// links, for a session-reference chain built beside it.
func referenceUsers(t *testing.T) *MockUserLoader {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id identity.UserID) (*identity.Details, error) {
			if id != oidcTestUserID {
				return nil, identity.ErrUserNotFound
			}

			return &identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}, nil
		})

	return users
}

// magicLinkReferenceChain builds a magic-link chain in the session-reference
// mode, given tokens or not.
func magicLinkReferenceChain(h *magicLinkHarness) (*httpsec.Chain, error) {
	h.chainOpts = append(h.chainOpts,
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: h.users}))

	return h.build()
}

// oidcReferenceChain builds a federated-login chain in the session-reference
// mode, given tokens or not.
func oidcReferenceChain(t *testing.T, h *oidcHarness, withTokens bool) (*httpsec.Chain, error) {
	t.Helper()

	h.chainOpts = append(h.chainOpts,
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: referenceUsers(t)}))

	opts := []httpsec.OIDCOption{httpsec.WithOIDCSessions(h.sessions)}
	if withTokens {
		opts = append(opts, httpsec.WithOIDCTokens(h.tokens))
	}

	return h.assemble(h.handoffs, opts...)
}

// passwordlessReferenceChain builds a passkey chain with passwordless login in
// the session-reference mode, given tokens or not. d is a deployment whose
// manager the chain reuses; its own chain options are not.
func passwordlessReferenceChain(t *testing.T, d *pwlDeployment, withTokens bool) (*httpsec.Chain, error) {
	t.Helper()

	_ = d.options(t)

	var settings []httpsec.PasswordlessSetting
	if withTokens {
		settings = append(settings, httpsec.PasswordlessTokens(d.tokens))
	}

	chain, err := httpsec.New(
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: d.sessions, Users: d.users}),
		httpsec.EnablePasskeys(
			httpsec.PasskeyDeps{Passkeys: d.manager, Sessions: d.sessions, Users: d.users},
			httpsec.WithPasskeyPasswordlessLogin(settings...)),
	)
	d.chain = chain

	return chain, err
}

// serveSessionBearer builds a chain with session-reference authentication
// enabled and runs one request through it.
func serveSessionBearer(
	t *testing.T,
	h *authHarness,
	req *http.Request,
	opts ...httpsec.SessionBearerOption,
) served {
	t.Helper()

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableSessionBearer(h.sessionBearerDeps(), opts...),
	)
	require.NoError(t, err)

	return serve(t, chain, req)
}

// TestSessionBearer pins which Authorization headers session-reference
// authentication claims, that a value that cannot be a session identifier is
// refused before the store is asked, and that the user is reloaded by the
// reference the session records, never by username.
func TestSessionBearer(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		header string
		opts   []httpsec.SessionBearerOption
		wire   func(h *authHarness)
		assert func(t *testing.T, s served)
	}

	// refused is a 401 that never ran the handler. The lookups a case allows
	// are the ones its wire function expects.
	refused := func(t *testing.T, s served) {
		t.Helper()
		require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
		assert.False(t, s.handlerRan)
	}

	// refusedWithoutLookup is refused by a case that wires no expectation, so
	// any store or user lookup fails the test.
	refusedWithoutLookup := refused

	authenticatedAsSessionUser := func(t *testing.T, s served) {
		t.Helper()
		require.NoError(t, s.err)
		require.True(t, s.handlerRan)

		auth, ok := authenticate.AuthenticationFromContext(s.handled.Context())
		require.True(t, ok)
		require.NotNil(t, auth.Principal)
		assert.Equal(t, identity.UserID("u-1"), auth.Principal.ID)
		assert.Equal(t, "administrator", auth.Principal.Roles[0].Name, "the principal is the store's")

		published, ok := httpsec.SessionFromContext(s.handled.Context())
		require.True(t, ok)
		assert.Equal(t, testReference, published.ID)
	}

	passedThrough := func(t *testing.T, s served) {
		t.Helper()
		require.NoError(t, s.err)
		require.True(t, s.handlerRan)

		_, ok := authenticate.AuthenticationFromContext(s.handled.Context())
		assert.False(t, ok, "nothing was authenticated")
	}

	liveReference := func(h *authHarness) {
		h.store.EXPECT().Load(gomock.Any(), testReference).Return(referencedSession(), nil)
		// Reloaded by the session's own user reference. LoadByUsername has no
		// expectation, so a lookup by username fails the test.
		h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil)
		h.acceptsActivityWriteBack()
	}

	cases := []testCase{
		{
			name:   "a live reference authenticates as the session's user, reloaded by reference",
			header: "Bearer " + testReference,
			wire:   liveReference,
			assert: authenticatedAsSessionUser,
		},
		{
			name:   "user reloaded by reference, though the session's user was renamed",
			header: "Bearer " + testReference,
			wire: func(h *authHarness) {
				renamed := storedUser()
				renamed.Username = "ada.renamed@example.com"

				h.store.EXPECT().Load(gomock.Any(), testReference).Return(referencedSession(), nil)
				// testSubject, the old username, now belongs to another user.
				// LoadByUsername has no expectation, so asking for it fails.
				h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(renamed, nil)
				h.acceptsActivityWriteBack()
			},
			assert: authenticatedAsSessionUser,
		},
		{
			name:   "the scheme is matched without regard to case",
			header: "bEaReR " + testReference,
			wire:   liveReference,
			assert: authenticatedAsSessionUser,
		},
		{
			name:   "a consumer scheme",
			header: "session " + testReference,
			opts:   []httpsec.SessionBearerOption{httpsec.WithSessionBearerScheme("Session")},
			wire:   liveReference,
			assert: authenticatedAsSessionUser,
		},
		{
			name:   "the default scheme is not claimed under a consumer scheme",
			header: "Bearer " + testReference,
			opts:   []httpsec.SessionBearerOption{httpsec.WithSessionBearerScheme("Session")},
			assert: passedThrough,
		},
		{
			name:   "another scheme passes through",
			header: "Basic " + testReference,
			assert: passedThrough,
		},
		{
			name:   "no Authorization header passes through",
			assert: passedThrough,
		},
		{
			name:   "a value one character short is refused before any lookup",
			header: "Bearer " + testReference[:42],
			assert: refusedWithoutLookup,
		},
		{
			name:   "a value one character long is refused before any lookup",
			header: "Bearer " + testReference + "A",
			assert: refusedWithoutLookup,
		},
		{
			name:   "a value outside the URL-safe alphabet is refused before any lookup",
			header: "Bearer " + strings.Repeat("+", 43),
			assert: refusedWithoutLookup,
		},
		{
			name:   "a signed token is refused before any lookup",
			header: "Bearer abc.def.ghi",
			assert: refusedWithoutLookup,
		},
		{
			name:   "a missing session",
			header: "Bearer " + testReference,
			wire: func(h *authHarness) {
				h.store.EXPECT().Load(gomock.Any(), testReference).Return(nil, session.ErrNotFound)
			},
			assert: refused,
		},
		{
			name:   "a user that no longer exists",
			header: "Bearer " + testReference,
			wire: func(h *authHarness) {
				h.store.EXPECT().Load(gomock.Any(), testReference).Return(referencedSession(), nil)
				h.acceptsFirstPresentation()
				h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
					Return(nil, identity.ErrUserNotFound)
			},
			assert: refused,
		},
		{
			name:   "a user store that is down",
			header: "Bearer " + testReference,
			wire: func(h *authHarness) {
				h.store.EXPECT().Load(gomock.Any(), testReference).Return(referencedSession(), nil)
				h.acceptsFirstPresentation()
				h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
					Return(nil, errors.New("users: connection refused"))
			},
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			if tc.wire != nil {
				tc.wire(h)
			}

			tc.assert(t, serveSessionBearer(t, h, bearerRequest(t.Context(), tc.header), tc.opts...))
		})
	}
}

// TestSessionBearerRefusesReusedReference pins that a session reference
// superseded by a renewal is refused once the renewal's window has ended, with
// an error both the authentication-required and the reused-session refusal,
// and that the family is revoked; inside the window it still authenticates.
func TestSessionBearerRefusesReusedReference(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		after  time.Duration
		assert func(t *testing.T, f resolveFixture, successor *session.Session, s served)
	}

	cases := []testCase{
		{
			name:  "inside the window",
			after: 29 * time.Second,
			assert: func(t *testing.T, _ resolveFixture, _ *session.Session, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
			},
		},
		{
			name:  "after the window",
			after: 31 * time.Second,
			assert: func(t *testing.T, f resolveFixture, successor *session.Session, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, s.err, session.ErrReused)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)

				_, err := f.sessions.Load(t.Context(), successor.ID)
				require.ErrorIs(t, err, session.ErrNotFound,
					"the family is revoked, its live successor with it")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)
			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

			successor, _, err := f.sessions.RotateWithGrace(t.Context(), f.session, 30*time.Second)
			require.NoError(t, err)

			f.clk.Advance(tc.after)

			chain, err := httpsec.New(
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.WithClock(f.clk),
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: users}),
			)
			require.NoError(t, err)

			tc.assert(t, f, successor, serve(t, chain, bearerRequest(t.Context(), "Bearer "+f.session.ID)))
		})
	}
}

// TestSessionBearerConstruction pins the wiring mistakes New refuses with a
// configuration error once the session-reference mode is on: a second bearer
// mode, a missing dependency, a scheme that would claim every header, and a
// token generator on any endpoint that issues a credential, whose token this
// chain would not accept. The same endpoints built without a generator are
// accepted.
func TestSessionBearerConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T, h *authHarness) error
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrConfig)
	}

	// refusedNaming is refused, by the check that names field.
	refusedNaming := func(field string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), field)
		}
	}

	built := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}

	chainOf := func(opts ...httpsec.Option) error {
		_, err := httpsec.New(opts...)

		return err
	}

	formLoginDeps := func(h *authHarness, withTokens bool) httpsec.FormLoginDeps {
		d := h.formLoginDeps()
		if !withTokens {
			d.Tokens = nil
		}

		return d
	}

	mfaChain := func(t *testing.T, h *authHarness, opts ...httpsec.MFAOption) error {
		t.Helper()

		return chainOf(
			httpsec.EnableSessionBearer(h.sessionBearerDeps()),
			httpsec.EnableMFA([]mfa.Method{mfaMethod(t, factor.AuthenticatorApp)}, opts...),
			httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}),
		)
	}

	recoveryChain := func(t *testing.T, opts ...httpsec.RecoveryOption) error {
		t.Helper()

		r := newRecoveryHarness(t)
		r.reference = true
		r.recOpts = opts

		_, err := httpsec.New(r.options(t)...)

		return err
	}

	cases := []testCase{
		{
			name: "both bearer modes, the session reference first",
			build: func(_ *testing.T, h *authHarness) error {
				return chainOf(
					httpsec.EnableSessionBearer(h.sessionBearerDeps()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()))
			},
			assert: refusedNaming("EnableBearerToken"),
		},
		{
			name: "both bearer modes, the signed token first",
			build: func(_ *testing.T, h *authHarness) error {
				return chainOf(
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
					httpsec.EnableSessionBearer(h.sessionBearerDeps()))
			},
			assert: refusedNaming("EnableBearerToken"),
		},
		{
			name: "the session-reference mode given twice",
			build: func(_ *testing.T, h *authHarness) error {
				return chainOf(
					httpsec.EnableSessionBearer(h.sessionBearerDeps()),
					httpsec.EnableSessionBearer(h.sessionBearerDeps()))
			},
			assert: refused,
		},
		{
			name: "no session manager",
			build: func(_ *testing.T, h *authHarness) error {
				return chainOf(httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Users: h.users}))
			},
			assert: refused,
		},
		{
			name: "no user loader",
			build: func(_ *testing.T, h *authHarness) error {
				return chainOf(httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: h.sessions}))
			},
			assert: refused,
		},
		{
			name: "an empty scheme",
			build: func(_ *testing.T, h *authHarness) error {
				return chainOf(httpsec.EnableSessionBearer(h.sessionBearerDeps(),
					httpsec.WithSessionBearerScheme(" ")))
			},
			assert: refused,
		},
		{
			name: "a scheme holding a space",
			build: func(_ *testing.T, h *authHarness) error {
				return chainOf(httpsec.EnableSessionBearer(h.sessionBearerDeps(),
					httpsec.WithSessionBearerScheme("Session Ref")))
			},
			assert: refused,
		},
		{
			name: "form login given a token generator",
			build: func(_ *testing.T, h *authHarness) error {
				return chainOf(
					httpsec.EnableSessionBearer(h.sessionBearerDeps()),
					httpsec.EnableFormLogin(formLoginDeps(h, true)))
			},
			assert: refusedNaming("FormLoginDeps.Tokens"),
		},
		{
			name: "form login given a token generator, the session reference enabled last",
			build: func(_ *testing.T, h *authHarness) error {
				return chainOf(
					httpsec.EnableFormLogin(formLoginDeps(h, true)),
					httpsec.EnableSessionBearer(h.sessionBearerDeps()))
			},
			assert: refusedNaming("FormLoginDeps.Tokens"),
		},
		{
			name: "form login with no token generator",
			build: func(_ *testing.T, h *authHarness) error {
				return chainOf(
					httpsec.EnableFormLogin(formLoginDeps(h, false)),
					httpsec.EnableSessionBearer(h.sessionBearerDeps()))
			},
			assert: built,
		},
		{
			name: "second-factor verification given a token generator",
			build: func(t *testing.T, h *authHarness) error {
				return mfaChain(t, h, httpsec.WithMFATokens(h.tokens))
			},
			assert: refusedNaming("WithMFATokens"),
		},
		{
			name: "second-factor verification with no token generator",
			build: func(t *testing.T, h *authHarness) error {
				return mfaChain(t, h)
			},
			assert: built,
		},
		{
			name: "recovery completion given a token generator",
			build: func(t *testing.T, h *authHarness) error {
				return recoveryChain(t, httpsec.WithRecoveryTokens(h.tokens))
			},
			assert: refusedNaming("WithRecoveryTokens"),
		},
		{
			name: "recovery completion with no token generator",
			build: func(t *testing.T, _ *authHarness) error {
				return recoveryChain(t)
			},
			assert: built,
		},
		{
			name: "magic link given a token generator",
			build: func(t *testing.T, _ *authHarness) error {
				_, err := magicLinkReferenceChain(newMagicLinkHarness(t))

				return err
			},
			assert: refusedNaming("WithMagicLinkTokens"),
		},
		{
			name: "magic link with no token generator",
			build: func(t *testing.T, _ *authHarness) error {
				h := newMagicLinkHarness(t)
				h.tokens = nil

				_, err := magicLinkReferenceChain(h)

				return err
			},
			assert: built,
		},
		{
			name: "federated login redemption given a token generator",
			build: func(t *testing.T, _ *authHarness) error {
				_, err := oidcReferenceChain(t, newOIDCHarness(t), true)

				return err
			},
			assert: refusedNaming("WithOIDCTokens"),
		},
		{
			name: "federated login with a callback success function given a token generator",
			build: func(t *testing.T, _ *authHarness) error {
				h := newOIDCHarness(t)
				h.chainOpts = append(h.chainOpts,
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: referenceUsers(t)}))

				_, err := h.assemble(nil,
					httpsec.WithOIDCSessions(h.sessions),
					httpsec.WithOIDCTokens(h.tokens),
					httpsec.WithOIDCCallbackSuccess(func(*httpsec.Exchange, oidc.CallbackResult, string) error { return nil }))

				return err
			},
			assert: refusedNaming("WithOIDCTokens"),
		},
		{
			name: "federated login redemption with no token generator",
			build: func(t *testing.T, _ *authHarness) error {
				_, err := oidcReferenceChain(t, newOIDCHarness(t), false)

				return err
			},
			assert: built,
		},
		{
			name: "passwordless login given a token generator",
			build: func(t *testing.T, _ *authHarness) error {
				_, err := passwordlessReferenceChain(t, newPwlDeployment(t), true)

				return err
			},
			assert: refusedNaming("PasswordlessTokens"),
		},
		{
			name: "passwordless login with no token generator",
			build: func(t *testing.T, _ *authHarness) error {
				_, err := passwordlessReferenceChain(t, newPwlDeployment(t), false)

				return err
			},
			assert: built,
		},
		{
			name: "limiter construction: nil",
			build: func(_ *testing.T, h *authHarness) error {
				_, err := httpsec.New(httpsec.EnableSessionBearer(h.sessionBearerDeps(),
					httpsec.WithSessionBearerLimiter(nil)))

				return err
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithSessionBearerLimiter")
			},
		},
		{
			name: "limiter construction: typed nil",
			build: func(_ *testing.T, h *authHarness) error {
				_, err := httpsec.New(httpsec.EnableSessionBearer(h.sessionBearerDeps(),
					httpsec.WithSessionBearerLimiter((*ratelimit.MemoryLimiter)(nil))))

				return err
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithSessionBearerLimiter")
			},
		},
		{
			// The chain's factory builds the flow's limiter under its own
			// namespace and default allowance.
			name: "shared factory",
			build: func(t *testing.T, h *authHarness) error {
				memory := ratelimit.MemoryLimiterFactory()
				factory := NewMockLimiterFactory(gomock.NewController(t))

				factory.EXPECT().NewLimiter("session-reference", 100, time.Minute).
					DoAndReturn(memory.NewLimiter)
				factory.EXPECT().NewLimiter(gomock.Not("session-reference"), gomock.Any(), gomock.Any()).
					AnyTimes().DoAndReturn(memory.NewLimiter)

				_, err := httpsec.New(
					httpsec.WithRateLimiterFactory(factory),
					httpsec.EnableSessionBearer(h.sessionBearerDeps()),
				)

				return err
			},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.build(t, newAuthHarness(t)))
		})
	}
}

// issued is the credential an endpoint handed its responder, and the session
// it handed with it.
type issued struct {
	credential string
	session    *session.Session
}

// TestSessionBearerIssuesSessionReferences pins that with the
// session-reference mode on, password login, second-factor verification,
// recovery completion, magic link, federated login and passwordless passkey
// login hand their responders the session's own identifier as
// the credential, and that a request bearing it authenticates on the same
// chain.
func TestSessionBearerIssuesSessionReferences(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// issue runs the credential-issuing request and returns the chain it
		// ran on and what the endpoint handed its responder.
		issue func(t *testing.T) (*httpsec.Chain, issued)

		// assert judges a request bearing the issued credential.
		assert func(t *testing.T, got issued, s served)
	}

	authenticatedOn := func(t *testing.T, got issued, s served) {
		t.Helper()
		require.NoError(t, s.err)
		require.True(t, s.handlerRan)

		published, ok := httpsec.SessionFromContext(s.handled.Context())
		require.True(t, ok)
		assert.Equal(t, got.session.ID, published.ID)
	}

	cases := []testCase{
		{
			name: "password login",
			issue: func(t *testing.T) (*httpsec.Chain, issued) {
				h := newAuthHarness(t)
				sessions, err := session.New()
				require.NoError(t, err)

				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil)

				var got issued
				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: h.authn, Sessions: sessions, Attempts: h.attempts,
					}, httpsec.WithLoginResponder(func(_ *httpsec.Exchange, r httpsec.LoginResult) error {
						got = issued{credential: r.Token, session: r.Session}

						return nil
					})),
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: h.users}),
				)
				require.NoError(t, err)

				out := serve(t, chain, formRequest(t.Context(), httpsec.DefaultLoginPath, "username=ada&password=pw"))
				require.NoError(t, out.err)

				return chain, got
			},
			assert: authenticatedOn,
		},
		{
			name: "second-factor verification",
			issue: func(t *testing.T) (*httpsec.Chain, issued) {
				h := newMFAHarness(t)
				h.channel(factor.AuthenticatorApp).allows().accepts().recordsNoFailure()
				h.users.EXPECT().LoadByUserID(gomock.Any(), testMFAUser).AnyTimes().
					Return(&identity.Details{ID: testMFAUser, Username: mfaUsername, Active: true}, nil)

				pending := h.pendingSession(t, factor.Password)

				var got issued
				chain, err := httpsec.New(
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: h.users}),
					httpsec.EnableMFA([]mfa.Method{h.method},
						httpsec.WithMFAVerifyLimiter(h.limiter),
						httpsec.WithMFAResponder(func(_ *httpsec.Exchange, r httpsec.MFAResult) error {
							got = issued{credential: r.Token, session: r.Session}

							return nil
						})),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}),
				)
				require.NoError(t, err)

				req := postCode(t.Context(), testMFAVerifyPath)
				req.Header.Set("Authorization", "Bearer "+pending.ID)

				out := serve(t, chain, req)
				require.NoError(t, out.err)
				require.NotNil(t, got.session)
				assert.NotEqual(t, pending.ID, got.session.ID, "the session was rotated")
				assert.Equal(t, session.MFASatisfied, got.session.MFA)

				return chain, got
			},
			assert: authenticatedOn,
		},
		{
			name: "recovery completion",
			issue: func(t *testing.T) (*httpsec.Chain, issued) {
				h := newRecoveryHarness(t)
				h.reference = true

				var got issued
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryResponder(
					func(_ *httpsec.Exchange, r httpsec.RecoveryResult) error {
						got = issued{credential: r.Token, session: r.Recovery.Session}

						return nil
					})}
				h.build(t)

				out := h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword))
				require.NoError(t, out.err)

				return h.chain, got
			},
			assert: func(t *testing.T, got issued, s served) {
				t.Helper()

				// A recovery-pending session is confined to binding a new
				// factor, so the request is refused by the recovery gate: which
				// it reaches only as an authenticated session.
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, s.err, &ch, "the reference authenticated, and the gate holds it")
				assert.Equal(t, policy.ChallengeAccountRecovery, ch.Kind)
				require.NotNil(t, ch.Session)
				assert.Equal(t, got.session.ID, ch.Session.ID)
			},
		},
		{
			name: "magic link",
			issue: func(t *testing.T) (*httpsec.Chain, issued) {
				h := newMagicLinkHarness(t)
				h.tokens = nil

				var got issued
				h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkResponder(
					func(_ *httpsec.Exchange, r httpsec.MagicLinkResult) error {
						got = issued{credential: r.Token, session: r.Session}

						return nil
					}))

				chain, err := magicLinkReferenceChain(h)
				require.NoError(t, err)

				tok, nonce := h.link(t, chain)
				require.NoError(t, h.redeem(t, chain, tok, nonce).err)

				return chain, got
			},
			assert: authenticatedOn,
		},
		{
			name: "federated login handoff redemption",
			issue: func(t *testing.T) (*httpsec.Chain, issued) {
				h := newOIDCHarness(t)

				chain, err := oidcReferenceChain(t, h, false)
				require.NoError(t, err)

				out := serve(t, chain, handoffRequest(t.Context(), oidcTestSource, h.issueHandoff(t, "")))
				require.NoError(t, out.err)

				return chain, issuedFromBody(t, h.sessions, out)
			},
			assert: authenticatedOn,
		},
		{
			name: "passwordless passkey login",
			issue: func(t *testing.T) (*httpsec.Chain, issued) {
				d := newPwlDeployment(t)

				chain, err := passwordlessReferenceChain(t, d, false)
				require.NoError(t, err)

				out := d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
				require.NoError(t, out.err)

				return chain, issuedFromBody(t, d.sessions, out)
			},
			assert: authenticatedOn,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, got := tc.issue(t)

			require.NotNil(t, got.session, "the responder was handed the session")
			assert.Equal(t, got.session.ID, got.credential, "the credential is the session's identifier")
			assert.True(t, session.ValidIdentifier(got.credential))

			tc.assert(t, got, serve(t, chain, bearerRequest(t.Context(), "Bearer "+got.credential)))
		})
	}
}

// issuedFromBody reads the credential an endpoint with no responder hook
// wrote into its JSON document, and the session it names from sessions.
func issuedFromBody(t *testing.T, sessions *session.Sessions, out served) issued {
	t.Helper()

	var doc loginBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.AccessToken)

	s, err := sessions.Load(t.Context(), doc.AccessToken)
	require.NoError(t, err, "the credential is a session identifier")

	return issued{credential: doc.AccessToken, session: s}
}

const sessionReferenceSource = "203.0.113.7"

var errReferencePolicyDenied = errors.New("sessionbearer_test: outside office hours")

// referenceStore wires the harness's store to know testReference alone, and
// counts the lookups by whether they asked for the live reference.
type referenceStore struct {
	unknown atomic.Int64
	live    atomic.Int64
}

func (h *authHarness) knowsOnlyTestReference() *referenceStore {
	counts := &referenceStore{}

	h.store.EXPECT().Load(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string) (*session.Session, error) {
			if id != testReference {
				counts.unknown.Add(1)

				return nil, session.ErrNotFound
			}

			counts.live.Add(1)

			return referencedSession(), nil
		})
	h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).AnyTimes().Return(storedUser(), nil)
	h.acceptsActivityWriteBack()

	return counts
}

// unknownReference is the n-th well-formed identifier no session answers to.
func unknownReference(n int) string {
	raw := make([]byte, 32)
	binary.BigEndian.PutUint32(raw, uint32(n)) //nolint:gosec // n is a small non-negative loop index
	raw[31] = 0xff

	return base64.RawURLEncoding.EncodeToString(raw)
}

func fromReferenceSource(t *testing.T, chain *httpsec.Chain, source, header string) served {
	t.Helper()

	req := bearerRequest(t.Context(), header)
	req.RemoteAddr = source + ":51000"

	return serve(t, chain, req)
}

// TestSessionBearerThrottle pins that references no session answers to are
// counted per source, that a source over its allowance is refused before any
// lookup, and that nothing but a refused reference is counted.
func TestSessionBearerThrottle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		engine func(t *testing.T) *policy.Engine
		drive  func(t *testing.T, chain *httpsec.Chain) []served
		assert func(t *testing.T, out []served, counts *referenceStore)
	}

	refusedAuth := func(t *testing.T, s served) {
		t.Helper()
		require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
		assert.False(t, s.handlerRan)
	}

	cases := []testCase{
		{
			name: "a flooded source is refused before any lookup",
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				var out []served
				for i := range 100 {
					out = append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+unknownReference(i)))
				}

				return append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference))
			},
			assert: func(t *testing.T, out []served, counts *referenceStore) {
				refusedAuth(t, out[100])
				assert.Zero(t, counts.live.Load(), "the live reference was never looked up")
				assert.Equal(t, int64(100), counts.unknown.Load())
			},
		},
		{
			name: "malformed values count",
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				var out []served
				for range 100 {
					out = append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer not-a-reference"))
				}

				return append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference))
			},
			assert: func(t *testing.T, out []served, counts *referenceStore) {
				refusedAuth(t, out[100])
				assert.Zero(t, counts.live.Load())
				assert.Zero(t, counts.unknown.Load(), "a malformed value costs no lookup")
			},
		},
		{
			name: "another source is unaffected",
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				for i := range 100 {
					_ = fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+unknownReference(i))
				}

				return []served{fromReferenceSource(t, chain, "198.51.100.4", "Bearer "+testReference)}
			},
			assert: func(t *testing.T, out []served, _ *referenceStore) {
				require.NoError(t, out[0].err)
				assert.True(t, out[0].handlerRan)
			},
		},
		{
			name: "live sessions spend nothing",
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				var out []served
				for range 1000 {
					out = append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference))
				}

				return out
			},
			assert: func(t *testing.T, out []served, _ *referenceStore) {
				for i, s := range out {
					require.NoError(t, s.err, "request %d", i)
				}
			},
		},
		{
			name: "a request carrying no reference never reaches the limiter",
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				var out []served
				for range 300 {
					out = append(out, fromReferenceSource(t, chain, sessionReferenceSource, ""))
				}

				return append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference))
			},
			assert: func(t *testing.T, out []served, _ *referenceStore) {
				require.NoError(t, out[300].err)
			},
		},
		{
			name: "a policy refusal is not recorded",
			engine: func(t *testing.T) *policy.Engine {
				return denyingIn(t, policy.PerRequest, errReferencePolicyDenied)
			},
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				var out []served
				for range 200 {
					out = append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference))
				}

				return out
			},
			assert: func(t *testing.T, out []served, counts *referenceStore) {
				for i, s := range out {
					require.ErrorIs(t, s.err, errReferencePolicyDenied, "request %d", i)
				}

				assert.Equal(t, int64(200), counts.live.Load(), "none was throttled before its lookup")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			counts := h.knowsOnlyTestReference()

			opts := []httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableSessionBearer(h.sessionBearerDeps()),
			}
			if tc.engine != nil {
				opts = append(opts, httpsec.WithPolicyEngine(tc.engine(t)))
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, tc.drive(t, chain), counts)
		})
	}
}

// TestSessionBearerConsumerLimiter pins that a consumer's limiter is asked
// about every claimed request and told about every refused reference, keyed by
// the source, and nothing else.
func TestSessionBearerConsumerLimiter(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		checks   int
		failures []string
	)

	limiter := NewMockLimiter(gomock.NewController(t))
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			checks++

			return false, nil
		})
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, key string) error {
			mu.Lock()
			defer mu.Unlock()
			failures = append(failures, key)

			return nil
		})

	h := newAuthHarness(t)
	h.knowsOnlyTestReference()

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableSessionBearer(h.sessionBearerDeps(), httpsec.WithSessionBearerLimiter(limiter)),
	)
	require.NoError(t, err)

	require.Error(t, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+unknownReference(1)).err)
	require.Error(t, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer junk").err)
	require.NoError(t, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference).err)

	mu.Lock()
	defer mu.Unlock()

	assert.Equal(t, 3, checks, "every claimed request is checked against its source")
	require.Len(t, failures, 2, "and only the two refused references are recorded")

	for _, key := range failures {
		assert.True(t, strings.Contains(key, sessionReferenceSource), "keyed by the source: %q", key)
	}
}

// errStoreDown is the store fault the late-renewal cases inject.
var errStoreDown = errors.New("store down")

// loadCountingStore counts the loads that reach the store, and can be armed to
// fail the loads from the nth one on.
type loadCountingStore struct {
	session.Store

	loads atomic.Int64

	// failFrom, when positive, is the load number from which loads fail with
	// failErr; loads before it reach the store.
	failFrom atomic.Int64
	failErr  error
}

func (s *loadCountingStore) Load(ctx context.Context, id string) (*session.Session, error) {
	n := s.loads.Add(1)

	if from := s.failFrom.Load(); from > 0 && n >= from {
		return nil, s.failErr
	}

	return s.Store.Load(ctx, id)
}

// failEndpointLoad makes the load the renewal endpoint makes of the old
// identifier fail with err: the bearer's load, which lets the late credential
// through, is the first after this call, and the endpoint's is the second.
func (s *loadCountingStore) failEndpointLoad(err error) {
	s.failErr = err
	s.failFrom.Store(s.loads.Load() + 2)
}

// failureRecordingLimiter is the default allowance, 100 failures a minute, that
// also lists the keys it was charged.
type failureRecordingLimiter struct {
	ratelimit.Limiter

	owner *lateRenewals
}

func (l *failureRecordingLimiter) RecordFailure(ctx context.Context, key string) error {
	l.owner.mu.Lock()
	l.owner.failures = append(l.owner.failures, key)
	l.owner.mu.Unlock()

	return l.Limiter.RecordFailure(ctx, key)
}

// lateRenewals is a session-reference chain with the renewal endpoint over a
// manager with unused-successor recovery, and a session whose renewal window
// has ended.
type lateRenewals struct {
	clk     *clockwork.FakeClock
	store   *loadCountingStore
	manager *session.Sessions
	chain   *httpsec.Chain

	mu       sync.Mutex
	failures []string
}

func newLateRenewals(t *testing.T) *lateRenewals {
	t.Helper()

	l := &lateRenewals{clk: clockwork.NewFakeClockAt(time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC))}
	l.store = &loadCountingStore{Store: session.NewMemoryStore(session.WithMemoryStoreClock(l.clk))}

	var err error

	l.manager, err = session.New(
		session.WithClock(l.clk),
		session.WithStore(l.store),
		session.WithUnusedSuccessorRecovery(),
		session.WithIdleTimeout(7*24*time.Hour),
		session.WithAbsoluteTimeout(30*24*time.Hour),
	)
	require.NoError(t, err)

	inner, err := ratelimit.NewMemoryLimiter(100, time.Minute, ratelimit.WithMemoryLimiterClock(l.clk))
	require.NoError(t, err)

	limiter := &failureRecordingLimiter{Limiter: inner, owner: l}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

	l.chain, err = httpsec.New(
		httpsec.WithClock(l.clk),
		httpsec.WithLogger(slog.New(slog.DiscardHandler)),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: l.manager, Users: users},
			httpsec.WithSessionBearerLimiter(limiter)),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: users}),
	)
	require.NoError(t, err)

	return l
}

// superseded creates a session and renews it directly through the manager, as
// a renewal whose response was lost would have, and returns the old identifier
// and the successor's.
func (l *lateRenewals) superseded(t *testing.T) (string, string) {
	t.Helper()

	s, err := l.manager.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	next, _, err := l.manager.RotateWithGrace(t.Context(), s, 30*time.Second)
	require.NoError(t, err)

	return s.ID, next.ID
}

func (l *lateRenewals) renew(t *testing.T, credential string) served {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	req.RemoteAddr = sessionReferenceSource + ":51000"

	return serve(t, l.chain, req)
}

func (l *lateRenewals) recorded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.failures...)
}

// TestSessionBearerLateRenewals pins that, under unused-successor recovery, a
// late renewal the endpoint refuses is counted against its source like any
// refused reference, and one it recovers is not.
func TestSessionBearerLateRenewals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		drive  func(t *testing.T, l *lateRenewals) []served
		assert func(t *testing.T, l *lateRenewals, out []served)
	}

	cases := []testCase{
		{
			name: "refused late renewals throttle the source",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, _ := l.superseded(t)

				// Past the window and past the session's own deadlines, with
				// the successor never used: each renewal is refused as
				// expired, and nothing is revoked, so the next one reaches
				// the endpoint again.
				l.clk.Advance(8 * 24 * time.Hour)

				var out []served
				for range 100 {
					out = append(out, l.renew(t, old))
				}

				l.store.loads.Store(0)

				return append(out, l.renew(t, old))
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				for _, s := range out[:100] {
					require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				}

				require.ErrorIs(t, out[100].err, httpsec.ErrAuthenticationRequired)
				assert.Zero(t, l.store.loads.Load(), "a throttled source is refused before any store lookup")
			},
		},
		{
			name: "a refused late renewal is recorded once against its source",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, _ := l.superseded(t)
				l.clk.Advance(8 * 24 * time.Hour)

				return []served{l.renew(t, old)}
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				require.ErrorIs(t, out[0].err, httpsec.ErrAuthenticationRequired)

				failures := l.recorded()
				require.Len(t, failures, 1)
				assert.Contains(t, failures[0], sessionReferenceSource)
			},
		},
		{
			name: "a reused late renewal is recorded against its source",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, successor := l.superseded(t)

				// The successor is used and kept alive past the old
				// session's own deadlines, then the old identifier is
				// presented late, which is reuse.
				next, err := l.manager.Load(t.Context(), successor)
				require.NoError(t, err)

				l.clk.Advance(6 * 24 * time.Hour)
				require.NoError(t, l.manager.Touch(t.Context(), next))
				l.clk.Advance(2 * 24 * time.Hour)

				return []served{l.renew(t, old)}
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				require.ErrorIs(t, out[0].err, session.ErrReused)
				assert.Len(t, l.recorded(), 1)
			},
		},
		{
			name: "a lost race at the endpoint's load is not recorded",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, _ := l.superseded(t)
				l.clk.Advance(8 * 24 * time.Hour)
				l.store.failEndpointLoad(session.ErrRenewalConflict)

				return []served{l.renew(t, old)}
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				require.ErrorIs(t, out[0].err, httpsec.ErrSessionRenewalConflict)
				assert.NotErrorIs(t, out[0].err, httpsec.ErrAuthenticationRequired)
				assert.Empty(t, l.recorded(), "a lost race is not a failed guess")
			},
		},
		{
			name: "a store fault at the endpoint's load is not recorded",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, _ := l.superseded(t)
				l.clk.Advance(8 * 24 * time.Hour)
				l.store.failEndpointLoad(errStoreDown)

				return []served{l.renew(t, old)}
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				require.ErrorIs(t, out[0].err, errStoreDown)
				assert.NotErrorIs(t, out[0].err, httpsec.ErrAuthenticationRequired)
				assert.Empty(t, l.recorded(), "a store fault is not a failed guess")
			},
		},
		{
			name: "a recovered late renewal spends nothing",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, _ := l.superseded(t)
				l.clk.Advance(time.Minute)

				return []served{l.renew(t, old)}
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				require.NoError(t, out[0].err)
				assert.Empty(t, l.recorded(), "a recovered renewal is not a failed guess")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l := newLateRenewals(t)
			out := tc.drive(t, l)
			tc.assert(t, l, out)
		})
	}
}
