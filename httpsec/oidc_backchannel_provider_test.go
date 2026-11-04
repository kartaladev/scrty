package httpsec_test

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

var cspNonce = regexp.MustCompile(`'nonce-[^']*'`)

// upstreamEnds is the provider's fixture with an upstream provider's back-channel
// logout on the same chain, and the same chain without the provider to compare with.
type upstreamEnds struct {
	*signInEnds

	h        *backchannelHarness
	baseline *opFlow
}

func newUpstreamEnds(t *testing.T, opts ...httpsec.OIDCOption) *upstreamEnds {
	t.Helper()

	h := newBackchannelHarness(t)

	login := func(sessions *session.Sessions) httpsec.Option {
		return httpsec.EnableOIDCLogin(httpsec.OIDCDeps{RelyingParty: h.manager, Handoff: h.handoffs},
			append([]httpsec.OIDCOption{httpsec.WithOIDCSessions(sessions)}, opts...)...)
	}

	f := newSignInEnds(t, endsSetup{chain: func(_ *testing.T, f *signInEnds) []httpsec.Option {
		return []httpsec.Option{login(f.sessions)}
	}})

	// The same chain but for the provider: what it answers is what the provider must not change.
	sessions, err := session.New(session.WithClock(f.clk))
	require.NoError(t, err)

	baseline, err := httpsec.New(
		httpsec.WithClock(f.clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: f.users}),
		httpsec.EnableJWKSEndpoint(tokenKeys()),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}),
		login(sessions),
	)
	require.NoError(t, err)

	return &upstreamEnds{signInEnds: f, h: h, baseline: &opFlow{issuer: opIssuer, clk: f.clk, chain: baseline}}
}

// federated is a sign-in of the linked user through the upstream session sid.
func (u *upstreamEnds) federated(t *testing.T, sid string) *session.Session {
	t.Helper()

	s, err := u.sessions.Create(t.Context(), oidcTestUserID,
		session.WithFirstFactor(factor.OIDC),
		session.WithExternalSession(testOIDCProvider, u.h.issuer(), sid, oidcTestIDToken))
	require.NoError(t, err)

	return s
}

// password is a sign-in of the linked user that came through no upstream.
func (u *upstreamEnds) password(t *testing.T) *session.Session {
	t.Helper()

	s, err := u.sessions.Create(t.Context(), oidcTestUserID, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	return s
}

// deliver posts a fresh logout token to chain-holder w.
func (u *upstreamEnds) deliver(t *testing.T, w *opFlow, sub, sid string) flowAnswer {
	t.Helper()

	r := backchannelRequest(t.Context(), testOIDCProvider, "application/x-www-form-urlencoded",
		strings.NewReader(url.Values{"logout_token": {u.h.provider.logoutToken(t, sub, sid)}}.Encode()))

	return w.serve(t, r, nil)
}

// answersAsWithoutTheProvider is the check that the answer tells nothing the chain
// without the provider would not: status, headers and bytes.
func (u *upstreamEnds) answersAsWithoutTheProvider(t *testing.T, a flowAnswer, sub, sid string) {
	t.Helper()

	plain := u.deliver(t, u.baseline, sub, sid)

	assert.Equal(t, http.StatusOK, a.status, a.body)
	assert.Equal(t, plain.status, a.status)
	assert.Equal(t, plain.body, a.body)
	assert.Empty(t, a.body)
	assert.Equal(t, withoutNonce(plain.header), withoutNonce(a.header))
	require.NoError(t, a.err)
}

// withoutNonce is header with the policy's nonce taken out, which differs per response
// on any chain.
func withoutNonce(header http.Header) http.Header {
	out := header.Clone()
	out.Set("Content-Security-Policy", cspNonce.ReplaceAllString(out.Get("Content-Security-Policy"), ""))

	return out
}

// TestOIDCBackchannel_EndsProviderGrants pins that an upstream back-channel logout ends
// the provider grants of the sessions it ends, and answers exactly as it did before.
func TestOIDCBackchannel_EndsProviderGrants(t *testing.T) {
	t.Parallel()

	type scene struct {
		named, sibling, local    *session.Session
		online, offline          endsGrant
		siblingGrant, localGrant endsGrant
	}

	type testCase struct {
		name    string
		opts    []httpsec.OIDCOption
		sub     string
		sid     string
		arrange func(u *upstreamEnds)
		assert  func(t *testing.T, u *upstreamEnds, sc scene)
	}

	cases := []testCase{
		{
			name: "a token naming an upstream session ends that sign-in's online grant, and tells its client",
			sub:  oidcTestSubject,
			sid:  "s-1",
			assert: func(t *testing.T, u *upstreamEnds, sc scene) {
				t.Helper()

				assert.False(t, u.loads(t, sc.named))
				assert.True(t, u.loads(t, sc.sibling))
				u.refreshRefused(t, sc.online)
				u.refreshWorks(t, sc.offline)
				u.refreshWorks(t, sc.siblingGrant)
				u.refreshWorks(t, sc.localGrant)
				assert.Equal(t, "login_required", u.silentError(t, sc.online))
				assert.Equal(t, []string{sc.named.FamilyID.String()}, sidsOf(u.toldOf(t)))
			},
		},
		{
			name: "a token naming only a subject ends every sign-in through that issuer, and no other",
			sub:  oidcTestSubject,
			assert: func(t *testing.T, u *upstreamEnds, sc scene) {
				t.Helper()

				assert.False(t, u.loads(t, sc.named))
				assert.False(t, u.loads(t, sc.sibling))
				assert.True(t, u.loads(t, sc.local))
				u.refreshRefused(t, sc.online)
				u.refreshWorks(t, sc.offline)
				u.refreshRefused(t, sc.siblingGrant)
				u.refreshWorks(t, sc.localGrant)
				assert.ElementsMatch(t,
					[]string{sc.named.FamilyID.String(), sc.sibling.FamilyID.String()}, sidsOf(u.toldOf(t)))
			},
		},
		{
			name: "the all-sessions scope also ends the grants of a sign-in through no upstream",
			opts: []httpsec.OIDCOption{httpsec.WithOIDCBackchannelLogoutScope(httpsec.BackchannelLogoutScopeAll)},
			sub:  oidcTestSubject,
			assert: func(t *testing.T, u *upstreamEnds, sc scene) {
				t.Helper()

				assert.False(t, u.loads(t, sc.local))
				u.refreshRefused(t, sc.online)
				u.refreshWorks(t, sc.offline)
				u.refreshRefused(t, sc.localGrant)
				assert.Len(t, u.toldOf(t), 3)
			},
		},
		{
			name: "a token naming no live session ends nothing, and answers the same",
			sub:  oidcTestSubject,
			sid:  "s-gone",
			assert: func(t *testing.T, u *upstreamEnds, sc scene) {
				t.Helper()

				assert.True(t, u.loads(t, sc.named))
				u.refreshWorks(t, sc.online)
				assert.Empty(t, u.toldOf(t))
			},
		},
		{
			name:    "a grant store failure leaves the session ended, answers the same, and is logged",
			sub:     oidcTestSubject,
			sid:     "s-1",
			arrange: func(u *upstreamEnds) { u.grants.failing.Store(true) },
			assert: func(t *testing.T, u *upstreamEnds, sc scene) {
				t.Helper()

				u.grants.failing.Store(false)

				assert.False(t, u.loads(t, sc.named))
				assert.Contains(t, u.logs.String(), "level=ERROR")
				assert.NotContains(t, u.logs.String(), endsOutageText)
				assert.Empty(t, u.toldOf(t))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u := newUpstreamEnds(t, tc.opts...)
			sc := scene{named: u.federated(t, "s-1"), sibling: u.federated(t, "s-2"), local: u.password(t)}
			sc.online = u.grantFrom(t, sc.named, endsOnlineScope)
			sc.offline = u.grantFrom(t, sc.named, endsOffline)
			sc.siblingGrant = u.grantFrom(t, sc.sibling, endsOnlineScope)
			sc.localGrant = u.grantFrom(t, sc.local, endsOnlineScope)

			if tc.arrange != nil {
				tc.arrange(u)
			}

			a := u.deliver(t, u.opFlow, tc.sub, tc.sid)
			u.answersAsWithoutTheProvider(t, a, tc.sub, tc.sid)
			tc.assert(t, u, sc)
		})
	}
}
