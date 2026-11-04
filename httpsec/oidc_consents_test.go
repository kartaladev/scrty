package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

const (
	consentsPath = "/oauth2/consents"

	// consentsGone is a client the consumer's registry no longer holds, and consentsSpaced one whose
	// identifier needs escaping in a path.
	consentsGone   = "gone-app"
	consentsSpaced = "spaced app"
)

// errConsentsDown is what a failing consent store answers.
var errConsentsDown = errors.New("consent store down")

// downConsents is a consent store that cannot answer a read or a revocation.
type downConsents struct {
	*oidcprovider.MemoryConsentStore
}

func (downConsents) Load(context.Context, identity.UserID, string) (*oidcprovider.Consent, error) {
	return nil, errConsentsDown
}

func (downConsents) Revoke(context.Context, identity.UserID, string) (bool, error) {
	return false, errConsentsDown
}

func (downConsents) ListByUser(context.Context, identity.UserID) ([]oidcprovider.Consent, error) {
	return nil, errConsentsDown
}

// consentsWorld is what a row finds stored: u-1 has allowed two clients, and u-2 one of the same.
type consentsWorld struct {
	// given is when each consent was last given.
	web, gone, other time.Time
	// families are the grants of u-1's web consent (offline), u-1's gone-app consent and u-2's web
	// consent.
	webGrant, goneGrant, otherGrant id.ID
}

// consentsSeed stores the world. It writes the stores directly, because what the endpoint lists and
// revokes is what they hold.
func consentsSeed(t *testing.T, w *opFlow) *consentsWorld {
	t.Helper()

	world := &consentsWorld{
		web:   time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC),
		gone:  time.Date(2026, 11, 2, 11, 30, 0, 0, time.UTC),
		other: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC),
	}

	ctx := t.Context()

	require.NoError(t, w.consents.Give(ctx, "u-1", flowWeb, []string{"openid", "email"}, true, world.web))
	require.NoError(t, w.consents.Give(ctx, "u-1", consentsGone, []string{"openid"}, false, world.gone))
	require.NoError(t, w.consents.Give(ctx, "u-1", consentsSpaced, []string{"openid"}, false, world.gone))
	require.NoError(t, w.consents.Give(ctx, "u-2", flowWeb, []string{"openid"}, false, world.other))

	world.webGrant = consentsGrant(t, w, "u-1", flowWeb, true)
	world.goneGrant = consentsGrant(t, w, "u-1", consentsGone, false)
	world.otherGrant = consentsGrant(t, w, "u-2", flowWeb, false)

	return world
}

func consentsGrant(t *testing.T, w *opFlow, user identity.UserID, client string, offline bool) id.ID {
	t.Helper()

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	require.NoError(t, w.grants.Create(t.Context(), &oidcprovider.Grant{
		Family:    family,
		User:      user,
		ClientID:  client,
		Scopes:    []string{"openid"},
		Offline:   offline,
		CreatedAt: w.clk.Now(),
		ExpiresAt: w.clk.Now().Add(time.Hour),
	}))

	return family
}

// revoked reports whether the grant is revoked, and why.
func consentsRevoked(t *testing.T, w *opFlow, family id.ID) (bool, oidcprovider.RevocationCause) {
	t.Helper()

	g, err := w.grants.Load(t.Context(), family)
	require.NoError(t, err)

	return g.Revoked, g.RevokeCause
}

// consentsGET lists the consents at path.
func (w *opFlow) consentsGET(t *testing.T, path string, change ...flowChange) flowAnswer {
	t.Helper()

	return w.consentsDo(t, http.MethodGet, path, change)
}

// consentsDELETE revokes the consent for client, which is written into the path as given.
func (w *opFlow) consentsDELETE(t *testing.T, path string, change ...flowChange) flowAnswer {
	t.Helper()

	return w.consentsDo(t, http.MethodDelete, path, change)
}

func (w *opFlow) consentsDo(t *testing.T, method, path string, change []flowChange) flowAnswer {
	t.Helper()

	return w.serve(t, httptest.NewRequestWithContext(t.Context(), method, w.issuer+path, nil), change)
}

// crossSite makes a request one a page of another site sent.
func crossSite(r *http.Request) {
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Origin", "https://evil.example.com")
}

// listedConsent is one member of the list.
type listedConsent struct {
	ClientID    string    `json:"client_id"`
	ClientName  string    `json:"client_name"`
	Scopes      []string  `json:"scopes"`
	Offline     bool      `json:"offline_access"`
	LastGivenAt time.Time `json:"last_given_at"`
}

// listed decodes the list, checking it holds exactly the documented members.
func consentsListed(t *testing.T, a flowAnswer) []listedConsent {
	t.Helper()

	var raw []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(a.body), &raw), a.body)

	for _, m := range raw {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}

		assert.ElementsMatch(t, []string{"client_id", "client_name", "scopes", "offline_access", "last_given_at"}, keys)
	}

	var list []listedConsent
	require.NoError(t, json.Unmarshal([]byte(a.body), &list), a.body)

	slices.SortFunc(list, func(x, y listedConsent) int { return strings.Compare(x.ClientID, y.ClientID) })

	return list
}

func TestOIDCConsents(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  flowSetup
		send   func(t *testing.T, w *opFlow, world *consentsWorld) flowAnswer
		assert func(t *testing.T, w *opFlow, world *consentsWorld, a flowAnswer)
	}

	// signedIn is a stored full session of u-1 presented as a bearer.
	signedIn := func(t *testing.T, w *opFlow) flowChange {
		t.Helper()

		return flowBearer(w.session(t).ID)
	}

	// nothingRevoked is the check that no grant was touched.
	nothingRevoked := func(t *testing.T, w *opFlow, world *consentsWorld) {
		t.Helper()

		for _, family := range []id.ID{world.webGrant, world.goneGrant, world.otherGrant} {
			revoked, _ := consentsRevoked(t, w, family)
			assert.False(t, revoked, "no grant is revoked")
		}

		for _, key := range []struct {
			user   identity.UserID
			client string
		}{{"u-1", flowWeb}, {"u-1", consentsGone}, {"u-2", flowWeb}} {
			_, err := w.consents.Load(t.Context(), key.user, key.client)
			assert.NoError(t, err, "%s's consent for %s stands", key.user, key.client)
		}
	}

	// refusedWith is the row that nothing was answered but a refusal, with no text and no cache.
	refusedWith := func(want error, status int) func(*testing.T, *opFlow, *consentsWorld, flowAnswer) {
		return func(t *testing.T, w *opFlow, world *consentsWorld, a flowAnswer) {
			t.Helper()

			require.ErrorIs(t, a.err, want)
			assert.Equal(t, status, a.status)
			assert.Empty(t, a.body)
			assert.False(t, a.passedOn, "the application never sees a request meant for the provider")
			assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			nothingRevoked(t, w, world)
		}
	}

	notAllowed := func(allow string) func(*testing.T, *opFlow, *consentsWorld, flowAnswer) {
		return func(t *testing.T, w *opFlow, world *consentsWorld, a flowAnswer) {
			t.Helper()

			assert.Equal(t, http.StatusMethodNotAllowed, a.status)
			assert.Equal(t, allow, a.header.Get("Allow"))
			assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			assert.False(t, a.passedOn, "the application never sees a request meant for the provider")
			nothingRevoked(t, w, world)
		}
	}

	owing := func(mutate func(w *opFlow, s *session.Session)) func(t *testing.T, w *opFlow) flowChange {
		return func(t *testing.T, w *opFlow) flowChange {
			t.Helper()

			s := w.session(t)
			mutate(w, s)
			require.NoError(t, w.sessions.Save(t.Context(), s))

			return flowBearer(s.ID)
		}
	}

	mfaPending := owing(func(_ *opFlow, s *session.Session) { s.MFA = session.MFAPending })

	cases := []testCase{
		{
			name: "the signed-in user lists their own consents, and no one else's",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath, signedIn(t, w))
			},
			assert: func(t *testing.T, _ *opFlow, world *consentsWorld, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
				assert.Equal(t, "application/json", a.header.Get("Content-Type"))

				list := consentsListed(t, a)
				require.Len(t, list, 3, "u-1's three, and not u-2's")

				assert.Equal(t, flowWeb, list[0].ClientID)
				assert.Equal(t, "Flow Web", list[0].ClientName)
				assert.ElementsMatch(t, []string{"openid", "email"}, list[0].Scopes)
				assert.True(t, list[0].Offline)
				assert.True(t, world.web.Equal(list[0].LastGivenAt))

				assert.Equal(t, consentsGone, list[1].ClientID)
				assert.Empty(t, list[1].ClientName, "a client no longer registered has no name")
				assert.Equal(t, []string{"openid"}, list[1].Scopes)
				assert.False(t, list[1].Offline)
				assert.True(t, world.gone.Equal(list[1].LastGivenAt))

				assert.Equal(t, consentsSpaced, list[2].ClientID)
			},
		},
		{
			name: "a user who has allowed no one lists an empty array",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				other, err := w.sessions.Create(t.Context(), "u-3", session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				return w.consentsGET(t, consentsPath, flowBearer(other.ID))
			},
			assert: func(t *testing.T, _ *opFlow, _ *consentsWorld, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusOK, a.status, a.body)
				assert.JSONEq(t, `[]`, a.body)
			},
		},
		{
			name: "a consent holding no scope lists them as an empty array, not null",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				require.NoError(t, w.consents.Give(t.Context(), "u-3", flowWeb, nil, false, w.clk.Now()))

				other, err := w.sessions.Create(t.Context(), "u-3", session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				return w.consentsGET(t, consentsPath, flowBearer(other.ID))
			},
			assert: func(t *testing.T, _ *opFlow, _ *consentsWorld, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.Contains(t, a.body, `"scopes":[]`)
			},
		},
		{
			name: "a user named in the query is ignored, only the caller's identity counts",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath+"?user=u-2&user_id=u-2", signedIn(t, w))
			},
			assert: func(t *testing.T, _ *opFlow, _ *consentsWorld, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusOK, a.status, a.body)

				for _, c := range consentsListed(t, a) {
					assert.NotEqual(t, "u-2", c.ClientID)
				}

				assert.Len(t, consentsListed(t, a), 3)
			},
		},
		{
			name: "revoking one's own consent revokes that user's and client's grants, and no other",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsDELETE(t, consentsPath+"/"+flowWeb, signedIn(t, w))
			},
			assert: func(t *testing.T, w *opFlow, world *consentsWorld, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, a.status, a.body)
				assert.Empty(t, a.body)
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
				assert.False(t, a.passedOn)

				revoked, cause := consentsRevoked(t, w, world.webGrant)
				assert.True(t, revoked, "the offline grant is revoked too")
				assert.Equal(t, oidcprovider.CauseConsentRevoked, cause)

				_, err := w.consents.Load(t.Context(), "u-1", flowWeb)
				assert.ErrorIs(t, err, oidcprovider.ErrNotFound, "the next authorization asks again")

				still, _ := consentsRevoked(t, w, world.goneGrant)
				assert.False(t, still, "another client's grant stands")

				still, _ = consentsRevoked(t, w, world.otherGrant)
				assert.False(t, still, "another user's grant stands")

				_, err = w.consents.Load(t.Context(), "u-2", flowWeb)
				assert.NoError(t, err, "another user's consent stands")
			},
		},
		{
			name: "a client whose identifier needs escaping is revoked by the escaped path",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsDELETE(t, consentsPath+"/spaced%20app", signedIn(t, w))
			},
			assert: func(t *testing.T, w *opFlow, _ *consentsWorld, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, a.status, a.body)

				_, err := w.consents.Load(t.Context(), "u-1", consentsSpaced)
				assert.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "a client the caller never allowed is a 404 refusal, whoever allowed it",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				other, err := w.sessions.Create(t.Context(), "u-3", session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				return w.consentsDELETE(t, consentsPath+"/"+flowWeb+"?user=u-2", flowBearer(other.ID))
			},
			assert: refusedWith(httpsec.ErrOIDCForeignConsent, http.StatusNotFound),
		},
		{
			name: "a path naming no client, or more than one segment, is the same 404",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				bearer := signedIn(t, w)
				for _, path := range []string{consentsPath + "/a/b", consentsPath + "/" + flowWeb + "/"} {
					a := w.consentsDELETE(t, path, bearer)
					require.ErrorIs(t, a.err, httpsec.ErrOIDCForeignConsent, path)
					require.Equal(t, http.StatusNotFound, a.status, path)
					require.False(t, a.passedOn, path)
				}

				return w.consentsDELETE(t, consentsPath+"/", bearer)
			},
			assert: refusedWith(httpsec.ErrOIDCForeignConsent, http.StatusNotFound),
		},
		{
			name: "a cross-site revocation is refused by CSRF protection, with nothing revoked",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsDELETE(t, consentsPath+"/"+flowWeb, signedIn(t, w), crossSite)
			},
			assert: func(t *testing.T, w *opFlow, world *consentsWorld, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrCrossSiteRequest)
				assert.Equal(t, http.StatusForbidden, a.status)
				assert.False(t, a.passedOn)
				nothingRevoked(t, w, world)
			},
		},
		{
			name: "no credential is unauthenticated at the list",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath)
			},
			assert: refusedWith(httpsec.ErrAuthenticationRequired, http.StatusUnauthorized),
		},
		{
			name: "no credential is unauthenticated at a revocation",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsDELETE(t, consentsPath+"/"+flowWeb)
			},
			assert: refusedWith(httpsec.ErrAuthenticationRequired, http.StatusUnauthorized),
		},
		{
			name: "an API key is no sign-in, so it lists nothing",
			setup: flowSetup{chain: func(t *testing.T, w *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.EnableAPIKey(w.apiKeys(t))}
			}},
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath, w.apiKeyHeader())
			},
			assert: refusedWith(httpsec.ErrAuthenticationRequired, http.StatusUnauthorized),
		},
		{
			name: "a principal another interceptor swapped in is not the session's user, and lists nothing",
			setup: flowSetup{chain: func(t *testing.T, _ *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.RegisterInterceptor(
					httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
						ex.Authentication = &authenticate.Authentication{Principal: &identity.Principal{ID: "u-2"}}

						return next(ex)
					}), httpsec.OrderOIDCProviderSession-1)}
			}},
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				bearer := signedIn(t, w)

				a := w.consentsDELETE(t, consentsPath+"/"+flowWeb, bearer)
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)

				return w.consentsGET(t, consentsPath, bearer)
			},
			assert: refusedWith(httpsec.ErrAuthenticationRequired, http.StatusUnauthorized),
		},
		{
			name: "a session owing a second factor reaches neither, on a chain with the gate",
			setup: flowSetup{chain: func(t *testing.T, _ *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{mfaOn(t)}
			}},
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				bearer := mfaPending(t, w)

				a := w.consentsDELETE(t, consentsPath+"/"+flowWeb, bearer)
				require.Equal(t, http.StatusUnauthorized, a.status)

				return w.consentsGET(t, consentsPath, bearer)
			},
			assert: func(t *testing.T, w *opFlow, world *consentsWorld, a flowAnswer) {
				t.Helper()

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, a.err, &challenge)
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				assert.False(t, a.passedOn)
				assert.Empty(t, a.body, "the list is not written")
				nothingRevoked(t, w, world)
			},
		},
		{
			name: "a session owing a second factor reaches neither, on a chain with no gate for it",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				bearer := mfaPending(t, w)

				a := w.consentsDELETE(t, consentsPath+"/"+flowWeb, bearer)
				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, a.err, &challenge)
				require.Equal(t, policy.ChallengeMFA, challenge.Kind)

				return w.consentsGET(t, consentsPath, bearer)
			},
			assert: func(t *testing.T, w *opFlow, world *consentsWorld, a flowAnswer) {
				t.Helper()

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, a.err, &challenge)
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				assert.Empty(t, a.body, "the list is not written")
				nothingRevoked(t, w, world)
			},
		},
		{
			name: "a session owing a password change reaches neither, on a chain with no gate for it",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath,
					owing(func(_ *opFlow, s *session.Session) { s.PasswordChangePending = true })(t, w))
			},
			assert: func(t *testing.T, w *opFlow, world *consentsWorld, a flowAnswer) {
				t.Helper()

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, a.err, &challenge)
				assert.Equal(t, policy.ChallengePasswordChange, challenge.Kind)
				assert.Empty(t, a.body)
				nothingRevoked(t, w, world)
			},
		},
		{
			name: "a wrong method at the list is answered, not passed on",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsDo(t, http.MethodPut, consentsPath, []flowChange{signedIn(t, w)})
			},
			assert: notAllowed(http.MethodGet),
		},
		{
			name: "a wrong method at a client is answered, not passed on",
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath+"/"+flowWeb, signedIn(t, w))
			},
			assert: notAllowed(http.MethodDelete),
		},
		{
			name:  "a store that cannot list is a 500 with no text",
			setup: flowSetup{provider: []oidcprovider.Option{oidcprovider.WithConsentStore(downConsents{})}},
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath, signedIn(t, w))
			},
			assert: func(t *testing.T, _ *opFlow, _ *consentsWorld, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, oidcprovider.ErrDependency)
				assert.Equal(t, http.StatusInternalServerError, a.status)
				assert.Empty(t, a.body)
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			},
		},
		{
			name:  "a store that cannot revoke is a 500 with no text",
			setup: flowSetup{provider: []oidcprovider.Option{oidcprovider.WithConsentStore(downConsents{})}},
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				return w.consentsDELETE(t, consentsPath+"/"+flowWeb, signedIn(t, w))
			},
			assert: func(t *testing.T, _ *opFlow, _ *consentsWorld, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, oidcprovider.ErrDependency)
				assert.Equal(t, http.StatusInternalServerError, a.status)
				assert.Empty(t, a.body)
			},
		},
		{
			name: "a consumer's own path serves the list and the revocation under it",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCProviderPath(httpsec.OIDCConsents, "/me/apps"),
			}},
			send: func(t *testing.T, w *opFlow, _ *consentsWorld) flowAnswer {
				t.Helper()

				bearer := signedIn(t, w)

				listed := w.consentsGET(t, "/me/apps", bearer)
				require.Equal(t, http.StatusOK, listed.status, listed.body)
				require.Len(t, consentsListed(t, listed), 3)

				moved := w.consentsGET(t, consentsPath, bearer)
				require.True(t, moved.passedOn, "the default path is the application's now")

				return w.consentsDELETE(t, "/me/apps/"+flowWeb, bearer)
			},
			assert: func(t *testing.T, w *opFlow, world *consentsWorld, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, a.status, a.body)

				revoked, _ := consentsRevoked(t, w, world.webGrant)
				assert.True(t, revoked)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, tc.setup)
			world := consentsSeed(t, w)

			tc.assert(t, w, world, tc.send(t, w, world))
		})
	}
}
