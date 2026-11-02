package httpsecconformance

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// otherUserID is the user whose sign-in a session management scenario must
// never reach.
const otherUserID identity.UserID = "u-2"

// sessionManagementScenarios is every behaviour of the session management
// endpoints that must be identical on every adapter: what the listing shows,
// the recency an end needs, what an end revokes, a foreign handle's refusal,
// and the no-store answer on all of them.
func sessionManagementScenarios() []Scenario {
	return []Scenario{
		sessionListingMarksTheCurrentSignIn(),
		staleSessionCannotEndASignIn(),
		freshSessionEndsItsOtherSignIns(),
		foreignHandleIsNotFound(),
	}
}

// newSessionManagementSpec wires the bearer and the session management
// endpoints over a fresh manager on a controlled clock, with the caller's
// current sign-in (Effects.SessionID), another sign-in of the caller's, and
// a sign-in of otherUserID. The clock then moves on by age, so the current
// sign-in authenticated that long ago when the first request arrives.
func newSessionManagementSpec(t *testing.T, age time.Duration) ChainSpec {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now())
	store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
	// An idle timeout longer than any age a scenario uses, so a stale session
	// is still alive.
	sessions := must.Must(session.New(session.WithClock(clk), session.WithStore(store),
		session.WithIdleTimeout(24*time.Hour)))

	effects := &Effects{Sessions: sessions, Store: store, Attempts: newEffects(t).Attempts}

	for _, user := range []identity.UserID{UserID, UserID, otherUserID} {
		s, err := sessions.Create(t.Context(), user, session.WithFirstFactor(factor.Password))
		require.NoError(t, err)

		if effects.SessionID == "" {
			effects.SessionID = s.ID
		}
	}

	clk.Advance(age)

	opts := append([]httpsec.Option{httpsec.WithClock(clk)}, bearerOptions(effects)...)
	opts = append(opts, httpsec.EnableSessionManagement())

	return ChainSpec{Options: opts, Effects: effects}
}

// managedRequest is a request of the caller's current sign-in.
func managedRequest(spec ChainSpec, method, path string) RequestSpec {
	return RequestSpec{
		Method:        method,
		Path:          path,
		Header:        map[string]string{"Authorization": "Bearer " + issuedTokenFor(Username, spec.Effects.SessionID)},
		ClientAddress: ClientAddress,
	}
}

// signInsOf is user's live sign-ins, the caller's current one marked.
func signInsOf(t *testing.T, spec ChainSpec, user identity.UserID) []session.SignIn {
	t.Helper()

	current, err := spec.Effects.Sessions.Load(t.Context(), spec.Effects.SessionID)
	require.NoError(t, err)

	list, err := spec.Effects.Sessions.ListSignIns(t.Context(), user, current)
	require.NoError(t, err)

	return list
}

// otherHandle is the handle of the one live sign-in of user that is not the
// caller's current one.
func otherHandle(t *testing.T, spec ChainSpec, user identity.UserID) string {
	t.Helper()

	for _, si := range signInsOf(t, spec, user) {
		if !si.Current {
			return si.Handle.String()
		}
	}

	require.FailNow(t, "no other sign-in", "user %s", user)

	return ""
}

func requireNoStore(t *testing.T, res Result) {
	t.Helper()

	assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
	assert.False(t, res.RouteRan, "the endpoint answers itself")
}

func sessionListingMarksTheCurrentSignIn() Scenario {
	return Scenario{
		Name: "a user lists their sign-ins, the current one marked, with no session identifier",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			// Older than the recency window: listing needs no recent proof.
			return newSessionManagementSpec(t, time.Hour)
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			res := send(managedRequest(spec, http.MethodGet, httpsec.DefaultSessionManagementPrefix))
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusOK, res.Status, "body: %q", res.Body)
			requireNoStore(t, res)

			var doc struct {
				Sessions []struct {
					Handle  string `json:"handle"`
					Current bool   `json:"current"`
				} `json:"sessions"`
			}
			require.NoError(t, json.Unmarshal([]byte(res.Body), &doc))
			require.Len(t, doc.Sessions, 2)

			current := 0
			for _, si := range doc.Sessions {
				if si.Current {
					current++
				}
			}
			assert.Equal(t, 1, current, "exactly the request's own sign-in is current")
			assert.NotContains(t, res.Body, spec.Effects.SessionID, "no session identifier is listed")
		},
	}
}

func staleSessionCannotEndASignIn() Scenario {
	return Scenario{
		Name: "a stale session cannot end a sign-in, and nothing is revoked",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return newSessionManagementSpec(t, 2*time.Hour)
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			handle := otherHandle(t, spec, UserID)

			res := send(managedRequest(spec, http.MethodDelete, httpsec.DefaultSessionManagementPrefix+"/"+handle))
			require.ErrorIs(t, res.Refusal, httpsec.ErrReauthenticationRequired)
			assert.Equal(t, http.StatusForbidden, res.Status)
			requireNoStore(t, res)
			assert.Len(t, signInsOf(t, spec, UserID), 2, "nothing was revoked")
		},
	}
}

func freshSessionEndsItsOtherSignIns() Scenario {
	return Scenario{
		Name: "a fresh session ends its other sign-ins and keeps its own",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return newSessionManagementSpec(t, 2*time.Minute)
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			res := send(managedRequest(spec, http.MethodDelete, httpsec.DefaultSessionManagementPrefix))
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusNoContent, res.Status)
			requireNoStore(t, res)

			left := signInsOf(t, spec, UserID)
			require.Len(t, left, 1)
			assert.True(t, left[0].Current, "the request's own sign-in remains")
			assert.Len(t, signInsOf(t, spec, otherUserID), 1, "another user's sign-in is untouched")
		},
	}
}

func foreignHandleIsNotFound() Scenario {
	return Scenario{
		Name: "another user's sign-in handle is not found, and nothing is revoked",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return newSessionManagementSpec(t, 2*time.Minute)
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			handle := signInsOf(t, spec, otherUserID)[0].Handle.String()

			res := send(managedRequest(spec, http.MethodDelete, httpsec.DefaultSessionManagementPrefix+"/"+handle))
			require.ErrorIs(t, res.Refusal, httpsec.ErrSessionHandleNotFound)
			assert.Equal(t, http.StatusNotFound, res.Status)
			requireNoStore(t, res)
			assert.NotContains(t, res.Body, handle, "the refusal names no handle")
			assert.Len(t, signInsOf(t, spec, otherUserID), 1, "nothing was revoked")
		},
	}
}
