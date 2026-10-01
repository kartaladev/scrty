package httpsec_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// The management endpoints' paths under the default prefix.
const (
	passkeyRenamePath = httpsec.DefaultPasskeyCredentialsPrefix + "/rename"
	passkeyRemovePath = httpsec.DefaultPasskeyCredentialsPrefix + "/remove"
)

// otherPasskeyUser holds passkeys the session's user must not reach.
const otherPasskeyUser identity.UserID = "u-other"

// passkeyListDocument is the listing's default answer, read back the way a
// client would.
type passkeyListDocument struct {
	Passkeys []struct {
		ID             string     `json:"id"`
		Name           string     `json:"name"`
		State          string     `json:"state"`
		CreatedAt      time.Time  `json:"created_at"`
		LastUsedAt     *time.Time `json:"last_used_at"`
		BackupEligible bool       `json:"backup_eligible"`
		BackupState    bool       `json:"backup_state"`
		Transports     []string   `json:"transports"`
		AAGUID         *string    `json:"aaguid"`
	} `json:"passkeys"`
}

// seedPasskey stores a passkey for user directly, as a finished registration
// would have, in state.
func seedPasskey(t *testing.T, h *passkeyHarness, user identity.UserID, credID string, state passkey.State) *passkey.Credential {
	t.Helper()

	cid, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	c := &passkey.Credential{
		ID:             cid,
		User:           user,
		CredentialID:   []byte(credID),
		PublicKey:      []byte("cose-public-key-" + credID),
		BackupEligible: true,
		BackupState:    true,
		Transports:     []string{"internal", "hybrid"},
		AAGUID:         []byte{0xad, 0xce, 0x00, 0x02, 0x35, 0xbc, 0xc6, 0x0a, 0x64, 0x8b, 0x0b, 0x25, 0xf1, 0xf0, 0x55, 0x03},
		Name:           "Laptop " + credID,
		CreatedAt:      time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
		State:          state,
	}
	require.NoError(t, h.creds.Insert(t.Context(), c))

	return c
}

// managePost is a form POST of values to path.
func managePost(t *testing.T, path string, values url.Values) *http.Request {
	t.Helper()

	return post(t.Context(), path, values.Encode())
}

// stillHeld reports whether user still holds the passkey cid.
func stillHeld(t *testing.T, h *passkeyHarness, user identity.UserID, cid id.ID) bool {
	t.Helper()

	_, err := h.creds.Find(t.Context(), user, cid)
	if err == nil {
		return true
	}

	require.ErrorIs(t, err, passkey.ErrNotFound)

	return false
}

// TestPasskeyManage drives the listing, rename and removal endpoints through a
// chain, with a session carried as bearer authentication would carry it.
func TestPasskeyManage(t *testing.T) {
	t.Parallel()

	type fixture struct {
		own, suspended, others *passkey.Credential
	}

	type testCase struct {
		name string

		// pending marks the carried session as owing a password change, and
		// anonymous carries no session.
		pending   bool
		anonymous bool

		// mfa is the second-factor state the carried session is in; the
		// zero value is no second factor asked for.
		mfa session.MFAState

		setup  func(t *testing.T, h *passkeyHarness)
		act    func(t *testing.T, f fixture, chain *httpsec.Chain) served
		assert func(t *testing.T, h *passkeyHarness, f fixture, out served)
	}

	cases := []testCase{
		{
			name: "list answers every state and no public key",
			act: func(t *testing.T, _ fixture, chain *httpsec.Chain) served {
				return serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet, passkeyListPath, nil))
			},
			assert: func(t *testing.T, _ *passkeyHarness, f fixture, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan, "the endpoint answers the request itself")
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
				assert.Contains(t, out.rec.Header().Get("Content-Type"), "application/json")

				body := out.rec.Body.String()
				assert.NotContains(t, body, "cose-public-key", "no public key is listed")
				assert.NotContains(t, body, "public_key")

				var doc passkeyListDocument
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				require.Len(t, doc.Passkeys, 2, "another user's passkey is not listed")

				states := map[string]string{}
				for _, p := range doc.Passkeys {
					states[p.ID] = p.State
				}
				assert.Equal(t, map[string]string{
					f.own.ID.String():       "active",
					f.suspended.ID.String(): "suspended",
				}, states)

				first := doc.Passkeys[0]
				if first.ID != f.own.ID.String() {
					first = doc.Passkeys[1]
				}
				assert.Equal(t, f.own.Name, first.Name)
				assert.True(t, f.own.CreatedAt.Equal(first.CreatedAt))
				assert.Nil(t, first.LastUsedAt, "a passkey never used has no last use")
				assert.True(t, first.BackupEligible)
				assert.True(t, first.BackupState)
				assert.Equal(t, []string{"internal", "hybrid"}, first.Transports)
				require.NotNil(t, first.AAGUID)
				assert.Equal(t, "adce0002-35bc-c60a-648b-0b25f1f05503", *first.AAGUID)
			},
		},
		{
			name: "rename names the passkey and answers 204",
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				return serve(t, chain, managePost(t, passkeyRenamePath,
					url.Values{"id": {f.own.ID.String()}, "name": {"Old phone"}}))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)

				stored, err := h.creds.Find(t.Context(), testMFAUser, f.own.ID)
				require.NoError(t, err)
				assert.Equal(t, "Old phone", stored.Name)
			},
		},
		{
			name: "rename without a name gives the default date name",
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				return serve(t, chain, managePost(t, passkeyRenamePath, url.Values{"id": {f.own.ID.String()}}))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)

				stored, err := h.creds.Find(t.Context(), testMFAUser, f.own.ID)
				require.NoError(t, err)
				assert.Equal(t, passkey.NormaliseName("", f.own.CreatedAt), stored.Name)
			},
		},
		{
			name: "rename of another user's passkey is not found",
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				return serve(t, chain, managePost(t, passkeyRenamePath,
					url.Values{"id": {f.others.ID.String()}, "name": {"Mine now"}}))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				require.ErrorIs(t, out.err, passkey.ErrNotFound)
				assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(out.err))

				stored, err := h.creds.Find(t.Context(), otherPasskeyUser, f.others.ID)
				require.NoError(t, err)
				assert.Equal(t, f.others.Name, stored.Name, "another user's passkey is unchanged")
			},
		},
		{
			name: "remove removes the passkey, notifies and answers 204",
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				return serve(t, chain, managePost(t, passkeyRemovePath, url.Values{"id": {f.suspended.ID.String()}}))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.False(t, stillHeld(t, h, testMFAUser, f.suspended.ID), "a suspended passkey is removable")
				assert.True(t, stillHeld(t, h, testMFAUser, f.own.ID))
				assert.Equal(t, 1, h.notices.count(), "the removal is notified")
			},
		},
		{
			name: "remove of another user's passkey is not found",
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				return serve(t, chain, managePost(t, passkeyRemovePath, url.Values{"id": {f.others.ID.String()}}))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				require.ErrorIs(t, out.err, passkey.ErrNotFound)
				assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(out.err))
				assert.True(t, stillHeld(t, h, otherPasskeyUser, f.others.ID), "another user's passkey still exists")
			},
		},
		{
			name: "stale remove needs reauthentication",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.pkOpts = append(h.pkOpts, passkey.WithClock(clockwork.NewFakeClockAt(time.Now().Add(20*time.Minute))))
			},
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				return serve(t, chain, managePost(t, passkeyRemovePath, url.Values{"id": {f.own.ID.String()}}))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				require.ErrorIs(t, out.err, passkey.ErrReauthenticationRequired)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.True(t, stillHeld(t, h, testMFAUser, f.own.ID), "the passkey still exists")
			},
		},
		{
			name: "an identifier that does not parse is not found",
			act: func(t *testing.T, _ fixture, chain *httpsec.Chain) served {
				return serve(t, chain, managePost(t, passkeyRemovePath, url.Values{"id": {"not-an-id"}}))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				require.ErrorIs(t, out.err, passkey.ErrNotFound)
				assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(out.err))
				assert.NotContains(t, out.err.Error(), "not-an-id")
				assert.True(t, stillHeld(t, h, testMFAUser, f.own.ID))
			},
		},
		{
			name: "a request without an identifier is missing credentials",
			act: func(t *testing.T, _ fixture, chain *httpsec.Chain) served {
				return serve(t, chain, managePost(t, passkeyRenamePath, url.Values{"name": {"x"}}))
			},
			assert: func(t *testing.T, _ *passkeyHarness, _ fixture, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
			},
		},
		{
			name: "the identifier in the query is not read",
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				return serve(t, chain, post(t.Context(), passkeyRemovePath+"?id="+f.own.ID.String(), ""))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
				assert.True(t, stillHeld(t, h, testMFAUser, f.own.ID))
			},
		},
		{
			name: "other methods pass through",
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				listed := serve(t, chain, post(t.Context(), passkeyListPath, ""))
				require.NoError(t, listed.err)
				require.True(t, listed.handlerRan, "a POST to the listing path passes through")

				return serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					passkeyRemovePath+"?id="+f.own.ID.String(), nil))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan, "a GET to the remove path passes through")
				assert.True(t, stillHeld(t, h, testMFAUser, f.own.ID))
			},
		},
		{
			name:      "no session is refused",
			anonymous: true,
			act: func(t *testing.T, _ fixture, chain *httpsec.Chain) served {
				return serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet, passkeyListPath, nil))
			},
			assert: func(t *testing.T, _ *passkeyHarness, _ fixture, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.False(t, out.handlerRan)
			},
		},
		{
			name: "a session owing account recovery's binding is refused with that challenge",
			mfa:  session.MFARecoveryPending,
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				return serve(t, chain, managePost(t, passkeyRemovePath, url.Values{"id": {f.own.ID.String()}}))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengeAccountRecovery, ch.Kind)
				assert.True(t, stillHeld(t, h, testMFAUser, f.own.ID), "nothing is removed")
			},
		},
		{
			name:  "a session owing a second factor's enrolment is refused with that challenge",
			mfa:   session.MFAEnrolmentPending,
			setup: func(_ *testing.T, h *passkeyHarness) { h.withoutEnrolment = true },
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				return serve(t, chain, managePost(t, passkeyRenamePath,
					url.Values{"id": {f.own.ID.String()}, "name": {"Old phone"}}))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)

				stored, err := h.creds.Find(t.Context(), testMFAUser, f.own.ID)
				require.NoError(t, err)
				assert.Equal(t, f.own.Name, stored.Name, "nothing is renamed")
			},
		},
		{
			name:    "a session owing a challenge is refused",
			pending: true,
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				return serve(t, chain, managePost(t, passkeyRenamePath,
					url.Values{"id": {f.own.ID.String()}, "name": {"Old phone"}}))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)

				stored, err := h.creds.Find(t.Context(), testMFAUser, f.own.ID)
				require.NoError(t, err)
				assert.Equal(t, f.own.Name, stored.Name, "nothing is renamed")
			},
		},
		{
			name: "consumer prefix and responders",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.passkeyOpts = append(h.passkeyOpts,
					httpsec.WithPasskeyCredentialsPrefix("/account/passkeys"),
					httpsec.WithPasskeyListResponder(func(ex *httpsec.Exchange, list []passkey.Summary) error {
						ex.Writer.WriteHeader(http.StatusAccepted)
						_, err := ex.Writer.Write([]byte(strings.Repeat("p", len(list))))

						return err
					}),
					httpsec.WithPasskeyRenameResponder(func(ex *httpsec.Exchange, cid id.ID) error {
						ex.Writer.WriteHeader(http.StatusOK)
						_, err := ex.Writer.Write([]byte("renamed " + cid.String()))

						return err
					}),
					httpsec.WithPasskeyRemoveResponder(func(ex *httpsec.Exchange, cid id.ID) error {
						ex.Writer.WriteHeader(http.StatusOK)
						_, err := ex.Writer.Write([]byte("removed " + cid.String()))

						return err
					}))
			},
			act: func(t *testing.T, f fixture, chain *httpsec.Chain) served {
				listed := serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/account/passkeys", nil))
				require.NoError(t, listed.err)
				assert.Equal(t, http.StatusAccepted, listed.rec.Code)
				assert.Equal(t, "pp", listed.rec.Body.String())

				renamed := serve(t, chain, managePost(t, "/account/passkeys/rename",
					url.Values{"id": {f.own.ID.String()}, "name": {"Old phone"}}))
				require.NoError(t, renamed.err)
				assert.Equal(t, "renamed "+f.own.ID.String(), renamed.rec.Body.String())

				return serve(t, chain, managePost(t, "/account/passkeys/remove", url.Values{"id": {f.own.ID.String()}}))
			},
			assert: func(t *testing.T, h *passkeyHarness, f fixture, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, "removed "+f.own.ID.String(), out.rec.Body.String())
				assert.False(t, stillHeld(t, h, testMFAUser, f.own.ID))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newPasskeyHarness(t)
			if tc.setup != nil {
				tc.setup(t, h)
			}

			f := fixture{
				own:       seedPasskey(t, h, testMFAUser, "cred-own", passkey.StateActive),
				suspended: seedPasskey(t, h, testMFAUser, "cred-suspended", passkey.StateSuspended),
				others:    seedPasskey(t, h, otherPasskeyUser, "cred-others", passkey.StateActive),
			}

			var s *session.Session
			if !tc.anonymous {
				s = h.sessionIn(t, factor.Password, tc.mfa)
				if tc.pending {
					s.PasswordChangePending = true
					require.NoError(t, h.sessions.Save(t.Context(), s))
				}
			}

			chain := h.build(t, s)

			tc.assert(t, h, f, tc.act(t, f, chain))
		})
	}
}

// TestPasskeyManageResponderOptions pins that a nil responder is a wiring
// mistake, refused at construction.
func TestPasskeyManageResponderOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opt    httpsec.PasskeyOption
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrConfig)
	}

	cases := []testCase{
		{name: "nil list responder", opt: httpsec.WithPasskeyListResponder(nil), assert: refused},
		{name: "nil rename responder", opt: httpsec.WithPasskeyRenameResponder(nil), assert: refused},
		{name: "nil remove responder", opt: httpsec.WithPasskeyRemoveResponder(nil), assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newPasskeyHarness(t)
			h.passkeyOpts = append(h.passkeyOpts, tc.opt)

			_, err := httpsec.New(h.chainOptions(t, nil)...)
			tc.assert(t, err)
		})
	}
}
