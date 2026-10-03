package oidc_test

import (
	"context"
	"sync"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// handoffAssuranceEnv is one code issued for a callback result, the store it
// was written to, and every candidate the redemption's check was handed.
type handoffAssuranceEnv struct {
	mem   *oidc.MemoryHandoffStore
	m     *oidc.HandoffManager
	users *MockUserLoader
	code  string

	mu   sync.Mutex
	seen []oidc.RedeemCandidate
}

// record returns a check that keeps each candidate it is handed, then lets
// mutate change it, so a row can show what writing to it reaches.
func (e *handoffAssuranceEnv) record(mutate func(c *oidc.RedeemCandidate)) oidc.RedeemCheck {
	return func(_ context.Context, c oidc.RedeemCandidate) error {
		e.mu.Lock()
		e.seen = append(e.seen, c)
		e.mu.Unlock()
		if mutate != nil {
			mutate(&c)
		}
		return nil
	}
}

// stored returns the record the env's code was issued as.
func (e *handoffAssuranceEnv) stored(t *testing.T) oidc.HandoffRecord {
	t.Helper()

	tokenID, _ := splitHandoffCode(t, e.code)
	rec, err := e.mem.FindByTokenID(t.Context(), tokenID)
	require.NoError(t, err)
	require.NotNil(t, rec)
	return *rec
}

// assertedCallback is handoffCallback for a login whose verified ID token
// asserted amr ["pwd","mfa"] and acr urn:corp:loa:2.
func assertedCallback() oidc.CallbackResult {
	res := handoffCallback()
	res.AMR = []string{"pwd", "mfa"}
	res.ACR = "urn:corp:loa:2"
	return res
}

// TestHandoff_Assurance pins that the amr and acr a verified ID token asserted
// travel with the handoff code: written at issue, handed to every redemption
// check with the record's provider and issuer, and returned at redemption,
// each as a copy no reader can write through.
func TestHandoff_Assurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		callback func() oidc.CallbackResult
		// afterIssue runs once the code is issued, before anything is read.
		afterIssue func(res *oidc.CallbackResult)
		mutate     func(c *oidc.RedeemCandidate)
		assert     func(t *testing.T, e *handoffAssuranceEnv, res oidc.HandoffResult, err error)
	}

	cases := []testCase{
		{
			name:     "issue then find: the record carries the asserted amr and acr",
			callback: assertedCallback,
			assert: func(t *testing.T, e *handoffAssuranceEnv, _ oidc.HandoffResult, err error) {
				require.NoError(t, err)
				rec := e.stored(t)
				assert.Equal(t, []string{"pwd", "mfa"}, rec.AMR)
				assert.Equal(t, "urn:corp:loa:2", rec.ACR)
			},
		},
		{
			name:     "issue copies the caller's amr",
			callback: assertedCallback,
			afterIssue: func(res *oidc.CallbackResult) {
				for i := range res.AMR {
					res.AMR[i] = "x"
				}
			},
			assert: func(t *testing.T, e *handoffAssuranceEnv, _ oidc.HandoffResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"pwd", "mfa"}, e.stored(t).AMR,
					"the record aliased the callback result's amr")
			},
		},
		{
			name:     "the check receives the record's provider, issuer, amr and acr",
			callback: assertedCallback,
			assert: func(t *testing.T, e *handoffAssuranceEnv, _ oidc.HandoffResult, err error) {
				require.NoError(t, err)
				require.Len(t, e.seen, 1)
				c := e.seen[0]
				assert.Equal(t, *identity.PrincipalFromDetails(handoffUser()), c.Principal)
				assert.Equal(t, handoffPasswordChangedAt, c.PasswordChangedAt)
				assert.Equal(t, "corp", c.Provider)
				assert.Equal(t, "https://corp.example", c.Issuer)
				assert.Equal(t, []string{"pwd", "mfa"}, c.AMR)
				assert.Equal(t, "urn:corp:loa:2", c.ACR)
			},
		},
		{
			name:     "the result carries the record's amr and acr",
			callback: assertedCallback,
			assert: func(t *testing.T, _ *handoffAssuranceEnv, res oidc.HandoffResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"pwd", "mfa"}, res.AMR)
				assert.Equal(t, "urn:corp:loa:2", res.ACR)
			},
		},
		{
			name:     "the check's amr is a copy: writing to it changes neither the result nor the record",
			callback: assertedCallback,
			mutate: func(c *oidc.RedeemCandidate) {
				for i := range c.AMR {
					c.AMR[i] = "x"
				}
			},
			assert: func(t *testing.T, e *handoffAssuranceEnv, res oidc.HandoffResult, err error) {
				require.NoError(t, err)
				require.Len(t, e.seen, 1)
				assert.Equal(t, []string{"x", "x"}, e.seen[0].AMR, "the check was handed the record's amr to write to")
				assert.Equal(t, []string{"pwd", "mfa"}, res.AMR, "the result shares the check's amr")
				assert.Equal(t, []string{"pwd", "mfa"}, e.stored(t).AMR, "the record shares the check's amr")
			},
		},
		{
			name:     "a login that asserted nothing carries no assurance",
			callback: handoffCallback,
			assert: func(t *testing.T, e *handoffAssuranceEnv, res oidc.HandoffResult, err error) {
				require.NoError(t, err)
				require.Len(t, e.seen, 1)
				assert.Empty(t, e.seen[0].AMR)
				assert.Empty(t, e.seen[0].ACR)
				assert.Equal(t, "corp", e.seen[0].Provider, "the provider is still named")
				assert.Empty(t, res.AMR)
				assert.Empty(t, res.ACR)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			clk := clockwork.NewFakeClockAt(handoffT0)
			e := &handoffAssuranceEnv{mem: oidc.NewMemoryHandoffStore(), users: NewMockUserLoader(ctrl)}
			e.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil).AnyTimes()

			var err error
			e.m, err = oidc.NewHandoffManager(e.mem, e.users, oidc.WithHandoffClock(clk))
			require.NoError(t, err)

			res := tc.callback()
			e.code, err = e.m.Issue(t.Context(), res)
			require.NoError(t, err)
			if tc.afterIssue != nil {
				tc.afterIssue(&res)
			}

			got, err := e.m.Redeem(t.Context(), e.code, e.record(tc.mutate))
			tc.assert(t, e, got, err)
		})
	}
}
