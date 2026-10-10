package httpsecconformance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
)

// holdCap is the consecutive-failure cap every hold scenario configures.
const holdCap = 20

// holdNewPassword is what the held user changes their password to.
const holdNewPassword = "a-new-s3cret" //nolint:gosec // a fixture credential, not a real one

// holdScenarios is every consecutive-failure hold behaviour that must be
// identical on every adapter, run over the recovery path's durable backend.
func holdScenarios() []Scenario {
	return []Scenario{
		heldAccountRecoversAndSignsInWithItsNewPassword(),
		heldAccountPasswordProofIsRefused(),
	}
}

// heldLockout is a lockout policy with a cap of holdCap, over the in-memory
// store, with Username already held: holdCap failures recorded through the
// policy's view, as the chain's logins record them.
func heldLockout(t *testing.T) *policy.AccountLockoutPolicy {
	t.Helper()

	lockout, err := policy.NewAccountLockoutPolicy(
		policy.WithAttemptStore(policy.NewMemoryAttemptStore()), policy.WithLockoutCap(holdCap))
	require.NoError(t, err)

	first := time.Now().Add(-time.Hour)
	for i := range holdCap {
		require.NoError(t, lockout.Attempts().RecordFailure(t.Context(), Username,
			first.Add(time.Duration(i)*time.Second)))
	}

	return lockout
}

// changingAccount is Username's account with a password the resolve endpoint
// can change, so a scenario signs in with the new password rather than the
// one it was held under. It counts every check into calls.
type changingAccount struct {
	calls *atomic.Int64

	mu       sync.Mutex
	password string
}

func (a *changingAccount) Authenticate(
	_ context.Context, c identity.Credentials,
) (*authenticate.Authentication, error) {
	a.calls.Add(1)

	a.mu.Lock()
	current := a.password
	a.mu.Unlock()

	up, ok := c.(*identity.UsernamePassword)
	if !ok || up.Username != Username || string(up.Password) != current {
		return nil, authenticate.ErrAuthenticationFailed
	}

	return &authenticate.Authentication{
		Principal:         TestPrincipal(),
		Time:              time.Now(),
		PasswordChangedAt: time.Now().Add(-time.Hour),
	}, nil
}

// changePassword is the resolve endpoint's password change: it sets the
// posted password as the account's.
func (a *changingAccount) changePassword(ex *httpsec.Exchange) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.password = ex.Request.FormValue("password")

	return nil
}

// heldAccountRecoversAndSignsInWithItsNewPassword pins spec http-security-chain
// "Recover, change, sign in": a held account completes a recovery with a saved
// code and an issued code, resolves a password change on the recovery session,
// and the change lifts the hold, so a form login with the new password is let
// in.
func heldAccountRecoversAndSignsInWithItsNewPassword() Scenario {
	return Scenario{
		Name: "a held account recovers, changes its password and signs in with the new one",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			lockout := heldLockout(t)
			engine, err := policy.NewEngine(lockout)
			require.NoError(t, err)

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofIssued)

			standalone, err := recovery.NewRecoverer(deps, coreOpts...)
			require.NoError(t, err)

			saved, err := fx.Codes.Generate(ctx, UserID)
			require.NoError(t, err)

			standalone.Start(ctx, Username)

			effects := &Effects{Sessions: sessions, Recovery: fx, Attempts: lockout.Attempts()}
			effects.recoverySavedCode = saved[0]
			effects.recoveryIssuedCode = fx.lastMessage(t)

			account := &changingAccount{calls: &effects.authCalls, password: Password}

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.WithPolicyEngine(engine),
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: fixtureTokens{}, Sessions: sessions, Users: fixtureUsers{},
					}),
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: account,
						Sessions:      sessions,
						Tokens:        fixtureTokens{},
						Attempts:      lockout.Attempts(),
					}),
					httpsec.EnableAccountRecovery(httpsec.RecoveryDeps(deps),
						httpsec.WithRecoveryCore(coreOpts...),
						httpsec.WithRecoveryTokens(fixtureTokens{}),
					),
					httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithChangePasswordEndpoint(recoveryResolvePath, account.changePassword)),
				},
				Effects: effects,
			}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			// The account is held before the recovery, so the last login is let
			// in because the password change lifted the hold and nothing else.
			held := send(formBody("username=" + Username + "&password=" + Password))
			require.ErrorIs(t, held.Refusal, policy.ErrAccountHeld, "the account starts held")
			require.Zero(t, spec.Effects.AuthenticatorCalls(), "a held account's password is not checked")

			complete := send(RequestSpec{
				Method: http.MethodPost,
				Path:   httpsec.DefaultRecoveryCompletePath,
				Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body: url.Values{
					httpsec.RecoveryUsernameParam:   {Username},
					httpsec.RecoverySavedCodeParam:  {spec.Effects.recoverySavedCode},
					httpsec.RecoveryIssuedCodeParam: {spec.Effects.recoveryIssuedCode},
				}.Encode(),
				ClientAddress: ClientAddress,
			})
			require.NoError(t, complete.Refusal, "a held account still recovers with codes")
			require.Equal(t, http.StatusOK, complete.Status)

			var doc struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.Unmarshal([]byte(complete.Body), &doc), "body: %q", complete.Body)
			require.NotEmpty(t, doc.AccessToken)

			resolve := send(RequestSpec{
				Method: http.MethodPost,
				Path:   recoveryResolvePath,
				Header: map[string]string{
					"Authorization": "Bearer " + doc.AccessToken,
					"Content-Type":  "application/x-www-form-urlencoded",
				},
				Body:          url.Values{"password": {holdNewPassword}}.Encode(),
				ClientAddress: ClientAddress,
			})
			require.NoError(t, resolve.Refusal, "the recovery session resolves a password change")

			res := send(formBody("username=" + Username + "&password=" + holdNewPassword))
			require.NoError(t, res.Refusal, "the password change did not lift the hold")
			assert.Equal(t, http.StatusOK, res.Status)
		},
	}
}

// heldAccountPasswordProofIsRefused pins spec http-security-chain "Password
// proof refused while held": a recovery offering a saved code and the
// password is refused as locked, concealed as any refused recovery is, and the
// password is never checked.
func heldAccountPasswordProofIsRefused() Scenario {
	return Scenario{
		Name: "a held account's recovery with the password is refused as locked, unchecked",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)

			lockout := heldLockout(t)
			engine, err := policy.NewEngine(lockout)
			require.NoError(t, err)

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: fx.Records, Sender: fx.Outbox, Codes: fx.Codes,
			}
			coreOpts := recoveryCoreOptions(fx, recovery.ProofSaved, recovery.ProofPassword)

			saved, err := fx.Codes.Generate(t.Context(), UserID)
			require.NoError(t, err)

			effects := &Effects{Sessions: sessions, Recovery: fx, Attempts: lockout.Attempts()}
			effects.recoverySavedCode = saved[0]

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.WithPolicyEngine(engine),
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: &fixtureAuthenticator{calls: &effects.authCalls},
						Sessions:      sessions,
						Tokens:        fixtureTokens{},
						Attempts:      lockout.Attempts(),
					}),
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
					httpsec.RecoveryUsernameParam:  {Username},
					httpsec.RecoverySavedCodeParam: {spec.Effects.recoverySavedCode},
					httpsec.RecoveryPasswordParam:  {Password},
				}.Encode(),
				ClientAddress: ClientAddress,
			}
		},
		Assert: func(t *testing.T, res Result) {
			require.ErrorIs(t, res.Refusal, policy.ErrAccountLocked)
			require.ErrorIs(t, res.Refusal, policy.ErrAccountHeld)
			require.ErrorIs(t, res.Refusal, recovery.ErrRefused, "concealed as any refused recovery is")
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.Zero(t, res.Effects.AuthenticatorCalls(), "the password was not checked")
		},
	}
}
