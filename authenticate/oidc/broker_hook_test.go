package oidc_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// The library broker asks for upstream access.
var _ oidc.UpstreamBroker = (*oidc.Broker)(nil)

// noopHook decides nothing; the wiring rows never call it.
func noopHook(context.Context, oidc.ExternalIdentity, oidc.Upstream, identity.UserID) (oidc.SignInDecision, error) {
	return oidc.SignInDecision{}, nil
}

func TestNewBroker_SignInHookWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		links  func() oidc.LinkStore // nil means a memory store
		opts   func(ctrl *gomock.Controller) []oidc.BrokerOption
		assert func(t *testing.T, b *oidc.Broker, err error)
	}

	refused := func(mentions ...string) func(t *testing.T, b *oidc.Broker, err error) {
		return func(t *testing.T, b *oidc.Broker, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidc.ErrConfig)
			assert.Nil(t, b)
			for _, m := range mentions {
				assert.Contains(t, err.Error(), m)
			}
		}
	}
	built := func(t *testing.T, b *oidc.Broker, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, b)
	}
	hook := oidc.WithBrokerSignInHook("corp", noopHook)

	enc := fastBcryptEncoder(t)
	// unapplied are the per-provider options the hooked login never applies
	// (D6, F14), each for provider p; JIT sub-options need JIT on p to be
	// accepted at all, and a password claim needs an encoder.
	unapplied := []struct {
		option string
		on     func(p string) oidc.BrokerOption
	}{
		{"WithBrokerNameClaim", func(p string) oidc.BrokerOption { return oidc.WithBrokerNameClaim(p, "name") }},
		{"WithBrokerPasswordClaim", func(p string) oidc.BrokerOption { return oidc.WithBrokerPasswordClaim(p, "pwd_hash") }},
		{"WithBrokerRoleClaim", func(p string) oidc.BrokerOption { return oidc.WithBrokerRoleClaim(p, "realm_access.roles") }},
		{"WithBrokerRoleMapping", func(p string) oidc.BrokerOption {
			return oidc.WithBrokerRoleMapping(p, map[string]string{"corp-admin": "admin"})
		}},
		{"WithBrokerAllowedRoles", func(p string) oidc.BrokerOption { return oidc.WithBrokerAllowedRoles(p, "viewer") }},
		// checkProvisioning refuses these two JIT sub-options first, so the
		// unappliedOption branches for them are defence in depth.
		{"WithBrokerJITAllowUnverifiedEmail", oidc.WithBrokerJITAllowUnverifiedEmail},
		{"WithBrokerJITEmailDomains", func(p string) oidc.BrokerOption {
			return oidc.WithBrokerJITEmailDomains(p, "corp.example")
		}},
	}

	cases := []testCase{
		{
			name: "a nil hook is refused",
			opts: func(*gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerSignInHook("corp", nil)}
			},
			assert: refused("WithBrokerSignInHook", "corp"),
		},
		{
			name: "an empty provider is refused",
			opts: func(*gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerSignInHook("", noopHook)}
			},
			assert: refused("WithBrokerSignInHook"),
		},
		{
			name: "a second hook for one provider is refused",
			opts: func(*gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{hook, oidc.WithBrokerSignInHook("corp", noopHook)}
			},
			assert: refused("WithBrokerSignInHook", "corp"),
		},
		{
			name: "allow-many with an empty provider is refused",
			opts: func(*gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{hook, oidc.WithBrokerSignInHookAllowManyLinks("")}
			},
			assert: refused("WithBrokerSignInHookAllowManyLinks"),
		},
		{
			name: "allow-many for a provider with no hook is refused",
			opts: func(*gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{hook, oidc.WithBrokerSignInHookAllowManyLinks("partner")}
			},
			assert: refused("WithBrokerSignInHookAllowManyLinks", "partner"),
		},
		{
			name: "a hook and JIT provisioning on one provider are refused",
			opts: func(ctrl *gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{hook,
					oidc.WithBrokerProvisioner(NewMockUserProvisioner(ctrl)), oidc.WithBrokerJIT("corp")}
			},
			assert: refused("WithBrokerSignInHook", "WithBrokerJIT", `"corp"`),
		},
		{
			name: "a hook and claim mirroring on one provider are refused",
			opts: func(ctrl *gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{hook,
					oidc.WithBrokerProvisioner(NewMockUserProvisioner(ctrl)),
					oidc.WithBrokerNameClaim("corp", "name"), oidc.WithBrokerClaimMirror("corp", true)}
			},
			assert: refused("WithBrokerSignInHook", "WithBrokerClaimMirror", `"corp"`),
		},
		{
			name: "a hook and role sync on one provider are refused",
			opts: func(*gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{hook,
					oidc.WithBrokerRoleClaim("corp", "realm_access.roles"), oidc.WithBrokerRoleSync("corp", true)}
			},
			assert: refused("WithBrokerSignInHook", "WithBrokerRoleSync", `"corp"`),
		},
		{
			name: "mirroring and role sync turned off beside a hook are built",
			opts: func(*gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{hook,
					oidc.WithBrokerClaimMirror("corp", false), oidc.WithBrokerRoleSync("corp", false)}
			},
			assert: built,
		},
		{
			name: "a hook on corp and JIT on partner are built",
			opts: func(ctrl *gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{hook,
					oidc.WithBrokerProvisioner(NewMockUserProvisioner(ctrl)), oidc.WithBrokerJIT("partner")}
			},
			assert: built,
		},
		{
			name: "a hooked provider is a configured provider",
			opts: func(*gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{hook, oidc.WithBrokerSignInHookAllowManyLinks("corp")}
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"corp"}, b.ConfiguredProviders())
			},
		},
	}

	for _, u := range unapplied {
		cases = append(cases, testCase{
			name: "a hook and " + u.option + " on one provider are refused",
			opts: func(*gomock.Controller) []oidc.BrokerOption {
				return []oidc.BrokerOption{hook, oidc.WithBrokerPasswordEncoder(enc), u.on("corp")}
			},
			assert: refused(u.option, `"corp"`),
		})
	}
	cases = append(cases, testCase{
		name: "a hook on corp and every option it refuses, on unhooked partner, are built",
		opts: func(ctrl *gomock.Controller) []oidc.BrokerOption {
			opts := []oidc.BrokerOption{hook, oidc.WithBrokerPasswordEncoder(enc),
				oidc.WithBrokerProvisioner(NewMockUserProvisioner(ctrl)), oidc.WithBrokerJIT("partner")}
			for _, u := range unapplied {
				opts = append(opts, u.on("partner"))
			}
			return opts
		},
		assert: built,
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			var links oidc.LinkStore = oidc.NewMemoryLinkStore()
			if tc.links != nil {
				links = tc.links()
			}
			b, err := oidc.NewBroker(links, NewMockUserLoader(ctrl), tc.opts(ctrl)...)
			tc.assert(t, b, err)
		})
	}
}

func TestNewRelyingParty_SignInHookForUnregisteredProvider(t *testing.T) {
	t.Parallel()

	registry, err := oidc.NewRegistry(oidc.Provider{ //nolint:gosec // G101: a placeholder secret in a test, not a credential
		Name:         "corp",
		Issuer:       "https://idp.example.com",
		ClientID:     "scrty",
		ClientSecret: "corp-client-secret",
		RedirectURL:  "https://app.example.com/sso/callback/corp",
	})
	require.NoError(t, err)
	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(gomock.NewController(t)),
		oidc.WithBrokerSignInHook("ghost", noopHook))
	require.NoError(t, err)

	_, err = oidc.NewRelyingParty(registry, broker)
	require.ErrorIs(t, err, oidc.ErrConfig)
	assert.Contains(t, err.Error(), `"ghost"`)
}

// hookCall is one call a recording hook saw.
type hookCall struct {
	ext    oidc.ExternalIdentity
	up     oidc.Upstream
	linked identity.UserID
}

// recordingHook returns a hook that records every call into calls, under mu,
// and answers with decide.
func recordingHook(mu *sync.Mutex, calls *[]hookCall, decide func() (oidc.SignInDecision, error)) oidc.SignInHook {
	return func(_ context.Context, ext oidc.ExternalIdentity, up oidc.Upstream, linked identity.UserID) (oidc.SignInDecision, error) {
		mu.Lock()
		*calls = append(*calls, hookCall{ext: ext, up: up, linked: linked})
		mu.Unlock()
		return decide()
	}
}

func TestBroker_HookDispatch(t *testing.T) {
	t.Parallel()

	const token = "at-secret"
	up := oidc.NewUpstreamForTest(token, "s-1", nil, nil)
	partner := oidc.ExternalIdentity{
		Provider: "partner", Issuer: "https://partner.example", Subject: "p-1",
		Email: "bob@partner.example", EmailVerified: true,
	}
	partnerUnlinked := partner
	partnerUnlinked.Subject = "p-404"
	corpUnlinked := brokerCorpIdentity()
	corpUnlinked.Subject = "s-404"

	type env struct {
		broker *oidc.Broker
		calls  func() []hookCall
	}
	type testCase struct {
		name   string
		links  func(t *testing.T, ctrl *gomock.Controller) oidc.LinkStore // nil means the seeded memory store
		call   func(ctx context.Context, b *oidc.Broker) (*identity.Principal, error)
		assert func(t *testing.T, e env, p *identity.Principal, err error)
	}

	cases := []testCase{
		{
			name: "an unhooked linked identity resolves through BrokerUpstream as through Broker",
			call: func(ctx context.Context, b *oidc.Broker) (*identity.Principal, error) {
				return b.BrokerUpstream(ctx, partner, up)
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.NoError(t, err)
				want, err := e.broker.Broker(t.Context(), partner)
				require.NoError(t, err)
				assert.Equal(t, want, p)
				assert.Equal(t, identity.UserID("u-2"), p.ID)
				assert.Empty(t, e.calls(), "corp's hook is not called for partner")
			},
		},
		{
			name: "an unhooked unlinked identity is refused through BrokerUpstream as through Broker",
			call: func(ctx context.Context, b *oidc.Broker) (*identity.Principal, error) {
				return b.BrokerUpstream(ctx, partnerUnlinked, up)
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				_, err = e.broker.Broker(t.Context(), partnerUnlinked)
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Empty(t, e.calls())
			},
		},
		{
			name: "a hooked provider through Broker is ErrUpstreamRequired and the hook is not called",
			links: func(_ *testing.T, ctrl *gomock.Controller) oidc.LinkStore {
				// No expectation: the store is not consulted either.
				return NewMockLinkStore(ctrl)
			},
			call: func(ctx context.Context, b *oidc.Broker) (*identity.Principal, error) {
				return b.Broker(ctx, brokerCorpIdentity())
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrUpstreamRequired)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, p)
				assert.Empty(t, e.calls())
			},
		},
		{
			name: "a hooked linked identity reaches the hook with its linked user and the upstream access",
			call: func(ctx context.Context, b *oidc.Broker) (*identity.Principal, error) {
				return b.BrokerUpstream(ctx, brokerCorpIdentity(), up)
			},
			assert: func(t *testing.T, e env, _ *identity.Principal, _ error) {
				calls := e.calls()
				require.Len(t, calls, 1)
				assert.Equal(t, brokerCorpIdentity(), calls[0].ext)
				assert.Equal(t, identity.UserID("u-1"), calls[0].linked)
				assert.Equal(t, token, calls[0].up.AccessToken())
			},
		},
		{
			name: "a hooked unlinked identity reaches the hook with no linked user",
			call: func(ctx context.Context, b *oidc.Broker) (*identity.Principal, error) {
				return b.BrokerUpstream(ctx, corpUnlinked, up)
			},
			assert: func(t *testing.T, e env, _ *identity.Principal, _ error) {
				calls := e.calls()
				require.Len(t, calls, 1)
				assert.Empty(t, calls[0].linked)
			},
		},
		{
			name: "a link store fault before the hook is a redacted broker failure, never no link, and the hook is not called",
			links: func(_ *testing.T, ctrl *gomock.Controller) oidc.LinkStore {
				s := NewMockLinkStore(ctrl)
				s.EXPECT().FindByExternal(gomock.Any(), "corp", brokerCorpIssuer, "s-1").
					Return(nil, errors.New("db down s-1 alice@corp.example"))
				return s
			},
			call: func(ctx context.Context, b *oidc.Broker) (*identity.Principal, error) {
				return b.BrokerUpstream(ctx, brokerCorpIdentity(), up)
			},
			assert: func(t *testing.T, e env, p *identity.Principal, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, p)
				assert.NotContains(t, err.Error(), "s-1")
				assert.NotContains(t, err.Error(), "alice@")
				assert.Empty(t, e.calls())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			var links oidc.LinkStore
			if tc.links != nil {
				links = tc.links(t, ctrl)
			} else {
				m := brokerSeededLinks(t)
				require.NoError(t, m.Insert(t.Context(), oidc.Link{
					Provider: "partner", Issuer: partner.Issuer, Subject: "p-1", UserID: "u-2", Username: "bob",
				}))
				links = m
			}
			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, u identity.UserID) (*identity.Details, error) {
					return &identity.Details{ID: u, Username: "user-" + string(u), Active: true}, nil
				}).AnyTimes()

			var (
				mu    sync.Mutex
				calls []hookCall
			)
			hook := recordingHook(&mu, &calls, func() (oidc.SignInDecision, error) {
				return oidc.SignInDecision{User: "u-1"}, nil
			})
			b, err := oidc.NewBroker(links, users, oidc.WithBrokerSignInHook("corp", hook))
			require.NoError(t, err)

			p, err := tc.call(t.Context(), b)
			tc.assert(t, env{broker: b, calls: func() []hookCall {
				mu.Lock()
				defer mu.Unlock()
				return slices.Clone(calls)
			}}, p, err)
		})
	}
}

// consumerHookError is a consumer's own error type, which a hook failure keeps
// reachable through errors.As.
type consumerHookError struct{ code int }

func (e *consumerHookError) Error() string { return fmt.Sprintf("consumer failure %d", e.code) }

// cyclicHookError unwraps to itself, so a stdlib walk of it never ends.
// valueHookError is a consumer error held by value, so a reflective print of
// a wrapper holding it shows its fields rather than an address.
type valueHookError struct{ msg string }

func (e valueHookError) Error() string { return e.msg }

type cyclicHookError struct{}

func (e *cyclicHookError) Error() string { return "cyclic" }
func (e *cyclicHookError) Unwrap() error { return e }

func TestBroker_HookDecisionErrors(t *testing.T) {
	t.Parallel()

	const token = "at-secret"
	ext := brokerCorpIdentity() // subject s-1, email alice@corp.example
	var hookRan atomic.Bool     // set by the one row that asserts the hook is skipped

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		link   *oidc.Link // what FindByExternal finds; nil means no link
		decide func(ctx context.Context) (oidc.SignInDecision, error)
		assert func(t *testing.T, p *identity.Principal, err error, logs string)
	}

	brokerFailure := func(t *testing.T, p *identity.Principal, err error) {
		t.Helper()
		require.Error(t, err)
		assert.Nil(t, p)
		assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		assert.NotErrorIs(t, err, oidc.ErrNoLinkedAccount)
		assert.NotErrorIs(t, err, oidc.ErrProvisioningRefused)
	}
	noSecrets := func(t *testing.T, text string) {
		t.Helper()
		for _, s := range []string{"alice@corp.example", "alice@", "s-1", token} {
			assert.NotContains(t, text, s)
		}
	}

	cases := []testCase{
		{
			name: "ErrNoLinkedAccount passes through as the authentication failure, scrubbed",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{User: "u-7"}, fmt.Errorf("alice@corp.example s-1 %s inactive: %w", token, oidc.ErrNoLinkedAccount)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, logs string) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, p)
				noSecrets(t, err.Error())
				noSecrets(t, logs)
			},
		},
		{
			name: "ErrProvisioningRefused passes through as the authentication failure",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{}, fmt.Errorf("refused: %w", oidc.ErrProvisioningRefused)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.ErrorIs(t, err, oidc.ErrProvisioningRefused)
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, p)
			},
		},
		{
			name: "a wrapped library outcome is a broker failure, not that outcome",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{}, fmt.Errorf("wrap: %w", errors.Join(oidc.ErrExchangeFailed, oidc.ErrFlowUnspent))
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				brokerFailure(t, p, err)
				assert.NotErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent)
			},
		},
		{
			name: "ErrUserInfoFailed passes through as the bare sentinel, with none of the hook's text",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{}, fmt.Errorf("lookup for %s %s: %w", ext.Email, token, oidc.ErrUserInfoFailed)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, logs string) {
				require.ErrorIs(t, err, oidc.ErrUserInfoFailed)
				assert.Equal(t, oidc.ErrUserInfoFailed.Error(), err.Error())
				assert.Nil(t, p)
				noSecrets(t, err.Error())
				noSecrets(t, logs)
				assert.NotContains(t, logs, "refused", "a provider failure writes no refusal record")
			},
		},
		{
			name: "an error naming the subject, email and token is scrubbed in the error and the logs",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{}, errors.New("db down alice@corp.example s-1 " + token)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, logs string) {
				brokerFailure(t, p, err)
				assert.NotContains(t, err.Error(), "db down", "the consumer's text never reaches the error")
				noSecrets(t, err.Error())
				noSecrets(t, logs)
			},
		},
		{
			name: "the consumer's own error type stays reachable through errors.As",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{}, fmt.Errorf("lookup: %w", &consumerHookError{code: 7})
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				brokerFailure(t, p, err)
				var ce *consumerHookError
				require.ErrorAs(t, err, &ce)
				assert.Equal(t, 7, ce.code)
			},
		},
		{
			name: "an interface target does not hand back the consumer's chain",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{}, fmt.Errorf("wrap: %w", oidc.ErrExchangeFailed)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				brokerFailure(t, p, err)
				var inner interface {
					error
					Unwrap() error
				}
				assert.False(t, errors.As(err, &inner))
			},
		},
		{
			name: "a library error type in the consumer's chain is not reachable through errors.As",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{}, fmt.Errorf("wrap: %w", &httpsec.ChallengeError{})
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				brokerFailure(t, p, err)
				var ce *httpsec.ChallengeError
				assert.False(t, errors.As(err, &ce))
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(err))
			},
		},
		{
			name: "every fmt verb prints the fixed text, not the consumer's",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{}, valueHookError{msg: "db down alice@corp.example " + token}
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				brokerFailure(t, p, err)
				for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
					text := fmt.Sprintf(verb, err)
					assert.NotContains(t, text, token, verb)
					assert.NotContains(t, text, "alice@corp.example", verb)
					assert.NotContains(t, text, "db down", verb)
				}
			},
		},
		{
			name: "a link with an empty user reference is a broker failure and the hook does not run",
			link: &oidc.Link{UserID: ""},
			decide: func(context.Context) (oidc.SignInDecision, error) {
				hookRan.Store(true)
				return oidc.SignInDecision{User: "u-7"}, nil
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				brokerFailure(t, p, err)
				assert.False(t, hookRan.Load(), "an empty linked user would read as no link")
			},
		},
		{
			name: "an empty decision with no error is a broker failure",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{}, nil
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				brokerFailure(t, p, err)
			},
		},
		{
			name: "an empty decision with an apply step is a broker failure and the step does not run",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{Apply: func(context.Context) error {
					panic("apply must not run")
				}}, nil
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				brokerFailure(t, p, err)
			},
		},
		{
			name: "an error whose chain cannot be walked is a broker failure, never a refusal",
			decide: func(context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{}, &cyclicHookError{}
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				brokerFailure(t, p, err)
			},
		},
		{
			name: "a cancelled context is the context's error",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			decide: func(ctx context.Context) (oidc.SignInDecision, error) {
				return oidc.SignInDecision{}, fmt.Errorf("lookup alice@corp.example: %w", ctx.Err())
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				brokerFailure(t, p, err)
				require.ErrorIs(t, err, context.Canceled)
				noSecrets(t, err.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			ctrl := gomock.NewController(t)
			links := NewMockLinkStore(ctrl)
			if tc.link != nil {
				links.EXPECT().FindByExternal(gomock.Any(), "corp", brokerCorpIssuer, "s-1").Return(tc.link, nil)
			} else {
				links.EXPECT().FindByExternal(gomock.Any(), "corp", brokerCorpIssuer, "s-1").Return(nil, oidc.ErrLinkNotFound)
			}
			links.EXPECT().Insert(gomock.Any(), gomock.Any()).Times(0)
			links.EXPECT().DeleteByUser(gomock.Any(), gomock.Any()).Times(0)
			links.EXPECT().ListByUser(gomock.Any(), gomock.Any()).Times(0)
			links.EXPECT().DeleteLink(gomock.Any(), gomock.Any()).Times(0)
			users := NewMockUserLoader(ctrl) // no call expected: nothing is loaded

			var logs bytes.Buffer
			hook := func(ctx context.Context, _ oidc.ExternalIdentity, _ oidc.Upstream, _ identity.UserID) (oidc.SignInDecision, error) {
				return tc.decide(ctx)
			}
			b, err := oidc.NewBroker(links, users,
				oidc.WithBrokerLogger(testTextLogger(&logs)), oidc.WithBrokerSignInHook("corp", hook))
			require.NoError(t, err)

			p, err := b.BrokerUpstream(ctx, ext, oidc.NewUpstreamForTest(token, "s-1", nil, nil))
			tc.assert(t, p, err, logs.String())
		})
	}
}
