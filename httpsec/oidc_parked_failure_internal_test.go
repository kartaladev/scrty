package httpsec

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
)

// parkedUnwrapPanics is an error whose Unwrap panics, which aborts the bounded walk.
type parkedUnwrapPanics struct{}

func (parkedUnwrapPanics) Error() string { return "unwrap panics" }
func (parkedUnwrapPanics) Unwrap() error { panic("unwrap") }

// TestParkedFailureCode pins the allow-list that maps a failure to the code a parked
// request's login page is answered with (D4): every listed failure gets its code, and
// every unlisted one gets none, so it keeps its answer (F8, F9).
func TestParkedFailureCode(t *testing.T) {
	t.Parallel()

	errStore := errors.New("store down")
	errBroker := errors.New("broker says no, unclassified")

	hungUp := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name string
		ctx  func(ctx context.Context) context.Context
		// code reads the failure as the site that met it does.
		code   func(ctx context.Context) (string, bool)
		assert func(t *testing.T, code string, ok bool)
	}

	callback := func(err error) func(ctx context.Context) (string, bool) {
		return func(ctx context.Context) (string, bool) {
			return parkedFailureCode(readCallbackFailure(ctx, err))
		}
	}

	completion := func(stage completionStage, err error) func(ctx context.Context) (string, bool) {
		return func(ctx context.Context) (string, bool) {
			return completionFailureCode(ctx, stage, err)
		}
	}

	start := func(err error) func(ctx context.Context) (string, bool) {
		return func(ctx context.Context) (string, bool) {
			return startFailureCode(ctx, err)
		}
	}

	is := func(want string) func(t *testing.T, code string, ok bool) {
		return func(t *testing.T, code string, ok bool) {
			t.Helper()

			assert.True(t, ok)
			assert.Equal(t, want, code)
		}
	}

	none := func(t *testing.T, code string, ok bool) {
		t.Helper()

		assert.False(t, ok, "keeps its answer")
		assert.Empty(t, code)
	}

	denied := is(oidcprovider.CodeAccessDenied)
	unavailable := is(oidcprovider.CodeTemporarilyUnavailable)
	serverError := is(oidcprovider.CodeServerError)

	cases := []testCase{
		// Listed at the callback.
		{name: "an invalid ID token", code: callback(fmt.Errorf("%w: nonce", oidc.ErrInvalidIDToken)), assert: denied},
		{name: "no linked account, the one-link rule included", code: callback(oidc.ErrNoLinkedAccount), assert: denied},
		{name: "a refused provisioning, a hook refusal included", code: callback(oidc.ErrProvisioningRefused), assert: denied},
		{
			name:   "a refusal beside an outage",
			code:   callback(errors.Join(oidc.ErrNoLinkedAccount, fmt.Errorf("%w: 503", oidc.ErrUserInfoFailed))),
			assert: denied,
		},
		{name: "discovery down", code: callback(fmt.Errorf("%w: 503", oidc.ErrDiscoveryFailed)), assert: unavailable},
		{name: "the exchange down", code: callback(fmt.Errorf("%w: 503", oidc.ErrExchangeFailed)), assert: unavailable},
		{name: "UserInfo down", code: callback(fmt.Errorf("%w: 503", oidc.ErrUserInfoFailed)), assert: unavailable},

		// Unlisted at the callback.
		{name: "no failure", code: callback(nil), assert: none},
		{name: "an invalid state", code: callback(oidc.ErrInvalidState), assert: none},
		{
			name:   "an unknown provider",
			code:   callback(errors.Join(oidc.ErrUnknownProvider, oidc.ErrFlowUnspent)),
			assert: none,
		},
		{name: "a flow-store fault before the flow is spent", code: callback(errors.Join(errStore, oidc.ErrFlowUnspent)), assert: none},
		{
			name:   "an unspent failure that also claims a refusal",
			code:   callback(errors.Join(oidc.ErrNoLinkedAccount, oidc.ErrFlowUnspent)),
			assert: none,
		},
		{name: "an aborted walk", code: callback(errors.Join(oidc.ErrNoLinkedAccount, parkedUnwrapPanics{})), assert: none},
		{
			name:   "a hung-up caller",
			ctx:    hungUp,
			code:   callback(fmt.Errorf("%w: %w", oidc.ErrExchangeFailed, context.Canceled)),
			assert: none,
		},
		{name: "the re-authentication refusal", code: callback(ErrOIDCReauthenticate), assert: none},
		{name: "an unclassifiable broker error", code: callback(errBroker), assert: none},

		// At the login start, only discovery is listed.
		{name: "start: discovery down", code: start(fmt.Errorf("%w: 404", oidc.ErrDiscoveryFailed)), assert: unavailable},
		{name: "start: no failure", code: start(nil), assert: none},
		{name: "start: a flow-store fault", code: start(errStore), assert: none},
		{name: "start: an unknown provider", code: start(oidc.ErrUnknownProvider), assert: none},
		{name: "start: an aborted walk", code: start(errors.Join(oidc.ErrDiscoveryFailed, parkedUnwrapPanics{})), assert: none},
		{
			name:   "start: a hung-up caller",
			ctx:    hungUp,
			code:   start(fmt.Errorf("%w: %w", oidc.ErrDiscoveryFailed, context.Canceled)),
			assert: none,
		},

		// Listed in completion.
		{name: "completion: unknown, inactive or mismatched user", code: completion(completionStageUser, oidc.ErrInvalidHandoff), assert: denied},
		{name: "completion: the user loader fails", code: completion(completionStageUser, errStore), assert: serverError},
		{
			name:   "completion: the user loader fails with an error wrapping the user refusal",
			code:   completion(completionStageUser, fmt.Errorf("loader: %w", oidc.ErrInvalidHandoff)),
			assert: serverError,
		},
		{name: "completion: a post-authentication denial", code: completion(completionStageRefusal, policy.ErrDenied), assert: denied},
		{name: "completion: a consumer's own denial reason", code: completion(completionStageRefusal, errBroker), assert: denied},
		{name: "completion: the session store fails", code: completion(completionStageSession, errStore), assert: serverError},

		// Unlisted in completion.
		{name: "completion: no failure", code: completion(completionStageUser, nil), assert: none},
		{name: "completion: an unnamed stage", code: completion(0, errStore), assert: none},
		{name: "completion: the transport or unknown-handle refusal", code: completion(completionStageUser, ErrOIDCUnknownHandle), assert: none},
		{name: "completion: the throttle", code: completion(completionStageRefusal, ErrOIDCThrottled), assert: none},
		{name: "completion: re-authentication", code: completion(completionStageSession, ErrOIDCReauthenticate), assert: none},
		{name: "completion: an aborted walk", code: completion(completionStageUser, parkedUnwrapPanics{}), assert: none},
		{
			name:   "completion: a hung-up caller",
			ctx:    hungUp,
			code:   completion(completionStageSession, fmt.Errorf("store: %w", context.Canceled)),
			assert: none,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			code, ok := tc.code(ctx)
			tc.assert(t, code, ok)
		})
	}
}
