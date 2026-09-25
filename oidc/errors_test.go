package oidc_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/oidc"
)

func TestOIDCSentinels(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, err error)
	}

	authFailures := []error{
		oidc.ErrInvalidState, oidc.ErrInvalidIDToken, oidc.ErrNoLinkedAccount,
		oidc.ErrProvisioningRefused, oidc.ErrInvalidHandoff,
	}
	others := []error{
		oidc.ErrInvalidLogoutToken, oidc.ErrUnknownProvider, oidc.ErrExchangeFailed,
		oidc.ErrDiscoveryFailed, oidc.ErrConfig, oidc.ErrLinkNotFound, oidc.ErrLinkExists,
		oidc.ErrHandoffNotFound, oidc.ErrRetainSinceRequired, oidc.ErrFlowUnspent,
	}

	var cases []testCase
	for _, e := range authFailures {
		cases = append(cases, testCase{name: e.Error(), err: e, assert: func(t *testing.T, err error) {
			assert.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			assert.ErrorIs(t, fmt.Errorf("wrapped: %w", err), err, "identifiable as itself when wrapped")
		}})
	}
	for _, e := range others {
		cases = append(cases, testCase{name: e.Error(), err: e, assert: func(t *testing.T, err error) {
			assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		}})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.err)
		})
	}

	t.Run("every sentinel is distinct", func(t *testing.T) {
		t.Parallel()
		all := append(append([]error{}, authFailures...), others...)
		for i, a := range all {
			for j, b := range all {
				if i != j {
					assert.NotErrorIs(t, a, b)
				}
			}
		}
	})
}
