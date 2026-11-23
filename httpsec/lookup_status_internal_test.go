package httpsec

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/seal"
	"github.com/kartaladev/scrty/token"
)

// errConn stands for a driver's connection failure, the cause a library
// dependency failure wraps.
var errConn = errors.New("dial tcp: connection refused")

// recognised asserts LookupStatus claims err with status, and agrees with
// StatusForError.
func recognised(status int) func(t *testing.T, err error, got int, ok bool) {
	return func(t *testing.T, err error, got int, ok bool) {
		t.Helper()

		assert.True(t, ok, "recognised")
		assert.Equal(t, status, got)
		assert.Equal(t, StatusForError(err), got, "agrees with StatusForError")
	}
}

// unrecognised asserts LookupStatus declines err with 500, and agrees with
// StatusForError.
func unrecognised(t *testing.T, err error, got int, ok bool) {
	t.Helper()

	assert.False(t, ok, "not recognised")
	assert.Equal(t, http.StatusInternalServerError, got)
	assert.Equal(t, StatusForError(err), got, "agrees with StatusForError")
}

func TestLookupStatus(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, err error, status int, ok bool)
	}

	cases := []testCase{
		{
			name:   "access denied wrapped",
			err:    fmt.Errorf("x: %w", authorize.ErrAccessDenied),
			assert: recognised(http.StatusForbidden),
		},
		{
			name:   "mfa challenge",
			err:    &ChallengeError{Kind: policy.ChallengeMFA},
			assert: recognised(http.StatusUnauthorized),
		},
		{
			name:   "password change challenge",
			err:    &ChallengeError{Kind: policy.ChallengePasswordChange},
			assert: recognised(http.StatusForbidden),
		},
		{
			name:   "enrolment challenge",
			err:    &ChallengeError{Kind: policy.ChallengeMFAEnrolment},
			assert: recognised(http.StatusForbidden),
		},
		{
			name:   "account recovery challenge",
			err:    &ChallengeError{Kind: policy.ChallengeAccountRecovery},
			assert: recognised(http.StatusForbidden),
		},
		{
			name:   "consumer challenge kind",
			err:    &ChallengeError{Kind: policy.ChallengeKind(99)},
			assert: recognised(http.StatusUnauthorized),
		},
		{
			name:   "wrapped challenge",
			err:    fmt.Errorf("x: %w", &ChallengeError{Kind: policy.ChallengeMFA}),
			assert: recognised(http.StatusUnauthorized),
		},
		{
			name:   "issuing failure",
			err:    issuingFailure(errConn, "fixed", authenticate.ErrAuthenticationFailed),
			assert: recognised(http.StatusInternalServerError),
		},
		{
			name:   "challenge verifier down",
			err:    fmt.Errorf("%w: %w", ErrChallengeUnavailable, errConn),
			assert: recognised(http.StatusInternalServerError),
		},
		{
			name:   "oidc provider dependency",
			err:    fmt.Errorf("%w: %w", oidcprovider.ErrDependency, errConn),
			assert: recognised(http.StatusInternalServerError),
		},
		{
			name:   "recovery dependency",
			err:    fmt.Errorf("%w: %w", recovery.ErrDependency, errConn),
			assert: recognised(http.StatusInternalServerError),
		},
		{
			name:   "library fault over store error",
			err:    diag.Wrap(errConn, "fixed", authenticate.ErrUnavailable),
			assert: recognised(http.StatusUnauthorized),
		},
		{
			name:   "library fault with no refusal kind",
			err:    diag.Wrap(errConn, "fixed"),
			assert: recognised(http.StatusInternalServerError),
		},
		{
			name:   "history unavailable",
			err:    fmt.Errorf("%w: %w", password.ErrHistoryUnavailable, errConn),
			assert: recognised(http.StatusInternalServerError),
		},
		{
			name:   "typed-nil challenge alone",
			err:    fmt.Errorf("x: %w", (*ChallengeError)(nil)),
			assert: unrecognised,
		},
		{
			name:   "typed-nil challenge beside a refusal",
			err:    errors.Join((*ChallengeError)(nil), authorize.ErrAccessDenied),
			assert: recognised(http.StatusForbidden),
		},
		{
			name:   "typed-nil challenge before a real challenge in a join",
			err:    errors.Join((*ChallengeError)(nil), &ChallengeError{Kind: policy.ChallengeMFA}),
			assert: recognised(http.StatusUnauthorized),
		},
		{
			name:   "real challenge before a typed-nil challenge in a join",
			err:    errors.Join(&ChallengeError{Kind: policy.ChallengeMFA}, (*ChallengeError)(nil)),
			assert: recognised(http.StatusUnauthorized),
		},
		{
			name: "typed-nil challenge before a real one in a nested join",
			err: fmt.Errorf("x: %w", errors.Join(
				(*ChallengeError)(nil), &ChallengeError{Kind: policy.ChallengePasswordChange})),
			assert: recognised(http.StatusForbidden),
		},
		{
			name:   "consumer error",
			err:    errors.New("app"),
			assert: unrecognised,
		},
		{
			name:   "nil",
			err:    nil,
			assert: unrecognised,
		},
	}

	for _, row := range statusTable {
		cases = append(cases, testCase{
			name:   fmt.Sprintf("table row %v", row.err),
			err:    fmt.Errorf("wrapped: %w", row.err),
			assert: recognised(row.status),
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.NotPanics(t, func() {
				status, ok := LookupStatus(tc.err)
				tc.assert(t, tc.err, status, ok)
			})
		})
	}
}

// TestLookupStatus_DependencySentinelInventory pins every exported sentinel
// the library documents as a dependency or availability failure answered 500:
// each is recognised, so a later mapper never re-reads it, for instance a
// driver mapper turning the connection error it wraps into 503.
func TestLookupStatus_DependencySentinelInventory(t *testing.T) {
	t.Parallel()

	inventory := []struct {
		name string
		err  error
	}{
		{"httpsec.ErrChallengeUnavailable", ErrChallengeUnavailable},
		{"oidcprovider.ErrDependency", oidcprovider.ErrDependency},
		{"recovery.ErrDependency", recovery.ErrDependency},
		{"password.ErrHistoryUnavailable", password.ErrHistoryUnavailable},
		{"password.ErrLookupUnavailable", password.ErrLookupUnavailable},
		{"session.ErrListUnavailable", session.ErrListUnavailable},
		{"session.ErrCipherUnavailable", session.ErrCipherUnavailable},
		{"seal.ErrUnavailable", seal.ErrUnavailable},
		{"ratelimit.ErrBackendUnavailable", ratelimit.ErrBackendUnavailable},
		{"oidc.ErrExchangeFailed", oidc.ErrExchangeFailed},
		{"oidc.ErrDiscoveryFailed", oidc.ErrDiscoveryFailed},
		{"oidc.ErrUserInfoFailed", oidc.ErrUserInfoFailed},
		{"token.ErrNoVerificationKeys", token.ErrNoVerificationKeys},
	}

	for _, sentinel := range inventory {
		t.Run(sentinel.name, func(t *testing.T) {
			t.Parallel()

			for _, err := range []error{
				sentinel.err,
				fmt.Errorf("%w: %w", sentinel.err, errConn),
				errors.Join(sentinel.err, errConn),
			} {
				status, ok := LookupStatus(err)
				recognised(http.StatusInternalServerError)(t, err, status, ok)
			}
		})
	}
}
