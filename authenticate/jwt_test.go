package authenticate_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token"
)

// presentedToken stands for a compact JWS a caller presents. Nothing here
// parses it: the verifier is the only thing that reads a token.
const presentedToken = "header.payload.signature"

func TestNewJwtAuthenticator(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T, ctrl *gomock.Controller) []authenticate.JwtOption
		assert func(t *testing.T, a authenticate.Authenticator, err error)
	}

	configError := func(t *testing.T, a authenticate.Authenticator, err error) {
		t.Helper()

		require.ErrorIs(t, err, authenticate.ErrConfig)
		assert.Nil(t, a, "a refused configuration still produced a provider")
	}

	cases := []testCase{
		{
			name: "a verifier alone constructs",
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.JwtOption {
				t.Helper()

				return []authenticate.JwtOption{authenticate.WithJwtVerifier(NewMockVerifier(ctrl))}
			},
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, a)
			},
		},
		{
			name:   "no verifier is refused, naming what is missing",
			assert: configError,
		},
		{
			name: "a nil verifier is refused",
			opts: func(t *testing.T, _ *gomock.Controller) []authenticate.JwtOption {
				t.Helper()

				return []authenticate.JwtOption{authenticate.WithJwtVerifier(nil)}
			},
			assert: configError,
		},
		{
			name: "a non-nil interface holding a nil pointer is refused too",
			opts: func(t *testing.T, _ *gomock.Controller) []authenticate.JwtOption {
				t.Helper()

				var unchecked *MockVerifier

				return []authenticate.JwtOption{authenticate.WithJwtVerifier(unchecked)}
			},
			assert: configError,
		},
		{
			name: "a nil identifier generator is refused rather than quietly restoring the default",
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.JwtOption {
				t.Helper()

				return []authenticate.JwtOption{
					authenticate.WithJwtVerifier(NewMockVerifier(ctrl)),
					authenticate.WithJwtIDGenerator(nil),
				}
			},
			assert: configError,
		},
		{
			name: "a nil option is skipped, so a conditionally built slice need not be filtered",
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.JwtOption {
				t.Helper()

				return []authenticate.JwtOption{nil, authenticate.WithJwtVerifier(NewMockVerifier(ctrl))}
			},
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, a)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			var opts []authenticate.JwtOption
			if tc.opts != nil {
				opts = tc.opts(t, ctrl)
			}

			a, err := authenticate.NewJwtAuthenticator(opts...)
			tc.assert(t, a, err)
		})
	}
}

func TestJwtAuthenticatorAuthenticate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		creds    func(t *testing.T) identity.Credentials
		verifier func(t *testing.T, ctrl *gomock.Controller) token.Verifier
		opts     func(t *testing.T, ctrl *gomock.Controller) []authenticate.JwtOption
		assert   func(t *testing.T, got *authenticate.Authentication, err error)
	}

	verifies := func(claims *token.Claims) func(t *testing.T, ctrl *gomock.Controller) token.Verifier {
		return func(t *testing.T, ctrl *gomock.Controller) token.Verifier {
			t.Helper()

			v := NewMockVerifier(ctrl)
			v.EXPECT().Verify(gomock.Any(), presentedToken).Return(claims, nil)

			return v
		}
	}

	cases := []testCase{
		{
			name:     "a token the verifier accepts yields a principal built from its subject",
			verifier: verifies(token.NewClaims("ada", tokenID.String())),
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, got)
				require.NotNil(t, got.Principal)
				assert.Equal(t, "ada", got.Principal.Username)
				assert.Equal(t, identity.CredentialsJWT, got.Credentials.Type())
				assert.True(t, got.PasswordChangedAt.IsZero(),
					"a bearer token said something about a password it never saw")
			},
		},
		{
			name:     "the result is named by the token's own identifier",
			verifier: verifies(token.NewClaims("ada", tokenID.String())),
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, tokenID, got.ID,
					"the event was given a fresh name, so it cannot be joined to the token that caused it")
			},
		},
		{
			name:     "a token identifier of another format still names the event, from the generator",
			verifier: verifies(token.NewClaims("ada", "opaque-issuer-reference")),
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, got.ID.IsZero(),
					"an issuer's own jti format left the event unnamed")
			},
		},
		{
			name:     "the presented token is dropped once it has been accepted",
			verifier: verifies(token.NewClaims("ada", tokenID.String())),
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)

				carried, ok := got.Credentials.(authenticate.BearerCredentials)
				require.True(t, ok)
				assert.Empty(t, carried.Token(), "the accepted token is still readable from the result")
			},
		},
		{
			name: "a rejected token matches the uniform failure and the verifier's own cause",
			verifier: func(t *testing.T, ctrl *gomock.Controller) token.Verifier {
				t.Helper()

				v := NewMockVerifier(ctrl)
				v.EXPECT().Verify(gomock.Any(), presentedToken).Return(nil, errTokenExpired)

				return v
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.ErrorIs(t, err, errTokenExpired,
					"the cause was collapsed, so a caller cannot log why the token was refused")
				assert.Nil(t, got)
			},
		},
		{
			name:     "a verified token with no subject is refused rather than made anonymous",
			verifier: verifies(token.NewClaims("", tokenID.String())),
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, got,
					"a principal with no username would pass every check that only asks whether someone is authenticated")
			},
		},
		{
			name:     "a verifier reporting neither claims nor an error is a refusal, not a nil dereference",
			verifier: verifies(nil),
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, got)
			},
		},
		{
			name: "credentials of another kind are skipped without reaching the verifier",
			creds: func(t *testing.T) identity.Credentials {
				t.Helper()

				return identity.NewUsernamePassword("ada", []byte(storedPassword))
			},
			verifier: func(t *testing.T, ctrl *gomock.Controller) token.Verifier {
				t.Helper()

				// No EXPECT: a provider that verifies before it knows the
				// credential kind hands the key source traffic it cannot use.
				return NewMockVerifier(ctrl)
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrUnsupportedCredentials)
				assert.Nil(t, got)
			},
		},
		{
			name:     "a generator failure is an error, never a result with no identifier",
			verifier: verifies(token.NewClaims("ada", "opaque-issuer-reference")),
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.JwtOption {
				t.Helper()

				ids := NewMockGenerator(ctrl)
				ids.EXPECT().NewID().Return(id.Nil, errNoIdentifier)

				return []authenticate.JwtOption{authenticate.WithJwtIDGenerator(ids)}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, errNoIdentifier)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"a failure to name the event was reported as a decision about the caller")
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			opts := []authenticate.JwtOption{authenticate.WithJwtVerifier(tc.verifier(t, ctrl))}
			if tc.opts != nil {
				opts = append(opts, tc.opts(t, ctrl)...)
			}

			auth, err := authenticate.NewJwtAuthenticator(opts...)
			require.NoError(t, err)

			creds := identity.Credentials(authenticate.NewBearerToken(presentedToken))
			if tc.creds != nil {
				creds = tc.creds(t)
			}

			got, err := auth.Authenticate(t.Context(), creds)
			tc.assert(t, got, err)
		})
	}
}

func TestBearerToken(t *testing.T) {
	t.Parallel()

	t.Run("carries the token it was built over, under the JWT credential type", func(t *testing.T) {
		t.Parallel()

		c := authenticate.NewBearerToken(presentedToken)
		assert.Equal(t, presentedToken, c.Token())
		assert.Equal(t, identity.CredentialsJWT, c.Type())
	})

	t.Run("cleanup drops the token", func(t *testing.T) {
		t.Parallel()

		c := authenticate.NewBearerToken(presentedToken)
		require.NoError(t, c.Cleanup())
		assert.Empty(t, c.Token())
	})

	t.Run("cleaning up an absent credential does nothing and reports no error", func(t *testing.T) {
		t.Parallel()

		var absent *authenticate.BearerToken
		require.NoError(t, absent.Cleanup())
		assert.Empty(t, absent.Token())
	})
}

// tokenID is the identifier a verified token carries as jti, in the canonical
// layout a consumer's own records would key on.
var tokenID = id.MustParse("0192f3a4-5b6c-7d8e-9f01-fedcba987654")

// errTokenExpired stands for a verifier's own refusal, which must stay
// matchable alongside the uniform failure.
var errTokenExpired = fmt.Errorf("%w: expired", errors.New("token: invalid"))
