package authenticate_test

import (
	"context"
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
	"github.com/kartaladev/scrty/token/signingkey"
)

func TestNewJwtAuthenticator(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T, ctrl *gomock.Controller) []authenticate.JWTOption
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
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.JWTOption {
				t.Helper()

				return []authenticate.JWTOption{authenticate.WithJWTVerifier(NewMockVerifier(ctrl))}
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
			opts: func(t *testing.T, _ *gomock.Controller) []authenticate.JWTOption {
				t.Helper()

				return []authenticate.JWTOption{authenticate.WithJWTVerifier(nil)}
			},
			assert: configError,
		},
		{
			name: "a non-nil interface holding a nil pointer is refused too",
			opts: func(t *testing.T, _ *gomock.Controller) []authenticate.JWTOption {
				t.Helper()

				var unchecked *MockVerifier

				return []authenticate.JWTOption{authenticate.WithJWTVerifier(unchecked)}
			},
			assert: configError,
		},
		{
			name: "a nil identifier generator is refused rather than quietly restoring the default",
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.JWTOption {
				t.Helper()

				return []authenticate.JWTOption{
					authenticate.WithJWTVerifier(NewMockVerifier(ctrl)),
					authenticate.WithJWTIDGenerator(nil),
				}
			},
			assert: configError,
		},
		{
			name: "a nil option is skipped, so a conditionally built slice need not be filtered",
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.JWTOption {
				t.Helper()

				return []authenticate.JWTOption{nil, authenticate.WithJWTVerifier(NewMockVerifier(ctrl))}
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

			var opts []authenticate.JWTOption
			if tc.opts != nil {
				opts = tc.opts(t, ctrl)
			}

			a, err := authenticate.NewJWTAuthenticator(opts...)
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
		opts     func(t *testing.T, ctrl *gomock.Controller) []authenticate.JWTOption
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
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.JWTOption {
				t.Helper()

				ids := NewMockGenerator(ctrl)
				ids.EXPECT().NewID().Return(id.Nil, errNoIdentifier)

				return []authenticate.JWTOption{authenticate.WithJWTIDGenerator(ids)}
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

			opts := []authenticate.JWTOption{authenticate.WithJWTVerifier(tc.verifier(t, ctrl))}
			if tc.opts != nil {
				opts = append(opts, tc.opts(t, ctrl)...)
			}

			auth, err := authenticate.NewJWTAuthenticator(opts...)
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

// errTokenExpired stands for a verifier's own refusal, which must stay
// matchable alongside the uniform failure. It matches token.ErrInvalid, as the
// verifier's contract requires of every rejection: any other error is an
// outage, not a refused token.
var errTokenExpired = fmt.Errorf("%w: expired", token.ErrInvalid)

// verificationKeysDown is a consumer key source whose key service cannot be
// reached: it signs with the keys it wraps, and cannot supply the keys to
// verify against.
type verificationKeysDown struct {
	signingkey.KeySource

	err error
}

func (s verificationKeysDown) VerificationKeys(context.Context) ([]signingkey.PublicKey, error) {
	return nil, s.err
}

// TestJWTProvider_KeySourceOutage pins that the bearer-token provider answers
// a verifier that could not obtain its keys as a dependency failure, not as
// the uniform authentication failure, and still refuses a token the same real
// verifier rejects. Real keys, a real generator and a real verifier are used,
// because the split rests on what the verifier reports for each.
func TestJWTProvider_KeySourceOutage(t *testing.T) {
	t.Parallel()

	const (
		issuer   = "https://issuer.example"
		audience = "orders-api"
	)

	errKMSTimeout := errors.New("kms: dependency timeout")

	type testCase struct {
		name string

		// verifyingWith is the key source the provider's verifier reads, given
		// the manager that signed the presented token.
		verifyingWith func(t *testing.T, signedBy *signingkey.Keys) signingkey.KeySource

		assert func(t *testing.T, got *authenticate.Authentication, err error)
	}

	cases := []testCase{
		{
			name: "the key source cannot supply the verification keys",
			verifyingWith: func(_ *testing.T, signedBy *signingkey.Keys) signingkey.KeySource {
				return verificationKeysDown{KeySource: signedBy, err: errKMSTimeout}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Nil(t, got)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"an outage was answered as a refused token")
				assert.NotErrorIs(t, err, token.ErrInvalid)
				require.ErrorIs(t, err, errKMSTimeout, "the key source's error stays reachable")
				assert.Equal(t, "authenticate: verification keys unavailable", err.Error(),
					"the text is the library's")
			},
		},
		{
			name: "a token signed by a key the source does not hold is still refused",
			verifyingWith: func(t *testing.T, _ *signingkey.Keys) signingkey.KeySource {
				t.Helper()

				other, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
				require.NoError(t, err)

				return other
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.ErrorIs(t, err, token.ErrInvalid, "the verifier's own cause stays matchable")
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
			require.NoError(t, err)

			gen, err := token.NewGenerator(keys, token.WithIssuer(issuer), token.WithAudience(audience))
			require.NoError(t, err)

			tok, err := gen.Generate(t.Context(), tokenID.String(), &identity.Principal{ID: "u-1", Username: "ada"})
			require.NoError(t, err)

			verifier, err := token.NewVerifier(
				token.WithVerifyKeySource(tc.verifyingWith(t, keys)),
				token.WithVerifyIssuer(issuer),
				token.WithVerifyAudience(audience),
			)
			require.NoError(t, err)

			auth, err := authenticate.NewJWTAuthenticator(authenticate.WithJWTVerifier(verifier))
			require.NoError(t, err)

			got, err := auth.Authenticate(t.Context(), authenticate.NewBearerToken(tok))
			tc.assert(t, got, err)
		})
	}
}

// TestJWTProvider_CallerLeavesDuringVerification pins that a caller whose
// own context ended while the token was verified is neither refused nor
// reported as a key outage: the error matches the context's error, behind
// fixed text of its own. A key source that times out on a deadline of its own
// while the caller still waits is an outage all the same. Real keys, a real
// generator and a real verifier are used, because the JOSE stack checks the
// context itself.
func TestJWTProvider_CallerLeavesDuringVerification(t *testing.T) {
	t.Parallel()

	errCallerGone := errors.New("test: the caller went away")

	const (
		issuer   = "https://issuer.example"
		audience = "orders-api"
	)

	type testCase struct {
		name string

		// ctx modifies the caller's context; nil leaves it live.
		ctx func(ctx context.Context) context.Context

		// verifyingWith is the key source the provider's verifier reads, given
		// the manager that signed the presented token.
		verifyingWith func(signedBy *signingkey.Keys) signingkey.KeySource

		// verifier, when set, replaces the real verifier with a double.
		verifier func(ctrl *gomock.Controller) token.Verifier

		assert func(t *testing.T, got *authenticate.Authentication, err error)
	}

	cases := []testCase{
		{
			name: "the caller left before the token was verified",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			verifyingWith: func(signedBy *signingkey.Keys) signingkey.KeySource { return signedBy },
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, got)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"a caller that left was answered as a refused token")
				assert.Equal(t, "authenticate: the caller left while the token was verified", err.Error(),
					"a caller that left is not reported as a key outage")
			},
		},
		{
			// A caller cancelled with a cause reports that cause through
			// context.Cause, and a verifier that returns it has returned the
			// caller's own ending, not a failure of its own.
			name: "the caller left with a cause, which the verifier returns",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancelCause(ctx)
				cancel(errCallerGone)

				return cctx
			},
			verifier: func(ctrl *gomock.Controller) token.Verifier {
				v := NewMockVerifier(ctrl)
				v.EXPECT().Verify(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ string) (*token.Claims, error) {
						return nil, fmt.Errorf("kms: %w", context.Cause(ctx))
					})

				return v
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, errCallerGone, "the cause stays reachable")
				assert.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, got)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"a caller that left was answered as a refused token")
				assert.Equal(t, "authenticate: the caller left while the token was verified", err.Error(),
					"a caller that left is not reported as a key outage")
			},
		},
		{
			// The verifier reached a verdict, and the context ending beside it
			// does not take the verdict back: a rejection is classified before
			// a hang-up.
			name: "a rejection that reaches the provider beside the ended context is still a refusal",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			verifier: func(ctrl *gomock.Controller) token.Verifier {
				v := NewMockVerifier(ctrl)
				v.EXPECT().Verify(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ string) (*token.Claims, error) {
						return nil, errors.Join(token.ErrInvalid, ctx.Err())
					})

				return v
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"a verdict was reported as a hang-up")
				assert.Nil(t, got)
				assert.NotEqual(t, "authenticate: the caller left while the token was verified", err.Error())
			},
		},
		{
			name: "a key source that times out of its own while the caller waits is an outage",
			verifyingWith: func(signedBy *signingkey.Keys) signingkey.KeySource {
				return verificationKeysDown{KeySource: signedBy, err: context.DeadlineExceeded}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, context.DeadlineExceeded, "the key source's error stays reachable")
				assert.Nil(t, got)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, "authenticate: verification keys unavailable", err.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
			require.NoError(t, err)

			gen, err := token.NewGenerator(keys, token.WithIssuer(issuer), token.WithAudience(audience))
			require.NoError(t, err)

			tok, err := gen.Generate(t.Context(), tokenID.String(), &identity.Principal{ID: "u-1", Username: "ada"})
			require.NoError(t, err)

			var verifier token.Verifier
			if tc.verifier != nil {
				verifier = tc.verifier(gomock.NewController(t))
			} else {
				verifier, err = token.NewVerifier(
					token.WithVerifyKeySource(tc.verifyingWith(keys)),
					token.WithVerifyIssuer(issuer),
					token.WithVerifyAudience(audience),
				)
				require.NoError(t, err)
			}

			auth, err := authenticate.NewJWTAuthenticator(authenticate.WithJWTVerifier(verifier))
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			got, err := auth.Authenticate(ctx, authenticate.NewBearerToken(tok))
			tc.assert(t, got, err)
		})
	}
}
