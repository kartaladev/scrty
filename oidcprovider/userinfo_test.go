package oidcprovider_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
)

// verified is what the UserInfo endpoint hands the provider for raw.
func verified(t *testing.T, f *refreshFixture, raw string) *oidcprovider.AccessToken {
	t.Helper()

	at, err := f.p.VerifyAccessToken(t.Context(), raw)
	require.NoError(t, err)

	return at
}

// TestProvider_UserInfo is UserInfo's table. Each row starts from a grant, says which token is
// handed over and what stands by then, and judges the answer.
func TestProvider_UserInfo(t *testing.T) {
	t.Parallel()

	// Values a source may point at: an empty string, a nil slice, and a value that is there.
	var (
		blank    = ""
		nilSlice []string
		word     = "word"
	)

	type testCase struct {
		name string
		// source, when set, is expected by the row, and given as the provider's claim source.
		source func(*MockClaimSource)
		start  func(*testing.T, *refreshFixture) *refreshScene
		ctx    func(context.Context) context.Context
		// arrange returns the token handed over, by default the scene's first.
		arrange func(*testing.T, *refreshFixture, *refreshScene) *oidcprovider.AccessToken
		assert  func(*testing.T, map[string]any, error)
	}

	refusedAs := func(code string) func(*testing.T, map[string]any, error) {
		return func(t *testing.T, answer map[string]any, err error) {
			t.Helper()

			assertRefused(t, err, code)
			assert.Nil(t, answer)
		}
	}
	invalidToken := refusedAs(oidcprovider.CodeInvalidToken)
	dependencyFailed := func(t *testing.T, answer map[string]any, err error) {
		t.Helper()

		assertDependencyFailure(t, err)
		var refusal *oidcprovider.Error
		assert.NotErrorAs(t, err, &refusal)
		assert.Nil(t, answer)
	}
	subOnly := func(t *testing.T, answer map[string]any, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.Equal(t, map[string]any{"sub": "u-1"}, answer)
	}
	naming := func(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.AccessToken {
		t.Helper()

		f.users.set(func(u *exchangeUsers) { u.name, u.username = "Ada", "ada" })

		return verified(t, f, s.first.AccessToken)
	}
	signedFor := func(scope string) func(*testing.T, *refreshFixture, *refreshScene) *oidcprovider.AccessToken {
		return func(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.AccessToken {
			t.Helper()

			return verified(t, f, signedAccess(t, f.exchangeFixture, s.grant.Family, func(claims map[string]any) {
				claims["scope"] = scope
			}))
		}
	}
	withUser := func(change func(*exchangeUsers)) func(*testing.T, *refreshFixture, *refreshScene) *oidcprovider.AccessToken {
		return func(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.AccessToken {
			t.Helper()

			at := verified(t, f, s.first.AccessToken)
			f.users.set(change)

			return at
		}
	}
	withUsername := func(username string) func(*testing.T, *refreshFixture, *refreshScene) *oidcprovider.AccessToken {
		return func(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.AccessToken {
			t.Helper()

			f.users.set(func(u *exchangeUsers) { u.name, u.username = "Ada", username })

			return verified(t, f, s.first.AccessToken)
		}
	}
	never := func(*MockClaimSource) {}

	cases := []testCase{
		{
			name:    "profile releases the user's name and username, and no email",
			start:   startBillingFor("openid", "profile"),
			arrange: naming,
			assert: func(t *testing.T, answer map[string]any, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, map[string]any{"sub": "u-1", "name": "Ada", "preferred_username": "ada"}, answer)
			},
		},
		{
			name:    "openid alone releases sub alone, whatever the user has",
			start:   startBillingFor("openid"),
			arrange: naming,
			assert:  subOnly,
		},
		{
			name:    "email releases a username that is exactly an address, unverified",
			start:   startBillingFor("openid", "email"),
			arrange: withUsername("ada@example.com"),
			assert: func(t *testing.T, answer map[string]any, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, map[string]any{"sub": "u-1", "email": "ada@example.com", "email_verified": false}, answer)
			},
		},
		{
			name:    "email with a username in display form releases neither claim",
			start:   startBillingFor("openid", "email"),
			arrange: withUsername("Ada <ada@example.com>"),
			assert:  subOnly,
		},
		{
			name:    "email with a username that is no address releases neither claim",
			start:   startBillingFor("openid", "email"),
			arrange: withUsername("ada"),
			assert:  subOnly,
		},
		{
			name:    "an address as the username is not released without the email scope",
			start:   startBillingFor("openid", "profile"),
			arrange: withUsername("ada@example.com"),
			assert: func(t *testing.T, answer map[string]any, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotContains(t, answer, "email")
				assert.NotContains(t, answer, "email_verified")
			},
		},
		{
			name: "a consumer's source replaces the default, and its verified email is answered unchanged",
			source: func(m *MockClaimSource) {
				m.EXPECT().Claims(gomock.Any(), identity.UserID("u-1"), []string{"openid", "email"}).Return(
					map[string]any{"email": "ada@corp.example", "email_verified": true}, nil)
			},
			start:   startBillingFor("openid", "email"),
			arrange: withUsername("ada@example.com"),
			assert: func(t *testing.T, answer map[string]any, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, map[string]any{"sub": "u-1", "email": "ada@corp.example", "email_verified": true}, answer)
			},
		},
		{
			name:   "claims a user does not have are omitted, never empty",
			start:  startBillingFor("openid", "profile"),
			assert: subOnly,
		},
		{
			name:   "an opaque token is read like a JWT",
			start:  startOpaque,
			assert: subOnly,
		},
		{
			name: "a consumer's source releases its own claim for its own scope, unchanged",
			source: func(m *MockClaimSource) {
				m.EXPECT().Claims(gomock.Any(), identity.UserID("u-1"), []string{"openid", "org"}).Return(map[string]any{
					"department": "ops",
					"levels":     []any{float64(1), "two"},
					"place":      map[string]any{"floor": 3},
				}, nil)
			},
			arrange: signedFor("openid org"),
			assert: func(t *testing.T, answer map[string]any, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, map[string]any{
					"sub":        "u-1",
					"department": "ops",
					"levels":     []any{float64(1), "two"},
					"place":      map[string]any{"floor": 3},
				}, answer)
			},
		},
		{
			name: "a consumer's source may release a standard claim for a scope of its choosing",
			source: func(m *MockClaimSource) {
				m.EXPECT().Claims(gomock.Any(), identity.UserID("u-1"), gomock.Any()).Return(map[string]any{"email": "a@example.com"}, nil)
			},
			arrange: signedFor("openid org"),
			assert: func(t *testing.T, answer map[string]any, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, map[string]any{"sub": "u-1", "email": "a@example.com"}, answer)
			},
		},
		{
			name: "a source cannot replace sub",
			source: func(m *MockClaimSource) {
				m.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Return(map[string]any{"sub": "someone-else"}, nil)
			},
			assert: subOnly,
		},
		{
			name: "what a source leaves null or an empty string is omitted, and anything else is a value",
			source: func(m *MockClaimSource) {
				m.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Return(map[string]any{
					"nothing": nil, "blank": "", "pointer": (*string)(nil),
					"nil_slice": []string(nil), "nil_map": map[string]any(nil), "to_blank": &blank, "to_nil_slice": &nilSlice,
					"raw_blank": json.RawMessage(`""`), "raw_spaced_blank": json.RawMessage(" \"\"\n"),
					"to_value": &word, "raw_null": json.RawMessage("null"), "raw_spaced_null": json.RawMessage(" null\n"),
					"list": []string{}, "object": map[string]any{}, "raw_list": json.RawMessage("[]"),
					"raw_object": json.RawMessage("{}"), "raw_zero": json.RawMessage("0"),
					"email_verified": false, "count": 0,
				}, nil)
			},
			assert: func(t *testing.T, answer map[string]any, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, map[string]any{
					"sub": "u-1", "email_verified": false, "count": 0,
					"list": []string{}, "object": map[string]any{}, "raw_list": json.RawMessage("[]"),
					"raw_object": json.RawMessage("{}"), "raw_zero": json.RawMessage("0"), "to_value": &word,
				}, answer)
				encoded, err := json.Marshal(answer)
				require.NoError(t, err)
				assert.NotContains(t, string(encoded), "null", "no claim is sent as null")
			},
		},
		{
			name: "a source answering nothing is sub alone",
			source: func(m *MockClaimSource) {
				m.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
			},
			assert: subOnly,
		},
		{
			name: "a source's failure is a dependency failure",
			source: func(m *MockClaimSource) {
				m.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errOutage)
			},
			assert: dependencyFailed,
		},
		{
			name: "a caller who left during the source matches its own context",
			ctx: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			source: func(m *MockClaimSource) {
				m.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, context.Canceled)
			},
			assert: func(t *testing.T, _ map[string]any, err error) {
				t.Helper()

				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidcprovider.ErrDependency)
			},
		},
		{
			name:    "a token without openid is insufficient_scope",
			arrange: signedFor("profile"),
			assert:  refusedAs(oidcprovider.CodeInsufficientScope),
		},
		{
			name:   "a token for no one but a named resource is invalid_token, its grant being live",
			start:  startResources("https://api.example.com"),
			source: never,
			assert: invalidToken,
		},
		{
			name:  "a token for no one but a named resource is invalid_token, its grant being revoked",
			start: startResources("https://api.example.com"),
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.AccessToken {
				t.Helper()

				at := verified(t, f, s.first.AccessToken)
				revokeWhole(t, f, s)

				return at
			},
			assert: invalidToken,
		},
		{
			name: "a token whose grant was revoked after it was read is invalid_token",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.AccessToken {
				t.Helper()

				at := verified(t, f, s.first.AccessToken)
				revokeWhole(t, f, s)

				return at
			},
			source: never,
			assert: invalidToken,
		},
		{
			name: "a token of a revoked grant without openid is invalid_token, and no question of scope",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.AccessToken {
				t.Helper()

				at := signedFor("profile")(t, f, s)
				revokeWhole(t, f, s)

				return at
			},
			assert: invalidToken,
		},
		{
			name: "a token whose grant row has gone is invalid_token",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.AccessToken {
				t.Helper()

				at := verified(t, f, s.first.AccessToken)
				f.grants.loads.Store(0)
				f.grants.missingAt.Store(1)

				return at
			},
			assert: invalidToken,
		},
		{
			name: "a grant that cannot be read is a dependency failure",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.AccessToken {
				t.Helper()

				at := verified(t, f, s.first.AccessToken)
				f.grants.loads.Store(0)
				f.grants.failLoadAt.Store(1)

				return at
			},
			assert: dependencyFailed,
		},
		{
			name: "a token past its expiry by the time it arrives is invalid_token",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.AccessToken {
				t.Helper()

				at := verified(t, f, s.first.AccessToken)
				f.clk.Advance(5 * time.Minute)

				return at
			},
			assert: invalidToken,
		},
		{
			name: "a token whose subject is not its grant's is invalid_token",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.AccessToken {
				t.Helper()

				at := verified(t, f, s.first.AccessToken)
				at.Subject = "someone-else"

				return at
			},
			assert: invalidToken,
		},
		{
			name: "no token is invalid_token",
			arrange: func(*testing.T, *refreshFixture, *refreshScene) *oidcprovider.AccessToken {
				return nil
			},
			assert: invalidToken,
		},
		{
			name:    "a disabled user is invalid_token, and no source is asked",
			source:  never,
			arrange: withUser(func(u *exchangeUsers) { u.disabled["u-1"] = true }),
			assert:  invalidToken,
		},
		{
			name:    "a missing user is invalid_token, and no source is asked",
			source:  never,
			arrange: withUser(func(u *exchangeUsers) { u.missing["u-1"] = true }),
			assert:  invalidToken,
		},
		{
			name:    "under the default source too, a disabled user is invalid_token",
			arrange: withUser(func(u *exchangeUsers) { u.disabled["u-1"] = true }),
			assert:  invalidToken,
		},
		{
			name:    "a loader answering another user is invalid_token",
			arrange: withUser(func(u *exchangeUsers) { u.impostor = true }),
			assert:  invalidToken,
		},
		{
			name:    "a loader answering nothing is invalid_token",
			arrange: withUser(func(u *exchangeUsers) { u.answersNothing = true }),
			assert:  invalidToken,
		},
		{
			name:    "a user store outage is a dependency failure, never invalid_token",
			source:  never,
			arrange: withUser(func(u *exchangeUsers) { u.failing = true }),
			assert:  dependencyFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []oidcprovider.Option
			if tc.source != nil {
				source := NewMockClaimSource(gomock.NewController(t))
				tc.source(source)
				opts = append(opts, oidcprovider.WithClaimSource(source))
			}
			f := newRefreshFixture(t, opts...)
			start := tc.start
			if start == nil {
				start = startBilling
			}
			s := start(t, f)

			var at *oidcprovider.AccessToken
			if tc.arrange != nil {
				at = tc.arrange(t, f, s)
			} else {
				at = verified(t, f, s.first.AccessToken)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			answer, err := f.p.UserInfo(ctx, at)
			tc.assert(t, answer, err)
		})
	}
}

// TestProvider_UserInfo_SourceMapKept pins that what a consumer's source returned stays its own.
func TestProvider_UserInfo_SourceMapKept(t *testing.T) {
	t.Parallel()

	held := map[string]any{"department": "ops", "blank": ""}
	source := NewMockClaimSource(gomock.NewController(t))
	source.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Return(held, nil)
	f := newRefreshFixture(t, oidcprovider.WithClaimSource(source))
	s := startBilling(t, f)

	_, err := f.p.UserInfo(t.Context(), verified(t, f, s.first.AccessToken))
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"department": "ops", "blank": ""}, held)
}

// TestProvider_UserInfo_SourceCannotChangeTheToken pins that a source is given a copy of the token's
// scopes, as the token stays what it was verified to be.
func TestProvider_UserInfo_SourceCannotChangeTheToken(t *testing.T) {
	t.Parallel()

	source := NewMockClaimSource(gomock.NewController(t))
	source.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ identity.UserID, scopes []string) (map[string]any, error) {
			scopes[0] = "tampered"

			return nil, nil
		})
	f := newRefreshFixture(t, oidcprovider.WithClaimSource(source))
	s := startBilling(t, f)
	at := verified(t, f, s.first.AccessToken)
	before := slices.Clone(at.Scopes)

	_, err := f.p.UserInfo(t.Context(), at)

	require.NoError(t, err)
	assert.Equal(t, before, at.Scopes, "a source rewrote the token's scopes")
}

// TestProvider_UserInfo_NilClaimSource pins a wiring mistake failing at construction.
func TestProvider_UserInfo_NilClaimSource(t *testing.T) {
	t.Parallel()

	var typedNil *MockClaimSource

	type testCase struct {
		name   string
		source oidcprovider.ClaimSource
	}
	for _, tc := range []testCase{{name: "nil"}, {name: "a typed nil", source: typedNil}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := oidcprovider.New(oidcprovider.Deps{
				Issuer: issuer, Clients: authzClients(), Keys: plainKeys(t), Users: activeUsers(t),
				LoginURL: issuer + "/login", ConsentURL: issuer + "/consent", LogoutURL: issuer + "/logout", LoggedOutURL: issuer + "/bye",
			}, oidcprovider.WithClaimSource(tc.source))
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.Contains(t, err.Error(), "WithClaimSource")
		})
	}
}
