package oidcprovider_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/signingkey"
)

var handleShape = regexp.MustCompile(`^rh\.([0-9a-f-]{36})\.([A-Za-z0-9_-]+)$`)

// parkFixture is a provider over a store and clock a row can reach.
type parkFixture struct {
	p        *oidcprovider.Provider
	store    *oidcprovider.MemoryPendingRequestStore
	consents *oidcprovider.MemoryConsentStore
	registry *oidcprovider.MemoryRegistry
	clk      *clockwork.FakeClock
	logs     *bytes.Buffer

	// given is the flow secret a row's request was given, and firstLocation where a
	// row's earlier request went.
	given, firstLocation string
}

func newParkFixture(t *testing.T, loginURL string, opts ...oidcprovider.Option) *parkFixture {
	t.Helper()

	return newParkFixtureKeys(t, loginURL, plainKeys(t), opts...)
}

// newParkFixtureKeys is newParkFixture over a key source a row chooses, for a hint it signs.
func newParkFixtureKeys(t *testing.T, loginURL string, keys signingkey.KeySource, opts ...oidcprovider.Option) *parkFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	store, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	consents, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)
	registry, err := oidcprovider.NewMemoryRegistry(authzClients())
	require.NoError(t, err)
	logs := &bytes.Buffer{}

	base := []oidcprovider.Option{
		oidcprovider.WithClock(clk),
		oidcprovider.WithPendingRequestStore(store),
		oidcprovider.WithConsentStore(consents),
		oidcprovider.WithLogger(slog.New(slog.NewTextHandler(logs, nil))),
	}
	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         keys,
		Users:        activeUsers(t),
		LoginURL:     loginURL,
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	}, append(base, opts...)...)
	require.NoError(t, err)

	return &parkFixture{p: p, store: store, consents: consents, registry: registry, clk: clk, logs: logs}
}

// handleOf reads the handle out of a login Location.
func handleOf(t *testing.T, location string) string {
	t.Helper()

	loc, err := url.Parse(location)
	require.NoError(t, err)
	require.Len(t, loc.Query()["req"], 1)

	return loc.Query().Get("req")
}

// digestOf is the SHA-256 of a secret's decoded bytes.
func digestOf(t *testing.T, secret string) []byte {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(secret)
	require.NoError(t, err)
	sum := sha256.Sum256(raw)

	return sum[:]
}

// handleParts splits a handle into its identifier and its secret.
func handleParts(t *testing.T, handle string) (recordID, secret string) {
	t.Helper()

	parts := handleShape.FindStringSubmatch(handle)
	require.NotNil(t, parts, "the handle has its shape")

	return parts[1], parts[2]
}

func handleDigestOf(t *testing.T, handle string) []byte {
	t.Helper()

	_, secret := handleParts(t, handle)

	return digestOf(t, secret)
}

// everyString is each string and byte slice reachable from v, as text.
func everyString(v reflect.Value) []string {
	switch v.Kind() {
	case reflect.String:
		return []string{v.String()}
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}

		return everyString(v.Elem())
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return []string{string(v.Bytes())}
		}
		fallthrough
	case reflect.Array:
		var out []string
		for i := range v.Len() {
			out = append(out, everyString(v.Index(i))...)
		}

		return out
	case reflect.Struct:
		var out []string
		for i := range v.NumField() {
			out = append(out, everyString(v.Field(i))...)
		}

		return out
	default:
		return nil
	}
}

// replacedFlow asserts the flow secret a request gave was not kept: the provider minted
// 32 fresh bytes instead.
func replacedFlow(t *testing.T, f *parkFixture, res oidcprovider.AuthorizeResult, err error) {
	t.Helper()
	require.NoError(t, err)
	assert.NotEqual(t, f.given, res.FlowSecret, "the provider never mints this")
	flow, decodeErr := base64.RawURLEncoding.Strict().DecodeString(res.FlowSecret)
	require.NoError(t, decodeErr)
	assert.Len(t, flow, 32)
}

func TestProvider_Park(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		loginURL string
		opts     func(t *testing.T) []oidcprovider.Option
		flow     func(t *testing.T, f *parkFixture) string
		params   func(url.Values)
		ctx      func(context.Context) context.Context
		assert   func(t *testing.T, f *parkFixture, res oidcprovider.AuthorizeResult, err error)
	}

	cases := []testCase{
		{
			name: "the browser goes to the login URL with the handle",
			assert: func(t *testing.T, _ *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				handle := handleOf(t, res.Location)
				assert.Regexp(t, handleShape, handle)
				assert.Equal(t, issuer+"/login?req="+url.QueryEscape(handle), res.Location)
			},
		},
		{
			name:     "a login URL's own query is kept",
			loginURL: issuer + "/login?tenant=a",
			assert: func(t *testing.T, _ *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(res.Location, issuer+"/login?tenant=a&req=rh."), res.Location)
			},
		},
		{
			name: "the handle and the flow secret carry enough, and differ",
			assert: func(t *testing.T, _ *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				recordID, rawSecret := handleParts(t, handleOf(t, res.Location))
				secret, decodeErr := base64.RawURLEncoding.DecodeString(rawSecret)
				require.NoError(t, decodeErr)
				assert.GreaterOrEqual(t, len(secret), 16, "at least 128 bits")

				flow, decodeErr := base64.RawURLEncoding.DecodeString(res.FlowSecret)
				require.NoError(t, decodeErr)
				assert.Len(t, flow, 32, "256 bits")
				assert.NotEqual(t, secret, flow)
				_, parseErr := id.Parse(recordID)
				require.NoError(t, parseErr)
			},
		},
		{
			name: "the store holds digests, never a secret",
			assert: func(t *testing.T, f *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				handle := handleOf(t, res.Location)
				digest := handleDigestOf(t, handle)

				stored, loadErr := f.store.Load(t.Context(), digest)
				require.NoError(t, loadErr)
				assert.Equal(t, digest, stored.HandleDigest)
				assert.Equal(t, digestOf(t, res.FlowSecret), stored.FlowDigest)

				_, secret := handleParts(t, handle)
				for _, held := range everyString(reflect.ValueOf(stored)) {
					assert.NotContains(t, held, handle)
					assert.NotContains(t, held, secret)
					assert.NotContains(t, held, res.FlowSecret)
				}
			},
		},
		{
			name: "the record is at the login stage, with its id, times and no sign-in",
			assert: func(t *testing.T, f *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				handle := handleOf(t, res.Location)
				stored, loadErr := f.store.Load(t.Context(), handleDigestOf(t, handle))
				require.NoError(t, loadErr)

				recordID, _ := handleParts(t, handle)
				assert.Equal(t, recordID, stored.ID.String())
				assert.Equal(t, oidcprovider.StageLogin, stored.Stage)
				assert.Equal(t, f.clk.Now(), stored.ParkedAt)
				assert.Equal(t, f.clk.Now().Add(10*time.Minute), stored.ExpiresAt)
				assert.Nil(t, stored.SignIn)
			},
		},
		{
			name: "a flow secret another parked request holds is kept",
			flow: func(t *testing.T, f *parkFixture) string {
				t.Helper()
				first, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: authzParams()})
				require.NoError(t, err)

				return first.FlowSecret
			},
			assert: func(t *testing.T, f *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, f.given, res.FlowSecret)
				stored, loadErr := f.store.Load(t.Context(), handleDigestOf(t, handleOf(t, res.Location)))
				require.NoError(t, loadErr)
				assert.Equal(t, digestOf(t, res.FlowSecret), stored.FlowDigest)
			},
		},
		{
			name: "a flow secret of the right shape is kept, as nothing can ask who holds it",
			flow: func(*testing.T, *parkFixture) string {
				return base64.RawURLEncoding.EncodeToString(append(make([]byte, 31), 7))
			},
			assert: func(t *testing.T, f *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, f.given, res.FlowSecret)
			},
		},
		{
			name: "a value that could not be a flow secret is replaced",
			flow: func(*testing.T, *parkFixture) string { return "planted" },
			assert: func(t *testing.T, _ *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEqual(t, "planted", res.FlowSecret)
				flow, decodeErr := base64.RawURLEncoding.DecodeString(res.FlowSecret)
				require.NoError(t, decodeErr)
				assert.Len(t, flow, 32)
			},
		},
		{
			name: "a flow secret of the wrong length is replaced",
			flow: func(*testing.T, *parkFixture) string {
				return base64.RawURLEncoding.EncodeToString(make([]byte, 16))
			},
			assert: func(t *testing.T, _ *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEqual(t, base64.RawURLEncoding.EncodeToString(make([]byte, 16)), res.FlowSecret)
				flow, decodeErr := base64.RawURLEncoding.DecodeString(res.FlowSecret)
				require.NoError(t, decodeErr)
				assert.Len(t, flow, 32)
			},
		},
		{
			name:   "a flow secret of newlines is replaced, as the decoder skips them",
			flow:   func(*testing.T, *parkFixture) string { return strings.Repeat("\n", 43) },
			assert: replacedFlow,
		},
		{
			name: "a flow secret one byte short and led by a newline is replaced",
			flow: func(*testing.T, *parkFixture) string {
				return "\n" + base64.RawURLEncoding.EncodeToString(make([]byte, 31))
			},
			assert: replacedFlow,
		},
		{
			name: "a flow secret with a carriage return inside is replaced",
			flow: func(*testing.T, *parkFixture) string {
				return base64.RawURLEncoding.EncodeToString(make([]byte, 32))[:41] + "\r" + "A"
			},
			assert: replacedFlow,
		},
		{
			name: "a flow secret spelled with non-canonical trailing bits is replaced",
			flow: func(*testing.T, *parkFixture) string {
				return base64.RawURLEncoding.EncodeToString(make([]byte, 32))[:42] + "B"
			},
			assert: replacedFlow,
		},
		{
			name: "the input prints and logs redacted too",
			flow: func(*testing.T, *parkFixture) string {
				return base64.RawURLEncoding.EncodeToString(append(make([]byte, 31), 9))
			},
			assert: func(t *testing.T, f *parkFixture, _ oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				in := oidcprovider.AuthorizeInput{Params: authzParams(), FlowSecret: f.given}
				for _, printed := range []string{
					fmt.Sprintf("%v", in), fmt.Sprintf("%+v", in), fmt.Sprintf("%#v", in), fmt.Sprintf("%s", in),
				} {
					assert.NotContains(t, printed, f.given)
				}

				var buf bytes.Buffer
				slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", slog.Any("input", in))
				assert.NotContains(t, buf.String(), f.given)
			},
		},
		{
			name:   "a refusal sets no flow cookie, even for a browser holding one",
			params: func(v url.Values) { v.Del("scope") },
			flow: func(t *testing.T, f *parkFixture) string {
				t.Helper()
				first, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: authzParams()})
				require.NoError(t, err)

				return first.FlowSecret
			},
			assert: func(t *testing.T, _ *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, res.FlowSecret)
				assert.Contains(t, res.Location, "error=invalid_request")
			},
		},
		{
			name: "two requests sharing a flow secret stay apart",
			flow: func(t *testing.T, f *parkFixture) string {
				t.Helper()
				params := authzParams()
				params.Set("state", "tab-1")
				params.Set("nonce", "nonce-1")
				first, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: params})
				require.NoError(t, err)
				f.firstLocation = first.Location

				return first.FlowSecret
			},
			params: func(v url.Values) {
				v.Set("state", "tab-2")
				v.Set("nonce", "nonce-2")
			},
			assert: func(t *testing.T, f *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, f.given, res.FlowSecret)
				firstHandle, secondHandle := handleOf(t, f.firstLocation), handleOf(t, res.Location)
				assert.NotEqual(t, firstHandle, secondHandle)

				for handle, want := range map[string][2]string{
					firstHandle:  {"tab-1", "nonce-1"},
					secondHandle: {"tab-2", "nonce-2"},
				} {
					stored, loadErr := f.store.Load(t.Context(), handleDigestOf(t, handle))
					require.NoError(t, loadErr)
					assert.Equal(t, want[0], stored.State)
					assert.Equal(t, want[1], stored.Nonce)

					_, viewErr := f.p.PendingRequest(t.Context(), handle, res.FlowSecret)
					require.NoError(t, viewErr, "each can still be answered")
				}
			},
		},
		{
			name: "a consumer shortens the lifetime",
			opts: func(*testing.T) []oidcprovider.Option {
				return []oidcprovider.Option{oidcprovider.WithPendingRequestLifetime(5 * time.Minute)}
			},
			assert: func(t *testing.T, f *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				stored, loadErr := f.store.Load(t.Context(), handleDigestOf(t, handleOf(t, res.Location)))
				require.NoError(t, loadErr)
				assert.Equal(t, f.clk.Now().Add(5*time.Minute), stored.ExpiresAt)
			},
		},
		{
			name: "a store failure parks nothing, and repeats nothing",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				store := NewMockPendingRequestStore(gomock.NewController(t))
				store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("store secret text"))

				return []oidcprovider.Option{oidcprovider.WithPendingRequestStore(store)}
			},
			assert: func(t *testing.T, _ *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				serverError(t, res, err)
				assert.NotContains(t, res.Location, "store secret text")
				assert.Empty(t, res.FlowSecret)
			},
		},
		{
			name: "a caller leaving during the write is no outage",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				store := NewMockPendingRequestStore(gomock.NewController(t))
				store.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, _ *oidcprovider.PendingRequest) error { return ctx.Err() },
				)

				return []oidcprovider.Option{oidcprovider.WithPendingRequestStore(store)}
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, _ *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Empty(t, res.Location)
			},
		},
		{
			name: "no randomness, no handle",
			opts: func(*testing.T) []oidcprovider.Option {
				return []oidcprovider.Option{oidcprovider.WithRandom(iotest.ErrReader(errors.New("entropy secret text")))}
			},
			assert: func(t *testing.T, _ *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				serverError(t, res, err)
				assert.NotContains(t, res.Location, "entropy secret text")
				assert.Empty(t, res.FlowSecret)
			},
		},
		{
			name: "the result prints and logs redacted, and nothing else logs it",
			assert: func(t *testing.T, f *parkFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				for _, printed := range []string{
					fmt.Sprintf("%v", res), fmt.Sprintf("%+v", res), fmt.Sprintf("%#v", res), fmt.Sprintf("%s", res),
				} {
					assert.NotContains(t, printed, res.FlowSecret)
					assert.NotContains(t, printed, "rh.")
				}

				var buf bytes.Buffer
				slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", slog.Any("result", res))
				assert.NotContains(t, buf.String(), res.FlowSecret)
				assert.NotContains(t, buf.String(), "rh.")
				assert.Empty(t, f.logs.String())
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
			loginURL := tc.loginURL
			if loginURL == "" {
				loginURL = issuer + "/login"
			}
			var opts []oidcprovider.Option
			if tc.opts != nil {
				opts = tc.opts(t)
			}
			f := newParkFixture(t, loginURL, opts...)

			if tc.flow != nil {
				f.given = tc.flow(t, f)
			}
			params := authzParams()
			if tc.params != nil {
				tc.params(params)
			}

			res, err := f.p.Authorize(ctx, oidcprovider.AuthorizeInput{Params: params, FlowSecret: f.given})
			tc.assert(t, f, res, err)
		})
	}
}

// TestProvider_Park_Lifetime reads a parked handle at points in its life. The resume is
// a later task's, and shares this read's refusal.
func TestProvider_Park_Lifetime(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		opts   []oidcprovider.Option
		after  time.Duration
		assert func(t *testing.T, view *oidcprovider.PendingView, err error)
	}{
		{
			name:  "alive just before the default lifetime ends",
			after: 10*time.Minute - time.Second,
			assert: func(t *testing.T, view *oidcprovider.PendingView, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, view)
			},
		},
		{
			name:  "unknown as the default lifetime ends",
			after: 10 * time.Minute,
			assert: func(t *testing.T, _ *oidcprovider.PendingView, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
			},
		},
		{
			name:  "unknown at 10 minutes 1 second",
			after: 10*time.Minute + time.Second,
			assert: func(t *testing.T, _ *oidcprovider.PendingView, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
			},
		},
		{
			name:  "unknown at 6 minutes under a 5 minute lifetime",
			opts:  []oidcprovider.Option{oidcprovider.WithPendingRequestLifetime(5 * time.Minute)},
			after: 6 * time.Minute,
			assert: func(t *testing.T, _ *oidcprovider.PendingView, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
			},
		},
		{
			name:  "alive at 20 minutes under a 30 minute lifetime",
			opts:  []oidcprovider.Option{oidcprovider.WithPendingRequestLifetime(30 * time.Minute)},
			after: 20 * time.Minute,
			assert: func(t *testing.T, view *oidcprovider.PendingView, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, view)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newParkFixture(t, issuer+"/login", tc.opts...)
			res, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: authzParams()})
			require.NoError(t, err)

			f.clk.Advance(tc.after)
			view, err := f.p.PendingRequest(t.Context(), handleOf(t, res.Location), res.FlowSecret)
			tc.assert(t, view, err)
		})
	}
}

// pendingParams is a request holding a distinct value in everything the view may or
// must not show.
func pendingParams() url.Values {
	params := authzParams()
	params.Set("state", "the-state-value")
	params.Set("nonce", "the-nonce-value")
	params.Set("scope", "openid profile")
	params.Set("prompt", "login select_account")
	params.Set("max_age", "300")
	params.Set("login_hint", "ada@example.com")
	params.Set("ui_locales", "fr-CA en")
	params.Set("claims_locales", "de")
	params.Set("acr_values", "urn:example:high")

	return params
}

// tweakLast returns s with its last character moved to the next one in the alphabet,
// which leaves a 43-character encoding of 32 bytes decoding to the same bytes, when
// strictness does not refuse it.
func tweakLast(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, s[len(s)-1])

	return s[:len(s)-1] + string(alphabet[last+1])
}

func TestProvider_PendingRequest(t *testing.T) {
	t.Parallel()

	type parked struct {
		handle, flow string
	}
	type testCase struct {
		name   string
		opts   func(t *testing.T) []oidcprovider.Option
		setup  func(t *testing.T, f *parkFixture, p parked) parked
		assert func(t *testing.T, f *parkFixture, p parked, view *oidcprovider.PendingView, err error)
	}

	unknown := func(t *testing.T, f *parkFixture, _ parked, view *oidcprovider.PendingView, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
		assert.Equal(t, oidcprovider.ErrUnknownHandle.Error(), err.Error(), "every refusal reads alike")
		assert.Nil(t, view)
		assert.Empty(t, f.logs.String(), "a refusal logs nothing, least of all a secret")
	}
	advanceTo := func(stage oidcprovider.Stage, s *oidcprovider.SignIn) func(*testing.T, *parkFixture, parked) parked {
		return func(t *testing.T, f *parkFixture, p parked) parked {
			t.Helper()
			require.NoError(t, f.store.Advance(t.Context(), handleDigestOf(t, p.handle), oidcprovider.StageLogin, stage, s))

			return p
		}
	}
	ada := &oidcprovider.SignIn{User: identity.UserID("u-1")}

	cases := []testCase{
		{
			name: "with the right flow secret, the view holds what the page needs",
			assert: func(t *testing.T, _ *parkFixture, _ parked, view *oidcprovider.PendingView, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, view)
				assert.Equal(t, "billing-web", view.ClientID)
				assert.Equal(t, "Billing", view.ClientName)
				assert.Equal(t, []string{"openid", "profile"}, view.Scopes)
				assert.Empty(t, view.GrantedScopes, "no one has signed in to have granted anything")
				assert.Equal(t, []string{"login", "select_account"}, view.Prompt)
				require.NotNil(t, view.MaxAge)
				assert.Equal(t, 300, *view.MaxAge)
				assert.Equal(t, "ada@example.com", view.LoginHint)
				assert.Equal(t, []string{"fr-CA", "en"}, view.UILocales)
				assert.Equal(t, []string{"de"}, view.ClaimsLocales)
				assert.Equal(t, []string{"urn:example:high"}, view.ACRValues)
				assert.Equal(t, oidcprovider.StageLogin, view.Stage)
			},
		},
		{
			name: "no field of the view holds a value the page must not see",
			assert: func(t *testing.T, _ *parkFixture, p parked, view *oidcprovider.PendingView, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, view)
				held := strings.Join(everyString(reflect.ValueOf(view)), "\n")
				for _, secret := range []string{
					authzChallenge, "the-nonce-value", "the-state-value", authzRedirect, p.handle, p.flow,
				} {
					assert.NotContains(t, held, secret)
				}
			},
		},
		{
			name: "the view's fields are the ones the requirement lists",
			assert: func(t *testing.T, _ *parkFixture, _ parked, view *oidcprovider.PendingView, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, view)
				var names []string
				for field := range reflect.TypeFor[oidcprovider.PendingView]().Fields() {
					names = append(names, field.Name)
				}
				assert.ElementsMatch(t, []string{
					"ClientID", "ClientName", "Scopes", "GrantedScopes", "Prompt", "MaxAge",
					"LoginHint", "UILocales", "ClaimsLocales", "ACRValues", "Stage",
				}, names)
			},
		},
		{
			name:  "at the consent stage the view holds what this user already granted",
			setup: advanceTo(oidcprovider.StageConsent, ada),
			assert: func(t *testing.T, _ *parkFixture, _ parked, view *oidcprovider.PendingView, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, view)
				assert.Equal(t, oidcprovider.StageConsent, view.Stage)
				assert.Empty(t, view.GrantedScopes)
			},
		},
		{
			name: "remembered consent of this user and client shows",
			setup: func(t *testing.T, f *parkFixture, p parked) parked {
				t.Helper()
				require.NoError(t, f.consents.Give(t.Context(), ada.User, "billing-web", []string{"openid"}, false, f.clk.Now()))
				require.NoError(t, f.consents.Give(t.Context(), ada.User, "crm-web", []string{"email"}, false, f.clk.Now()))
				require.NoError(t, f.consents.Give(t.Context(), "u-2", "billing-web", []string{"profile"}, false, f.clk.Now()))

				return advanceTo(oidcprovider.StageConsent, ada)(t, f, p)
			},
			assert: func(t *testing.T, _ *parkFixture, _ parked, view *oidcprovider.PendingView, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, view)
				assert.Equal(t, []string{"openid"}, view.GrantedScopes)
			},
		},
		{
			name: "before a sign-in, the consent store is not asked",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()

				return []oidcprovider.Option{oidcprovider.WithConsentStore(NewMockConsentStore(gomock.NewController(t)))}
			},
			assert: func(t *testing.T, _ *parkFixture, _ parked, view *oidcprovider.PendingView, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, view)
				assert.Empty(t, view.GrantedScopes)
			},
		},
		{
			name: "a consent store failure is no refusal",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				consents := NewMockConsentStore(gomock.NewController(t))
				consents.EXPECT().Load(gomock.Any(), ada.User, "billing-web").Return(nil, errors.New("consent secret text"))

				return []oidcprovider.Option{oidcprovider.WithConsentStore(consents)}
			},
			setup: advanceTo(oidcprovider.StageConsent, ada),
			assert: func(t *testing.T, _ *parkFixture, _ parked, view *oidcprovider.PendingView, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.NotContains(t, err.Error(), "consent secret text")
				assert.Nil(t, view)
			},
		},
		{
			name: "the login hint looks no one up",
			assert: func(t *testing.T, _ *parkFixture, _ parked, view *oidcprovider.PendingView, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, view)
				// The user loader is a mock with no expectations, so a call fails the test.
				assert.Equal(t, "ada@example.com", view.LoginHint)
			},
		},

		{name: "a wrong flow secret", setup: func(_ *testing.T, _ *parkFixture, p parked) parked {
			p.flow = base64.RawURLEncoding.EncodeToString(make([]byte, 32))

			return p
		}, assert: unknown},
		{name: "no flow secret", setup: func(_ *testing.T, _ *parkFixture, p parked) parked {
			p.flow = ""

			return p
		}, assert: unknown},
		{name: "a flow secret of the wrong shape", setup: func(_ *testing.T, _ *parkFixture, p parked) parked {
			p.flow = "not-a-secret"

			return p
		}, assert: unknown},
		{name: "a flow secret in a form that decodes the same", setup: func(_ *testing.T, _ *parkFixture, p parked) parked {
			p.flow = tweakLast(p.flow)

			return p
		}, assert: unknown},
		{name: "the handle's secret as the flow secret", setup: func(t *testing.T, _ *parkFixture, p parked) parked {
			t.Helper()
			_, p.flow = handleParts(t, p.handle)

			return p
		}, assert: unknown},
		{name: "no handle", setup: func(_ *testing.T, _ *parkFixture, p parked) parked {
			p.handle = ""

			return p
		}, assert: unknown},
		{name: "a handle of another kind", setup: func(_ *testing.T, _ *parkFixture, p parked) parked {
			p.handle = "rt" + strings.TrimPrefix(p.handle, "rh")

			return p
		}, assert: unknown},
		{name: "a handle with another id", setup: func(t *testing.T, _ *parkFixture, p parked) parked {
			t.Helper()
			_, secret := handleParts(t, p.handle)
			p.handle = "rh.00000000-0000-7000-8000-000000000000." + secret

			return p
		}, assert: unknown},
		{name: "a handle with no id", setup: func(t *testing.T, _ *parkFixture, p parked) parked {
			t.Helper()
			_, secret := handleParts(t, p.handle)
			p.handle = "rh.." + secret

			return p
		}, assert: unknown},
		{name: "a handle with another secret", setup: func(t *testing.T, _ *parkFixture, p parked) parked {
			t.Helper()
			recordID, _ := handleParts(t, p.handle)
			p.handle = "rh." + recordID + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))

			return p
		}, assert: unknown},
		{name: "a handle's secret in a form that decodes the same", setup: func(t *testing.T, _ *parkFixture, p parked) parked {
			t.Helper()
			recordID, secret := handleParts(t, p.handle)
			p.handle = "rh." + recordID + "." + tweakLast(secret)

			return p
		}, assert: unknown},
		{name: "an expired handle", setup: func(_ *testing.T, f *parkFixture, p parked) parked {
			f.clk.Advance(10*time.Minute + time.Second)

			return p
		}, assert: unknown},
		{name: "a handle at the wrong stage: answered", setup: advanceTo(oidcprovider.StageDone, ada), assert: unknown},
		{name: "a handle at the wrong stage: an end-session request", setup: func(t *testing.T, f *parkFixture, _ parked) parked {
			t.Helper()
			secret := base64.RawURLEncoding.EncodeToString(append(make([]byte, 31), 1))
			flow := base64.RawURLEncoding.EncodeToString(append(make([]byte, 31), 2))
			recordID := id.MustParse("00000000-0000-7000-8000-000000000001")
			require.NoError(t, f.store.Create(t.Context(), &oidcprovider.PendingRequest{
				ID:           recordID,
				HandleDigest: digestOf(t, secret),
				FlowDigest:   digestOf(t, flow),
				ClientID:     "billing-web",
				ExpiresAt:    f.clk.Now().Add(time.Minute),
				Stage:        oidcprovider.StageLogout,
			}))

			return parked{handle: "rh." + recordID.String() + "." + secret, flow: flow}
		}, assert: unknown},
		{name: "a client removed since the request was parked", setup: func(t *testing.T, f *parkFixture, p parked) parked {
			t.Helper()
			require.NoError(t, f.registry.Delete(t.Context(), "billing-web"))

			return p
		}, assert: unknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []oidcprovider.Option
			if tc.opts != nil {
				opts = tc.opts(t)
			}
			f := newParkFixture(t, issuer+"/login", opts...)
			res, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: pendingParams()})
			require.NoError(t, err)

			p := parked{handle: handleOf(t, res.Location), flow: res.FlowSecret}
			if tc.setup != nil {
				p = tc.setup(t, f, p)
			}
			view, err := f.p.PendingRequest(t.Context(), p.handle, p.flow)
			tc.assert(t, f, p, view, err)
		})
	}
}

// TestProvider_PendingRequest_StoreFailure uses a store standing in entirely, unlike the
// table above, whose rows read what a real one holds.
func TestProvider_PendingRequest_StoreFailure(t *testing.T) {
	t.Parallel()

	secret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	handle := "rh.00000000-0000-7000-8000-000000000000." + secret

	cases := []struct {
		name   string
		load   func(ctx context.Context, digest []byte) (*oidcprovider.PendingRequest, error)
		ctx    func(context.Context) context.Context
		assert func(t *testing.T, view *oidcprovider.PendingView, err error)
	}{
		{
			name: "a store failure is no refusal",
			load: func(context.Context, []byte) (*oidcprovider.PendingRequest, error) {
				return nil, errors.New("store secret text")
			},
			assert: func(t *testing.T, view *oidcprovider.PendingView, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				require.NotErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.NotContains(t, err.Error(), "store secret text")
				assert.Nil(t, view)
			},
		},
		{
			name: "a caller who left is no outage",
			load: func(ctx context.Context, _ []byte) (*oidcprovider.PendingRequest, error) {
				return nil, ctx.Err()
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, _ *oidcprovider.PendingView, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, oidcprovider.ErrDependency)
			},
		},
		{
			name: "an unknown digest is an unknown handle",
			load: func(context.Context, []byte) (*oidcprovider.PendingRequest, error) {
				return nil, oidcprovider.ErrNotFound
			},
			assert: func(t *testing.T, _ *oidcprovider.PendingView, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				require.NotErrorIs(t, err, oidcprovider.ErrNotFound)
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
			store := NewMockPendingRequestStore(gomock.NewController(t))
			store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(tc.load)
			f := newParkFixture(t, issuer+"/login", oidcprovider.WithPendingRequestStore(store))

			view, err := f.p.PendingRequest(ctx, handle, secret)
			tc.assert(t, view, err)
		})
	}
}

// TestProvider_Park_Resume holds the parking rows only a resume can answer: a handle's
// lifetime as a resume meets it, and a browser's two tabs.
func TestProvider_Park_Resume(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		opts   []oidcprovider.Option
		after  time.Duration
		assert func(t *testing.T, res oidcprovider.ResumeResult, err error)
	}{
		{
			name:  "a resume at 10 minutes 1 second is an unknown handle",
			after: 10*time.Minute + time.Second,
			assert: func(t *testing.T, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Empty(t, res.RedirectTo)
			},
		},
		{
			name:  "a resume at 6 minutes under a 5 minute lifetime is an unknown handle",
			opts:  []oidcprovider.Option{oidcprovider.WithPendingRequestLifetime(5 * time.Minute)},
			after: 6 * time.Minute,
			assert: func(t *testing.T, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Empty(t, res.RedirectTo)
			},
		},
		{
			name:  "a resume just before the lifetime ends proceeds",
			after: 10*time.Minute - time.Second,
			assert: func(t *testing.T, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEmpty(t, res.RedirectTo)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newParkFixture(t, issuer+"/login", tc.opts...)
			res, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: authzParams()})
			require.NoError(t, err)

			f.clk.Advance(tc.after)
			signIn := testSignIn(f, "u-1")
			got, err := f.p.Resume(t.Context(), oidcprovider.ResumeInput{
				Handle:     handleOf(t, res.Location),
				FlowSecret: res.FlowSecret,
				SignIn:     &signIn,
			})
			tc.assert(t, got, err)
		})
	}

	t.Run("two tabs of one browser each resume, with their own state and nonce", func(t *testing.T) {
		t.Parallel()

		f := newParkFixture(t, issuer+"/login")
		require.NoError(t, f.consents.Give(t.Context(), "u-1", "billing-web", []string{"openid", "profile"}, false, f.clk.Now()))

		tab := func(state, nonce, flow string) oidcprovider.AuthorizeResult {
			params := authzParams()
			params.Set("state", state)
			params.Set("nonce", nonce)
			res, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: params, FlowSecret: flow})
			require.NoError(t, err)

			return res
		}
		first := tab("state-1", "nonce-1", "")
		second := tab("state-2", "nonce-2", first.FlowSecret)
		require.Equal(t, first.FlowSecret, second.FlowSecret)

		for _, want := range []struct {
			res          oidcprovider.AuthorizeResult
			state, nonce string
		}{{first, "state-1", "nonce-1"}, {second, "state-2", "nonce-2"}} {
			signIn := testSignIn(f, "u-1")
			got, err := f.p.Resume(t.Context(), oidcprovider.ResumeInput{
				Handle:     handleOf(t, want.res.Location),
				FlowSecret: first.FlowSecret,
				SignIn:     &signIn,
			})
			require.NoError(t, err)

			answer := queryOf(t, got.RedirectTo)
			assert.Equal(t, want.state, answer.Get("state"))
			assert.Equal(t, want.nonce, recordOf(t, f, answer.Get("code")).Nonce)
		}
	})
}

// activeUsers is a user loader whose every user exists and may sign in, for the rows whose
// browser session is judged against its user.
func activeUsers(t *testing.T) identity.UserLoader {
	t.Helper()

	loader := NewMockUserLoader(gomock.NewController(t))
	loader.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) { return activeUser(user) },
	).AnyTimes()

	return loader
}
