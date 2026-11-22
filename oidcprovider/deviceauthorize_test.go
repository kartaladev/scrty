package oidcprovider_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

var (
	deviceNow = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	// deviceKey is the user-code key every row's provider digests under.
	deviceKey = bytes.Repeat([]byte{7}, oidcprovider.MinUserCodeKeyBytes)
	// deviceRaw is what the scripted source gives the device code: 32 bytes of 0xAA.
	deviceRaw = bytes.Repeat([]byte{0xAA}, 32)
	// errSourceBoom is a random source's failure, whose text must never leave the provider.
	errSourceBoom = errors.New("entropy-device-on-fire")
	// errStoreBoom is a store's failure, whose text must never leave the provider.
	errStoreBoom = errors.New("pg-password-hunter2")
	// errIDsBoom is an identifier generator's failure, whose text must never leave the provider.
	errIDsBoom = errors.New("idgen-clock-rollback-secret")
)

const (
	// The user codes the scripted indexes draw from the default alphabet, a byte's value
	// being its index there.
	firstCode  = "BCDFGHJK"
	secondCode = "LMNPQRST"
)

// stream is a scripted random source: the bytes given in order, then err (io.EOF when nil).
// Until arm is called it serves crypto/rand, so that whatever New draws at construction
// leaves the script alone.
type stream struct {
	data  []byte
	err   error
	armed atomic.Bool
}

// arm starts the script, once the provider is built.
func (s *stream) arm() { s.armed.Store(true) }

func (s *stream) Read(p []byte) (int, error) {
	if !s.armed.Load() {
		return rand.Read(p)
	}
	if len(s.data) == 0 {
		if s.err != nil {
			return 0, s.err
		}

		return 0, io.EOF
	}
	n := copy(p, s.data)
	s.data = s.data[n:]

	return n, nil
}

// scripted is a device code's 32 bytes followed by the user codes given as alphabet indexes.
func scripted(err error, codes ...[]byte) *stream {
	data := slicesConcat(deviceRaw, codes...)

	return &stream{data: data, err: err}
}

func slicesConcat(first []byte, rest ...[]byte) []byte {
	out := append([]byte(nil), first...)
	for _, r := range rest {
		out = append(out, r...)
	}

	return out
}

var (
	indexesFirst  = []byte{0, 1, 2, 3, 4, 5, 6, 7}
	indexesSecond = []byte{8, 9, 10, 11, 12, 13, 14, 15}
)

// deviceClients are the clients the device authorization rows ask as.
func deviceClients() []oidcprovider.Client {
	tv := func(c oidcprovider.Client) oidcprovider.Client {
		c.Type = oidcprovider.Public
		c.Secret = nil
		c.ApplicationType = oidcprovider.Native
		c.RedirectURIs = nil
		c.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantDeviceCode}
		c.Scopes = []string{"openid", "profile", "offline_access"}
		c.Resources = []string{"https://api.example.com"}

		return c
	}
	plain := webClient()
	plain.ID = "tv"
	complete := webClient()
	complete.ID = "tv-complete"
	complete.DeviceCompleteURI = true
	cli := webClient()
	cli.ID = "cli"
	cli.AuthMethod = oidcprovider.ClientSecretPost
	cli.RedirectURIs = nil
	cli.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantDeviceCode}
	cli.Scopes = []string{"openid"}
	web := webClient()
	web.Scopes = []string{"openid"}

	return []oidcprovider.Client{tv(plain), tv(complete), cli, web}
}

// idsDown is an identifier generator that works until armed, and fails every identifier
// after, with an error whose text must never leave the provider.
type idsDown struct {
	next  id.Generator
	armed atomic.Bool
}

func (g *idsDown) NewID() (id.ID, error) {
	if g.armed.Load() {
		return id.ID{}, errIDsBoom
	}

	return g.next.NewID()
}

func TestAuthorizeDevice(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// noGrant builds the provider without the device grant.
		noGrant bool
		// entry is the code-entry URL, "/activate" by default.
		entry string
		req   oidcprovider.DeviceAuthorizationRequest
		// random is the provider's source, the scripted one with a first code by default.
		random *stream
		// idsDown makes the identifier generator fail once the provider is built.
		idsDown bool
		ctx     func(ctx context.Context) context.Context
		// creates is how many records the store is to be asked to keep. A row that stores
		// nothing leaves it at 0, and the mock is told so with Times(0).
		creates int
		assert  func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, logs string)
	}

	publicForm := func(extra url.Values) url.Values {
		form := url.Values{"client_id": {"tv"}}
		for k, v := range extra {
			form[k] = v
		}

		return form
	}
	refusedAs := func(code string, leaks ...string) func(*testing.T, *oidcprovider.DeviceAuthorizationResponse, error, []*oidcprovider.DeviceAuthorization, string) {
		return func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, logs string) {
			t.Helper()
			var refusal *oidcprovider.Error
			require.ErrorAs(t, err, &refusal)
			assert.Equal(t, code, refusal.Code)
			assert.Nil(t, resp)
			assert.Empty(t, stored)
			for _, leak := range leaks {
				assert.NotContains(t, err.Error(), leak)
				assert.NotContains(t, logs, leak)
			}
		}
	}
	dependencyFailed := func(leaks ...string) func(*testing.T, *oidcprovider.DeviceAuthorizationResponse, error, []*oidcprovider.DeviceAuthorization, string) {
		return func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, logs string) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrDependency)
			assert.Nil(t, resp)
			assert.Empty(t, stored)
			for _, leak := range leaks {
				assert.NotContains(t, err.Error(), leak)
				assert.NotContains(t, logs, leak)
			}
		}
	}
	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	cases := []testCase{
		{
			name: "a wrong secret is invalid_client",
			req: oidcprovider.DeviceAuthorizationRequest{
				Form: url.Values{"client_id": {"cli"}, "client_secret": {"wrong-secret-wrong-secret-wrong-sec"}, "scope": {"openid"}},
			},
			assert: refusedAs(oidcprovider.CodeInvalidClient, "wrong-secret"),
		},
		{
			name:   "an unknown client is invalid_client",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: url.Values{"client_id": {"nobody"}, "scope": {"openid"}}},
			assert: refusedAs(oidcprovider.CodeInvalidClient),
		},
		{
			name: "a secret in the query is invalid_request",
			req: oidcprovider.DeviceAuthorizationRequest{
				Form:  publicForm(url.Values{"scope": {"openid"}}),
				Query: url.Values{"client_secret": {"query-secret"}},
			},
			assert: refusedAs(oidcprovider.CodeInvalidRequest, "query-secret"),
		},
		{
			name: "a client for the code flow only is unauthorized_client",
			req: oidcprovider.DeviceAuthorizationRequest{
				Form: url.Values{"client_id": {"billing-web"}, "scope": {"openid"}},
				Credentials: oidcprovider.ClientCredentials{
					Authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("billing-web:"+string(webClient().Secret))),
				},
			},
			assert: refusedAs(oidcprovider.CodeUnauthorizedClient),
		},
		{
			name:    "a provider without the grant is unauthorized_client",
			noGrant: true,
			req: oidcprovider.DeviceAuthorizationRequest{
				Form: url.Values{"client_id": {"billing-web"}, "scope": {"openid"}},
				Credentials: oidcprovider.ClientCredentials{
					Authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("billing-web:"+string(webClient().Secret))),
				},
			},
			assert: refusedAs(oidcprovider.CodeUnauthorizedClient),
		},
		{
			name:   "a repeated scope is invalid_request",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid", "profile"}})},
			assert: refusedAs(oidcprovider.CodeInvalidRequest),
		},
		{
			name:   "an empty scope is read as none, and a request needs one",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {""}})},
			assert: refusedAs(oidcprovider.CodeInvalidRequest),
		},
		{
			name:   "no scope is invalid_request",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: publicForm(nil)},
			assert: refusedAs(oidcprovider.CodeInvalidRequest),
		},
		{
			name:   "a NUL byte in the scope is invalid_request, never echoed",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid\x00evil-marker"}})},
			assert: refusedAs(oidcprovider.CodeInvalidRequest, "evil-marker", "\x00"),
		},
		{
			name:   "invalid UTF-8 in the scope is invalid_request, never echoed",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid \xff\xfebad-marker"}})},
			assert: refusedAs(oidcprovider.CodeInvalidRequest, "bad-marker"),
		},
		{
			name:   "an oversized scope is invalid_request",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid " + strings.Repeat("s", 5000)}})},
			assert: refusedAs(oidcprovider.CodeInvalidRequest),
		},
		{
			name:   "a scope the client may not ask for is invalid_scope",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid admin"}})},
			assert: refusedAs(oidcprovider.CodeInvalidScope),
		},
		{
			name:   "a resource the client may not ask for is invalid_target",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid"}, "resource": {"https://other.example.com"}})},
			assert: refusedAs(oidcprovider.CodeInvalidTarget),
		},
		{
			name:   "a NUL byte in a resource is invalid_request",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid"}, "resource": {"https://api.example.com\x00"}})},
			assert: refusedAs(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "an already cancelled context stores nothing",
			req:  oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid"}})},
			ctx:  cancelled,
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, _ string) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Nil(t, resp)
				assert.Empty(t, stored)
			},
		},
		{
			name:   "a failing source for the device code is a dependency failure, nothing stored",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid"}})},
			random: &stream{err: errSourceBoom},
			assert: dependencyFailed(errSourceBoom.Error()),
		},
		{
			name:   "a failing source for the user code is a dependency failure, nothing stored",
			req:    oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid"}})},
			random: scripted(errSourceBoom),
			assert: dependencyFailed(errSourceBoom.Error()),
		},
		{
			name:    "a failing identifier generator is a dependency failure, nothing stored",
			req:     oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid"}})},
			idsDown: true,
			assert:  dependencyFailed(errIDsBoom.Error()),
		},
		{
			name:    "a public client gets the defaults and no complete URI",
			req:     oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{"scope": {"openid profile"}})},
			creates: 1,
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, logs string) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Len(t, stored, 1)
				rec := stored[0]

				assert.Equal(t, issuer+"/activate", resp.VerificationURI)
				assert.Empty(t, resp.VerificationURIComplete)
				assert.Equal(t, 600, resp.ExpiresIn)
				assert.Equal(t, 5, resp.Interval)
				assert.Equal(t, "BCDF-GHJK", resp.UserCode)

				raw, decodeErr := base64.RawURLEncoding.DecodeString(resp.DeviceCode)
				require.NoError(t, decodeErr)
				assert.Equal(t, deviceRaw, raw)

				// The record holds digests: the device code's SHA-256, and the user code's
				// HMAC over the raw code, never the displayed form.
				sum := sha256.Sum256(deviceRaw)
				assert.Equal(t, sum[:], rec.DeviceCodeDigest)
				mac := hmac.New(sha256.New, deviceKey)
				mac.Write([]byte(firstCode))
				assert.Equal(t, mac.Sum(nil), rec.UserCodeDigest)
				assert.Empty(t, rec.ClaimFlowDigest)

				assert.Equal(t, "tv", rec.ClientID)
				assert.Equal(t, []string{"openid", "profile"}, rec.Scopes)
				assert.Empty(t, rec.Resources)
				assert.NotEqual(t, id.Nil, rec.ID)
				assert.Equal(t, deviceNow, rec.IssuedAt)
				assert.Equal(t, deviceNow.Add(600*time.Second), rec.ExpiresAt)
				assert.Equal(t, 5*time.Second, rec.Interval)
				assert.Equal(t, oidcprovider.DeviceIssued, rec.State)
				assert.Nil(t, rec.Approval)

				// No dump of the record, nor any log line, holds either code.
				dump := fmt.Sprintf("%#v %+v", rec, rec)
				for _, secret := range []string{resp.DeviceCode, resp.UserCode, firstCode} {
					assert.NotContains(t, dump, secret)
					assert.NotContains(t, logs, secret)
				}
			},
		},
		{
			name:    "a client registered for it gets the complete URI, with the displayed code",
			req:     oidcprovider.DeviceAuthorizationRequest{Form: url.Values{"client_id": {"tv-complete"}, "scope": {"openid"}}},
			creates: 1,
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, _ []*oidcprovider.DeviceAuthorization, _ string) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, issuer+"/activate", resp.VerificationURI)
				assert.Equal(t, issuer+"/activate?user_code=BCDF-GHJK", resp.VerificationURIComplete)
			},
		},
		{
			name:    "the complete URI keeps the entry URL's own query",
			entry:   "/activate?src=tv&lang=en",
			req:     oidcprovider.DeviceAuthorizationRequest{Form: url.Values{"client_id": {"tv-complete"}, "scope": {"openid"}}},
			creates: 1,
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, _ []*oidcprovider.DeviceAuthorization, _ string) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, issuer+"/activate?src=tv&lang=en", resp.VerificationURI)
				u, parseErr := url.Parse(resp.VerificationURIComplete)
				require.NoError(t, parseErr)
				assert.Equal(t, url.Values{"src": {"tv"}, "lang": {"en"}, "user_code": {"BCDF-GHJK"}}, u.Query())
				assert.Equal(t, "/activate", u.Path)
			},
		},
		{
			name: "a confidential client authenticates and is served",
			req: oidcprovider.DeviceAuthorizationRequest{
				Form: url.Values{"client_id": {"cli"}, "client_secret": {string(webClient().Secret)}, "scope": {"openid"}},
			},
			creates: 1,
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, _ string) {
				t.Helper()
				require.NoError(t, err)
				require.Len(t, stored, 1)
				assert.Equal(t, "cli", stored[0].ClientID)
				assert.NotEmpty(t, resp.DeviceCode)
			},
		},
		{
			name: "empty and repeated resources, unknown parameters and offline_access are read as the authorization endpoint reads them",
			req: oidcprovider.DeviceAuthorizationRequest{Form: publicForm(url.Values{
				"scope":    {"openid offline_access"},
				"resource": {"", "https://api.example.com", "https://api.example.com"},
				// Unknown parameters are ignored, whatever their size and count.
				"state": {strings.Repeat("x", 100000)},
				"foo":   {"bar"},
			})},
			creates: 1,
			assert: func(t *testing.T, _ *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, _ string) {
				t.Helper()
				// A repeated unknown parameter is still a repeated parameter, so this row
				// has none: state and foo are given once.
				require.NoError(t, err)
				require.Len(t, stored, 1)
				assert.Equal(t, []string{"openid"}, stored[0].Scopes, "offline_access is dropped for a client with no refresh grant")
				assert.Equal(t, []string{"https://api.example.com"}, stored[0].Resources)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			store := NewMockDeviceAuthorizationStore(ctrl)
			var stored []*oidcprovider.DeviceAuthorization
			call := store.EXPECT().Create(gomock.Any(), gomock.Any(), deviceNow).
				DoAndReturn(func(_ context.Context, rec *oidcprovider.DeviceAuthorization, _ time.Time) error {
					stored = append(stored, rec)

					return nil
				})
			if tc.creates == 0 {
				call.Times(0)
			} else {
				call.Times(tc.creates)
			}

			random := tc.random
			if random == nil {
				random = scripted(nil, indexesFirst)
			}
			entry := tc.entry
			if entry == "" {
				entry = "/activate"
			}
			logs := &bytes.Buffer{}
			ids := &idsDown{next: id.NewV7Generator()}
			opts := []oidcprovider.Option{
				oidcprovider.WithClock(clockwork.NewFakeClockAt(deviceNow)),
				oidcprovider.WithRandom(random),
				oidcprovider.WithIDGenerator(ids),
				oidcprovider.WithLogger(slog.New(slog.NewTextHandler(logs, nil))),
			}
			if !tc.noGrant {
				opts = append(opts, oidcprovider.WithDeviceAuthorization(issuer+entry,
					oidcprovider.WithUserCodeKey(deviceKey),
					oidcprovider.WithDeviceAuthorizationStore(store)))
			}
			deps := validDeps(t)
			if !tc.noGrant {
				// A client listing the device grant is refused by a provider without it.
				deps.Clients = deviceClients()
			}
			p, err := oidcprovider.New(deps, opts...)
			require.NoError(t, err)
			random.arm()
			ids.armed.Store(tc.idsDown)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			resp, err := p.AuthorizeDevice(ctx, tc.req)
			tc.assert(t, resp, err, stored, logs.String())
		})
	}
}

func TestDeviceLifetimeAndInterval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []oidcprovider.DeviceOption
		// assert reads the construction result, and the response of one request when it built.
		assert func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, rec *oidcprovider.DeviceAuthorization, err error)
	}

	refused := func(option string) func(*testing.T, *oidcprovider.DeviceAuthorizationResponse, *oidcprovider.DeviceAuthorization, error) {
		return func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, _ *oidcprovider.DeviceAuthorization, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, option)
			assert.Nil(t, resp)
		}
	}
	served := func(expiresIn, interval int) func(*testing.T, *oidcprovider.DeviceAuthorizationResponse, *oidcprovider.DeviceAuthorization, error) {
		return func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, rec *oidcprovider.DeviceAuthorization, err error) {
			t.Helper()
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotNil(t, rec)
			assert.Equal(t, expiresIn, resp.ExpiresIn)
			assert.Equal(t, interval, resp.Interval)
			assert.Equal(t, deviceNow.Add(time.Duration(expiresIn)*time.Second), rec.ExpiresAt)
			assert.Equal(t, time.Duration(interval)*time.Second, rec.Interval)
		}
	}

	cases := []testCase{
		{
			name:   "the defaults are 600 and 5",
			assert: served(600, 5),
		},
		{
			name:   "15 minutes",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDeviceLifetime(15 * time.Minute)},
			assert: served(900, 5),
		},
		{
			name:   "the bounds themselves are accepted",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDeviceLifetime(30 * time.Minute), oidcprovider.WithDevicePollInterval(time.Second)},
			assert: served(1800, 1),
		},
		{
			name:   "the shortest lifetime with the longest interval below it",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDeviceLifetime(time.Minute), oidcprovider.WithDevicePollInterval(59 * time.Second)},
			assert: served(60, 59),
		},
		{
			name:   "a custom interval",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDevicePollInterval(10 * time.Second)},
			assert: served(600, 10),
		},
		{
			name:   "an hour is refused",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDeviceLifetime(time.Hour)},
			assert: refused("WithDeviceLifetime"),
		},
		{
			name:   "59 seconds is refused",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDeviceLifetime(59 * time.Second)},
			assert: refused("WithDeviceLifetime"),
		},
		{
			name:   "a zero lifetime is refused, not read as the default",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDeviceLifetime(0)},
			assert: refused("WithDeviceLifetime"),
		},
		{
			name:   "a negative lifetime is refused",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDeviceLifetime(-time.Minute)},
			assert: refused("WithDeviceLifetime"),
		},
		{
			name:   "a zero interval is refused, not read as the default",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDevicePollInterval(0)},
			assert: refused("WithDevicePollInterval"),
		},
		{
			name:   "a sub-second interval is refused",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDevicePollInterval(999 * time.Millisecond)},
			assert: refused("WithDevicePollInterval"),
		},
		{
			name:   "61 seconds is refused",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDevicePollInterval(61 * time.Second)},
			assert: refused("WithDevicePollInterval"),
		},
		{
			name:   "an interval equal to the lifetime is refused",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDeviceLifetime(time.Minute), oidcprovider.WithDevicePollInterval(time.Minute)},
			assert: refused("WithDevicePollInterval"),
		},
		{
			name:   "an interval above the lifetime is refused",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDeviceLifetime(time.Minute), oidcprovider.WithDevicePollInterval(2 * time.Minute)},
			assert: refused("WithDevicePollInterval"),
		},
		{
			name:   "a whole-second lifetime is the response's, not a truncated one",
			opts:   []oidcprovider.DeviceOption{oidcprovider.WithDeviceLifetime(90 * time.Second)},
			assert: served(90, 5),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockDeviceAuthorizationStore(gomock.NewController(t))
			var stored *oidcprovider.DeviceAuthorization
			store.EXPECT().Create(gomock.Any(), gomock.Any(), deviceNow).
				DoAndReturn(func(_ context.Context, rec *oidcprovider.DeviceAuthorization, _ time.Time) error {
					stored = rec

					return nil
				}).AnyTimes()

			device := append([]oidcprovider.DeviceOption{
				oidcprovider.WithUserCodeKey(deviceKey),
				oidcprovider.WithDeviceAuthorizationStore(store),
			}, tc.opts...)
			deps := validDeps(t)
			deps.Clients = deviceClients()
			random := scripted(nil, indexesFirst)
			p, err := oidcprovider.New(deps,
				oidcprovider.WithClock(clockwork.NewFakeClockAt(deviceNow)),
				oidcprovider.WithRandom(random),
				oidcprovider.WithIDGenerator(id.NewV7Generator()),
				oidcprovider.WithDeviceAuthorization(issuer+"/activate", device...),
			)
			if err != nil {
				tc.assert(t, nil, nil, err)

				return
			}
			random.arm()
			resp, err := p.AuthorizeDevice(t.Context(), oidcprovider.DeviceAuthorizationRequest{
				Form: url.Values{"client_id": {"tv"}, "scope": {"openid"}},
			})
			tc.assert(t, resp, stored, err)
		})
	}
}

func TestAuthorizeDevice_UserCodeCollision(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// random is the source; each user code draws 8 bytes.
		random func() *stream
		// script is the store's answers to Create, in order, and so how many calls it is to
		// receive.
		script []error
		// cancelAt is the Create call, counted from 1, that cancels the caller's context as
		// it answers; 0 leaves the context alone.
		cancelAt int
		assert   func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, logs string)
	}

	taken := oidcprovider.ErrUserCodeTaken
	dependencyFailed := func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, _ []*oidcprovider.DeviceAuthorization, logs string) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrDependency)
		assert.Nil(t, resp)
		assert.NotContains(t, err.Error(), errStoreBoom.Error())
		assert.NotContains(t, logs, errStoreBoom.Error())
		for _, code := range []string{firstCode, secondCode} {
			assert.NotContains(t, err.Error(), code)
			assert.NotContains(t, logs, code)
		}
	}

	cases := []testCase{
		{
			name:   "a first collision draws another code, and the response carries the second",
			random: func() *stream { return scripted(nil, indexesFirst, indexesSecond) },
			script: []error{taken, nil},
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, _ string) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "LMNP-QRST", resp.UserCode)
				require.Len(t, stored, 2)
				mac := hmac.New(sha256.New, deviceKey)
				mac.Write([]byte(firstCode))
				assert.Equal(t, mac.Sum(nil), stored[0].UserCodeDigest)
				mac = hmac.New(sha256.New, deviceKey)
				mac.Write([]byte(secondCode))
				assert.Equal(t, mac.Sum(nil), stored[1].UserCodeDigest)
				assert.Equal(t, stored[0].DeviceCodeDigest, stored[1].DeviceCodeDigest, "only the user code is drawn again")
			},
		},
		{
			name: "five collisions in a row are a server error, with no sixth attempt",
			random: func() *stream {
				return scripted(nil, indexesFirst, indexesSecond, indexesFirst, indexesSecond, indexesFirst, indexesSecond)
			},
			script: []error{taken, taken, taken, taken, taken},
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, logs string) {
				t.Helper()
				dependencyFailed(t, resp, err, stored, logs)
				assert.Len(t, stored, 5)
			},
		},
		{
			name: "four collisions then a free code succeeds",
			random: func() *stream {
				return scripted(nil, indexesFirst, indexesFirst, indexesFirst, indexesFirst, indexesSecond)
			},
			script: []error{taken, taken, taken, taken, nil},
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, _ string) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "LMNP-QRST", resp.UserCode)
				assert.Len(t, stored, 5)
			},
		},
		{
			name:   "a store error that is no collision fails at once, without retrying",
			random: func() *stream { return scripted(nil, indexesFirst, indexesSecond) },
			script: []error{errStoreBoom},
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, logs string) {
				t.Helper()
				dependencyFailed(t, resp, err, stored, logs)
				assert.Len(t, stored, 1)
			},
		},
		{
			name:   "a collision followed by a store error fails there, without a third attempt",
			random: func() *stream { return scripted(nil, indexesFirst, indexesSecond, indexesFirst) },
			script: []error{taken, errStoreBoom},
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, logs string) {
				t.Helper()
				dependencyFailed(t, resp, err, stored, logs)
				assert.Len(t, stored, 2)
			},
		},
		{
			name:   "the source failing on the second code ends the request after one attempt",
			random: func() *stream { return scripted(errSourceBoom, indexesFirst) },
			script: []error{taken},
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, logs string) {
				t.Helper()
				dependencyFailed(t, resp, err, stored, logs)
				assert.NotContains(t, err.Error(), errSourceBoom.Error())
				assert.Len(t, stored, 1)
			},
		},
		{
			name:     "a caller who leaves during a collision gets no second attempt",
			random:   func() *stream { return scripted(nil, indexesFirst, indexesSecond) },
			script:   []error{taken},
			cancelAt: 1,
			assert: func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error, stored []*oidcprovider.DeviceAuthorization, _ string) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, resp)
				assert.Len(t, stored, 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			store := NewMockDeviceAuthorizationStore(gomock.NewController(t))
			var stored []*oidcprovider.DeviceAuthorization
			// Expectations with the same matchers are consumed in the order they are declared.
			for _, answer := range tc.script {
				store.EXPECT().Create(gomock.Any(), gomock.Any(), deviceNow).
					DoAndReturn(func(_ context.Context, rec *oidcprovider.DeviceAuthorization, _ time.Time) error {
						stored = append(stored, rec)
						if len(stored) == tc.cancelAt {
							cancel()
						}

						return answer
					})
			}

			logs := &bytes.Buffer{}
			deps := validDeps(t)
			deps.Clients = deviceClients()
			random := tc.random()
			p, err := oidcprovider.New(deps,
				oidcprovider.WithClock(clockwork.NewFakeClockAt(deviceNow)),
				oidcprovider.WithRandom(random),
				oidcprovider.WithIDGenerator(id.NewV7Generator()),
				oidcprovider.WithLogger(slog.New(slog.NewTextHandler(logs, nil))),
				oidcprovider.WithDeviceAuthorization(issuer+"/activate",
					oidcprovider.WithUserCodeKey(deviceKey),
					oidcprovider.WithDeviceAuthorizationStore(store)),
			)
			require.NoError(t, err)
			random.arm()

			resp, err := p.AuthorizeDevice(ctx, oidcprovider.DeviceAuthorizationRequest{
				Form: url.Values{"client_id": {"tv"}, "scope": {"openid"}},
			})
			tc.assert(t, resp, err, stored, logs.String())
		})
	}
}

func TestDeviceAuthorization_PrintsRedacted(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-device-value"
	cases := []struct {
		name  string
		value any
	}{
		{"request form", oidcprovider.DeviceAuthorizationRequest{Form: url.Values{"client_id": {"tv"}, "scope": {secret}}}},
		{"request query", oidcprovider.DeviceAuthorizationRequest{Query: url.Values{"client_secret": {secret}}}},
		{"request credentials", oidcprovider.DeviceAuthorizationRequest{Credentials: oidcprovider.ClientCredentials{Authorization: "Basic " + secret}}},
		{"response device code", oidcprovider.DeviceAuthorizationResponse{DeviceCode: secret}},
		{"response user code", oidcprovider.DeviceAuthorizationResponse{UserCode: secret}},
		{"response complete URI", oidcprovider.DeviceAuthorizationResponse{VerificationURIComplete: "https://id.example.com/activate?user_code=" + secret}},
		{"response pointer", &oidcprovider.DeviceAuthorizationResponse{DeviceCode: secret}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logs := &bytes.Buffer{}
			slog.New(slog.NewJSONHandler(logs, nil)).Info("value", "value", tc.value)
			for _, printed := range []string{
				fmt.Sprintf("%v", tc.value), fmt.Sprintf("%+v", tc.value), fmt.Sprintf("%#v", tc.value),
				fmt.Sprintf("%s", tc.value), logs.String(),
			} {
				assert.NotContains(t, printed, secret)
			}
		})
	}
}
