package oidcprovider_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
)

const (
	basicSecret   = "basic-0123456789abcdef0123456789abcdef"
	postSecret    = "post-0123456789abcdef0123456789abcdef"
	reservedChars = "a+b/c-0123456789abcdef0123456789abcdef"
	holdsColon    = "a:b-0123456789abcdef0123456789abcdef"
	oldSecret     = "old-0123456789abcdef0123456789abcdef"
	newSecret     = "new-0123456789abcdef0123456789abcdef"
)

// authNow is the moment the authentication tables run at.
var authNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// basic builds a Basic header the way the standard says: each half form-URL-encoded,
// then the whole Base64-encoded.
func basic(id, secret string) string {
	return rawBasic(url.QueryEscape(id) + ":" + url.QueryEscape(secret))
}

// rawBasic builds a Basic header from text taken as it is.
func rawBasic(text string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(text))
}

// form builds url.Values from name, value pairs, which may repeat a name.
func form(pairs ...string) url.Values {
	out := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out.Add(pairs[i], pairs[i+1])
	}

	return out
}

// secretProvider is a provider holding one client per secret method and kind.
func secretProvider(t *testing.T, opts ...oidcprovider.Option) *oidcprovider.Provider {
	t.Helper()

	registered := func(id string, method oidcprovider.AuthMethod, secret string) oidcprovider.Client {
		return oidcprovider.Client{
			ID:           id,
			Type:         oidcprovider.Confidential,
			AuthMethod:   method,
			Secret:       []byte(secret),
			RedirectURIs: []string{"https://rp.example.com/cb"},
		}
	}

	registry, err := oidcprovider.NewMemoryRegistry([]oidcprovider.Client{
		registered("billing-web", oidcprovider.ClientSecretBasic, basicSecret),
		registered("crm-web", oidcprovider.ClientSecretPost, postSecret),
		registered("reserved-web", oidcprovider.ClientSecretBasic, reservedChars),
		registered("colon-web", oidcprovider.ClientSecretBasic, holdsColon),
		registered("name with space", oidcprovider.ClientSecretBasic, basicSecret),
		{
			ID:           "spa",
			Type:         oidcprovider.Public,
			RedirectURIs: []string{"https://spa.example.com/cb"},
		},
	})
	require.NoError(t, err)

	old, err := oidcprovider.NewClientSecret([]byte(oldSecret), authNow.Add(-time.Minute))
	require.NoError(t, err)
	current, err := oidcprovider.NewClientSecret([]byte(newSecret), time.Time{})
	require.NoError(t, err)
	require.NoError(t, registry.PutRegistered(t.Context(), oidcprovider.RegisteredClient{
		Client:  registered("rotating-web", oidcprovider.ClientSecretBasic, ""),
		Secrets: []oidcprovider.ClientSecret{old, current},
	}))

	d := validDeps(t)
	d.Clients = nil
	d.Registry = registry

	p, err := oidcprovider.New(d, append([]oidcprovider.Option{oidcprovider.WithClock(clockwork.NewFakeClockAt(authNow))}, opts...)...)
	require.NoError(t, err)

	return p
}

// refusedAs asserts a protocol refusal whose text is the code and nothing else, so
// it can carry no presented value.
func refusedAs(t *testing.T, code string, rc *oidcprovider.RegisteredClient, err error) {
	t.Helper()

	assert.Nil(t, rc)
	var refusal *oidcprovider.Error
	require.ErrorAs(t, err, &refusal, "a refusal must be a protocol error")
	assert.Equal(t, code, refusal.Code)
	assert.Equal(t, "oidcprovider: "+code, err.Error())
}

func TestAuthenticateClient(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		creds  oidcprovider.ClientCredentials
		assert func(t *testing.T, rc *oidcprovider.RegisteredClient, err error)
	}

	authenticated := func(id string) func(*testing.T, *oidcprovider.RegisteredClient, error) {
		return func(t *testing.T, rc *oidcprovider.RegisteredClient, err error) {
			t.Helper()
			require.NoError(t, err)
			require.NotNil(t, rc)
			assert.Equal(t, id, rc.ID)
		}
	}
	invalidClient := func(t *testing.T, rc *oidcprovider.RegisteredClient, err error) {
		t.Helper()
		refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)
	}
	invalidRequest := func(t *testing.T, rc *oidcprovider.RegisteredClient, err error) {
		t.Helper()
		refusedAs(t, oidcprovider.CodeInvalidRequest, rc, err)
	}

	cases := []testCase{
		// client_secret_basic.
		{
			name:   "basic with the right secret",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret)},
			assert: authenticated("billing-web"),
		},
		{
			name:   "the scheme compares without case",
			creds:  oidcprovider.ClientCredentials{Authorization: "bAsIc " + basic("billing-web", basicSecret)[len("Basic "):]},
			assert: authenticated("billing-web"),
		},
		{
			name:   "basic with a wrong secret",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret+"x")},
			assert: invalidClient,
		},
		{
			name:   "a secret with reserved characters sent form-URL-encoded",
			creds:  oidcprovider.ClientCredentials{Authorization: rawBasic("reserved-web:a%2Bb%2Fc-0123456789abcdef0123456789abcdef")},
			assert: authenticated("reserved-web"),
		},
		{
			name:   "a plus left unencoded decodes to a space, and so is the wrong secret",
			creds:  oidcprovider.ClientCredentials{Authorization: rawBasic("reserved-web:a+b/c-0123456789abcdef0123456789abcdef")},
			assert: invalidClient,
		},
		{
			name:   "an encoded colon in the secret",
			creds:  oidcprovider.ClientCredentials{Authorization: rawBasic("colon-web:a%3Ab-0123456789abcdef0123456789abcdef")},
			assert: authenticated("colon-web"),
		},
		{
			name:   "the header splits at the first colon, so a raw colon stays in the secret",
			creds:  oidcprovider.ClientCredentials{Authorization: rawBasic("colon-web:" + holdsColon)},
			assert: authenticated("colon-web"),
		},
		{
			name:   "an encoded client identifier is decoded",
			creds:  oidcprovider.ClientCredentials{Authorization: rawBasic("name+with%20space:" + basicSecret)},
			assert: authenticated("name with space"),
		},
		{
			name:   "basic that is not base64",
			creds:  oidcprovider.ClientCredentials{Authorization: "Basic !!!not-base64!!!"},
			assert: invalidClient,
		},
		{
			name:   "basic with no colon",
			creds:  oidcprovider.ClientCredentials{Authorization: rawBasic("billing-web")},
			assert: invalidClient,
		},
		{
			name:   "basic whose identifier does not URL-decode",
			creds:  oidcprovider.ClientCredentials{Authorization: rawBasic("%zz:" + basicSecret)},
			assert: invalidClient,
		},
		{
			name:   "basic whose secret does not URL-decode",
			creds:  oidcprovider.ClientCredentials{Authorization: rawBasic("billing-web:%zz")},
			assert: invalidClient,
		},
		{
			name:   "basic with no identifier",
			creds:  oidcprovider.ClientCredentials{Authorization: rawBasic(":" + basicSecret)},
			assert: invalidClient,
		},
		{
			name:   "the scheme with nothing after it",
			creds:  oidcprovider.ClientCredentials{Authorization: "Basic"},
			assert: invalidClient,
		},
		{
			name:   "another scheme is no method a client can use",
			creds:  oidcprovider.ClientCredentials{Authorization: "Bearer abc", Form: form("client_id", "spa")},
			assert: invalidClient,
		},
		{
			name:   "an unknown client over basic",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("nobody", basicSecret)},
			assert: invalidClient,
		},
		{
			name:   "an expired secret",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("rotating-web", oldSecret)},
			assert: invalidClient,
		},
		{
			name:   "the live secret beside an expired one",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("rotating-web", newSecret)},
			assert: authenticated("rotating-web"),
		},

		// client_secret_post.
		{
			name:   "post with the right secret",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "crm-web", "client_secret", postSecret)},
			assert: authenticated("crm-web"),
		},
		{
			name:   "post with a wrong secret",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "crm-web", "client_secret", postSecret+"x")},
			assert: invalidClient,
		},
		{
			name:   "post with no client_id",
			creds:  oidcprovider.ClientCredentials{Form: form("client_secret", postSecret)},
			assert: invalidClient,
		},
		{
			name:   "an unknown client over post",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "nobody", "client_secret", postSecret)},
			assert: invalidClient,
		},

		// The wrong method, each with the client's right secret.
		{
			name:   "a basic client sending its secret in the body",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "billing-web", "client_secret", basicSecret)},
			assert: invalidClient,
		},
		{
			name:   "a post client sending its secret in the header",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("crm-web", postSecret)},
			assert: invalidClient,
		},
		{
			name:   "a confidential client naming itself with no secret",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "billing-web")},
			assert: invalidClient,
		},
		{
			name:   "a confidential client with an empty secret, which counts as omitted",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "billing-web", "client_secret", "")},
			assert: invalidClient,
		},

		// none.
		{
			name:   "a public client with only client_id",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "spa")},
			assert: authenticated("spa"),
		},
		{
			name:   "a public client with an empty secret, which counts as omitted",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "spa", "client_secret", "")},
			assert: authenticated("spa"),
		},
		{
			name:   "a public client sending a secret in the body",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "spa", "client_secret", postSecret)},
			assert: invalidClient,
		},
		{
			name:   "a public client sending a secret in the header",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("spa", postSecret)},
			assert: invalidClient,
		},
		{
			name:   "an unknown client naming itself",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "nobody")},
			assert: invalidClient,
		},
		{
			name:   "a Digest scheme carrying a right id and secret",
			creds:  oidcprovider.ClientCredentials{Authorization: "Digest " + base64.StdEncoding.EncodeToString([]byte("billing-web:"+basicSecret))},
			assert: invalidClient,
		},
		{
			name:   "nothing presented at all",
			creds:  oidcprovider.ClientCredentials{},
			assert: invalidClient,
		},

		// Two methods, two identifiers (R11).
		{
			name:   "basic and a client_assertion",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret), Form: form("client_assertion", "a.b.c")},
			assert: invalidRequest,
		},
		{
			name:   "basic and only a client_assertion_type",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret), Form: form("client_assertion_type", "x")},
			assert: invalidRequest,
		},
		{
			name:   "basic and a body secret",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret), Form: form("client_secret", basicSecret)},
			assert: invalidRequest,
		},
		{
			name:   "a body secret and a client_assertion",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "crm-web", "client_secret", postSecret, "client_assertion", "a.b.c")},
			assert: invalidRequest,
		},
		{
			name:   "an undecodable header and a client_assertion is still two methods",
			creds:  oidcprovider.ClientCredentials{Authorization: "Basic !!!", Form: form("client_assertion", "a.b.c")},
			assert: invalidRequest,
		},
		{
			name:   "basic naming one client and the body another",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret), Form: form("client_id", "crm-web")},
			assert: invalidRequest,
		},
		{
			name:   "basic and the body naming the same client",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret), Form: form("client_id", "billing-web")},
			assert: authenticated("billing-web"),
		},
		{
			name:   "basic and an empty client_id, which counts as omitted",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret), Form: form("client_id", "")},
			assert: authenticated("billing-web"),
		},

		// A credential in the query (R11).
		{
			name:   "client_secret in the query",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "crm-web"), Query: form("client_secret", postSecret)},
			assert: invalidRequest,
		},
		{
			name:   "client_assertion in the query",
			creds:  oidcprovider.ClientCredentials{Query: form("client_assertion", "a.b.c")},
			assert: invalidRequest,
		},
		{
			name:   "client_assertion_type in the query",
			creds:  oidcprovider.ClientCredentials{Query: form("client_assertion_type", "x")},
			assert: invalidRequest,
		},
		{
			name:   "a query credential beside a right header",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret), Query: form("client_secret", basicSecret)},
			assert: invalidRequest,
		},
		{
			name:   "an empty client_secret in the query counts as omitted",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret), Query: form("client_secret", "")},
			assert: authenticated("billing-web"),
		},
		{
			name:   "an empty client_assertion and client_assertion_type in the query count as omitted",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret), Query: form("client_assertion", "", "client_assertion_type", "")},
			assert: authenticated("billing-web"),
		},
		{
			name:   "client_id in the query is no credential",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret), Query: form("client_id", "billing-web")},
			assert: authenticated("billing-web"),
		},

		// A repeated parameter.
		{
			name:   "client_id given twice",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "spa", "client_id", "spa")},
			assert: invalidRequest,
		},
		{
			name:   "client_secret given twice",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "crm-web", "client_secret", postSecret, "client_secret", postSecret)},
			assert: invalidRequest,
		},
		{
			name:   "client_assertion given twice",
			creds:  oidcprovider.ClientCredentials{Form: form("client_assertion", "a.b.c", "client_assertion", "a.b.c")},
			assert: invalidRequest,
		},
		{
			name:   "client_assertion_type given twice",
			creds:  oidcprovider.ClientCredentials{Form: form("client_assertion_type", "x", "client_assertion_type", "x")},
			assert: invalidRequest,
		},
	}

	p := secretProvider(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rc, err := p.AuthenticateClient(t.Context(), tc.creds)
			tc.assert(t, rc, err)
		})
	}
}

// countingClock counts the reads of the time, which the secret comparison makes once.
type countingClock struct {
	now   time.Time
	reads atomic.Int64
}

func (c *countingClock) Now() time.Time {
	c.reads.Add(1)

	return c.now
}

// A wrong secret and an unknown client must not be told apart. The answers are
// compared whole. A wall-clock measurement would be flaky, so the shared comparison
// is pinned through its one read of the clock: a path that skips it answers faster.
func TestAuthenticateClient_RefusalsAreAlike(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		creds oidcprovider.ClientCredentials
	}

	cases := []testCase{
		{name: "a right secret, the baseline", creds: oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret)}},
		{name: "a wrong secret", creds: oidcprovider.ClientCredentials{Authorization: basic("billing-web", "wrong")}},
		{name: "an unknown client", creds: oidcprovider.ClientCredentials{Authorization: basic("nobody", "wrong")}},
		{name: "the wrong method", creds: oidcprovider.ClientCredentials{Authorization: basic("crm-web", postSecret)}},
		{name: "a public client sending a secret", creds: oidcprovider.ClientCredentials{Authorization: basic("spa", "wrong")}},
		{name: "an unknown client over post", creds: oidcprovider.ClientCredentials{Form: form("client_id", "nobody", "client_secret", "wrong")}},
		{name: "a wrong secret over post", creds: oidcprovider.ClientCredentials{Form: form("client_id", "crm-web", "client_secret", "wrong")}},
		{name: "an identifier no client could hold", creds: oidcprovider.ClientCredentials{Authorization: basic("no\x00body", "wrong")}},
	}

	var refusal string
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := &countingClock{now: authNow}
			p := secretProvider(t, oidcprovider.WithClock(clk))

			_, err := p.AuthenticateClient(t.Context(), tc.creds)

			assert.EqualValues(t, 1, clk.reads.Load(), "the path must run the secret comparison once")
			if i == 0 {
				require.NoError(t, err)

				return
			}
			require.Error(t, err)
			if refusal == "" {
				refusal = err.Error()
			}
			assert.Equal(t, refusal, err.Error(), "a refusal must not say why")
		})
	}
}

// A client identifier no client could hold never reaches a consumer's registry,
// where a NUL in a SQL parameter would turn a stranger's request into a server error.
func TestAuthenticateClient_ImpossibleIdentifier(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		creds oidcprovider.ClientCredentials
	}

	cases := []testCase{
		{name: "a NUL in basic", creds: oidcprovider.ClientCredentials{Authorization: basic("a\x00b", "wrong")}},
		{name: "an encoded NUL in basic", creds: oidcprovider.ClientCredentials{Authorization: rawBasic("a%00b:wrong")}},
		{name: "invalid UTF-8 in basic", creds: oidcprovider.ClientCredentials{Authorization: rawBasic("a%ffb:wrong")}},
		{name: "a NUL in the body", creds: oidcprovider.ClientCredentials{Form: form("client_id", "a\x00b")}},
		{name: "a newline in the body", creds: oidcprovider.ClientCredentials{Form: form("client_id", "a\nb", "client_secret", "wrong")}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// No expectation is set, so any read fails the test.
			p := providerOver(t, nil, func(*MockClientRegistry) {})

			rc, err := p.AuthenticateClient(t.Context(), tc.creds)
			refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)
		})
	}
}

// A registry that fails says nothing about the client: it is a dependency failure,
// which is no refusal, and is charged to no throttle.
func TestAuthenticateClient_RegistryFailure(t *testing.T) {
	t.Parallel()

	errRegistry := errors.New("pq: password authentication failed for host db.internal")

	type testCase struct {
		name   string
		creds  oidcprovider.ClientCredentials
		answer func(ctx context.Context) error
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, err error)
	}

	dependency := func(t *testing.T, _ context.Context, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrDependency)
		var refusal *oidcprovider.Error
		assert.False(t, errors.As(err, &refusal), "a dependency failure is no refusal")
		assert.NotContains(t, err.Error(), "db.internal", "the dependency's text must not surface")
	}

	cases := []testCase{
		{
			name:   "over basic",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret)},
			answer: func(context.Context) error { return errRegistry },
			assert: dependency,
		},
		{
			name:   "over post",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "crm-web", "client_secret", postSecret)},
			answer: func(context.Context) error { return errRegistry },
			assert: dependency,
		},
		{
			name:   "naming a public client",
			creds:  oidcprovider.ClientCredentials{Form: form("client_id", "spa")},
			answer: func(context.Context) error { return errRegistry },
			assert: dependency,
		},
		{
			name:   "a caller who left matches its own context",
			creds:  oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret)},
			answer: func(ctx context.Context) error { return ctx.Err() },
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, _ context.Context, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidcprovider.ErrDependency)
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
			p := providerOver(t, nil, func(r *MockClientRegistry) {
				r.EXPECT().Client(gomock.Any(), gomock.Any()).Return(nil, tc.answer(ctx))
			})

			rc, err := p.AuthenticateClient(ctx, tc.creds)
			assert.Nil(t, rc)
			tc.assert(t, ctx, err)
		})
	}
}
