package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/signingkey"
)

// The library's own key manager is a key set provider, so a consumer wires the
// one they already have rather than marshalling a set of their own.
var _ httpsec.KeySetProvider = (*signingkey.KeyManager)(nil)

// errKeySetUnavailable is what a provider that cannot produce a key set fails
// with, so a test can assert the chain passed that failure on rather than
// serving something in its place.
var errKeySetUnavailable = errors.New("jwks_test: the signing keys could not be read")

// publicKeySet is what a well-behaved provider serves: verification keys and
// nothing else.
const publicKeySet = `{"keys":[
	{"kty":"EC","crv":"P-256","kid":"key-1","alg":"ES256","use":"sig",
	 "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
	 "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
	{"kty":"RSA","kid":"key-2","alg":"RS256","use":"sig","e":"AQAB",
	 "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
]}`

// privateKeySet is the same set with the EC private scalar left in. It exists
// so a test can prove the private-member check actually fails when one is
// served.
const privateKeySet = `{"keys":[
	{"kty":"EC","crv":"P-256","kid":"key-1","alg":"ES256","use":"sig",
	 "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
	 "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	 "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}
]}`

// privateJWKMembers are the members a JWK carries private key material in. A
// key set answering with any of them is not a published key set, it is the
// signing keys themselves.
var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k"}

// privateMembersIn parses a served key set and reports every member of it that
// carries private key material.
func privateMembersIn(t *testing.T, body []byte) []string {
	t.Helper()

	var set struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(body, &set))
	require.NotEmpty(t, set.Keys, "a key set with no keys verifies nothing")

	var found []string
	for _, key := range set.Keys {
		assert.Contains(t, key, "kid", "a key nothing can name is a key nothing can select")
		for _, member := range privateJWKMembers {
			if _, ok := key[member]; ok {
				found = append(found, member)
			}
		}
	}

	return found
}

// assertNoPrivateMaterial fails when a served key set carries any private key
// material. It is the difference between publishing a key set and publishing
// the signing keys.
func assertNoPrivateMaterial(t *testing.T, body []byte) {
	t.Helper()

	assert.Empty(t, privateMembersIn(t, body),
		"the served key set carries private key material")
}

// TestPrivateMembersIn pins that the check the key set test rests on notices a
// private key, so a green key set test means the response was actually clean.
func TestPrivateMembersIn(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		set    string
		assert func(t *testing.T, found []string)
	}

	cases := []testCase{
		{
			name: "a published key set carries none",
			set:  publicKeySet,
			assert: func(t *testing.T, found []string) {
				assert.Empty(t, found)
			},
		},
		{
			name: "a signing key is reported",
			set:  privateKeySet,
			assert: func(t *testing.T, found []string) {
				assert.Equal(t, []string{"d"}, found)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, privateMembersIn(t, []byte(tc.set)))
		})
	}
}

func jwksRequest(ctx context.Context, method, path string) *http.Request {
	return httptest.NewRequestWithContext(ctx, method, path, nil)
}

// TestJWKSEndpoint pins what the key set endpoint answers, and what it never
// answers with.
func TestJWKSEndpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []httpsec.JWKSOption
		wire    func(t *testing.T, keys *MockKeySetProvider)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, s served)
	}

	serves := func(_ *testing.T, keys *MockKeySetProvider) {
		keys.EXPECT().JWKS().Return([]byte(publicKeySet), nil)
	}

	// No expectation at all: a request the endpoint does not claim must not
	// even ask for the keys.
	neverAsked := func(*testing.T, *MockKeySetProvider) {}

	passedThrough := func(t *testing.T, s served) {
		require.NoError(t, s.err)
		assert.True(t, s.handlerRan, "the request continues to the application untouched")
	}

	cases := []testCase{
		{
			name: "a GET on the default path answers the public key set",
			wire: serves,
			request: func(ctx context.Context) *http.Request {
				return jwksRequest(ctx, http.MethodGet, httpsec.DefaultJWKSPath)
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.False(t, s.handlerRan, "the key set is this library's own endpoint")
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.Equal(t, "application/json", s.rec.Header().Get("Content-Type"))
				assertNoPrivateMaterial(t, s.rec.Body.Bytes())
			},
		},
		{
			name: "a POST on the key set path passes through",
			wire: neverAsked,
			request: func(ctx context.Context) *http.Request {
				return jwksRequest(ctx, http.MethodPost, httpsec.DefaultJWKSPath)
			},
			assert: passedThrough,
		},
		{
			name: "a consumer path serves the key set",
			opts: []httpsec.JWKSOption{httpsec.WithJWKSEndpointPath("/keys")},
			wire: serves,
			request: func(ctx context.Context) *http.Request {
				return jwksRequest(ctx, http.MethodGet, "/keys")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assertNoPrivateMaterial(t, s.rec.Body.Bytes())
			},
		},
		{
			name: "a consumer path leaves the default passing through",
			opts: []httpsec.JWKSOption{httpsec.WithJWKSEndpointPath("/keys")},
			wire: neverAsked,
			request: func(ctx context.Context) *http.Request {
				return jwksRequest(ctx, http.MethodGet, httpsec.DefaultJWKSPath)
			},
			assert: passedThrough,
		},
		{
			name: "a provider failure propagates as an error",
			wire: func(_ *testing.T, keys *MockKeySetProvider) {
				keys.EXPECT().JWKS().Return(nil, errKeySetUnavailable)
			},
			request: func(ctx context.Context) *http.Request {
				return jwksRequest(ctx, http.MethodGet, httpsec.DefaultJWKSPath)
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, errKeySetUnavailable,
					"a key set that could not be read is an outage, not an empty set")
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
				assert.Empty(t, s.rec.Body.String(), "nothing was served in its place")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := NewMockKeySetProvider(gomock.NewController(t))
			tc.wire(t, keys)

			chain, err := httpsec.New(httpsec.EnableJWKSEndpoint(keys, tc.opts...))
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.request(t.Context())))
		})
	}
}

// TestJWKSEndpointConstruction pins that an endpoint wired to nothing, or
// answering nothing, is refused before it serves a request.
func TestJWKSEndpointConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(names ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain)
			for _, name := range names {
				assert.Contains(t, err.Error(), name)
			}
		}
	}

	cases := []testCase{
		{
			name: "a wired endpoint builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.EnableJWKSEndpoint(NewMockKeySetProvider(gomock.NewController(t))),
				}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, chain)
			},
		},
		{
			name: "no key set provider",
			build: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableJWKSEndpoint(nil)}
			},
			assert: refused("EnableJWKSEndpoint", "key set provider"),
		},
		{
			name: "a provider holding a typed nil",
			build: func(*testing.T) []httpsec.Option {
				var keys *MockKeySetProvider

				return []httpsec.Option{httpsec.EnableJWKSEndpoint(keys)}
			},
			assert: refused("EnableJWKSEndpoint", "key set provider"),
		},
		{
			name: "an empty key set path",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.EnableJWKSEndpoint(NewMockKeySetProvider(gomock.NewController(t)),
						httpsec.WithJWKSEndpointPath("")),
				}
			},
			assert: refused("WithJWKSEndpointPath"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.build(t)...)
			tc.assert(t, chain, err)
		})
	}
}
