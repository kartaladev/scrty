package httpsec_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

// The machine caller these tests authenticate.
const (
	apiKeyPrincipal identity.UserID = "svc-billing"
	apiKeySource    string          = "203.0.113.7"
)

// errAPIKeyDenied is what a consumer's stateless policy refuses a valid key
// with.
var errAPIKeyDenied = errors.New("apikey_test: outside office hours")

// countingStore forwards to the real store and counts the reads a verification
// makes, which is how a test pins that a request refused earlier never reached
// the store at all.
type countingStore struct {
	apikey.Store

	reads atomic.Int64
}

func (s *countingStore) Get(ctx context.Context, keyID id.ID) (apikey.Key, error) {
	s.reads.Add(1)

	return s.Store.Get(ctx, keyID)
}

// apiKeyHarness is a real key manager holding one live key, because what is
// being pinned is which requests reach the verification at all.
type apiKeyHarness struct {
	keys  *apikey.Manager
	store *countingStore
	valid string

	keyOpts []httpsec.APIKeyOption
	engine  *policy.Engine
}

func newAPIKeyHarness(t *testing.T) *apiKeyHarness {
	t.Helper()

	store := &countingStore{Store: apikey.NewMemoryStore()}

	keys, err := apikey.NewManager(apikey.WithStore(store))
	require.NoError(t, err)

	presented, _, err := keys.Issue(
		t.Context(), apiKeyPrincipal, "billing", []string{"invoices:read"}, 0)
	require.NoError(t, err)

	// The issuance wrote a record; only what a verification reads is counted.
	store.reads.Store(0)

	return &apiKeyHarness{keys: keys, store: store, valid: presented}
}

func (h *apiKeyHarness) chain(t *testing.T) *httpsec.Chain {
	t.Helper()

	c, err := h.build()
	require.NoError(t, err)

	return c
}

func (h *apiKeyHarness) build() (*httpsec.Chain, error) {
	opts := []httpsec.Option{httpsec.EnableAPIKey(h.keys, h.keyOpts...)}
	if h.engine != nil {
		opts = append(opts, httpsec.WithPolicyEngine(h.engine))
	}

	return httpsec.New(opts...)
}

// present sends a request carrying header, from source.
func (h *apiKeyHarness) present(t *testing.T, c *httpsec.Chain, source, header string) served {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil)
	req.RemoteAddr = source + ":51000"

	if header != "" {
		req.Header.Set("Authorization", header)
	}

	return serve(t, c, req)
}

// withKey presents the live key under the default scheme.
func (h *apiKeyHarness) withKey(t *testing.T, c *httpsec.Chain, source, key string) served {
	t.Helper()

	return h.present(t, c, source, httpsec.DefaultAPIKeyScheme+key)
}

// TestEnableAPIKey pins what the chain refuses to be built with.
func TestEnableAPIKey(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		manager func(h *apiKeyHarness) *apikey.Manager
		opts    []httpsec.APIKeyOption
		assert  func(t *testing.T, c *httpsec.Chain, err error)
	}

	configured := func(h *apiKeyHarness) *apikey.Manager { return h.keys }

	configError := func(t *testing.T, c *httpsec.Chain, err error) {
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Nil(t, c)
	}

	built := func(t *testing.T, c *httpsec.Chain, err error) {
		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	cases := []testCase{
		{name: "the defaults", manager: configured, assert: built},
		{
			name:    "a consumer scheme and limiter",
			manager: configured,
			opts: []httpsec.APIKeyOption{
				httpsec.WithAPIKeyScheme("Service "),
				httpsec.WithAPIKeyLimiter(NewMockLimiter(gomock.NewController(t))),
			},
			assert: built,
		},
		{
			name:    "a nil manager",
			manager: func(*apiKeyHarness) *apikey.Manager { return nil },
			assert:  configError,
		},
		{
			name:    "a nil limiter",
			manager: configured,
			opts:    []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(nil)},
			assert:  configError,
		},
		{
			name:    "a limiter interface holding a nil pointer",
			manager: configured,
			opts:    []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter((*ratelimit.MemoryLimiter)(nil))},
			assert:  configError,
		},
		{
			name:    "an empty scheme",
			manager: configured,
			opts:    []httpsec.APIKeyOption{httpsec.WithAPIKeyScheme("")},
			assert:  configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAPIKeyHarness(t)

			c, err := httpsec.New(httpsec.EnableAPIKey(tc.manager(h), tc.opts...))
			tc.assert(t, c, err)
		})
	}
}

// TestAPIKeyHeaderMatching pins where a key may be presented. The query-string
// row is the important one: a credential in a URL is already in every access
// log, proxy log and Referer header that saw it.
func TestAPIKeyHeaderMatching(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		scheme  string
		request func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) served
		assert  func(t *testing.T, out served)
	}

	passesThrough := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		require.True(t, out.handlerRan, "the request reaches the application unauthenticated")
		assert.Nil(t, out.handled.Authentication, "and nothing was authenticated")
	}

	authenticated := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		require.True(t, out.handlerRan)
		require.NotNil(t, out.handled.Authentication)

		p := out.handled.Authentication.Principal
		require.NotNil(t, p)
		assert.Equal(t, apiKeyPrincipal, p.ID)
		assert.True(t, p.IsService(), "a key authenticates a machine, not a person")
		assert.Nil(t, out.handled.Session, "and establishes no session")
	}

	cases := []testCase{
		{
			name: "no Authorization header",
			request: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) served {
				return h.present(t, c, apiKeySource, "")
			},
			assert: passesThrough,
		},
		{
			name: "a key in the query string only",
			request: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) served {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					"/invoices?api_key="+url.QueryEscape(h.valid), nil)
				req.RemoteAddr = apiKeySource + ":51000"

				return serve(t, c, req)
			},
			assert: passesThrough,
		},
		{
			name: "a Bearer token",
			request: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) served {
				return h.present(t, c, apiKeySource, "Bearer "+h.valid)
			},
			assert: passesThrough,
		},
		{
			name: "the wrong case of the scheme",
			request: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) served {
				return h.present(t, c, apiKeySource, "apikey "+h.valid)
			},
			assert: passesThrough,
		},
		{
			name: "the default scheme",
			request: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) served {
				return h.withKey(t, c, apiKeySource, h.valid)
			},
			assert: authenticated,
		},
		{
			name:   "a consumer scheme",
			scheme: "Service ",
			request: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) served {
				return h.present(t, c, apiKeySource, "Service "+h.valid)
			},
			assert: authenticated,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAPIKeyHarness(t)
			if tc.scheme != "" {
				h.keyOpts = []httpsec.APIKeyOption{httpsec.WithAPIKeyScheme(tc.scheme)}
			}

			tc.assert(t, tc.request(t, h, h.chain(t)))
		})
	}
}

// TestAPIKeyUnclaimedRequestsAreNotCounted pins that ordinary unauthenticated
// traffic never touches the limiter. Counting it would fill the buckets that
// exist to catch guessing.
func TestAPIKeyUnclaimedRequestsAreNotCounted(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Times(0)
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)

	h := newAPIKeyHarness(t)
	h.keyOpts = []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(limiter)}

	c := h.chain(t)

	require.NoError(t, h.present(t, c, apiKeySource, "").err)
	require.NoError(t, h.present(t, c, apiKeySource, "Bearer "+h.valid).err)
}

// TestAPIKeyThrottle pins that a source guessing keys is cut off, and that the
// refusal it then gets is indistinguishable from a wrong key.
func TestAPIKeyThrottle(t *testing.T) {
	t.Parallel()

	t.Run("twenty invalid keys then a valid one is refused", func(t *testing.T) {
		t.Parallel()

		h := newAPIKeyHarness(t)
		c := h.chain(t)

		for range 20 {
			err := h.withKey(t, c, apiKeySource, "sk_0199a0e1-0000-7000-8000-000000000000.bm9wZQ").err
			require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			require.ErrorIs(t, err, apikey.ErrVerificationFailed)
		}

		reads := h.store.reads.Load()

		out := h.withKey(t, c, apiKeySource, h.valid)
		require.ErrorIs(t, out.err, apikey.ErrVerificationFailed,
			"a throttled source is refused exactly as a wrong key is")
		assert.False(t, out.handlerRan)
		assert.Equal(t, reads, h.store.reads.Load(),
			"and the key it presented was never looked up: the source is checked first")

		require.NoError(t, h.withKey(t, c, "198.51.100.4", h.valid).err,
			"another source is unaffected")
	})

	t.Run("an unattributable source is refused without verifying", func(t *testing.T) {
		t.Parallel()

		h := newAPIKeyHarness(t)

		out := h.withKey(t, h.chain(t), "", h.valid)

		require.ErrorIs(t, out.err, apikey.ErrVerificationFailed)
		assert.Zero(t, h.store.reads.Load(), "the key was never looked up")
		assert.False(t, out.handlerRan,
			"an address that names no single client keys no bucket, so it is refused outright")
	})
}

// TestAPIKeyStateless pins that a key authenticates a machine and nothing more:
// no session, and a policy refusal that costs the caller none of its allowance.
func TestAPIKeyStateless(t *testing.T) {
	t.Parallel()

	t.Run("a valid key creates no session", func(t *testing.T) {
		t.Parallel()

		h := newAPIKeyHarness(t)

		out := h.withKey(t, h.chain(t), apiKeySource, h.valid)

		require.NoError(t, out.err)
		require.True(t, out.handlerRan)
		assert.Nil(t, out.handled.Session,
			"a machine has nobody to prompt and nothing to keep between requests")

		p, ok := identity.PrincipalFromContext(out.handled.Context())
		require.True(t, ok, "the caller is published for the guards behind the chain")
		assert.Equal(t, apiKeyPrincipal, p.ID)
	})

	t.Run("a stateless deny refuses with the policy's reason", func(t *testing.T) {
		t.Parallel()

		h := newAPIKeyHarness(t)
		h.engine = statelessDenyingEngine(t, errAPIKeyDenied)

		out := h.withKey(t, h.chain(t), apiKeySource, h.valid)

		require.ErrorIs(t, out.err, errAPIKeyDenied)
		assert.False(t, out.handlerRan, "the principal does not reach later handlers")
	})

	t.Run("policy denials of a valid key are not counted", func(t *testing.T) {
		t.Parallel()

		h := newAPIKeyHarness(t)

		gate := &statelessSwitchable{}
		h.engine = gate.engine(t)

		c := h.chain(t)

		for range 25 {
			require.ErrorIs(t, h.withKey(t, c, apiKeySource, h.valid).err, errAPIKeyDenied)
		}

		gate.allow.Store(true)

		require.NoError(t, h.withKey(t, c, apiKeySource, h.valid).err,
			"the credential was valid every time; only the policy refused")
	})
}

// TestAPIKeyConsumerLimiter pins that a consumer's own limiter receives every
// check and every failure this flow makes.
func TestAPIKeyConsumerLimiter(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)

	var (
		checks   atomic.Int64
		failures atomic.Int64
	)

	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) (bool, error) {
			checks.Add(1)

			return false, nil
		})
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) error {
			failures.Add(1)

			return nil
		})

	h := newAPIKeyHarness(t)
	h.keyOpts = []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(limiter)}

	c := h.chain(t)

	require.Error(t, h.withKey(t, c, apiKeySource, "sk_nope.nope").err)
	require.NoError(t, h.withKey(t, c, apiKeySource, h.valid).err)

	assert.Equal(t, int64(2), checks.Load(), "every presented key is checked against the source")
	assert.Equal(t, int64(1), failures.Load(), "and only the wrong one is recorded")
}

// TestAPIKeyThrottleLogSampling pins that a source guessing keys cannot flood
// the log, and that no record carries what was presented.
func TestAPIKeyThrottleLogSampling(t *testing.T) {
	t.Parallel()

	logs := &capturingHandler{}

	h := newAPIKeyHarness(t)

	c, err := httpsec.New(
		httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableAPIKey(h.keys),
	)
	require.NoError(t, err)

	const presented = "sk_0199a0e1-0000-7000-8000-000000000000.Z3Vlc3M"

	for range 300 {
		_ = h.withKey(t, c, apiKeySource, presented)
	}

	var throttled int

	for _, r := range logs.records() {
		if r.Message == guardThrottledMsg {
			throttled++
		}

		assert.NotContains(t, r.Message, presented)

		r.Attrs(func(a slog.Attr) bool {
			assert.NotContains(t, a.Value.String(), presented, "no record carries a presented key")

			return true
		})
	}

	assert.Equal(t, 1, throttled, "one record stands for every refusal in the window")
}

// statelessDenyingEngine refuses in the stateless phase, which is the one a
// credential that establishes no session is judged in.
func statelessDenyingEngine(t *testing.T, reason error) *policy.Engine {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("apikey_test: stateless deny").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.StatelessAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		Return(policy.Decision{Outcome: policy.Deny, Reason: reason})

	return engineOf(t, p)
}

// statelessSwitchable is a stateless policy a test turns from denying to
// allowing.
type statelessSwitchable struct {
	allow atomic.Bool
}

func (s *statelessSwitchable) engine(t *testing.T) *policy.Engine {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("apikey_test: switchable").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.StatelessAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, *policy.Input) policy.Decision {
			if s.allow.Load() {
				return policy.Decision{Outcome: policy.Allow}
			}

			return policy.Decision{Outcome: policy.Deny, Reason: errAPIKeyDenied}
		})

	return engineOf(t, p)
}
