package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

// errAPIKeyDenied is what a consumer's stateless policy refuses a valid key
// with.
var errAPIKeyDenied = errors.New("apikey_test: outside office hours")

// TestEnableAPIKey pins what the chain refuses to be built with.
func TestEnableAPIKey(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		manager func(h *apiKeyHarness) *apikey.Keys
		opts    []httpsec.APIKeyOption
		assert  func(t *testing.T, c *httpsec.Chain, err error)
	}

	configured := func(h *apiKeyHarness) *apikey.Keys { return h.keys }

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
			manager: func(*apiKeyHarness) *apikey.Keys { return nil },
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

// errOwnerClientGone is the cause a departing client's request ends with.
var errOwnerClientGone = errors.New("apikey_test: the client went away")

// apiKeyLeaveKey carries, in a request's context, the function that ends it,
// so a user loader can end the request mid-load as a departing client does.
type apiKeyLeaveKey struct{}

// leavable gives a request a context its user loader can end.
func leavable(ctx context.Context) context.Context {
	ctx, leave := context.WithCancelCause(ctx)

	return context.WithValue(ctx, apiKeyLeaveKey{}, leave)
}

// leave ends the request whose context ctx is, with cause.
func leave(ctx context.Context, cause error) {
	ctx.Value(apiKeyLeaveKey{}).(context.CancelCauseFunc)(cause)
}

// apiKeyOwnerOutcome is what one request to an owner-checking chain produced.
type apiKeyOwnerOutcome struct {
	served

	// logs are the records written while the request was served, not while
	// the chain was built.
	logs []slog.Record

	// record is the key's stored record after the request was served.
	record apikey.Key
}

// TestAPIKeyOwners pins the owner check. With a user loader, a verified key is
// refused as a wrong key is when its owner is missing or inactive, or when the
// loader answers with another user. An outage is unavailable, answered 401 as
// a wrong key is, and not counted against the source, and neither is a client
// that leaves mid-load. Without a loader, nothing is looked up.
func TestAPIKeyOwners(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		ctx  func(ctx context.Context) context.Context

		// owners sets what the loader expects and returns the options that
		// wire it, if any.
		owners func(m *MockUserLoader) []httpsec.APIKeyOption

		// failures is how many failures the source limiter is to record.
		failures int

		assert func(t *testing.T, out apiKeyOwnerOutcome, err error)
	}

	owned := func(m *MockUserLoader) []httpsec.APIKeyOption {
		return []httpsec.APIKeyOption{httpsec.WithAPIKeyOwners(m)}
	}

	loads := func(details *identity.Details, err error) func(*MockUserLoader) []httpsec.APIKeyOption {
		return func(m *MockUserLoader) []httpsec.APIKeyOption {
			m.EXPECT().LoadByUserID(gomock.Any(), apiKeyPrincipal).Return(details, err)

			return owned(m)
		}
	}

	// What a wrong key is refused with, which a missing or inactive owner
	// must not be told apart from.
	wrongKey := func() error {
		h := newAPIKeyHarness(t)

		return h.withKey(t, h.chain(t), apiKeySource, "sk_0199a0e1-0000-7000-8000-000000000000.bm9wZQ").err
	}()
	require.Error(t, wrongKey)

	authenticated := func(t *testing.T, out apiKeyOwnerOutcome, err error) {
		t.Helper()

		require.NoError(t, err)
		require.True(t, out.handlerRan)
		require.NotNil(t, out.handled.Authentication)

		p := out.handled.Authentication.Principal
		require.NotNil(t, p)
		assert.Equal(t, apiKeyPrincipal, p.ID)
		assert.True(t, p.IsService(), "the key's service principal, not the owner as a user")
	}

	refusedWrongKeyError := func(t *testing.T, out apiKeyOwnerOutcome, err error) {
		t.Helper()

		require.Error(t, err)
		assert.Equal(t, wrongKey.Error(), err.Error(), "the error a wrong key gets")
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		require.ErrorIs(t, err, apikey.ErrVerificationFailed)
		assert.NotErrorIs(t, err, authenticate.ErrUnavailable)
		assert.Equal(t, httpsec.StatusForError(wrongKey), httpsec.StatusForError(err))
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err))
		assert.False(t, out.handlerRan)
	}

	refusedAsWrongKey := func(t *testing.T, out apiKeyOwnerOutcome, err error) {
		t.Helper()

		refusedWrongKeyError(t, out, err)
		assert.Empty(t, out.logs, "and the chain writes what it writes for a wrong key: nothing")
	}

	// A loader that answers for another user is a fault the operator can fix,
	// so it is logged once, under its own reason, with nothing about the user.
	refusedAsMismatch := func(t *testing.T, out apiKeyOwnerOutcome, err error) {
		t.Helper()

		refusedWrongKeyError(t, out, err)

		require.Len(t, out.logs, 1, "one record for the one refusal")

		r := out.logs[0]
		assert.Equal(t, slog.LevelError, r.Level)

		attrs := map[string]string{}

		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()

			return true
		})

		assert.Equal(t, "owner-mismatch", attrs["reason"])
		assert.NotContains(t, r.Message, string(apiKeyPrincipal))
		assert.NotContains(t, r.Message, "another-user")

		for _, v := range attrs {
			assert.NotContains(t, v, string(apiKeyPrincipal), "no record names the key's owner")
			assert.NotContains(t, v, "another-user", "or the user the loader answered for")
		}
	}

	unavailable := func(t *testing.T, out apiKeyOwnerOutcome, err error) {
		t.Helper()

		require.ErrorIs(t, err, authenticate.ErrUnavailable)
		assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed, "no key was refused")
		assert.NotContains(t, err.Error(), "10.0.0.5", "the loader's text stays out")
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err),
			"the outage was not answered as a wrong key is")
		assert.False(t, out.handlerRan)

		var faults int

		for _, r := range out.logs {
			if r.Level == slog.LevelError {
				faults++
			}

			assert.NotContains(t, r.Message, "10.0.0.5")

			r.Attrs(func(a slog.Attr) bool {
				assert.NotContains(t, a.Value.String(), "10.0.0.5", "no record carries the loader's text")

				return true
			})
		}

		assert.Equal(t, 1, faults, "the operator is told the store could not answer")
	}

	callerLeft := func(t *testing.T, out apiKeyOwnerOutcome, err error) {
		t.Helper()

		require.ErrorIs(t, err, context.Canceled, "the request's own context's error")
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed, "refused as a wrong key is")
		assert.NotErrorIs(t, err, authenticate.ErrUnavailable, "a client leaving is not an outage")
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err))
		assert.False(t, out.handlerRan)

		var debugs int

		for _, r := range out.logs {
			assert.NotEqual(t, slog.LevelError, r.Level, "nothing an operator can act on: %s", r.Message)

			if r.Level == slog.LevelDebug {
				debugs++
			}
		}

		assert.Equal(t, 1, debugs, "the one debug record of the one hang-up")
	}

	configError := func(t *testing.T, _ apiKeyOwnerOutcome, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
	}

	// A key whose owner the loader refuses was still verified, so its last-use
	// stamp stays: the stamp says the key was presented and checked, not that
	// the request went through.
	keepsLastUse := func(t *testing.T, out apiKeyOwnerOutcome, err error) {
		t.Helper()

		refusedAsWrongKey(t, out, err)
		require.NotNil(t, out.record.LastUsedAt, "a key refused for its owner keeps its last-use stamp")
		assert.False(t, out.record.LastUsedAt.IsZero())
	}

	cases := []testCase{
		{
			name:   "no loader looks nothing up",
			owners: func(*MockUserLoader) []httpsec.APIKeyOption { return nil },
			assert: authenticated,
		},
		{
			name:     "inactive owner",
			owners:   loads(&identity.Details{ID: apiKeyPrincipal, Active: false}, nil),
			failures: 1,
			assert:   refusedAsWrongKey,
		},
		{
			name:     "a key refused for its owner keeps its last-use stamp",
			owners:   loads(&identity.Details{ID: apiKeyPrincipal, Active: false}, nil),
			failures: 1,
			assert:   keepsLastUse,
		},
		{
			name:     "missing owner",
			owners:   loads(nil, fmt.Errorf("users: %w", identity.ErrUserNotFound)),
			failures: 1,
			assert:   refusedAsWrongKey,
		},
		{
			name:     "loader answers nothing",
			owners:   loads(nil, nil),
			failures: 1,
			assert:   refusedAsWrongKey,
		},
		{
			name:     "loader answers for another user",
			owners:   loads(&identity.Details{ID: "another-user", Active: true}, nil),
			failures: 1,
			assert:   refusedAsMismatch,
		},
		{
			name:   "active owner",
			owners: loads(&identity.Details{ID: apiKeyPrincipal, Active: true}, nil),
			assert: authenticated,
		},
		{
			name:   "loader outage",
			owners: loads(nil, errors.New("dial tcp 10.0.0.5:5432: connection refused")),
			assert: unavailable,
		},
		{
			name: "a deadline the loader met on its own is an outage",
			owners: loads(nil, fmt.Errorf("users: query: %w",
				context.DeadlineExceeded)),
			assert: func(t *testing.T, out apiKeyOwnerOutcome, err error) {
				t.Helper()

				unavailable(t, out, err)
				assert.NotContains(t, err.Error(), "query", "the loader's text stays out")
			},
		},
		{
			name: "caller left during the owner load",
			ctx:  leavable,
			owners: func(m *MockUserLoader) []httpsec.APIKeyOption {
				m.EXPECT().LoadByUserID(gomock.Any(), apiKeyPrincipal).DoAndReturn(
					func(ctx context.Context, _ identity.UserID) (*identity.Details, error) {
						leave(ctx, nil)

						return nil, fmt.Errorf("users: %w", ctx.Err())
					})

				return owned(m)
			},
			assert: callerLeft,
		},
		{
			name: "caller left with a cause during the owner load",
			ctx:  leavable,
			owners: func(m *MockUserLoader) []httpsec.APIKeyOption {
				m.EXPECT().LoadByUserID(gomock.Any(), apiKeyPrincipal).DoAndReturn(
					func(ctx context.Context, _ identity.UserID) (*identity.Details, error) {
						leave(ctx, errOwnerClientGone)

						return nil, context.Cause(ctx)
					})

				return owned(m)
			},
			assert: func(t *testing.T, out apiKeyOwnerOutcome, err error) {
				t.Helper()

				callerLeft(t, out, err)
				assert.ErrorIs(t, err, errOwnerClientGone, "and the cause it ended with")
			},
		},
		{
			name: "nil loader",
			owners: func(*MockUserLoader) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyOwners(nil)}
			},
			assert: configError,
		},
		{
			name: "a loader interface holding a nil pointer",
			owners: func(*MockUserLoader) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyOwners((*MockUserLoader)(nil))}
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			ctrl := gomock.NewController(t)

			limiter := NewMockLimiter(ctrl)
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
			limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).Times(tc.failures)

			h := newAPIKeyHarness(t)
			logs := &capturingHandler{}

			opts := append([]httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(limiter)},
				tc.owners(NewMockUserLoader(ctrl))...)

			c, err := httpsec.New(httpsec.WithLogger(slog.New(logs)),
				httpsec.EnableAPIKey(h.keys, opts...))
			if err != nil {
				tc.assert(t, apiKeyOwnerOutcome{}, err)

				return
			}

			built := len(logs.records())
			out := serveAPIKey(ctx, c, httpsec.DefaultAPIKeyScheme+h.valid)

			// The key's identifier is the part between the prefix and the secret.
			rest, _ := strings.CutPrefix(h.valid, "sk_")
			idPart, _, _ := strings.Cut(rest, ".")
			keyID, err := id.Parse(idPart)
			require.NoError(t, err)

			rec, err := h.store.Store.Get(t.Context(), keyID)
			require.NoError(t, err)

			tc.assert(t, apiKeyOwnerOutcome{
				served: out, logs: logs.records()[built:], record: rec,
			}, out.err)
		})
	}
}

// serveAPIKey sends a request carrying header from apiKeySource, on ctx, so a
// test can end the request while the chain is serving it.
func serveAPIKey(ctx context.Context, c *httpsec.Chain, header string) served {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/invoices", nil)
	req.RemoteAddr = apiKeySource + ":51000"
	req.Header.Set("Authorization", header)

	out := served{rec: httptest.NewRecorder()}
	run := c.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	ex := httpsec.NewExchange(ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
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
