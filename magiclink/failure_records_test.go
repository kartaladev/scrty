package magiclink_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/onetime"
)

// errStoreFailure is the dependency error every row proves against: a store's own
// text, quoting a username and a user reference the record must never repeat.
var errStoreFailure = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// countFailsStore reads like any other store and fails the issuance count.
type countFailsStore struct {
	onetime.Store
}

func (countFailsStore) CountRecentBySubject(context.Context, string, string, time.Time) (int, error) {
	return 0, errStoreFailure
}

// failingRandomSource is a consumer-supplied WithRandom port that is down. Its
// error carries the same store text every other row proves against, so the
// row shows that a port's error text is redacted here too, not only a store's.
type failingRandomSource struct{}

func (failingRandomSource) Read([]byte) (int, error) { return 0, errStoreFailure }

// magiclinkFailureRecords decodes every JSON line buf holds, so a case can
// assert on fields rather than on message text.
func magiclinkFailureRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()

	var out []map[string]any

	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}

		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec), "log line %q", line)
		out = append(out, rec)
	}

	return out
}

// assertReasonRecorded is what every row here asserts: that some record among
// recs carries reason and names the failing error's Go type. It is shared
// rather than repeated per case because every row makes the identical claim
// about a different reason word.
func assertReasonRecorded(t *testing.T, recs []map[string]any, reason string) {
	t.Helper()

	var found bool

	for _, rec := range recs {
		if rec["reason"] == reason {
			found = true

			assert.NotEmpty(t, rec["error_type"], "the record does not name the error's type")
		}
	}

	assert.True(t, found, "no record carried reason %q", reason)
}

// TestMagicLinkFailureRecords pins the diagnostic-redaction requirement: every
// dependency this manager depends on — the token store's count and issue, the
// sender, the address resolver and the redemption user loader — is recorded by
// a fixed reason and the error's Go type, never by the error's own text.
//
// Each row's manager is built differently — a failing count, a failing
// insert, a failing sender, a failing resolver, a failing redemption loader —
// so each is a run closure rather than a shared call shape.
func TestMagicLinkFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T) *bytes.Buffer
		assert func(t *testing.T, recs []map[string]any)
	}

	known := &identity.Details{ID: "u-1", Username: "ada@example.com", Active: true}

	cases := []testCase{
		{
			name: "the issuance count is unavailable",
			assert: func(t *testing.T, recs []map[string]any) {
				assertReasonRecorded(t, recs, "token-count")
			},
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				tokens := tokensWithStore(t, countFailsStore{Store: onetime.NewMemoryStore()})

				loader := stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}}

				m, err := magiclink.NewManager(tokens, loader, &recordingSender{}, "https://app.example.com",
					magiclink.WithLogger(logger))
				require.NoError(t, err)

				m.Request(t.Context(), "ada@example.com", "/")

				return &buf
			},
		},
		{
			name: "the link cannot be issued",
			assert: func(t *testing.T, recs []map[string]any) {
				assertReasonRecorded(t, recs, "token-issue")
			},
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				tokens := tokensWithStore(t, insertFailsStore{Store: onetime.NewMemoryStore()})

				loader := stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}}

				m, err := magiclink.NewManager(tokens, loader, &recordingSender{}, "https://app.example.com",
					magiclink.WithLogger(logger))
				require.NoError(t, err)

				m.Request(t.Context(), "ada@example.com", "/")

				return &buf
			},
		},
		{
			name: "the sign-in message cannot be sent",
			assert: func(t *testing.T, recs []map[string]any) {
				assertReasonRecorded(t, recs, "sender")
			},
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				loader := stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}}
				sender := &failingSender{err: errStoreFailure}

				m, err := magiclink.NewManager(testTokens(t), loader, sender, "https://app.example.com",
					magiclink.WithLogger(logger))
				require.NoError(t, err)

				m.Request(t.Context(), "ada@example.com", "/")

				return &buf
			},
		},
		{
			name: "the submitted address cannot be resolved",
			assert: func(t *testing.T, recs []map[string]any) {
				assertReasonRecorded(t, recs, "resolver")
			},
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				loader := stubLoader{err: errStoreFailure}

				m, err := magiclink.NewManager(testTokens(t), loader, &recordingSender{}, "https://app.example.com",
					magiclink.WithLogger(logger))
				require.NoError(t, err)

				m.Request(t.Context(), "ada@example.com", "/")

				return &buf
			},
		},
		{
			name: "the binding nonce's random source fails",
			assert: func(t *testing.T, recs []map[string]any) {
				assertReasonRecorded(t, recs, "random-source")
			},
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				loader := stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}}

				m, err := magiclink.NewManager(testTokens(t), loader, &recordingSender{}, "https://app.example.com",
					magiclink.WithRandom(failingRandomSource{}), magiclink.WithLogger(logger))
				require.NoError(t, err)

				m.Request(t.Context(), "ada@example.com", "/")

				return &buf
			},
		},
		{
			name: "the link's user cannot be loaded at redemption",
			assert: func(t *testing.T, recs []map[string]any) {
				assertReasonRecorded(t, recs, "user-loader")
			},
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				tokens := testTokens(t)
				presented := issueFor(t, tokens, "u-1")

				loader := stubLoader{err: errStoreFailure}

				m, err := magiclink.NewManager(tokens, loader, &recordingSender{}, "https://app.example.com",
					magiclink.WithSameDeviceBinding(false), magiclink.WithLogger(logger))
				require.NoError(t, err)

				_, _ = m.Redeem(t.Context(), presented, "")

				return &buf
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			buf := tc.run(t)
			rendered := buf.String()

			assert.NotContains(t, rendered, "alice@example.com", "a written record leaked the store's address")
			assert.NotContains(t, rendered, "u-123", "a written record leaked the store's user reference")
			assert.NotContains(t, rendered, "ada@example.com", "a written record leaked the submitted address")

			recs := magiclinkFailureRecords(t, buf)
			require.NotEmpty(t, recs, "the failure was never reported")

			tc.assert(t, recs)
		})
	}
}
