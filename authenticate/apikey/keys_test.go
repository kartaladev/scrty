package apikey_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

func TestNewAPIKeyManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []apikey.Option
		assert func(t *testing.T, m *apikey.Keys, err error)
	}

	configError := func(t *testing.T, m *apikey.Keys, err error) {
		require.Error(t, err)
		assert.ErrorIs(t, err, apikey.ErrConfig)
		assert.Nil(t, m)
	}

	// consumerClockAt is what a consumer's own read-only clock reports, for
	// the "consumer clock" row below.
	consumerClockAt := time.Date(2035, time.July, 7, 7, 7, 7, 0, time.UTC)

	cases := []testCase{
		{
			name: "defaults",
			assert: func(t *testing.T, m *apikey.Keys, err error) {
				require.NoError(t, err)
				assert.Equal(t, "sk", m.Prefix())
			},
		},
		{name: "uppercase prefix", opts: []apikey.Option{apikey.WithPrefix("Bad-Prefix")}, assert: configError},
		{name: "prefix with a hyphen", opts: []apikey.Option{apikey.WithPrefix("acme-co")}, assert: configError},
		{name: "prefix with an underscore", opts: []apikey.Option{apikey.WithPrefix("ac_me")}, assert: configError},
		{name: "empty prefix", opts: []apikey.Option{apikey.WithPrefix("")}, assert: configError},
		{name: "prefix too long", opts: []apikey.Option{apikey.WithPrefix("abcdefghijklmnopq")}, assert: configError},
		{name: "nil digest", opts: []apikey.Option{apikey.WithDigest(nil)}, assert: configError},
		{
			name:   "a digest returning nothing",
			opts:   []apikey.Option{apikey.WithDigest(func([]byte) []byte { return nil })},
			assert: configError,
		},
		{
			name:   "a digest returning an empty value",
			opts:   []apikey.Option{apikey.WithDigest(func([]byte) []byte { return []byte{} })},
			assert: configError,
		},
		{
			name:   "a digest returning the same value for different inputs",
			opts:   []apikey.Option{apikey.WithDigest(func([]byte) []byte { return []byte("constant") })},
			assert: configError,
		},
		{name: "nil id generator", opts: []apikey.Option{apikey.WithIDGenerator(nil)}, assert: configError},
		{name: "nil clock", opts: []apikey.Option{apikey.WithClock(nil)}, assert: configError},
		{
			// *clockwork.FakeClock implements Now through a pointer receiver,
			// so a nil one is an interface holding a nil pointer: `== nil`
			// misses it, and only the reflect-based check the constructor now
			// uses catches it before the first issued key reads from a nil
			// receiver.
			name:   "typed-nil clock",
			opts:   []apikey.Option{apikey.WithClock((*clockwork.FakeClock)(nil))},
			assert: configError,
		},
		{
			// A Now-only consumer type: `time-source` "Read-only source for a
			// read-only component". Construction succeeds, and Issue reads
			// the issued key's created-at from the consumer's clock.
			name: "a consumer's own read-only clock is the manager's time source",
			opts: []apikey.Option{apikey.WithClock(fixedClock{at: consumerClockAt})},
			assert: func(t *testing.T, m *apikey.Keys, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, m)

				_, rec, issueErr := m.Issue(t.Context(), "u-consumer-clock", "consumer clock key", nil, 0)
				require.NoError(t, issueErr)
				assert.True(t, consumerClockAt.Equal(rec.CreatedAt),
					"the issued key's created-at did not come from the consumer's clock")
			},
		},
		{name: "nil random", opts: []apikey.Option{apikey.WithRandom(nil)}, assert: configError},
		{name: "nil store", opts: []apikey.Option{apikey.WithStore(nil)}, assert: configError},
		{name: "typed-nil store", opts: []apikey.Option{apikey.WithStore((*apikey.MemoryStore)(nil))}, assert: configError},
		{
			name: "a sixteen-character alphanumeric prefix",
			opts: []apikey.Option{apikey.WithPrefix("acme0123456789ab")},
			assert: func(t *testing.T, m *apikey.Keys, err error) {
				require.NoError(t, err)
				assert.Equal(t, "acme0123456789ab", m.Prefix())
			},
		},
		{
			name: "a single-character prefix",
			opts: []apikey.Option{apikey.WithPrefix("k")},
			assert: func(t *testing.T, m *apikey.Keys, err error) {
				require.NoError(t, err)
				assert.Equal(t, "k", m.Prefix())
			},
		},
		{
			name: "every port replaced at once",
			opts: []apikey.Option{
				apikey.WithStore(apikey.NewMemoryStore()),
				apikey.WithPrefix("acme"),
				apikey.WithDigest(func(b []byte) []byte { sum := sha512.Sum512(b); return sum[:] }),
				apikey.WithIDGenerator(id.NewV7Generator()),
				apikey.WithClock(clock.System()),
				apikey.WithRandom(rand.Reader),
			},
			assert: func(t *testing.T, m *apikey.Keys, err error) {
				require.NoError(t, err)
				assert.Equal(t, "acme", m.Prefix())
			},
		},
		{
			// A nil logger has an obvious reading — "do not log from this
			// component" — so it is ignored rather than refused.
			name: "a nil logger is accepted",
			opts: []apikey.Option{apikey.WithLogger(nil)},
			assert: func(t *testing.T, m *apikey.Keys, err error) {
				require.NoError(t, err)
				assert.Equal(t, "sk", m.Prefix())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := apikey.New(tc.opts...)
			tc.assert(t, m, err)
		})
	}
}

// TestAPIKeyConsumerOverrides covers the other half of every default: that a
// consumer can replace it without forking the library, and that the
// replacement is what both issuance and verification then use.
//
// Each subtest wires a structurally different manager — two managers, a
// replaced digest, a counting store, a fixed clock — so these are subtests
// rather than rows of one table.
func TestAPIKeyConsumerOverrides(t *testing.T) {
	t.Parallel()

	t.Run("a consumer prefix, and a key from another prefix is refused without a lookup", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		def, err := apikey.New()
		require.NoError(t, err)

		underDefault, _, err := def.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		store := &countingKeyStore{Store: apikey.NewMemoryStore()}

		acme, err := apikey.New(apikey.WithPrefix("acme"), apikey.WithStore(store))
		require.NoError(t, err)

		underAcme, _, err := acme.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(underAcme, "acme_"), "got %q", underAcme)

		before := store.Reads()

		_, _, err = acme.Verify(ctx, underDefault)
		assert.ErrorIs(t, err, apikey.ErrVerificationFailed)
		assert.Equal(t, before, store.Reads(), "a wrong prefix costs no lookup")
	})

	t.Run("a consumer digest is used for issuance and verification", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		digest := func(b []byte) []byte {
			sum := sha512.Sum512(b)

			return sum[:]
		}

		store := apikey.NewMemoryStore()

		m, err := apikey.New(apikey.WithStore(store), apikey.WithDigest(digest))
		require.NoError(t, err)

		presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		_, secret, _ := strings.Cut(strings.TrimPrefix(presented, "sk_"), ".")

		raw, err := base64.RawURLEncoding.DecodeString(secret)
		require.NoError(t, err)

		stored, err := store.Get(ctx, rec.ID)
		require.NoError(t, err)
		assert.Equal(t, digest(raw), stored.SecretDigest)

		_, _, err = m.Verify(ctx, presented)
		assert.NoError(t, err)
	})

	t.Run("the default digest is SHA-256 of the secret", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		store := apikey.NewMemoryStore()

		m, err := apikey.New(apikey.WithStore(store))
		require.NoError(t, err)

		presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		_, secret, _ := strings.Cut(strings.TrimPrefix(presented, "sk_"), ".")

		raw, err := base64.RawURLEncoding.DecodeString(secret)
		require.NoError(t, err)

		stored, err := store.Get(ctx, rec.ID)
		require.NoError(t, err)

		want := sha256Of(raw)
		assert.Equal(t, want, stored.SecretDigest)
		assert.NotContains(t, string(stored.SecretDigest), secret)
	})

	t.Run("a consumer store serves every operation", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		store := &countingKeyStore{Store: apikey.NewMemoryStore()}

		m, err := apikey.New(apikey.WithStore(store))
		require.NoError(t, err)

		presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		_, _, err = m.Verify(ctx, presented)
		require.NoError(t, err)

		_, err = m.List(ctx, "svc-billing")
		require.NoError(t, err)

		_, _, err = m.Rotate(ctx, rec.ID, 0)
		require.NoError(t, err)

		assert.Positive(t, store.Writes())
		assert.Positive(t, store.Reads())
		assert.Positive(t, store.Lists())
	})

	t.Run("a consumer identifier generator mints the record identifiers", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		want := id.MustParse("01930000-0000-7000-8000-0000000000aa")

		m, err := apikey.New(apikey.WithIDGenerator(fixedIDs{want}))
		require.NoError(t, err)

		presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		assert.Equal(t, want, rec.ID)
		assert.True(t, strings.HasPrefix(presented, "sk_"+want.String()+"."), "got %q", presented)
	})

	t.Run("a consumer clock decides issue time and expiry", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		at := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

		m, err := apikey.New(apikey.WithClock(clockwork.NewFakeClockAt(at)))
		require.NoError(t, err)

		_, rec, err := m.Issue(ctx, "svc-billing", "k", nil, time.Hour)
		require.NoError(t, err)

		assert.True(t, rec.CreatedAt.Equal(at))
		require.NotNil(t, rec.ExpiresAt)
		assert.True(t, rec.ExpiresAt.Equal(at.Add(time.Hour)))
	})
}

// fixedIDs is a generator that always mints the same identifier.
type fixedIDs struct {
	value id.ID
}

func (g fixedIDs) NewID() (id.ID, error) { return g.value, nil }

func TestManagerIssue(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		principal identity.UserID
		lifetime  time.Duration
		random    io.Reader
		digest    func([]byte) []byte
		assert    func(t *testing.T, presented string, rec apikey.Key, err error, stored int)
	}

	cases := []testCase{
		{
			name:      "the presented key carries the prefix, the id and the secret",
			principal: "svc-billing",
			assert: func(t *testing.T, presented string, rec apikey.Key, err error, stored int) {
				require.NoError(t, err)
				assert.Equal(t, 1, stored)

				assert.True(t, strings.HasPrefix(presented, "sk_"), "got %q", presented)

				rest := strings.TrimPrefix(presented, "sk_")
				idPart, secretPart, found := strings.Cut(rest, ".")
				require.True(t, found)
				assert.Equal(t, rec.ID.String(), idPart)

				raw, decErr := base64.RawURLEncoding.DecodeString(secretPart)
				require.NoError(t, decErr)
				assert.Len(t, raw, 32, "32 bytes from the OS random source")

				assert.Equal(t, identity.UserID("svc-billing"), rec.Principal)
				assert.Equal(t, "nightly export", rec.Name)
				assert.Equal(t, []string{"invoices:read", "invoices:export"}, rec.Scopes)
				assert.NotContains(t, fmt.Sprintf("%+v", rec), secretPart,
					"the record must not carry the secret")

				assert.Nil(t, rec.ExpiresAt, "a lifetime of zero never expires")
				assert.Nil(t, rec.RevokedAt)
				assert.Nil(t, rec.LastUsedAt)
			},
		},
		{
			name:      "a positive lifetime expires at issue time plus it",
			principal: "svc-billing",
			lifetime:  7 * 24 * time.Hour,
			assert: func(t *testing.T, _ string, rec apikey.Key, err error, _ int) {
				require.NoError(t, err)
				require.NotNil(t, rec.ExpiresAt)
				assert.True(t, rec.ExpiresAt.Equal(rec.CreatedAt.Add(7*24*time.Hour)))
			},
		},
		{
			name:      "a negative lifetime never expires",
			principal: "svc-billing",
			lifetime:  -time.Hour,
			assert: func(t *testing.T, _ string, rec apikey.Key, err error, _ int) {
				require.NoError(t, err)
				assert.Nil(t, rec.ExpiresAt, "a lifetime of zero or less means no expiry")
			},
		},
		{
			name:      "an empty principal is refused and stores nothing",
			principal: "",
			assert: func(t *testing.T, presented string, _ apikey.Key, err error, stored int) {
				require.Error(t, err)
				assert.Empty(t, presented)
				assert.Zero(t, stored)
			},
		},
		{
			name:      "a random source failure stores nothing",
			principal: "svc-billing",
			random:    failingReader{},
			assert: func(t *testing.T, presented string, _ apikey.Key, err error, stored int) {
				require.Error(t, err)
				assert.Empty(t, presented)
				assert.Zero(t, stored, "the store must receive no write")
			},
		},
		{
			// The secret drawn here starts with a zero byte, the one input
			// this consumer digest returns nothing for.
			name:      "a digest returning nothing for the secret stores nothing",
			principal: "svc-billing",
			random:    zeroReader{},
			digest:    emptyForLeadingZero,
			assert: func(t *testing.T, presented string, _ apikey.Key, err error, stored int) {
				require.Error(t, err)
				assert.ErrorIs(t, err, apikey.ErrConfig, "a digest that returns nothing is a broken configuration")
				assert.Empty(t, presented)
				assert.Zero(t, stored, "a key stored under no digest would accept any secret its digest also drops")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			store := &countingKeyStore{Store: apikey.NewMemoryStore()}

			opts := []apikey.Option{apikey.WithStore(store)}
			if tc.random != nil {
				opts = append(opts, apikey.WithRandom(tc.random))
			}
			if tc.digest != nil {
				opts = append(opts, apikey.WithDigest(tc.digest))
			}

			m, err := apikey.New(opts...)
			require.NoError(t, err)

			presented, rec, issueErr := m.Issue(ctx, tc.principal, "nightly export",
				[]string{"invoices:read", "invoices:export"}, tc.lifetime)

			tc.assert(t, presented, rec, issueErr, store.Writes())
		})
	}
}

func TestListRevealsNoSecret(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	m, err := apikey.New()
	require.NoError(t, err)

	presented, _, err := m.Issue(ctx, "svc-billing", "nightly export", []string{"invoices:read"}, 0)
	require.NoError(t, err)

	_, secret, _ := strings.Cut(strings.TrimPrefix(presented, "sk_"), ".")
	require.NotEmpty(t, secret)

	keys, err := m.List(ctx, "svc-billing")
	require.NoError(t, err)
	require.Len(t, keys, 1)

	assert.NotContains(t, fmt.Sprintf("%+v", keys[0]), secret)
}

// Standalone from TestManagerIssue: it mutates the caller's scopes slice after Issue returns.
func TestIssuedScopesAreACopy(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	m, err := apikey.New()
	require.NoError(t, err)

	scopes := []string{"invoices:read"}

	_, rec, err := m.Issue(ctx, "svc-billing", "nightly export", scopes, 0)
	require.NoError(t, err)

	scopes[0] = "invoices:write"

	assert.Equal(t, []string{"invoices:read"}, rec.Scopes,
		"the caller's slice must not reach into the issued record")
}

// TestManagerVerify pins that every refusal is one error. A revoked key that
// looked different from an unknown one would tell a scanner which identifiers
// were ever real, and an outage that looked different from a refusal would
// announce when the store was down.
func TestManagerVerify(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name    string
		prepare func(t *testing.T, m *apikey.Keys, valid string) string
		store   func(t *testing.T, inner apikey.Store) apikey.Store
		at      time.Time
		assert  func(t *testing.T, p identity.Principal, rec apikey.Key, err error)
	}

	unchanged := func(_ *testing.T, _ *apikey.Keys, valid string) string { return valid }

	refused := func(t *testing.T, p identity.Principal, rec apikey.Key, err error) {
		assert.ErrorIs(t, err, apikey.ErrVerificationFailed)
		assert.Empty(t, p.ID)
		assert.Empty(t, p.Scopes)
		assert.Zero(t, rec.ID, "a refusal yields no record")
	}

	cases := []testCase{
		{
			name:    "a valid key yields a service principal",
			prepare: unchanged,
			at:      base,
			assert: func(t *testing.T, p identity.Principal, rec apikey.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.KindService, p.Kind)
				assert.True(t, p.IsService())
				assert.Equal(t, identity.UserID("svc-billing"), p.ID)
				assert.Equal(t, "nightly export", p.Name)
				assert.Equal(t, []string{"invoices:read", "invoices:export"}, p.Scopes)
				assert.Equal(t, identity.UserID("svc-billing"), rec.Principal)
			},
		},
		{
			name: "an unknown identifier",
			prepare: func(t *testing.T, _ *apikey.Keys, valid string) string {
				other, err := newID()
				require.NoError(t, err)

				_, secret, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")

				return "sk_" + other.String() + "." + secret
			},
			at:     base,
			assert: refused,
		},
		{
			name: "a wrong secret",
			prepare: func(_ *testing.T, _ *apikey.Keys, valid string) string {
				idPart, _, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")

				return "sk_" + idPart + "." +
					base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, 32))
			},
			at:     base,
			assert: refused,
		},
		{
			name:    "an expired key",
			prepare: unchanged,
			at:      base.Add(8 * 24 * time.Hour),
			assert:  refused,
		},
		{
			name:    "a key verified on the instant it expires is still accepted",
			prepare: unchanged,
			at:      base.Add(7 * 24 * time.Hour),
			assert: func(t *testing.T, _ identity.Principal, _ apikey.Key, err error) {
				require.NoError(t, err, "accepted while now is not after expiry")
			},
		},
		{
			name: "a revoked key",
			prepare: func(t *testing.T, m *apikey.Keys, valid string) string {
				idPart, _, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")

				parsed, err := id.Parse(idPart)
				require.NoError(t, err)
				require.NoError(t, m.Revoke(t.Context(), parsed))

				return valid
			},
			at:     base,
			assert: refused,
		},
		{
			name:    "a store outage",
			prepare: unchanged,
			store: func(t *testing.T, _ apikey.Store) apikey.Store {
				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Return(apikey.Key{}, errStore).
					AnyTimes()

				return store
			},
			at:     base,
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			clk := clockwork.NewFakeClockAt(base)
			inner := apikey.NewMemoryStore()

			m, err := apikey.New(
				apikey.WithStore(inner),
				apikey.WithClock(clk),
			)
			require.NoError(t, err)

			valid, _, err := m.Issue(ctx, "svc-billing", "nightly export",
				[]string{"invoices:read", "invoices:export"}, 7*24*time.Hour)
			require.NoError(t, err)

			presented := tc.prepare(t, m, valid)

			verifier := m
			if tc.store != nil {
				verifier, err = apikey.New(
					apikey.WithStore(tc.store(t, inner)),
					apikey.WithClock(clk),
				)
				require.NoError(t, err)
			}

			clk.Advance(tc.at.Sub(clk.Now()))

			p, rec, verifyErr := verifier.Verify(ctx, presented)
			tc.assert(t, p, rec, verifyErr)
		})
	}
}

// Standalone from TestManagerVerify: it issues a key with no lifetime, where every TestManagerVerify case shares one seven-day key.
func TestManagerExpiry(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	clk := clockwork.NewFakeClockAt(base)

	m, err := apikey.New(apikey.WithClock(clk))
	require.NoError(t, err)

	never, _, err := m.Issue(ctx, "svc-billing", "forever", nil, 0)
	require.NoError(t, err)

	clk.Advance(base.AddDate(5, 0, 0).Sub(clk.Now()))

	_, _, err = m.Verify(ctx, never)
	assert.NoError(t, err, "a lifetime of zero or less never expires")
}

// Standalone: it verifies, revokes and verifies again in sequence, then revokes an unknown key.
func TestManagerRevoke(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	m, err := apikey.New()
	require.NoError(t, err)

	presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
	require.NoError(t, err)

	_, _, err = m.Verify(ctx, presented)
	require.NoError(t, err)

	require.NoError(t, m.Revoke(ctx, rec.ID))

	_, _, err = m.Verify(ctx, presented)
	assert.ErrorIs(t, err, apikey.ErrVerificationFailed)

	unknown, err := newID()
	require.NoError(t, err)
	assert.ErrorIs(t, m.Revoke(ctx, unknown), apikey.ErrKeyNotFound)
}

// TestVerifyNeverDiscloseThePresentedKey pins that neither the error a refusal
// returns nor anything this package logs carries the string the caller
// presented. A refusal that echoed the key would put it in every log line the
// caller's own error handling writes.
// Standalone from TestManagerVerify: it verifies through a capturing logger, and its case names would collide with TestManagerVerify's.
func TestVerifyNeverDiscloseThePresentedKey(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		prepare func(t *testing.T, m *apikey.Keys, valid string) string
	}

	cases := []testCase{
		{
			name:    "a malformed key",
			prepare: func(_ *testing.T, _ *apikey.Keys, _ string) string { return "sk_nonsense.aaaa" },
		},
		{
			name: "an unknown identifier",
			prepare: func(t *testing.T, _ *apikey.Keys, valid string) string {
				other, err := newID()
				require.NoError(t, err)

				_, secret, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")

				return "sk_" + other.String() + "." + secret
			},
		},
		{
			name: "a revoked key",
			prepare: func(t *testing.T, m *apikey.Keys, valid string) string {
				idPart, _, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")

				parsed, err := id.Parse(idPart)
				require.NoError(t, err)
				require.NoError(t, m.Revoke(t.Context(), parsed))

				return valid
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			var logged bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))

			m, err := apikey.New(apikey.WithLogger(logger))
			require.NoError(t, err)

			valid, _, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
			require.NoError(t, err)

			presented := tc.prepare(t, m, valid)

			_, _, verifyErr := m.Verify(ctx, presented)
			require.ErrorIs(t, verifyErr, apikey.ErrVerificationFailed)

			assert.NotContains(t, verifyErr.Error(), presented, "the error echoed the presented key")

			_, secret, found := strings.Cut(strings.TrimPrefix(presented, "sk_"), ".")
			if found {
				assert.NotContains(t, logged.String(), secret, "a log record carried the secret")
			}

			assert.NotContains(t, logged.String(), presented, "a log record carried the presented key")
		})
	}
}

// Standalone from TestManagerVerify: it writes the record into the store directly instead of issuing it.
func TestVerify_EmptyDigestDoesNotAcceptAnySecret(t *testing.T) {
	t.Parallel()

	// A well-formed secret whose first byte is zero, so emptyForLeadingZero
	// returns nothing for it.
	zeroSecret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	type testCase struct {
		name   string
		digest func([]byte) []byte
		stored []byte
		assert func(t *testing.T, p identity.Principal, err error)
	}

	refused := func(t *testing.T, p identity.Principal, err error) {
		assert.ErrorIs(t, err, apikey.ErrVerificationFailed)
		assert.Empty(t, p.ID, "a refusal names no principal")
	}

	cases := []testCase{
		{
			name:   "a digest returning nothing for the secret, against a record stored with no digest",
			digest: emptyForLeadingZero,
			stored: nil,
			assert: refused,
		},
		{
			name:   "a digest returning nothing for the secret, against a record stored with an empty digest",
			digest: emptyForLeadingZero,
			stored: []byte{},
			assert: refused,
		},
		{
			name:   "the default digest against a record stored with no digest",
			stored: nil,
			assert: refused,
		},
		{
			name:   "a digest returning nothing for the secret, against a record with a digest",
			digest: emptyForLeadingZero,
			stored: sha256Of([]byte("some other secret")),
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			store := apikey.NewMemoryStore()
			opts := []apikey.Option{apikey.WithStore(store)}
			if tc.digest != nil {
				opts = append(opts, apikey.WithDigest(tc.digest))
			}

			m, err := apikey.New(opts...)
			require.NoError(t, err)

			keyID, err := newID()
			require.NoError(t, err)

			// The record reaches the store directly, as one written by an
			// earlier deployment or another writer would.
			require.NoError(t, store.Put(ctx, apikey.Key{
				ID:           keyID,
				Principal:    "svc-admin",
				Scopes:       []string{"admin"},
				SecretDigest: tc.stored,
				CreatedAt:    time.Now(),
			}))

			p, _, verifyErr := m.Verify(ctx, "sk_"+keyID.String()+"."+zeroSecret)
			tc.assert(t, p, verifyErr)
		})
	}
}

// TestManagerParsePresented pins that a key whose shape is wrong costs one
// string comparison rather than a store query. A scanner firing malformed
// strings at an endpoint must not be able to turn that endpoint into load on
// the database behind it.
// Standalone from TestManagerVerify: it verifies through a read-counting store and asserts the store was never read.
func TestManagerParsePresented(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		presented func(valid string) string
	}

	cases := []testCase{
		{name: "empty", presented: func(string) string { return "" }},
		{name: "no prefix", presented: func(v string) string { return strings.TrimPrefix(v, "sk_") }},
		{name: "wrong prefix", presented: func(v string) string { return "acme_" + strings.TrimPrefix(v, "sk_") }},
		{name: "prefix only", presented: func(string) string { return "sk_" }},
		{name: "no dot", presented: func(v string) string { return strings.ReplaceAll(v, ".", "") }},
		{name: "unparsable id", presented: func(string) string { return "sk_not-an-id.c2VjcmV0" }},
		{name: "empty secret", presented: func(v string) string { return v[:strings.Index(v, ".")+1] }},
		{name: "prefix of the prefix", presented: func(v string) string { return "s_" + strings.TrimPrefix(v, "sk_") }},
		{
			name: "a secret that is not base64url",
			presented: func(v string) string {
				return v[:strings.Index(v, ".")+1] + "not a secret!!"
			},
		},
		{
			name:      "the separator is the underscore, not a bare prefix",
			presented: func(v string) string { return "sk" + strings.TrimPrefix(v, "sk_") },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			store := &countingKeyStore{Store: apikey.NewMemoryStore()}

			m, err := apikey.New(apikey.WithStore(store))
			require.NoError(t, err)

			valid, _, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
			require.NoError(t, err)

			before := store.Reads()

			_, _, verifyErr := m.Verify(ctx, tc.presented(valid))
			assert.ErrorIs(t, verifyErr, apikey.ErrVerificationFailed)
			assert.Equal(t, before, store.Reads(), "a malformed key must not reach the store")
		})
	}
}

// errRedactionFixture is the dependency error every diagnostic-redaction
// reproduction in this change quotes: a username and a user reference the
// library never saw, which no record may carry.
var errRedactionFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// failsWithFixture is a working store whose last-use write alone fails, with
// an error a test chooses rather than the package's own fixed errStore.
type failsWithFixture struct {
	apikey.Store
	err error
}

func (s failsWithFixture) TouchLastUsed(context.Context, id.ID, time.Time) error { return s.err }

// TestAPIKeyStoreFailureRecords pins that a store failure at either of the
// manager's two store call sites during Verify — reading the record and
// recording last use — is recorded through a fixed reason and the error's
// type, never the store's own text, while the public key identifier stays.
// Standalone from TestManagerVerify: it verifies through a second manager with a failing store and a capturing logger.
func TestAPIKeyStoreFailureRecords(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		store  func(t *testing.T, inner apikey.Store) apikey.Store
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "the record read fails",
			store: func(t *testing.T, _ apikey.Store) apikey.Store {
				t.Helper()
				s := NewMockStore(gomock.NewController(t))
				s.EXPECT().Get(gomock.Any(), gomock.Any()).Return(apikey.Key{}, errRedactionFixture)
				return s
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				assert.ErrorIs(t, err, apikey.ErrVerificationFailed)
			},
		},
		{
			name: "the last-use write fails, and verification still succeeds",
			store: func(_ *testing.T, inner apikey.Store) apikey.Store {
				return failsWithFixture{Store: inner, err: errRedactionFixture}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err, "a best-effort write never fails the verification it rode in on")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(base)
			inner := apikey.NewMemoryStore()
			issuer, err := apikey.New(
				apikey.WithStore(inner), apikey.WithClock(clk))
			require.NoError(t, err)

			presented, rec, err := issuer.Issue(t.Context(), "svc-billing", "nightly export",
				[]string{"invoices:read"}, 7*24*time.Hour)
			require.NoError(t, err)

			var logs bytes.Buffer
			verifier, err := apikey.New(
				apikey.WithStore(tc.store(t, inner)),
				apikey.WithClock(clk),
				apikey.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
			require.NoError(t, err)

			_, _, verifyErr := verifier.Verify(t.Context(), presented)
			tc.assert(t, verifyErr)

			out := logs.String()
			assert.NotContains(t, out, "alice@example.com")
			assert.NotContains(t, out, "u-123")
			assert.Contains(t, out, "reason=key-store")
			assert.Contains(t, out, "error_type=")
			assert.Contains(t, out, "key_id="+rec.ID.String(), "the public key identifier stays")
		})
	}
}

// Standalone from TestManagerVerify: it asserts what the store recorded about the key's last use, not the verification's outcome.
func TestManagerLastUsed(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		store  func(inner apikey.Store) apikey.Store
		assert func(t *testing.T, inner apikey.Store, rec apikey.Key, err error)
	}

	cases := []testCase{
		{
			name: "a successful verification records the time",
			assert: func(t *testing.T, inner apikey.Store, rec apikey.Key, err error) {
				require.NoError(t, err)

				stored, getErr := inner.Get(t.Context(), rec.ID)
				require.NoError(t, getErr)
				require.NotNil(t, stored.LastUsedAt)
				assert.True(t, stored.LastUsedAt.Equal(at))
			},
		},
		{
			name:  "a failure to record does not fail verification",
			store: func(inner apikey.Store) apikey.Store { return touchFailsStore{Store: inner} },
			assert: func(t *testing.T, inner apikey.Store, rec apikey.Key, err error) {
				assert.NoError(t, err, "a best-effort write may not refuse a valid key")

				stored, getErr := inner.Get(t.Context(), rec.ID)
				require.NoError(t, getErr)
				assert.Nil(t, stored.LastUsedAt, "nothing was recorded, and nothing pretended otherwise")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			inner := apikey.NewMemoryStore()

			store := apikey.Store(inner)
			if tc.store != nil {
				store = tc.store(inner)
			}

			m, err := apikey.New(
				apikey.WithStore(store),
				apikey.WithClock(clockwork.NewFakeClockAt(at)),
				// The best-effort case logs a warning by design; this keeps it
				// out of the test output without silencing the behaviour.
				apikey.WithLogger(slog.New(slog.DiscardHandler)),
			)
			require.NoError(t, err)

			presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
			require.NoError(t, err)

			_, verified, verifyErr := m.Verify(ctx, presented)
			if verifyErr == nil {
				require.NotNil(t, verified.LastUsedAt)
				assert.True(t, verified.LastUsedAt.Equal(at),
					"the returned record carries the time whether or not the write landed")
			}

			tc.assert(t, inner, rec, verifyErr)
		})
	}
}

func TestManagerRotate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// lifetime is how long the key rotated lives; zero is no expiry.
		lifetime time.Duration
		// advance moves the manager's clock once the key is issued.
		advance time.Duration
		// store wraps the inner store; clk is the manager's clock and cancel
		// ends the context Rotate is called with.
		store  func(inner apikey.Store, clk *clockwork.FakeClock, cancel context.CancelFunc) apikey.Store
		target func(t *testing.T, rec apikey.Key) id.ID
		assert func(t *testing.T, m *apikey.Keys, old string, fresh string, rec apikey.Key, err error)
	}

	// noLiveReplacement fails when a key without an expiry, which is what a
	// replacement rotated with a zero lifetime is, is still live.
	noLiveReplacement := func(t *testing.T, m *apikey.Keys) {
		t.Helper()

		keys, err := m.List(t.Context(), "svc-billing")
		require.NoError(t, err)

		for _, k := range keys {
			if k.ExpiresAt == nil {
				assert.NotNil(t, k.RevokedAt, "replacement %s was left live", k.ID)
			}
		}
	}

	// onlyOldLive fails unless exactly one key is live, which is the old one
	// whose revoke failed: the replacement must have been ended.
	onlyOldLive := func(t *testing.T, m *apikey.Keys) {
		t.Helper()

		keys, err := m.List(t.Context(), "svc-billing")
		require.NoError(t, err)

		live := 0

		for _, k := range keys {
			if k.RevokedAt == nil {
				live++
			}
		}

		assert.Equal(t, 1, live, "only the old key, whose revoke failed, may stay live")
	}

	sameKey := func(_ *testing.T, rec apikey.Key) id.ID { return rec.ID }

	cases := []testCase{
		{
			name:   "the new key works and the old one does not",
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Keys, old, fresh string, _ apikey.Key, err error) {
				require.NoError(t, err)

				p, _, verifyErr := m.Verify(t.Context(), fresh)
				require.NoError(t, verifyErr)
				assert.Equal(t, identity.UserID("svc-billing"), p.ID)
				assert.Equal(t, "nightly export", p.Name)
				assert.Equal(t, []string{"invoices:read"}, p.Scopes)

				_, _, oldErr := m.Verify(t.Context(), old)
				assert.ErrorIs(t, oldErr, apikey.ErrVerificationFailed)
			},
		},
		{
			name:   "the replacement is a different record",
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Keys, old, fresh string, _ apikey.Key, err error) {
				require.NoError(t, err)
				assert.NotEqual(t, old, fresh)

				keys, listErr := m.List(t.Context(), "svc-billing")
				require.NoError(t, listErr)
				assert.Len(t, keys, 2, "the old record stays, revoked, for whoever audits it")
			},
		},
		{
			name:   "the caller's lifetime is used, not the old key's",
			target: sameKey,
			assert: func(t *testing.T, _ *apikey.Keys, _, _ string, rec apikey.Key, err error) {
				require.NoError(t, err)
				assert.Nil(t, rec.ExpiresAt, "rotated here with a lifetime of zero")
			},
		},
		{
			name: "an unknown key issues nothing",
			target: func(t *testing.T, _ apikey.Key) id.ID {
				other, err := newID()
				require.NoError(t, err)

				return other
			},
			assert: func(t *testing.T, m *apikey.Keys, _, fresh string, _ apikey.Key, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, apikey.ErrKeyNotFound)
				assert.Empty(t, fresh)

				keys, listErr := m.List(t.Context(), "svc-billing")
				require.NoError(t, listErr)
				assert.Len(t, keys, 1, "nothing new may be issued for an unknown key")
			},
		},
		{
			name: "a failed revoke is an error rather than a silently split credential",
			store: func(inner apikey.Store, _ *clockwork.FakeClock, _ context.CancelFunc) apikey.Store {
				return revokeFailsStore{Store: inner}
			},
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Keys, old, fresh string, _ apikey.Key, err error) {
				require.Error(t, err)
				assert.Empty(t, fresh, "the new key is returned only when both steps succeed")

				_, _, oldErr := m.Verify(t.Context(), old)
				assert.NoError(t, oldErr,
					"outside a transaction these are two writes: the old key is still live, and the error says so")
			},
		},
		{
			name:     "a key that expires while the replacement is issued is refused and nothing stays live",
			lifetime: time.Hour,
			advance:  time.Hour, // on the instant it expires: still live at the first check
			store: func(inner apikey.Store, clk *clockwork.FakeClock, _ context.CancelFunc) apikey.Store {
				return advanceOnPutStore{Store: inner, clk: clk, by: time.Second, puts: new(atomic.Int32)}
			},
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Keys, _, fresh string, _ apikey.Key, err error) {
				assert.ErrorIs(t, err, apikey.ErrRotationRefused)
				assert.Empty(t, fresh)
				noLiveReplacement(t, m)
			},
		},
		{
			name: "a store failure on the old key's revoke ends the replacement and keeps the old key",
			store: func(inner apikey.Store, _ *clockwork.FakeClock, _ context.CancelFunc) apikey.Store {
				return &failOldRevokeStore{Store: inner}
			},
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Keys, old, fresh string, _ apikey.Key, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, errStore, "the store failure stays identifiable")
				assert.Empty(t, fresh)
				onlyOldLive(t, m)

				_, _, oldErr := m.Verify(t.Context(), old)
				assert.NoError(t, oldErr, "the old key's revoke failed, so the old key is still live")
			},
		},
		{
			name: "both revokes failing wraps both failures and names the replacement",
			store: func(inner apikey.Store, _ *clockwork.FakeClock, _ context.CancelFunc) apikey.Store {
				return &revokeFailsTwiceStore{Store: inner}
			},
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Keys, _, fresh string, old apikey.Key, err error) {
				require.Error(t, err)
				assert.Empty(t, fresh)
				assert.ErrorIs(t, err, errOldRevoke)
				assert.ErrorIs(t, err, errUndoRevoke)

				keys, listErr := m.List(t.Context(), "svc-billing")
				require.NoError(t, listErr)
				require.Len(t, keys, 2)

				for _, k := range keys {
					if k.ID != old.ID {
						assert.Contains(t, err.Error(), k.ID.String(),
							"an operator needs the replacement's ID to revoke it by hand")
					}
				}
			},
		},
		{
			name: "a caller cancelled at the old key's revoke still ends the replacement",
			store: func(inner apikey.Store, _ *clockwork.FakeClock, cancel context.CancelFunc) apikey.Store {
				return &failOldRevokeStore{Store: inner, cancel: cancel}
			},
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Keys, _, fresh string, _ apikey.Key, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, context.Canceled, "the revoke failure stays identifiable")
				assert.Empty(t, fresh)
				onlyOldLive(t, m)
			},
		},
		{
			name: "a cancelled caller still ends the replacement of a rotation that lost",
			store: func(inner apikey.Store, _ *clockwork.FakeClock, cancel context.CancelFunc) apikey.Store {
				return &loseThenCancelStore{Store: inner, cancel: cancel}
			},
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Keys, _, fresh string, _ apikey.Key, err error) {
				assert.ErrorIs(t, err, apikey.ErrRotationRefused)
				assert.Empty(t, fresh)
				noLiveReplacement(t, m)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			clk := clockwork.NewFakeClockAt(time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC))
			inner := apikey.NewMemoryStore()

			store := apikey.Store(inner)
			if tc.store != nil {
				store = tc.store(inner, clk, cancel)
			}

			m, err := apikey.New(apikey.WithStore(store), apikey.WithClock(clk))
			require.NoError(t, err)

			old, issued, err := m.Issue(ctx, "svc-billing", "nightly export", []string{"invoices:read"}, tc.lifetime)
			require.NoError(t, err)

			clk.Advance(tc.advance)

			fresh, rec, rotateErr := m.Rotate(ctx, tc.target(t, issued), 0)
			tc.assert(t, m, old, fresh, rec, rotateErr)
		})
	}
}

// Standalone from TestManagerRotate: it ends the key first and rotates through a second manager on a write-counting store.
func TestRotate_RefusesRevokedOrExpiredKey(t *testing.T) {
	t.Parallel()

	issuedAt := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name     string
		lifetime time.Duration
		// end makes the issued key one Rotate must refuse.
		end    func(t *testing.T, m *apikey.Keys, clk *clockwork.FakeClock, rec apikey.Key)
		assert func(t *testing.T, m *apikey.Keys, store *countingKeyStore, fresh string, err error)
	}

	refusedIssuingNothing := func(t *testing.T, m *apikey.Keys, store *countingKeyStore, fresh string, err error) {
		require.ErrorIs(t, err, apikey.ErrRotationRefused)
		assert.Empty(t, fresh)
		assert.Zero(t, store.Writes(), "a refused rotation writes nothing")

		keys, listErr := m.List(t.Context(), "svc-admin")
		require.NoError(t, listErr)
		assert.Len(t, keys, 1, "nothing new may be issued for a key that is no longer accepted")
	}

	cases := []testCase{
		{
			name: "a revoked admin-scoped key",
			end: func(t *testing.T, m *apikey.Keys, _ *clockwork.FakeClock, rec apikey.Key) {
				require.NoError(t, m.Revoke(t.Context(), rec.ID))
			},
			assert: refusedIssuingNothing,
		},
		{
			name:     "a key past its lifetime",
			lifetime: time.Hour,
			end: func(_ *testing.T, _ *apikey.Keys, clk *clockwork.FakeClock, _ apikey.Key) {
				clk.Advance(time.Hour + time.Second)
			},
			assert: refusedIssuingNothing,
		},
		{
			name:     "a key on the instant it expires is still live, and rotates",
			lifetime: time.Hour,
			end: func(_ *testing.T, _ *apikey.Keys, clk *clockwork.FakeClock, _ apikey.Key) {
				clk.Advance(time.Hour)
			},
			assert: func(t *testing.T, m *apikey.Keys, _ *countingKeyStore, fresh string, err error) {
				require.NoError(t, err)

				_, _, verifyErr := m.Verify(t.Context(), fresh)
				assert.NoError(t, verifyErr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			clk := clockwork.NewFakeClockAt(issuedAt)
			inner := apikey.NewMemoryStore()

			m, err := apikey.New(apikey.WithStore(inner), apikey.WithClock(clk))
			require.NoError(t, err)

			_, rec, err := m.Issue(ctx, "svc-admin", "break glass", []string{"admin"}, tc.lifetime)
			require.NoError(t, err)

			tc.end(t, m, clk, rec)

			// Counting starts here, so only the rotation's own writes count.
			store := &countingKeyStore{Store: inner}
			rotator, err := apikey.New(apikey.WithStore(store), apikey.WithClock(clk))
			require.NoError(t, err)

			fresh, _, rotateErr := rotator.Rotate(ctx, rec.ID, 0)
			tc.assert(t, m, store, fresh, rotateErr)
		})
	}
}

// Standalone: it races several rotations of one key through a barrier store.
func TestRotate_ConcurrentRotationsLeaveOneLiveReplacement(t *testing.T) {
	t.Parallel()

	const rotations = 8

	ctx := t.Context()

	inner := apikey.NewMemoryStore()
	m, err := apikey.New(apikey.WithStore(inner))
	require.NoError(t, err)

	old, rec, err := m.Issue(ctx, "svc-billing", "nightly export", []string{"invoices:read"}, 0)
	require.NoError(t, err)

	// Every rotation reads the key live and issues its replacement before any
	// of them revokes it.
	rotator, err := apikey.New(apikey.WithStore(newRevokeBarrierStore(inner, rec.ID, rotations)))
	require.NoError(t, err)

	type outcome struct {
		presented string
		rec       apikey.Key
		err       error
	}

	outcomes := make([]outcome, rotations)

	var wg sync.WaitGroup
	for i := range rotations {
		wg.Go(func() {
			presented, fresh, rotateErr := rotator.Rotate(ctx, rec.ID, 0)
			outcomes[i] = outcome{presented: presented, rec: fresh, err: rotateErr}
		})
	}
	wg.Wait()

	var winners []outcome
	for _, o := range outcomes {
		if o.err == nil {
			winners = append(winners, o)
			continue
		}
		require.ErrorIs(t, o.err, apikey.ErrRotationRefused, "a rotation that lost the race is refused")
		assert.Empty(t, o.presented, "a refused rotation returns no key")
	}
	require.Equal(t, 1, len(winners), "exactly one concurrent rotation returns a new key") //nolint:testifylint // Len would print every presented key

	keys, err := m.List(ctx, "svc-billing")
	require.NoError(t, err)
	require.Len(t, keys, rotations+1, "every replacement issued is kept, revoked, for whoever audits it")

	var live []id.ID
	for _, k := range keys {
		if k.RevokedAt == nil {
			live = append(live, k.ID)
		}
	}
	assert.Equal(t, []id.ID{winners[0].rec.ID}, live, "exactly one key derived from the old one is live")

	_, _, err = m.Verify(ctx, winners[0].presented)
	require.NoError(t, err, "the returned replacement verifies")
	_, _, err = m.Verify(ctx, old)
	assert.ErrorIs(t, err, apikey.ErrVerificationFailed, "the old key is revoked")
}

// TestAPIKeyReturnedErrors pins task 5.7: an error caused by the store at
// Issue, List, Revoke or Rotate carries fixed library text, with the store's
// own error still reachable by identity — except a bare ErrKeyNotFound, which
// a store's contract documents and which comes back unchanged, text
// included, so nothing that already matched on it changes.
func TestAPIKeyReturnedErrors(t *testing.T) {
	t.Parallel()

	const principal = identity.UserID("svc-billing")

	newKeyID := func(t *testing.T) id.ID {
		t.Helper()
		keyID, err := id.NewV7Generator().NewID()
		require.NoError(t, err)
		return keyID
	}

	// oldKeyID is fixed, rather than minted per case, so the
	// "keeps both identifiers" row below can assert it appears in the text.
	oldKeyID := newKeyID(t)

	// lostRace is a store on which Rotate reads oldKeyID live and issues its
	// replacement, then finds the old key already revoked by a concurrent
	// writer, in that order; revokeReplacement answers the revoke of the
	// replacement, and replacement receives its identifier.
	lostRace := func(ctrl *gomock.Controller, replacement *id.ID, revokeReplacement func() (bool, error)) apikey.Store {
		s := NewMockStore(ctrl)
		gomock.InOrder(
			s.EXPECT().Get(gomock.Any(), oldKeyID).Return(apikey.Key{ID: oldKeyID, Principal: principal}, nil),
			s.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, rec apikey.Key) error {
				*replacement = rec.ID
				return nil
			}),
			s.EXPECT().Revoke(gomock.Any(), oldKeyID, gomock.Any()).Return(false, nil),
			s.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, keyID id.ID, _ time.Time) (bool, error) {
					if keyID != *replacement {
						return false, errors.New("revoked something other than the replacement")
					}
					return revokeReplacement()
				}),
		)
		return s
	}

	// Each lost-race row writes its own replacement identifier.
	var revokedReplacement, unrevokedReplacement id.ID

	type testCase struct {
		name   string
		store  func(t *testing.T, ctrl *gomock.Controller) apikey.Store
		call   func(t *testing.T, m *apikey.Keys) error
		assert func(t *testing.T, err error)
	}

	// wrapped is the shape shared by every site that always wraps: the
	// fixture's own error is reachable, its text is gone, and a sentinel this
	// call never matched before still does not match now.
	wrapped := func(t *testing.T, err error) {
		t.Helper()

		require.Error(t, err)
		assert.NotContains(t, err.Error(), "alice@example.com")
		assert.NotContains(t, err.Error(), "u-123")
		assert.ErrorIs(t, err, errRedactionFixture, "the store's own error is still reachable")
		assert.NotErrorIs(t, err, apikey.ErrKeyNotFound,
			"an outage must not read as a key nobody issued")
	}

	// bareSentinel is the shape a call whose store answers with the bare
	// sentinel shares: the exact value comes back, unchanged.
	bareSentinel := func(t *testing.T, err error) {
		t.Helper()
		assert.Same(t, apikey.ErrKeyNotFound, err, "a bare sentinel comes back unchanged, text included")
	}

	cases := []testCase{
		{
			name: "Issue's store put fails",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Put(gomock.Any(), gomock.Any()).Return(errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *apikey.Keys) error {
				t.Helper()
				_, _, err := m.Issue(t.Context(), principal, "nightly export", nil, 0)
				return err
			},
			assert: wrapped,
		},
		{
			name: "List's store list fails",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *apikey.Keys) error {
				t.Helper()
				_, err := m.List(t.Context(), principal)
				return err
			},
			assert: wrapped,
		},
		{
			name: "Revoke's store revoke fails with an outage",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *apikey.Keys) error {
				t.Helper()
				return m.Revoke(t.Context(), newKeyID(t))
			},
			assert: wrapped,
		},
		{
			name: "Revoke's store returns ErrKeyNotFound bare",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, apikey.ErrKeyNotFound)
				return s
			},
			call: func(t *testing.T, m *apikey.Keys) error {
				t.Helper()
				return m.Revoke(t.Context(), newKeyID(t))
			},
			assert: bareSentinel,
		},
		{
			name: "Rotate's store get fails with an outage",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Get(gomock.Any(), gomock.Any()).Return(apikey.Key{}, errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *apikey.Keys) error {
				t.Helper()
				_, _, err := m.Rotate(t.Context(), newKeyID(t), 0)
				return err
			},
			assert: wrapped,
		},
		{
			name: "Rotate's store get returns ErrKeyNotFound bare",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Get(gomock.Any(), gomock.Any()).Return(apikey.Key{}, apikey.ErrKeyNotFound)
				return s
			},
			call: func(t *testing.T, m *apikey.Keys) error {
				t.Helper()
				_, _, err := m.Rotate(t.Context(), newKeyID(t), 0)
				return err
			},
			assert: bareSentinel,
		},
		{
			name: "Rotate's own revoke fails, keeping both key identifiers in the text",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Get(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, keyID id.ID) (apikey.Key, error) {
						return apikey.Key{ID: keyID, Principal: principal}, nil
					})
				s.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)
				gomock.InOrder(
					s.EXPECT().Revoke(gomock.Any(), oldKeyID, gomock.Any()).Return(false, errRedactionFixture),
					// The replacement is ended on the way out.
					s.EXPECT().Revoke(gomock.Any(), gomock.Not(oldKeyID), gomock.Any()).Return(true, nil),
				)
				return s
			},
			call: func(t *testing.T, m *apikey.Keys) error {
				t.Helper()
				_, _, err := m.Rotate(t.Context(), oldKeyID, 0)
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				wrapped(t, err)
				assert.Contains(t, err.Error(), oldKeyID.String(), "the old key's identifier stays, for an operator to revoke by hand")
			},
		},
		{
			name: "Rotate finds the old key already revoked, revokes its replacement and is refused",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				return lostRace(ctrl, &revokedReplacement, func() (bool, error) { return true, nil })
			},
			call: func(t *testing.T, m *apikey.Keys) error {
				t.Helper()
				fresh, _, err := m.Rotate(t.Context(), oldKeyID, 0)
				assert.Empty(t, fresh, "a refused rotation returns no key")
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				assert.ErrorIs(t, err, apikey.ErrRotationRefused)
			},
		},
		{
			name: "Rotate loses the race and cannot revoke its replacement, naming it for an operator",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				return lostRace(ctrl, &unrevokedReplacement, func() (bool, error) { return false, errRedactionFixture })
			},
			call: func(t *testing.T, m *apikey.Keys) error {
				t.Helper()
				fresh, _, err := m.Rotate(t.Context(), oldKeyID, 0)
				assert.Empty(t, fresh, "a refused rotation returns no key")
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.ErrorIs(t, err, apikey.ErrRotationRefused)
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.ErrorIs(t, err, errRedactionFixture, "the store's own error is still reachable")
				assert.Contains(t, err.Error(), unrevokedReplacement.String(),
					"the replacement left live is named, for an operator to revoke by hand")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			m, err := apikey.New(apikey.WithStore(tc.store(t, ctrl)))
			require.NoError(t, err)

			tc.assert(t, tc.call(t, m))
		})
	}
}

// errStore is what the stores below report. Its text is the shape of a real
// outage, so a test that let it escape would show it in the failure output.
var errStore = errors.New("dial tcp: connection refused")

// fixedClock is a consumer's own read-only clock: the "Read-only source for a
// read-only component" scenario (time-source spec). It carries only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// failingReader is a random source that cannot answer.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy source unavailable")
}

// countingKeyStore counts what reaches the store behind it.
//
// It is a decorator rather than a generated mock because what these tests
// assert is that a call did *not* happen — that a malformed key costs no
// lookup — while every other call still behaves exactly as the real store
// does. A mock would have to restate the real store's behaviour to say that.
type countingKeyStore struct {
	apikey.Store

	mu     sync.Mutex
	writes int
	reads  int
	lists  int
}

func (s *countingKeyStore) Put(ctx context.Context, rec apikey.Key) error {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()

	return s.Store.Put(ctx, rec)
}

func (s *countingKeyStore) Get(ctx context.Context, keyID id.ID) (apikey.Key, error) {
	s.mu.Lock()
	s.reads++
	s.mu.Unlock()

	return s.Store.Get(ctx, keyID)
}

func (s *countingKeyStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) (bool, error) {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()

	return s.Store.Revoke(ctx, keyID, at)
}

func (s *countingKeyStore) TouchLastUsed(ctx context.Context, keyID id.ID, at time.Time) error {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()

	return s.Store.TouchLastUsed(ctx, keyID, at)
}

func (s *countingKeyStore) List(ctx context.Context, principal identity.UserID) ([]apikey.Key, error) {
	s.mu.Lock()
	s.lists++
	s.mu.Unlock()

	return s.Store.List(ctx, principal)
}

func (s *countingKeyStore) Writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.writes
}

func (s *countingKeyStore) Reads() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.reads
}

func (s *countingKeyStore) Lists() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.lists
}

// revokeFailsStore is a working store whose Revoke alone cannot succeed.
type revokeFailsStore struct {
	apikey.Store
}

func (s revokeFailsStore) Revoke(context.Context, id.ID, time.Time) (bool, error) {
	return false, errStore
}

// errOldRevoke and errUndoRevoke tell apart the two failures of a rotation
// whose old-key revoke and compensating revoke both fail.
var (
	errOldRevoke  = errors.New("revoke of the old key: deadline exceeded")
	errUndoRevoke = errors.New("revoke of the replacement: connection reset")
)

// revokeFailsTwiceStore fails the first Revoke with errOldRevoke and every
// later one with errUndoRevoke, so neither failure can pass for the other.
type revokeFailsTwiceStore struct {
	apikey.Store

	calls atomic.Int32
}

func (s *revokeFailsTwiceStore) Revoke(context.Context, id.ID, time.Time) (bool, error) {
	if s.calls.Add(1) == 1 {
		return false, errOldRevoke
	}

	return false, errUndoRevoke
}

// touchFailsStore is a working store whose last-use write alone cannot succeed.
type touchFailsStore struct {
	apikey.Store
}

func (s touchFailsStore) TouchLastUsed(context.Context, id.ID, time.Time) error { return errStore }

// newID mints an identifier for a key that was never issued.
func newID() (id.ID, error) { return id.NewV7Generator().NewID() }

// sha256Of is the digest a manager with no WithDigest uses, restated here so
// the test asserts the documented default rather than whatever the package
// happens to call.
func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)

	return sum[:]
}

// revokeBarrierStore holds every Revoke of one key until a set number of
// callers have reached it, then lets them all through at once.
//
// It is how a test makes concurrent rotations of one key meet at the write
// that decides them: each has read the key live and issued its replacement
// before any of them revokes, which is the interleaving a read-then-write
// rotation loses to. A revoke of any other key passes straight through. It is
// a decorator, not a generated mock, because every call must still behave as
// the real store does.
type revokeBarrierStore struct {
	apikey.Store

	target  id.ID
	parties int

	mu      sync.Mutex
	arrived int
	all     chan struct{}
}

func newRevokeBarrierStore(inner apikey.Store, target id.ID, parties int) *revokeBarrierStore {
	return &revokeBarrierStore{Store: inner, target: target, parties: parties, all: make(chan struct{})}
}

func (s *revokeBarrierStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) (bool, error) {
	if keyID != s.target {
		return s.Store.Revoke(ctx, keyID, at)
	}

	s.mu.Lock()
	s.arrived++
	if s.arrived == s.parties {
		close(s.all)
	}
	s.mu.Unlock()

	select {
	case <-s.all:
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(10 * time.Second):
		return false, fmt.Errorf("only some of %d rotations reached the revoke", s.parties)
	}

	return s.Store.Revoke(ctx, keyID, at)
}

// advanceOnPutStore moves a fake clock forward each time a key is stored
// after the first, so the key a test issued first can expire between a
// rotation's liveness check and its revoke.
type advanceOnPutStore struct {
	apikey.Store

	clk  *clockwork.FakeClock
	by   time.Duration
	puts *atomic.Int32
}

func (s advanceOnPutStore) Put(ctx context.Context, rec apikey.Key) error {
	if s.puts.Add(1) > 1 {
		s.clk.Advance(s.by)
	}

	return s.Store.Put(ctx, rec)
}

// loseThenCancelStore makes the first Revoke lose: another caller ends the
// key first, and the context of the call in flight is cancelled, as a client
// hanging up would. Every later Revoke refuses a cancelled context, as a
// database driver does, and otherwise behaves as the store beneath.
type loseThenCancelStore struct {
	apikey.Store

	cancel context.CancelFunc
	calls  atomic.Int32
}

func (s *loseThenCancelStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) (bool, error) {
	if s.calls.Add(1) == 1 {
		if _, err := s.Store.Revoke(context.WithoutCancel(ctx), keyID, at); err != nil {
			return false, err
		}

		s.cancel()

		return false, nil
	}

	if err := ctx.Err(); err != nil {
		return false, err
	}

	return s.Store.Revoke(ctx, keyID, at)
}

// zeroReader is a random source that answers with zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)

	return len(p), nil
}

// emptyForLeadingZero is a consumer digest that returns nothing for an input
// whose first byte is zero, and SHA-256 for every other input. It passes any
// construction probe whose inputs do not start with a zero byte, so it is how
// a test reaches an empty digest at issue and at verification.
func emptyForLeadingZero(b []byte) []byte {
	if len(b) > 0 && b[0] == 0 {
		return nil
	}

	return sha256Of(b)
}

// failOldRevokeStore fails the first Revoke, the one that ends the key being
// rotated, and lets every later one through to the store beneath, refusing a
// cancelled context as a database driver does. When cancel is set the failure
// is the caller hanging up: it cancels the caller's context and returns that
// context's error instead of errStore.
type failOldRevokeStore struct {
	apikey.Store

	cancel context.CancelFunc
	calls  atomic.Int32
}

func (s *failOldRevokeStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) (bool, error) {
	if s.calls.Add(1) == 1 {
		if s.cancel != nil {
			s.cancel()

			return false, ctx.Err()
		}

		return false, errStore
	}

	if err := ctx.Err(); err != nil {
		return false, err
	}

	return s.Store.Revoke(ctx, keyID, at)
}
