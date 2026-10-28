// The tests here are split by setup shape, not by case: one table per store
// shape (the in-memory store, a gomock store, a store that lists records in its
// own order), because the setup — not the assertion — is what differs.
//
// The JWKS tests are split by what they establish rather than folded into one
// table: the document's shape is read from the parsed JSON, the
// private-material check is derived from the records the store holds, and the
// override case renders a second document from the port. The setups do not
// share a shape, so each keeps its own table.
//
// The tests numbered F1 to F11, here and in generate_test.go and
// record_test.go, are for the boundaries this package does not control: the
// store's rows, which another writer may have produced, the keys it hands
// callers, and the configuration a consumer supplies. Each one was written
// against a defect it reproduced, and each is proven by a mutation that makes
// it fail.
//
// The keyring-lock test is not parallel: goleak counts goroutines
// process-wide.
package signingkey_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/token/signingkey"
)

func TestNewKeyManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []signingkey.Option
		assert func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, err error)
	}

	refused := func(mentions string) func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, err error) {
		return func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, err error) {
			require.ErrorIs(t, err, signingkey.ErrConfig,
				"a wiring mistake is a configuration error, identifiable without matching text")
			assert.Nil(t, km, "a refused configuration yields no manager")
			assert.Contains(t, err.Error(), mentions, "the error names what is wrong")
		}
	}

	accepted := func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, err error) {
		require.NoError(t, err)
		require.NotNil(t, km)
		_, _, ok := km.Signer(signingkey.RS256)
		assert.True(t, ok)
	}

	cases := []testCase{
		{
			name: "empty store gets a current RS256 key that is stored first",
			assert: func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, err error) {
				require.NoError(t, err)

				kid, signer, ok := km.Signer(signingkey.RS256)
				require.True(t, ok)
				require.NotEmpty(t, kid)
				pub, isRSA := signer.Public().(*rsa.PublicKey)
				require.True(t, isRSA, "RS256 signs with an RSA key, got %T", signer.Public())
				assert.Equal(t, 2048, pub.N.BitLen(), "RSA keys are 2048 bits")

				recs, loadErr := store.LoadAll(t.Context())
				require.NoError(t, loadErr)
				require.Len(t, recs, 1, "the key is written to the store before it is used")
				assert.Equal(t, kid, recs[0].Kid)
				assert.Equal(t, signingkey.RS256, recs[0].Alg)
			},
		},
		{
			name: "consumer algorithms",
			opts: []signingkey.Option{signingkey.WithAlgs(signingkey.ES256, signingkey.EdDSA)},
			assert: func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, err error) {
				require.NoError(t, err)

				_, es, ok := km.Signer(signingkey.ES256)
				require.True(t, ok)
				_, isEC := es.Public().(*ecdsa.PublicKey)
				assert.True(t, isEC, "ES256 signs with an ECDSA key, got %T", es.Public())

				_, ed, ok := km.Signer(signingkey.EdDSA)
				require.True(t, ok)
				_, isEd := ed.Public().(ed25519.PublicKey)
				assert.True(t, isEd, "EdDSA signs with an Ed25519 key, got %T", ed.Public())

				assert.ElementsMatch(t,
					[]signingkey.Alg{signingkey.ES256, signingkey.EdDSA}, km.SupportedAlgs())

				_, _, rsOK := km.Signer(signingkey.RS256)
				assert.False(t, rsOK, "an algorithm the consumer did not configure has no key")
			},
		},
		{
			name: "unsupported algorithm is refused",
			opts: []signingkey.Option{signingkey.WithAlgs("HS256")},
			assert: func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, err error) {
				require.Error(t, err)
				assert.Nil(t, km)
				assert.Contains(t, err.Error(), "HS256")

				recs, loadErr := store.LoadAll(t.Context())
				require.NoError(t, loadErr)
				assert.Empty(t, recs, "a refused configuration writes nothing")
			},
		},
		{
			name:   "defaults need no configuration",
			assert: accepted,
		},
		{
			name: "a consistent consumer configuration is accepted",
			opts: []signingkey.Option{
				signingkey.WithRotateInterval(6 * time.Hour),
				signingkey.WithReloadInterval(10 * time.Second),
				signingkey.WithLifetime(48 * time.Hour),
				signingkey.WithHousekeepingInterval(30 * time.Minute),
			},
			assert: accepted,
		},
		{
			name: "a lifetime no longer than the rotate interval",
			opts: []signingkey.Option{
				signingkey.WithLifetime(30 * time.Minute),
				signingkey.WithRotateInterval(time.Hour),
			},
			assert: refused("lifetime"),
		},
		{
			name: "a lifetime exactly the rotate interval",
			opts: []signingkey.Option{
				signingkey.WithLifetime(time.Hour),
				signingkey.WithRotateInterval(time.Hour),
			},
			assert: refused("lifetime"),
		},
		{
			name: "a reload interval no shorter than the rotate interval",
			opts: []signingkey.Option{
				signingkey.WithReloadInterval(2 * time.Hour),
				signingkey.WithRotateInterval(time.Hour),
			},
			assert: refused("reload interval"),
		},
		{
			name: "a reload interval exactly the rotate interval",
			opts: []signingkey.Option{
				signingkey.WithReloadInterval(time.Hour),
				signingkey.WithRotateInterval(time.Hour),
			},
			assert: refused("reload interval"),
		},
		{
			name:   "a zero reload interval",
			opts:   []signingkey.Option{signingkey.WithReloadInterval(0)},
			assert: refused("reload interval must be positive"),
		},
		{
			name:   "a negative lifetime",
			opts:   []signingkey.Option{signingkey.WithLifetime(-time.Second)},
			assert: refused("lifetime must be positive"),
		},
		{
			name:   "a zero rotate interval",
			opts:   []signingkey.Option{signingkey.WithRotateInterval(0)},
			assert: refused("rotate interval must be positive"),
		},
		{
			name:   "a negative housekeeping interval",
			opts:   []signingkey.Option{signingkey.WithHousekeepingInterval(-time.Minute)},
			assert: refused("housekeeping interval must be positive"),
		},
		{
			name:   "no algorithms at all",
			opts:   []signingkey.Option{signingkey.WithAlgs()},
			assert: refused("at least one algorithm"),
		},
		{
			name:   "a nil logger",
			opts:   []signingkey.Option{signingkey.WithLogger(nil)},
			assert: refused("logger must not be nil"),
		},
		{
			name:   "a nil clock",
			opts:   []signingkey.Option{signingkey.WithClock(nil)},
			assert: refused("clock must not be nil"),
		},
		{
			name:   "a typed-nil clock",
			opts:   []signingkey.Option{signingkey.WithClock((*clockwork.FakeClock)(nil))},
			assert: refused("clock must not be nil"),
		},
		{
			name:   "a nil key store",
			opts:   []signingkey.Option{signingkey.WithKeyStore(nil)},
			assert: refused("key store must not be nil"),
		},
		{
			name:   "an unsupported algorithm",
			opts:   []signingkey.Option{signingkey.WithAlgs(signingkey.RS256, "HS256")},
			assert: refused("HS256"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := signingkey.NewMemoryKeyStore()
			opts := append([]signingkey.Option{signingkey.WithKeyStore(store)}, tc.opts...)

			km, err := signingkey.New(t.Context(), opts...)
			tc.assert(t, km, store, err)
		})
	}
}

// Standalone: its gomock store records the order of the calls and captures the record written.
func TestNewKeyManagerStoresBeforeUse(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	store := NewMockKeyStore(ctrl)

	minted := time.Date(2030, 6, 1, 9, 30, 0, 0, time.UTC)

	var written signingkey.Record
	load := store.EXPECT().LoadAll(gomock.Any()).Return(nil, nil)
	store.EXPECT().
		Store(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, rec signingkey.Record) error {
			written = rec
			return nil
		}).
		After(load.Call)

	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clockwork.NewFakeClockAt(minted)),
	)
	require.NoError(t, err)

	kid, signer, ok := km.Signer(signingkey.RS256)
	require.True(t, ok)

	assert.Equal(t, kid, written.Kid,
		"the key the manager signs with is the one the store was given")
	assert.Equal(t, signingkey.RS256, written.Alg)
	assert.Equal(t, minted, written.CreatedAt, "the creation time comes from the clock")
	assert.NotEmpty(t, written.Private, "the private key is persisted, not left to be regenerated")

	set := publishedSet(t, km)
	published, ok := set.LookupKeyID(kid)
	require.True(t, ok, "the stored key is the published key")

	publicOfSigner, err := jwk.Import[jwk.Key](signer.Public())
	require.NoError(t, err)
	ownThumb, err := publicOfSigner.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	publishedThumb, err := published.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, ownThumb, publishedThumb, "the published key is the public part of the signer")
}

// TestNewKeyManagerConstructionContext pins what the caller's context reaches.
//
// Construction reads the store and may write to it, and a store is where a
// deployment's slowest dependency sits: a database, a KMS. The context the
// caller passes is the only way to give up on one that never answers, so what
// matters here is not that the manager inspects the context itself, but that
// the store is handed the caller's own — cancellation and deadline included —
// rather than one that can never be cancelled.
//
// Each case therefore reads the context inside the store, which is the only
// place the difference is observable.
// Standalone: its cases modify the context and observe it inside the store.
func TestNewKeyManagerConstructionContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// ctx modifies the context construction is given; nil means the
		// subtest's own, which is live.
		ctx func(ctx context.Context) context.Context
		// store is the store construction is given; nil means no
		// WithKeyStore at all, so the default in-memory one.
		store  func(t *testing.T, ctrl *gomock.Controller) signingkey.KeyStore
		assert func(t *testing.T, km *signingkey.Keys, err error)
	}

	cases := []testCase{
		{
			name: "loading the store sees the caller's cancellation",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			store: func(_ *testing.T, ctrl *gomock.Controller) signingkey.KeyStore {
				store := NewMockKeyStore(ctrl)
				// The store answers from the context it was given, as a
				// durable one would. No write is expected: a load that failed
				// must never be treated as an empty store.
				store.EXPECT().LoadAll(gomock.Any()).
					DoAndReturn(func(ctx context.Context) ([]signingkey.Record, error) {
						return nil, ctx.Err()
					})

				return store
			},
			assert: func(t *testing.T, km *signingkey.Keys, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, km)
			},
		},
		{
			name: "loading the store sees the caller's expired deadline",
			ctx: func(ctx context.Context) context.Context {
				dctx, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Minute))
				t.Cleanup(cancel)

				return dctx
			},
			store: func(_ *testing.T, ctrl *gomock.Controller) signingkey.KeyStore {
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).
					DoAndReturn(func(ctx context.Context) ([]signingkey.Record, error) {
						return nil, ctx.Err()
					})

				return store
			},
			assert: func(t *testing.T, km *signingkey.Keys, err error) {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Nil(t, km)
			},
		},
		{
			name: "writing the initial key sees the caller's cancellation",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			store: func(_ *testing.T, ctrl *gomock.Controller) signingkey.KeyStore {
				store := NewMockKeyStore(ctrl)
				// The load ignores the context and reports an empty store, so
				// the only place this case can fail is the write that follows.
				store.EXPECT().LoadAll(gomock.Any()).Return(nil, nil)
				store.EXPECT().Store(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ signingkey.Record) error {
						return ctx.Err()
					})

				return store
			},
			assert: func(t *testing.T, km *signingkey.Keys, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, km)
			},
		},
		{
			name: "a live context constructs, and the store sees no cancellation",
			store: func(t *testing.T, ctrl *gomock.Controller) signingkey.KeyStore {
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).
					DoAndReturn(func(ctx context.Context) ([]signingkey.Record, error) {
						assert.NoError(t, ctx.Err(), "the store was handed a context already done")

						return nil, nil
					})
				store.EXPECT().Store(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ signingkey.Record) error {
						assert.NoError(t, ctx.Err(), "the store was handed a context already done")

						return nil
					})

				return store
			},
			assert: func(t *testing.T, km *signingkey.Keys, err error) {
				require.NoError(t, err)
				require.NotNil(t, km)

				_, _, ok := km.Signer(signingkey.RS256)
				assert.True(t, ok, "construction left no current key")
			},
		},
		{
			// Nothing here is a loophole: the manager inspects the context
			// nowhere, and the default store performs no I/O, so a cancelled
			// context reaches a store with nothing to abandon. That is a
			// documented limit of the default store rather than a rule about
			// cancellation, and it is pinned so that adding a ctx.Err() gate
			// to construction cannot quietly change the contract instead of
			// being a decision someone makes deliberately.
			name: "the default store cannot be cancelled",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, km *signingkey.Keys, err error) {
				require.NoError(t, err, "the default store has no I/O to cancel")
				require.NotNil(t, km)

				_, _, ok := km.Signer(signingkey.RS256)
				assert.True(t, ok, "construction left no current key")
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

			var opts []signingkey.Option
			if tc.store != nil {
				ctrl := gomock.NewController(t)
				opts = append(opts, signingkey.WithKeyStore(tc.store(t, ctrl)))
			}

			km, err := signingkey.New(ctx, opts...)
			tc.assert(t, km, err)
		})
	}
}

func TestNewKeyManagerFailsClosed(t *testing.T) {
	t.Parallel()

	storedAt := time.Date(2030, 3, 4, 5, 6, 7, 0, time.UTC)

	// corrupt returns a real record whose private bytes have been damaged in
	// place. Everything else about it — its kid, its algorithm, its public JWK,
	// its creation time — is genuine, so the manager has no other ground to
	// reject it on, and an implementation that never looked at the private
	// bytes would succeed.
	corrupt := func(t *testing.T, damage func(der []byte) []byte) signingkey.Record {
		t.Helper()

		rec := realRecord(t, storedAt)
		rec.Private = damage(slices.Clone(rec.Private))
		return rec
	}

	type testCase struct {
		name string
		// store returns the store to construct over, and the kid the failure
		// must name, if any.
		store  func(t *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string)
		assert func(t *testing.T, km *signingkey.Keys, kid string, err error)
	}

	// redacted is the shape every site here shares: the fixture's text is
	// gone, and the store's own error is still reachable by identity.
	redacted := func(t *testing.T, err error) {
		t.Helper()

		require.Error(t, err)
		assert.NotContains(t, err.Error(), "alice@example.com")
		assert.NotContains(t, err.Error(), "u-123")
		assert.ErrorIs(t, err, errRedactionFixture, "the store's own error is still reachable")
	}

	cases := []testCase{
		{
			name: "the store cannot be read",
			store: func(_ *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string) {
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).Return(nil, errStoreUnreachable)
				// No Store call is expected: an unreadable store must never be
				// treated as an empty one.
				return store, ""
			},
			assert: func(t *testing.T, km *signingkey.Keys, _ string, err error) {
				require.ErrorIs(t, err, errStoreUnreachable)
				assert.Nil(t, km)
			},
		},
		{
			name: "a stored key whose private bytes are truncated is never skipped",
			store: func(t *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string) {
				rec := corrupt(t, func(der []byte) []byte { return der[:len(der)-8] })
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).Return([]signingkey.Record{rec}, nil)
				return store, rec.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, kid string, err error) {
				require.Error(t, err)
				assert.Nil(t, km)
				assert.Contains(t, err.Error(), kid, "the error names the key it could not decode")
			},
		},
		{
			name: "a stored key whose private bytes were flipped is never skipped",
			store: func(t *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string) {
				rec := corrupt(t, func(der []byte) []byte {
					der[len(der)/2] ^= 0xff
					return der
				})
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).Return([]signingkey.Record{rec}, nil)
				return store, rec.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, kid string, err error) {
				require.Error(t, err)
				assert.Nil(t, km)
				assert.Contains(t, err.Error(), kid, "the error names the key it could not decode")
			},
		},
		{
			name: "the initial write fails",
			store: func(_ *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string) {
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).Return(nil, nil)
				store.EXPECT().Store(gomock.Any(), gomock.Any()).Return(errStoreUnreachable)
				return store, ""
			},
			assert: func(t *testing.T, km *signingkey.Keys, _ string, err error) {
				require.ErrorIs(t, err, errStoreUnreachable)
				assert.Nil(t, km)
			},
		},
		// Construction's own load and store of a key carry fixed library text
		// when the configured KeyStore fails, with the store's own error still
		// reachable by identity.
		{
			name: "construction's load fails",
			store: func(t *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string) {
				t.Helper()
				s := NewMockKeyStore(ctrl)
				s.EXPECT().LoadAll(gomock.Any()).Return(nil, errRedactionFixture)
				return s, ""
			},
			assert: func(t *testing.T, _ *signingkey.Keys, _ string, err error) {
				redacted(t, err)
				assert.EqualError(t, err, "signingkey: load keys")
			},
		},
		{
			name: "construction's store of a freshly minted key fails",
			store: func(t *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string) {
				t.Helper()
				s := NewMockKeyStore(ctrl)
				s.EXPECT().LoadAll(gomock.Any()).Return(nil, nil)
				s.EXPECT().Store(gomock.Any(), gomock.Any()).Return(errRedactionFixture)
				return s, ""
			},
			assert: func(t *testing.T, _ *signingkey.Keys, _ string, err error) {
				redacted(t, err)
				assert.Regexp(t, `^signingkey: store \S+ key$`, err.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			store, kid := tc.store(t, ctrl)

			km, err := signingkey.New(t.Context(), signingkey.WithKeyStore(store))
			tc.assert(t, km, kid, err)
		})
	}
}

// Standalone: each case seeds its own store and the kid that must be current.
func TestKeyManagerAdoptsStoredKeys(t *testing.T) {
	t.Parallel()

	at := func(h int) time.Time { return time.Date(2030, 1, 1, h, 0, 0, 0, time.UTC) }
	// Every manager here reads the time as noon on the day the records are
	// dated, so none of them is dated ahead of the present by accident. A
	// clockwork clock only read, never advanced, is safe to share.
	noon := signingkey.WithClock(clockwork.NewFakeClockAt(at(12)))

	type testCase struct {
		name   string
		setup  func(t *testing.T) (store signingkey.KeyStore, wantKid string)
		assert func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, wantKid string)
	}

	cases := []testCase{
		{
			name: "a restart adopts the stored key and mints no replacement",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				store := signingkey.NewMemoryKeyStore()
				first, err := signingkey.New(t.Context(), signingkey.WithKeyStore(store), noon)
				require.NoError(t, err)
				kid, _, ok := first.Signer(signingkey.RS256)
				require.True(t, ok)
				return store, kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, wantKid string) {
				kid, _, ok := km.Signer(signingkey.RS256)
				require.True(t, ok)
				assert.Equal(t, wantKid, kid, "the second manager signs with the stored key")

				recs, err := store.LoadAll(t.Context())
				require.NoError(t, err)
				assert.Len(t, recs, 1,
					"an algorithm that already has a stored key gets no replacement")

				assert.True(t, publishes(km, wantKid),
					"the stored key is published, so its tokens still verify")
			},
		},
		{
			name: "the key created most recently is current, not the one listed last",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				newer := realRecord(t, at(11))
				older := realRecord(t, at(10))
				// 11:00 is listed before 10:00.
				return &listingStore{recs: []signingkey.Record{newer, older}}, newer.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, wantKid string) {
				kid, _, ok := km.Signer(signingkey.RS256)
				require.True(t, ok)
				assert.Equal(t, wantKid, kid, "the current key is the latest CreatedAt")

				assert.Zero(t, store.(*listingStore).stored, "nothing is minted or rewritten")

				published, err := km.VerificationKeys()
				require.NoError(t, err)
				assert.Len(t, published, 2, "the key it replaced stays published")
			},
		},
		{
			name: "an exact tie in CreatedAt goes to the record listed later",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				first := realRecord(t, at(10))
				second := realRecord(t, at(10))
				require.NotEqual(t, first.Kid, second.Kid)
				return &listingStore{recs: []signingkey.Record{first, second}}, second.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, wantKid string) {
				kid, _, ok := km.Signer(signingkey.RS256)
				require.True(t, ok)
				assert.Equal(t, wantKid, kid, "the tie goes to the record the store listed later")
			},
		},
		{
			name: "a key dated a year ahead is neither current nor published",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				present := realRecord(t, at(12))
				future := realRecord(t, at(12).Add(365*24*time.Hour))
				return &listingStore{recs: []signingkey.Record{present, future}}, present.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, wantKid string) {
				assert.Equal(t, wantKid, currentKid(t, km, signingkey.RS256),
					"the current key is the one created now")
				published, err := km.VerificationKeys()
				require.NoError(t, err)
				assert.Equal(t, []string{wantKid}, kidsOf(published),
					"a key dated more than one lifetime ahead is not published")
				assert.Zero(t, store.(*listingStore).stored, "nothing is minted")
			},
		},
		{
			name: "a key ahead by less than the reload interval is current",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				present := realRecord(t, at(12))
				skewed := realRecord(t, at(12).Add(30*time.Second))
				return &listingStore{recs: []signingkey.Record{present, skewed}}, skewed.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, wantKid string) {
				assert.Equal(t, wantKid, currentKid(t, km, signingkey.RS256),
					"a key a slightly fast replica just minted is adopted")
			},
		},
		{
			name: "a key ahead by more than the reload interval is published but not current",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				present := realRecord(t, at(12))
				ahead := realRecord(t, at(14))
				return &listingStore{recs: []signingkey.Record{present, ahead}}, ahead.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, ahead string) {
				assert.NotEqual(t, ahead, currentKid(t, km, signingkey.RS256),
					"a key dated beyond the reload interval does not sign yet")
				assert.True(t, publishes(km, ahead),
					"but it is within one lifetime, so the tokens it signed still verify")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, wantKid := tc.setup(t)

			km, err := signingkey.New(t.Context(), signingkey.WithKeyStore(store), noon)
			require.NoError(t, err)

			tc.assert(t, km, store, wantKid)
		})
	}
}

// Standalone: it seeds one far-future record and reads the store back.
func TestConstructionOverOnlyAFarFutureKeyMintsACurrentKey(t *testing.T) {
	clk := newClock()
	store := signingkey.NewMemoryKeyStore()
	future := realRecord(t, epoch.Add(365*24*time.Hour))
	require.NoError(t, store.Store(t.Context(), future))

	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.RS256),
	)
	require.NoError(t, err)

	kid := currentKid(t, km, signingkey.RS256)
	assert.NotEqual(t, future.Kid, kid, "the far-future key does not sign")
	assert.False(t, publishes(km, future.Kid), "and is not published")
	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	assert.Len(t, recs, 2, "a new key was stored")
}

// F6 — one algorithm named twice is accepted and mints one key per mention on
// every rotation.
// Standalone: if accepted, it starts the manager and counts the keys one rotation mints.
func TestDuplicateAlgsAreRefused(t *testing.T) {
	store := signingkey.NewMemoryKeyStore()
	clk := newClock()

	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA, signingkey.EdDSA, signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(30*time.Minute),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	if err != nil {
		require.ErrorIs(t, err, signingkey.ErrConfig)
		return // refused, which is what this test asks for
	}
	t.Cleanup(func() { _ = km.Stop() })

	assert.Len(t, km.SupportedAlgs(), 1,
		"one algorithm named three times is one algorithm")

	require.NoError(t, km.Start(t.Context()))
	advance(t, clk, time.Hour, loopCount)

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	assert.Len(t, recs, 2,
		"one rotation of one algorithm mints one key, not one per mention")
}

// F8 — a non-nil KeyStore interface holding a nil pointer gets past validate().
type auditNilStore struct{ records []signingkey.Record }

func (s *auditNilStore) Store(context.Context, signingkey.Record) error { return nil }

func (s *auditNilStore) LoadAll(context.Context) ([]signingkey.Record, error) {
	return s.records, nil
}

// TestNewKeyManagerWiringMistakes holds the boundary cases of construction's
// validation. They are not parallel, unlike TestNewKeyManager, so they keep a
// table of their own.
func TestNewKeyManagerWiringMistakes(t *testing.T) {
	type testCase struct {
		name   string
		opts   []signingkey.Option
		assert func(t *testing.T, km *signingkey.Keys, err error)
	}

	cases := []testCase{
		{
			// F7 — a housekeeping interval longer than the key lifetime
			// silently extends how long a key stays published, with no error
			// and no documented limit.
			name: "housekeeping interval must honour the lifetime",
			opts: []signingkey.Option{
				signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
				signingkey.WithAlgs(signingkey.EdDSA),
				signingkey.WithRotateInterval(time.Hour),
				signingkey.WithLifetime(2 * time.Hour),
				signingkey.WithHousekeepingInterval(1000 * time.Hour),
			},
			assert: func(t *testing.T, km *signingkey.Keys, err error) {
				require.ErrorIs(t, err, signingkey.ErrConfig,
					"a housekeeping interval 500x the lifetime cannot honour the lifetime it is asked to enforce")
				assert.Nil(t, km)
			},
		},
		{
			name: "typed nil port is a configuration error",
			opts: []signingkey.Option{signingkey.WithKeyStore((*auditNilStore)(nil))},
			assert: func(t *testing.T, km *signingkey.Keys, err error) {
				require.Error(t, err, "a nil store is a configuration error whatever its static type")
				assert.Nil(t, km)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("construction panicked rather than reporting a wiring mistake: %v", r)
				}
			}()

			km, err := signingkey.New(t.Context(), tc.opts...)
			tc.assert(t, km, err)
		})
	}
}

// F9 — the configured algorithms are shared with the consumer in both
// directions: WithAlgs keeps the caller's slice and SupportedAlgs hands the
// manager's own back. A caller that sorts, filters or reuses either one
// rewrites what the manager treats as configured, after the configuration was
// validated — and the reload path reads that list on every run.
// Standalone: it rewrites the slices handed in and out after construction.
func TestTheConfiguredAlgorithmsAreNotSharedWithTheConsumer(t *testing.T) {
	// want is built here, and never handed to the manager, so no assertion can
	// be satisfied by comparing a corrupted list with itself.
	want := []signingkey.Alg{signingkey.EdDSA, signingkey.ES256}

	given := []signingkey.Alg{signingkey.EdDSA, signingkey.ES256}
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
		signingkey.WithAlgs(given...),
	)
	require.NoError(t, err)
	require.Equal(t, want, km.SupportedAlgs())

	given[0] = "HS256" // the caller reuses the slice it configured with

	assert.Equal(t, want, km.SupportedAlgs(),
		"the manager keeps the algorithms it validated, not a window onto the caller's slice")

	got := km.SupportedAlgs()
	got[0] = "HS256" // and rewrites an answer it was handed

	assert.Equal(t, want, km.SupportedAlgs(),
		"the manager reports the algorithms it was configured with, "+
			"whatever a caller did to an answer it was handed earlier")
}

// F10 — the record handed to the store carries no public JWK, although its
// contract promises a store can publish the set without decoding private
// material. Nothing in the package reads the field back, so nothing noticed.
// Standalone: it decodes the stored record's public JWK.
func TestStoredRecordCarriesThePublishablePublicKey(t *testing.T) {
	store := signingkey.NewMemoryKeyStore()
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithAlgs(signingkey.ES256),
	)
	require.NoError(t, err)

	kid, _, ok := km.Signer(signingkey.ES256)
	require.True(t, ok)

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	require.Len(t, recs, 1)
	require.NotEmpty(t, recs[0].PublicJWK,
		"a store must be able to publish the set without decoding private material")

	var published map[string]any
	require.NoError(t, json.Unmarshal(recs[0].PublicJWK, &published))

	assert.Equal(t, kid, published["kid"], "the stored JWK names the key it belongs to")
	assert.Equal(t, signingkey.ES256, published["alg"], "and declares its algorithm")
	assert.Equal(t, "sig", published["use"], "and its signature use")
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		assert.NotContains(t, published, private,
			"the publishable half carries no private parameter, found %q", private)
	}
}

// F11 — a store listing one key twice makes the manager hold it twice, so the
// order it publishes by and the keys it holds fall out of step: the set
// publishes the key twice, and the first sweep that drops it reads the entry it
// has just deleted. Reload dedups against the keys already held, but not within
// one batch, so a store that lists a new key twice is enough.
// Standalone: it lists one record twice, then runs housekeeping on a controlled clock.
func TestADuplicateStoreRecordIsHeldOnce(t *testing.T) {
	// Exactly one lifetime old: construction publishes it, and one second
	// later it is past the lifetime.
	dup := realRecord(t, epoch.Add(-24*time.Hour))
	current := realRecord(t, epoch)

	clk := newClock()
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(&listingStore{recs: []signingkey.Record{dup, dup, current}}),
		signingkey.WithClock(clk),
		signingkey.WithLifetime(24*time.Hour),
		signingkey.WithHousekeepingInterval(time.Second),
		signingkey.WithReloadInterval(30*time.Minute),
		signingkey.WithRotateInterval(6*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	published, err := km.VerificationKeys()
	require.NoError(t, err)
	assert.Len(t, published, 2, "a key listed twice is one key")
	require.Equal(t, current.Kid, currentKid(t, km, signingkey.RS256))

	// Housekeeping walks the order it publishes by and deletes as it goes, so a
	// second entry for a kid it has just dropped would have nothing to read.
	require.NoError(t, km.Start(t.Context()))
	advance(t, clk, time.Second, loopCount)
	require.False(t, publishes(km, dup.Kid),
		"the duplicated key stops being published once it is past its lifetime")
	assert.True(t, publishes(km, current.Kid), "and the current key is untouched")
}

// blockingStore holds one write inside the store until it is released, so a
// test can ask what the manager serves while a rotation is waiting on I/O.
type blockingStore struct {
	inner   signingkey.KeyStore
	writing chan struct{} // receives once a held write is inside the store
	release chan struct{} // closed to let the held write finish
	armed   bool          // set after construction, so construction's write is not held
}

func (s *blockingStore) Store(ctx context.Context, rec signingkey.Record) error {
	if s.armed {
		s.writing <- struct{}{}
		<-s.release
	}
	return s.inner.Store(ctx, rec)
}

func (s *blockingStore) LoadAll(ctx context.Context) ([]signingkey.Record, error) {
	return s.inner.LoadAll(ctx)
}

// TestSigningStaysAvailableDuringASlowStoreWrite pins the reason the keyring
// lock is taken after the store write and not before it: signing and
// verification must not queue behind store I/O.
//
// A durable store on a slow network makes a rotation's write arbitrarily long,
// and every signature and every JWK Set read would wait for it. Nothing else
// in the suite observes the order — the shutdown test holds a write too, but it
// never reads the keyring while the write is held.
// Standalone: it holds a rotation inside a blocking store write.
func TestSigningStaysAvailableDuringASlowStoreWrite(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	store := &blockingStore{
		inner:   signingkey.NewMemoryKeyStore(),
		writing: make(chan struct{}, 1),
		release: make(chan struct{}),
	}

	clk := newClock()
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)

	signing := currentKid(t, km, signingkey.EdDSA)

	store.armed = true
	require.NoError(t, km.Start(t.Context()))

	awaitParked(t, clk, loopCount)
	clk.Advance(time.Hour)
	<-store.writing // a rotation is now inside the store write

	// Both halves of KeySource, asked from another goroutine so a blocked one
	// is a failed assertion rather than a hung test.
	served := make(chan string, 1)
	go func() {
		kid, signer, ok := km.Signer(signingkey.EdDSA)
		if !ok || signer == nil || !publishes(km, kid) {
			kid = ""
		}
		served <- kid
	}()

	select {
	case kid := <-served:
		require.Equal(t, signing, kid,
			"the key the rotation is replacing still signs and is still published")
	case <-time.After(10 * time.Second):
		t.Fatal("Signer blocked while a rotation was inside the store write: " +
			"the keyring lock is held across store I/O")
	}

	close(store.release)
	require.NoError(t, km.Stop())
	goleak.VerifyNone(t, ignore)
}

// kidsOf lists the identifiers a source published, in the order it published
// them, so a case can assert the order without repeating the loop.
func kidsOf(keys []signingkey.PublicKey) []string {
	kids := make([]string, 0, len(keys))
	for _, key := range keys {
		kids = append(kids, key.Kid)
	}

	return kids
}

// TestVerificationKeysPublishesThePublicHalfOfEveryHeldKey pins what the
// manager hands a verifier: one entry per key it holds, in the order it holds
// them, each naming the key and the algorithm it verifies, and each carrying
// public material only.
//
// The order matters because it is the one a consumer's own publisher would
// render a key set in, and a key that moves between two reads for no reason
// makes a cached set look stale when it is not.
func TestVerificationKeysPublishesThePublicHalfOfEveryHeldKey(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		manager func(t *testing.T) *signingkey.Keys
		assert  func(t *testing.T, km *signingkey.Keys, keys []signingkey.PublicKey, err error)
	}

	cases := []testCase{
		{
			name: "one entry per configured algorithm, naming the key that signs for it",
			manager: func(t *testing.T) *signingkey.Keys {
				km, err := signingkey.New(t.Context(),
					signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
					signingkey.WithAlgs(signingkey.RS256, signingkey.ES256),
				)
				require.NoError(t, err)

				return km
			},
			assert: func(t *testing.T, km *signingkey.Keys, keys []signingkey.PublicKey, err error) {
				require.NoError(t, err)
				require.Len(t, keys, 2)

				rsaKid := currentKid(t, km, signingkey.RS256)
				ecKid := currentKid(t, km, signingkey.ES256)
				assert.Equal(t, []string{rsaKid, ecKid}, kidsOf(keys),
					"the keys are published in the order they were held")

				assert.Equal(t, signingkey.RS256, keys[0].Alg)
				assert.IsType(t, &rsa.PublicKey{}, keys[0].Key)

				assert.Equal(t, signingkey.ES256, keys[1].Alg)
				assert.IsType(t, &ecdsa.PublicKey{}, keys[1].Key)
			},
		},
		{
			name: "a key held for an algorithm this manager was not configured with is published too",
			manager: func(t *testing.T) *signingkey.Keys {
				// A replica configured for EdDSA wrote to the same store. Its
				// key never signs here, but publishing it is what lets this
				// manager verify the tokens that replica issued.
				foreign := realRecordFor(t, signingkey.EdDSA, epoch)
				store := signingkey.NewMemoryKeyStore()
				require.NoError(t, store.Store(t.Context(), foreign))

				// The manager reads the time the record is dated at, or the
				// record would be dated years ahead and not published at all.
				km, err := signingkey.New(t.Context(),
					signingkey.WithKeyStore(store),
					signingkey.WithAlgs(signingkey.RS256),
					signingkey.WithClock(newClock()),
				)
				require.NoError(t, err)

				return km
			},
			assert: func(t *testing.T, km *signingkey.Keys, keys []signingkey.PublicKey, err error) {
				require.NoError(t, err)
				require.Len(t, keys, 2,
					"the foreign key is published alongside the one this manager minted")

				assert.Equal(t, signingkey.EdDSA, keys[0].Alg,
					"the stored key is held before the minted one, so it is published first")
				assert.IsType(t, ed25519.PublicKey{}, keys[0].Key)

				_, _, signs := km.Signer(signingkey.EdDSA)
				assert.False(t, signs, "publishing a foreign key is not signing with it")

				assert.Equal(t, currentKid(t, km, signingkey.RS256), keys[1].Kid)
			},
		},
		{
			name: "no published key can sign",
			manager: func(t *testing.T) *signingkey.Keys {
				km, err := signingkey.New(t.Context(),
					signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
					signingkey.WithAlgs(signingkey.RS256, signingkey.ES256, signingkey.EdDSA),
				)
				require.NoError(t, err)

				return km
			},
			assert: func(t *testing.T, _ *signingkey.Keys, keys []signingkey.PublicKey, err error) {
				require.NoError(t, err)
				require.Len(t, keys, 3)

				for _, key := range keys {
					// Every private key this package can produce is a
					// crypto.Signer and no public half is, so this catches a
					// whole private key handed over where its public part was
					// meant, whatever its type.
					_, signs := key.Key.(crypto.Signer)
					assert.False(t, signs,
						"key %q is a signer, so private material left the manager", key.Kid)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			km := tc.manager(t)

			keys, err := km.VerificationKeys()
			tc.assert(t, km, keys, err)
		})
	}
}

// TestVerificationKeysDoNotShareKeyMaterialWithTheManager pins that a caller
// is handed its own copy of every key.
//
// A crypto.PublicKey is a pointer or a slice into structure the manager's own
// key is built from: an *rsa.PublicKey shares its modulus, an *ecdsa.PublicKey
// its coordinates, an ed25519.PublicKey its bytes. Handing the live value over
// lets a caller that normalises, caches or simply reuses what it was given
// rewrite the key the manager verifies with, and every token signed by that
// key then fails to verify for everyone.
//
// Each case corrupts the key it was handed and asks the manager again. The
// second answer is what the manager still publishes.
// Standalone: its cases write to the keys handed out, unlike the table above.
func TestVerificationKeysDoNotShareKeyMaterialWithTheManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		alg  signingkey.Alg
		// corrupt writes to the key the caller was handed, as a caller
		// reusing the value it was given would.
		corrupt func(t *testing.T, key crypto.PublicKey)
	}

	cases := []testCase{
		{
			name: "RS256 shares its modulus",
			alg:  signingkey.RS256,
			corrupt: func(t *testing.T, key crypto.PublicKey) {
				pub, ok := key.(*rsa.PublicKey)
				require.True(t, ok, "expected an *rsa.PublicKey, got %T", key)
				pub.N.SetInt64(1)
			},
		},
		{
			name: "ES256 shares its coordinates",
			alg:  signingkey.ES256,
			corrupt: func(t *testing.T, key crypto.PublicKey) {
				pub, ok := key.(*ecdsa.PublicKey)
				require.True(t, ok, "expected an *ecdsa.PublicKey, got %T", key)
				pub.X.SetInt64(1) //nolint:staticcheck // SA1019: corrupting the coordinate is the point
			},
		},
		{
			name: "EdDSA shares its bytes",
			alg:  signingkey.EdDSA,
			corrupt: func(t *testing.T, key crypto.PublicKey) {
				pub, ok := key.(ed25519.PublicKey)
				require.True(t, ok, "expected an ed25519.PublicKey, got %T", key)
				require.NotEmpty(t, pub)
				pub[0] ^= 0xFF
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			km, err := signingkey.New(t.Context(),
				signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
				signingkey.WithAlgs(tc.alg),
			)
			require.NoError(t, err)

			// want is read before anything is written to, and is a value, not
			// a handle, so no assertion below can be satisfied by comparing
			// corrupted material with itself.
			before, err := km.VerificationKeys()
			require.NoError(t, err)
			require.Len(t, before, 1)
			want := publicKeyBytes(t, before[0].Key)

			handed, err := km.VerificationKeys()
			require.NoError(t, err)
			require.Len(t, handed, 1)
			tc.corrupt(t, handed[0].Key)

			after, err := km.VerificationKeys()
			require.NoError(t, err,
				"a manager that shared its key material cannot publish at all once a caller has written to it")
			require.Len(t, after, 1)
			assert.Equal(t, want, publicKeyBytes(t, after[0].Key),
				"a caller writing to a key it was handed must not change the key the manager publishes")

			_, signer, ok := km.Signer(tc.alg)
			require.True(t, ok)
			assert.Equal(t, want, publicKeyBytes(t, signer.Public()),
				"nor the public half of the key the manager still signs with")
		})
	}
}

// publicKeyBytes renders a public key as the bytes that identify it, so an
// assertion compares material rather than two pointers into the same
// structure — which would agree however corrupted that structure is.
//
// An ECDSA key is rendered by PublicKey.Bytes, which reads the coordinates as
// they are now and refuses a point that is not on its curve. A key that fails
// to encode is therefore a key something has already written through, which is
// the very failure these cases look for, so it is reported here rather than
// compared.
func publicKeyBytes(t *testing.T, key crypto.PublicKey) []byte {
	t.Helper()

	switch pub := key.(type) {
	case *rsa.PublicKey:
		return pub.N.Bytes()
	case *ecdsa.PublicKey:
		encoded, err := pub.Bytes()
		require.NoError(t, err,
			"an ECDSA key that no longer encodes has had its coordinates rewritten")

		return encoded
	case ed25519.PublicKey:
		return []byte(pub)
	default:
		t.Fatalf("unexpected public key type %T", key)

		return nil
	}
}

// F1 — the manager hands out its own live key material, so a caller writing
// to what it was given breaks the manager's verification.
//
// The unit of that defect is covered case by case in
// TestVerificationKeysDoNotShareKeyMaterialWithTheManager. This one keeps the
// end the defect was found at: a token the manager signed still verifies
// against what the manager publishes afterwards.
// Standalone: it signs a token, corrupts a handed key, and verifies.
func TestPublishedKeysDoNotBreakTheManagersOwnVerification(t *testing.T) {
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
		signingkey.WithAlgs(signingkey.EdDSA),
	)
	require.NoError(t, err)

	kid, signer, ok := km.Signer(signingkey.EdDSA)
	require.True(t, ok)

	exported, err := km.VerificationKeys()
	require.NoError(t, err)
	require.Len(t, exported, 1)
	handed, isEd25519 := exported[0].Key.(ed25519.PublicKey)
	require.True(t, isEd25519)
	for i := range handed {
		handed[i] ^= 0xFF // the caller writes to the key it was given
	}

	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.KeyIDKey, kid))
	token, err := jws.Sign([]byte(`{"sub":"alice"}`),
		jws.WithKey(auditAlg(t, signingkey.EdDSA), signer, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)

	_, verr := jws.Verify(token, jws.WithKeySet(publishedSet(t, km)))
	assert.NoError(t, verr,
		"a caller writing to a key it was handed must not break the manager's own verification")
}

// publishedKeys returns the key objects of the document, decoded as plain JSON
// rather than through a JOSE library, so what is asserted is what an endpoint
// serving these bytes would actually send — parameters a jwk.Key would not
// round-trip included.
func publishedKeys(t *testing.T, doc []byte) []map[string]any {
	t.Helper()

	var document map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc, &document),
		"the document is a JSON object")

	raw, isSet := document["keys"]
	require.True(t, isSet, "an RFC 7517 JWK Set is a JSON object with a keys array")

	var keys []map[string]any
	require.NoError(t, json.Unmarshal(raw, &keys), "keys is an array of JWKs")

	return keys
}

// publishedKids lists the identifiers the document names, in the order it
// names them.
func publishedKids(t *testing.T, doc []byte) []string {
	t.Helper()

	keys := publishedKeys(t, doc)
	kids := make([]string, 0, len(keys))
	for _, key := range keys {
		kid, isString := key["kid"].(string)
		require.True(t, isString, "every entry carries a string kid, got %T", key["kid"])
		kids = append(kids, kid)
	}

	return kids
}

// memberNames lists the JSON member names a key renders to, which is what a
// published entry can be compared against parameter by parameter.
func memberNames(t *testing.T, key jwk.Key) []string {
	t.Helper()

	raw, err := json.Marshal(key)
	require.NoError(t, err)

	var members map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &members))

	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	slices.Sort(names)

	return names
}

// privateOnlyFields returns the JWK parameters that appear only when the
// private half of rec's key is rendered: it renders that half, renders the
// public half of the same key, and takes the difference.
//
// It is derived rather than listed so the check it feeds cannot go stale. A
// fixed list — "d", "p", "q", "dp", "dq", "qi" — names the parameters of the
// algorithms supported today, and the first algorithm added whose private half
// has a parameter outside it would be published in full while the test still
// passed.
func privateOnlyFields(t *testing.T, rec signingkey.Record) []string {
	t.Helper()

	raw, err := x509.ParsePKCS8PrivateKey(rec.Private)
	require.NoError(t, err, "the record holds the key as PKCS #8 DER")

	private, err := jwk.Import[jwk.Key](raw)
	require.NoError(t, err)

	public, err := private.PublicKey()
	require.NoError(t, err)

	publicNames := memberNames(t, public)
	secret := make([]string, 0, len(publicNames))
	for _, name := range memberNames(t, private) {
		if !slices.Contains(publicNames, name) {
			secret = append(secret, name)
		}
	}

	return secret
}

// assertNoPrivateMaterial fails for every parameter of a published entry that
// only the private half of that same key has.
//
// The records are read back from the store the manager minted into, so each
// published entry is compared against the very key it was rendered from rather
// than against an expectation written here.
func assertNoPrivateMaterial(t *testing.T, store signingkey.KeyStore, doc []byte) {
	t.Helper()

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)

	byKid := make(map[string]signingkey.Record, len(recs))
	for _, rec := range recs {
		byKid[rec.Kid] = rec
	}

	for _, key := range publishedKeys(t, doc) {
		kid, _ := key["kid"].(string)
		rec, stored := byKid[kid]
		require.True(t, stored, "published key %q is one the store holds", kid)

		secret := privateOnlyFields(t, rec)
		require.NotEmpty(t, secret,
			"rendering the private half of the %s key found no parameter the public "+
				"half lacks, so the check below would pass whatever was published",
			rec.Alg)

		for _, name := range secret {
			assert.NotContains(t, key, name,
				"published key %q carries %q, which only the private half of a %s key has",
				kid, name, rec.Alg)
		}
	}

	set, err := jwk.Parse(doc)
	require.NoError(t, err)

	for _, key := range set.All() {
		isPrivate, privErr := jwk.IsPrivateKey(key)
		require.NoError(t, privErr)
		assert.False(t, isPrivate, "no published key is a private key")
	}
}

// renderSet builds a JWK Set document from keys the way a consumer with its
// own publishing rules would: it reads the port, and the port hands over kid,
// alg and a crypto.PublicKey, so nothing about obtaining the keys needs a JOSE
// library. Turning them into a document does, and that library is then the
// consumer's own choice rather than this package's.
func renderSet(t *testing.T, keys []signingkey.PublicKey) []byte {
	t.Helper()

	set := jwk.NewSet()
	for _, pk := range keys {
		key, err := jwk.Import[jwk.Key](pk.Key)
		require.NoError(t, err)
		require.NoError(t, key.Set(jwk.KeyIDKey, pk.Kid))
		require.NoError(t, key.Set(jwk.AlgorithmKey, pk.Alg))
		require.NoError(t, key.Set(jwk.KeyUsageKey, string(jwk.ForSignature)))
		require.NoError(t, set.AddKey(key))
	}

	doc, err := json.Marshal(set)
	require.NoError(t, err)

	return doc
}

// TestJWKSPublishesTheDocumentAnEndpointServes pins what a consumer writes to
// the wire: an RFC 7517 JWK Set naming every key the manager holds, in the
// order it holds them, each entry carrying the kid a token's header names, the
// algorithm it verifies and signature use.
//
// The order matters because a verifier caches the document, and a key that
// moves between two reads for no reason makes a cached copy look stale when it
// is not.
func TestJWKSPublishesTheDocumentAnEndpointServes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		manager func(t *testing.T) *signingkey.Keys
		assert  func(t *testing.T, km *signingkey.Keys, doc []byte, err error)
	}

	cases := []testCase{
		{
			name: "one entry per configured algorithm, each naming its key and its algorithm",
			manager: func(t *testing.T) *signingkey.Keys {
				km, err := signingkey.New(t.Context(),
					signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
					signingkey.WithAlgs(signingkey.RS256, signingkey.ES256),
				)
				require.NoError(t, err)

				return km
			},
			assert: func(t *testing.T, km *signingkey.Keys, doc []byte, err error) {
				require.NoError(t, err)

				keys := publishedKeys(t, doc)
				require.Len(t, keys, 2)

				rsaKid := currentKid(t, km, signingkey.RS256)
				ecKid := currentKid(t, km, signingkey.ES256)
				assert.Equal(t, []string{rsaKid, ecKid}, publishedKids(t, doc),
					"the keys are published in the order they were held")

				assert.Equal(t, signingkey.RS256, keys[0]["alg"])
				assert.Equal(t, "RSA", keys[0]["kty"])
				assert.Equal(t, signingkey.ES256, keys[1]["alg"])
				assert.Equal(t, "EC", keys[1]["kty"])

				for _, key := range keys {
					assert.Equal(t, "sig", key["use"],
						"every entry declares signature use")
				}

				set, parseErr := jwk.Parse(doc)
				require.NoError(t, parseErr, "the JOSE stack parses what is published")
				assert.Equal(t, 2, set.Len())
			},
		},
		{
			name: "a key held for an algorithm this manager was not configured with is published too",
			manager: func(t *testing.T) *signingkey.Keys {
				// A replica configured for EdDSA wrote to the same store. Its
				// key never signs here, and publishing it is what verifies the
				// tokens that replica issued.
				foreign := realRecordFor(t, signingkey.EdDSA, epoch)
				store := signingkey.NewMemoryKeyStore()
				require.NoError(t, store.Store(t.Context(), foreign))

				// The manager reads the time the record is dated at, or the
				// record would be dated years ahead and not published at all.
				km, err := signingkey.New(t.Context(),
					signingkey.WithKeyStore(store),
					signingkey.WithAlgs(signingkey.RS256),
					signingkey.WithClock(newClock()),
				)
				require.NoError(t, err)

				return km
			},
			assert: func(t *testing.T, km *signingkey.Keys, doc []byte, err error) {
				require.NoError(t, err)

				keys := publishedKeys(t, doc)
				require.Len(t, keys, 2,
					"the foreign key is published alongside the one this manager minted")

				assert.Equal(t, signingkey.EdDSA, keys[0]["alg"],
					"the stored key is held before the minted one, so it is published first")
				assert.Equal(t, "OKP", keys[0]["kty"])

				_, _, signs := km.Signer(signingkey.EdDSA)
				assert.False(t, signs, "publishing a foreign key is not signing with it")

				assert.Equal(t, currentKid(t, km, signingkey.RS256), keys[1]["kid"])
			},
		},
		{
			name: "the document names the same keys, in the same order, as the port reports",
			manager: func(t *testing.T) *signingkey.Keys {
				km, err := signingkey.New(t.Context(),
					signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
					signingkey.WithAlgs(signingkey.RS256, signingkey.ES256, signingkey.EdDSA),
				)
				require.NoError(t, err)

				return km
			},
			assert: func(t *testing.T, km *signingkey.Keys, doc []byte, err error) {
				require.NoError(t, err)

				// Two views of one set of keys. A verifier reading the
				// document and this process verifying a token in hand must
				// agree on which keys exist, so they cannot be allowed to
				// drift apart.
				reported, keysErr := km.VerificationKeys()
				require.NoError(t, keysErr)
				assert.Equal(t, kidsOf(reported), publishedKids(t, doc))

				published := publishedKeys(t, doc)
				require.Len(t, published, len(reported))
				for i, key := range reported {
					assert.Equal(t, key.Alg, published[i]["alg"],
						"both views agree on what key %q verifies", key.Kid)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			km := tc.manager(t)

			doc, err := km.JWKS()
			tc.assert(t, km, doc, err)
		})
	}
}

// TestJWKSPublishesNoPrivateMaterial is the security-critical case: the
// document goes to anyone who asks for it, so a private parameter in it hands
// out the signing key itself and every token ever issued can then be forged.
//
// A rendering check alone would not catch that. A private JWK satisfies every
// kid, alg and use claim the test above makes, and it parses as a JWK Set, so
// what is asserted here is the parameters each entry carries, derived from the
// private half of that very key rather than listed.
func TestJWKSPublishesNoPrivateMaterial(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		algs   []signingkey.Alg
		assert func(t *testing.T, store signingkey.KeyStore, doc []byte, err error)
	}

	cases := []testCase{
		{
			name: "RS256 publishes its modulus and exponent only",
			algs: []signingkey.Alg{signingkey.RS256},
			assert: func(t *testing.T, store signingkey.KeyStore, doc []byte, err error) {
				require.NoError(t, err)
				require.Len(t, publishedKeys(t, doc), 1)
				assertNoPrivateMaterial(t, store, doc)
			},
		},
		{
			name: "ES256 publishes its coordinates only",
			algs: []signingkey.Alg{signingkey.ES256},
			assert: func(t *testing.T, store signingkey.KeyStore, doc []byte, err error) {
				require.NoError(t, err)
				require.Len(t, publishedKeys(t, doc), 1)
				assertNoPrivateMaterial(t, store, doc)
			},
		},
		{
			name: "EdDSA publishes its public point only",
			algs: []signingkey.Alg{signingkey.EdDSA},
			assert: func(t *testing.T, store signingkey.KeyStore, doc []byte, err error) {
				require.NoError(t, err)
				require.Len(t, publishedKeys(t, doc), 1)
				assertNoPrivateMaterial(t, store, doc)
			},
		},
		{
			name: "every supported algorithm at once",
			algs: []signingkey.Alg{signingkey.RS256, signingkey.ES256, signingkey.EdDSA},
			assert: func(t *testing.T, store signingkey.KeyStore, doc []byte, err error) {
				require.NoError(t, err)
				require.Len(t, publishedKeys(t, doc), 3,
					"one entry per algorithm, so no entry escapes the check below")
				assertNoPrivateMaterial(t, store, doc)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := signingkey.NewMemoryKeyStore()
			km, err := signingkey.New(t.Context(),
				signingkey.WithKeyStore(store),
				signingkey.WithAlgs(tc.algs...),
			)
			require.NoError(t, err)

			doc, err := km.JWKS()
			tc.assert(t, store, doc, err)
		})
	}
}

// TestAConsumerPublishesItsOwnDocumentFromThePort pins that the document this
// package produces is a default and not the only one available. A consumer
// whose infrastructure needs something else — a filtered set, another order,
// extra JWK parameters, a wrapper object — renders it from VerificationKeys,
// which hands over kid, alg and a crypto.PublicKey and obliges the consumer to
// import nothing from a JOSE library to obtain them.
//
// The cheapest honest example is a filter: the manager publishes every key it
// holds, and a consumer that wants only the key it is signing with today
// cannot ask this package for that document.
// Standalone: it renders a second document from the port.
func TestAConsumerPublishesItsOwnDocumentFromThePort(t *testing.T) {
	t.Parallel()

	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
		signingkey.WithAlgs(signingkey.RS256, signingkey.ES256),
	)
	require.NoError(t, err)

	doc, err := km.JWKS()
	require.NoError(t, err)
	require.Len(t, publishedKeys(t, doc), 2, "the default publishes every key held")

	// The consumer's own rule: publish the key currently signing RS256 and
	// nothing else.
	signing := currentKid(t, km, signingkey.RS256)
	reported, err := km.VerificationKeys()
	require.NoError(t, err)

	own := make([]signingkey.PublicKey, 0, len(reported))
	for _, key := range reported {
		if key.Kid == signing {
			own = append(own, key)
		}
	}
	require.Len(t, own, 1)

	consumerDoc := renderSet(t, own)

	set, err := jwk.Parse(consumerDoc)
	require.NoError(t, err, "what the consumer renders is still a JWK Set")
	assert.Equal(t, 1, set.Len())

	assert.Equal(t, []string{signing}, publishedKids(t, consumerDoc),
		"the consumer publishes the subset it chose")
	assert.Subset(t, publishedKids(t, doc), publishedKids(t, consumerDoc),
		"and chose it out of what the default publishes")
	assert.NotEqual(t, publishedKids(t, doc), publishedKids(t, consumerDoc),
		"which is a document this package deliberately does not produce")
}
