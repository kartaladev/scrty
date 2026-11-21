package seal_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/store/seal"
	"github.com/kartaladev/scrty/token/signingkey"
)

// The hostile error types, the abort recorder, the outcome type and the
// bound, the child-process env var and the default swap are the ones
// cipher_porterr_test.go and mfa_porterr_test.go declare for this package's
// port tests. The child-process marker is this file's own.

func skeChildMarker(row string) string { return "SCRTY-SEAL-SIGNINGKEY-PORTERR-ROW-RAN:" + row }

// skeInChild re-runs the current top-level test in a child process limited to
// row, and fails unless the child exits 0 within a minute and prints a line
// equal to row's marker, which it does only after the row passed.
func skeInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), mpeChildEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	want := skeChildMarker(row)
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q (no line equals %q); output:\n%s", row, want, out)
}

// skeSite is one port call in signingkey.go: run arranges the port's mock to
// return err and drives the sealing signing-key store.
type skeSite struct {
	name   string
	cipher bool // the port is the consumer's Cipher: a plain outage matches ErrUnavailable
	run    func(t *testing.T, ctx context.Context, err error) mpeOutcome
}

func skeStore(t *testing.T, inner signingkey.KeyStore, c seal.Cipher) signingkey.KeyStore {
	t.Helper()

	store, err := seal.NewSigningKeyStore(inner, nil, c, seal.WithResealOnRead(false))
	require.NoError(t, err)

	return store
}

func skeSites() []skeSite {
	return []skeSite{
		{name: "Store seals the private material", cipher: true,
			run: func(t *testing.T, ctx context.Context, err error) mpeOutcome {
				ctrl := gomock.NewController(t)
				c := NewMockCipher(ctrl)
				c.EXPECT().Seal(gomock.Any(), gomock.Any(), seal.SigningKeyAAD("kid-a")).Return(nil, err)
				store := skeStore(t, NewMockKeyStore(ctrl), c) // the inner store is never called: nothing is stored

				return mpeWithin(t, func() mpeOutcome { return mpeClassify(false, store.Store(ctx, signingRecord("kid-a", 1))) })
			}},
		{name: "Store asks the inner store",
			run: func(t *testing.T, ctx context.Context, err error) mpeOutcome {
				ctrl := gomock.NewController(t)
				inner := NewMockKeyStore(ctrl)
				inner.EXPECT().Store(gomock.Any(), gomock.Any()).Return(err)
				store := skeStore(t, inner, newCiphers(t).current)

				return mpeWithin(t, func() mpeOutcome { return mpeClassify(false, store.Store(ctx, signingRecord("kid-a", 1))) })
			}},
		{name: "LoadAll asks the inner store",
			run: func(t *testing.T, ctx context.Context, err error) mpeOutcome {
				ctrl := gomock.NewController(t)
				inner := NewMockKeyStore(ctrl)
				inner.EXPECT().LoadAll(gomock.Any()).Return([]signingkey.Record{signingRecord("kid-a", 1)}, err)
				store := skeStore(t, inner, newCiphers(t).current)

				return mpeWithin(t, func() mpeOutcome {
					recs, got := store.LoadAll(ctx)

					return mpeClassify(len(recs) > 0, got)
				})
			}},
		{name: "LoadAll opens a stored key", cipher: true,
			run: func(t *testing.T, ctx context.Context, err error) mpeOutcome {
				ctrl := gomock.NewController(t)
				inner := NewMockKeyStore(ctrl)
				inner.EXPECT().LoadAll(gomock.Any()).Return([]signingkey.Record{signingRecord("kid-a", 1)}, nil)
				c := NewMockCipher(ctrl)
				c.EXPECT().Open(gomock.Any(), gomock.Any(), seal.SigningKeyAAD("kid-a")).Return(nil, "", err)
				store := skeStore(t, inner, c)

				return mpeWithin(t, func() mpeOutcome {
					recs, got := store.LoadAll(ctx)

					return mpeClassify(len(recs) > 0, got)
				})
			}},
		{name: "Delete asks the inner store",
			run: func(t *testing.T, ctx context.Context, err error) mpeOutcome {
				ctrl := gomock.NewController(t)
				inner := NewMockKeyStore(ctrl)
				inner.EXPECT().Delete(gomock.Any(), "kid-a").Return(err)
				store := skeStore(t, inner, newCiphers(t).current)

				return mpeWithin(t, func() mpeOutcome { return mpeClassify(false, store.Delete(ctx, "kid-a")) })
			}},
	}
}

// skeKinds is every error a port returns. The claims are the two a signing-key
// read must never be told by a hostile error: a value that does not open, and
// a key id the ring no longer holds.
func skeKinds() []mpeKind { return mceKinds() }

// TestPortErrors_SealSigningKeyStore: an inner signing-key store, or a
// consumer cipher, that returns an error the library cannot walk gets the
// outcome of a plain outage of that port: no hang, no panic, the same flags
// and error class (ErrUnavailable at the cipher site, as cipher.go documents),
// never a decryption refusal or an unknown key, exactly one abort record on
// slog.Default(), and nothing of the consumer's text in the error or any
// record. Not parallel: it swaps slog.Default().
func TestPortErrors_SealSigningKeyStore(t *testing.T) {
	child := os.Getenv(mpeChildEnv)
	if child != "" {
		debug.SetMaxStack(64 << 20)
	}

	for _, site := range skeSites() {
		for _, kind := range skeKinds() {
			row := site.name + "/" + kind.name
			if child != "" && child != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if child == "" && kind.child {
					skeInChild(t, row)

					return
				}

				ctx := t.Context()
				if kind.cancelled {
					ctx = cancelled(ctx)
				}

				rec := mpeSwapDefault(t)

				plainErr := errors.New("store down: " + cpeSecret)
				if site.cipher {
					plainErr = cpePlainOutage()
				}

				plain := site.run(t, ctx, plainErr)
				require.Zero(t, rec.aborts(), "a plain outage writes no abort record")
				require.True(t, plain.failed)
				require.Equal(t, site.cipher, plain.unavailable)

				got := site.run(t, ctx, kind.make())

				assert.Equal(t, 1, rec.aborts(), "abort records on slog.Default()")
				assert.True(t, got.unwalkable, "the error is the sanitizer's fault")
				assert.Equal(t, site.cipher, got.unavailable, "a hostile cipher error is a cipher outage")
				assert.False(t, got.decryption, "a hostile error is never read as a value that does not open")
				assert.False(t, got.unknownKey, "a hostile error is never read as a removed key")
				assert.NotContains(t, got.text, cpeSecret, "the returned error carries no consumer text")

				want, have := plain, got
				want.unwalkable, have.unwalkable = false, false
				want.text, have.text = "", ""
				assert.Equal(t, want, have, "the hostile error takes the plain outage's branch")

				for _, text := range rec.texts() {
					assert.NotContains(t, text, cpeSecret)
				}

				if child != "" && !t.Failed() {
					fmt.Println(skeChildMarker(row))
				}
			})
		}
	}
}

// TestPortErrors_SealSigningKeyStoreOutcomes pins what the sites answer for
// the errors that are not hostile, so the sanitizer changes none of them.
func TestPortErrors_SealSigningKeyStoreOutcomes(t *testing.T) {
	type testCase struct {
		name   string
		site   int // index into skeSites
		err    error
		assert func(t *testing.T, o mpeOutcome, aborts int)
	}

	sealSite, storeSite, loadSite, openSite, deleteSite := 0, 1, 2, 3, 4

	cases := []testCase{
		{name: "Store: a cipher error matching ErrUnavailable stays an outage, no record", site: sealSite,
			err: fmt.Errorf("kms: %w", seal.ErrUnavailable),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.unavailable)
				assert.False(t, o.unwalkable)
				assert.Zero(t, aborts)
			}},
		{name: "Store: a typed-nil cipher error is a failure, no panic, no record", site: sealSite,
			err: (*cpeTypedNil)(nil),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.failed)
				assert.Zero(t, aborts)
			}},
		{name: "Store: an inner failure stays a failure with no consumer text", site: storeSite,
			err: errors.New("db down: " + cpeSecret),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.failed)
				assert.False(t, o.unwalkable)
				assert.NotContains(t, o.text, cpeSecret)
				assert.Zero(t, aborts)
			}},
		{name: "LoadAll: a wrapped decryption error from the inner store keeps matching it", site: loadSite,
			err: fmt.Errorf("store: %w", seal.ErrDecryptionFailed),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.decryption)
				assert.False(t, o.unwalkable)
				assert.Zero(t, aborts)
			}},
		{name: "LoadAll: an Open error matching ErrDecryptionFailed stays a refusal, no record", site: openSite,
			err: fmt.Errorf("aead: %w", seal.ErrDecryptionFailed),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.decryption)
				assert.False(t, o.unwalkable)
				assert.Zero(t, aborts)
			}},
		{name: "LoadAll: an Open error matching ErrUnknownKeyID stays an unknown key, no record", site: openSite,
			err: fmt.Errorf("ring: %w", seal.ErrUnknownKeyID),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.unknownKey)
				assert.False(t, o.unwalkable)
				assert.Zero(t, aborts)
			}},
		{name: "LoadAll: an Open error matching ErrUnavailable stays an outage, no record", site: openSite,
			err: fmt.Errorf("kms: %w", seal.ErrUnavailable),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.unavailable)
				assert.False(t, o.unwalkable)
				assert.Zero(t, aborts)
			}},
		{name: "Delete: an inner failure stays a failure with no consumer text", site: deleteSite,
			err: errors.New("db down: " + cpeSecret),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.failed)
				assert.False(t, o.unwalkable)
				assert.NotContains(t, o.text, cpeSecret)
				assert.Zero(t, aborts)
			}},
	}

	sites := skeSites()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := mpeSwapDefault(t)

			o := sites[tc.site].run(t, t.Context(), tc.err)
			tc.assert(t, o, rec.aborts())
		})
	}
}

// TestPortErrors_SealSigningKeyStoreDropped pins the three consumer port calls
// whose error signingkey.go only compares with nil or discards, so it is never
// walked: a hostile ActiveKeyID error, re-seal error or resealer error leaves
// the load answered, with no abort record. They are not sanitized, and nothing
// observable changes.
func TestPortErrors_SealSigningKeyStoreDropped(t *testing.T) {
	type testCase struct {
		name  string
		setup func(c *MockCipher, r *MockSigningKeyResealer)
	}

	cases := []testCase{
		{name: "ActiveKeyID fails with a hostile error",
			setup: func(c *MockCipher, _ *MockSigningKeyResealer) {
				c.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("plain"), "k1", nil)
				c.EXPECT().ActiveKeyID(gomock.Any()).Return("", &cpeCycleOne{})
			}},
		{name: "re-seal fails with a hostile error",
			setup: func(c *MockCipher, _ *MockSigningKeyResealer) {
				c.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("plain"), "k1", nil)
				c.EXPECT().ActiveKeyID(gomock.Any()).Return("k2", nil)
				c.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, cpePanicUnwrap{})
			}},
		{name: "the resealer fails with a hostile error",
			setup: func(c *MockCipher, r *MockSigningKeyResealer) {
				c.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("plain"), "k1", nil)
				c.EXPECT().ActiveKeyID(gomock.Any()).Return("k2", nil)
				c.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("resealed"), nil)
				r.EXPECT().ResealSigningKey(gomock.Any(), "kid-a", gomock.Any(), []byte("resealed")).Return(&cpeCycleOne{})
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := mpeSwapDefault(t)
			ctrl := gomock.NewController(t)
			inner := NewMockKeyStore(ctrl)
			inner.EXPECT().LoadAll(gomock.Any()).Return([]signingkey.Record{signingRecord("kid-a", 1)}, nil)
			c := NewMockCipher(ctrl)
			r := NewMockSigningKeyResealer(ctrl)
			tc.setup(c, r)

			store, err := seal.NewSigningKeyStore(inner, r, c)
			require.NoError(t, err)

			o := mpeWithin(t, func() mpeOutcome {
				recs, got := store.LoadAll(t.Context())

				return mpeClassify(len(recs) == 1, got)
			})

			assert.False(t, o.failed)
			assert.True(t, o.ok)
			assert.Zero(t, rec.aborts())
		})
	}
}
