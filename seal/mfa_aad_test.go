package seal_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/seal"
)

// TestSealedEnrolment_RefusesSecretRestoredFromEarlierGeneration copies the
// sealed secret of a removed enrolment, out of band, back onto the same user's
// enrolment after a re-enrolment moved it to a new generation. The old secret
// is one the user gave up: it must not open as the new enrolment's.
func TestSealedEnrolment_RefusesSecretRestoredFromEarlierGeneration(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	c := newCiphers(t).current
	inner := mfa.NewMemoryEnrolmentStore()
	store, err := seal.NewEnrolmentStore(inner, nil, c, seal.WithResealOnRead(false))
	require.NoError(t, err)

	first := pendingEnrolment(t, userRef)
	require.NoError(t, store.PutPending(ctx, first))
	removed := innerSecret(t, inner, userRef)
	require.NoError(t, store.Delete(ctx, userRef))

	renewed := pendingEnrolment(t, userRef)
	renewed.Secret = []byte("a-new-secret-of-" + string(userRef))
	require.NoError(t, store.PutPending(ctx, renewed))

	// The restore: the first generation's ciphertext, on the renewed row.
	restored := renewed
	restored.Secret = removed
	require.NoError(t, inner.PutPending(ctx, restored))

	got, found, err := store.Get(ctx, userRef)
	require.ErrorIs(t, err, seal.ErrDecryptionFailed, "a secret sealed for an earlier generation must not open")
	assert.False(t, found)
	assert.Empty(t, got.Secret)
}
