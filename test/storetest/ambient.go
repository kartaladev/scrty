package storetest

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Ambient is what the ambient-transaction suite needs from one store: a
// write, an out-of-band check for it, and a refusal. Every field is required,
// and probes missing one fail the suite at once, naming it.
type Ambient[S any] struct {
	// Write makes the store write record i through ctx, which may carry a
	// caller's transaction. Each case writes records of its own i, so the
	// cases share one database without meeting.
	Write func(ctx context.Context, s S, i int) error

	// Present reports whether record i is committed, read through raw
	// (DurableHarness.Raw) and never through the store.
	Present func(t *testing.T, raw *sql.DB, i int) bool

	// Refuse makes the store refuse an operation through ctx, as a durable
	// store refuses: consuming a token that does not exist, say, or inserting
	// a link that does. It may write what it needs first, through the same
	// ctx, and must return an error matching Refusal.
	Refuse func(ctx context.Context, s S) error

	// Refusal is the sentinel Refuse's error must match through errors.Is,
	// such as onetime.ErrTokenNotFound. It is what tells a refusal apart from
	// a failed statement, which would abort the caller's transaction.
	Refusal error
}

// RunAmbientTx holds a durable store to taking part in a transaction its
// caller owns, checking what it wrote through h.Raw rather than through the
// store:
//   - a write inside a transaction attached with h.Begin is not visible until
//     the transaction ends, is discarded by a rollback and kept by a commit;
//   - a refusal inside the transaction leaves it usable: a write after it
//     succeeds, and a commit keeps the writes on both sides of it;
//   - a store h.BeginResolved configured with a transaction resolver writes
//     in that transaction, though the context carries none;
//   - a transaction h.BeginForeign attaches for another backend is ignored:
//     the store writes through its own handle, and the foreign rollback does
//     not take the write with it.
//
// It fails at once, naming every missing input, when h or a is missing one.
func RunAmbientTx[S any](t *testing.T, h DurableHarness[S], a Ambient[S]) {
	t.Helper()

	requireAmbient(t, h, a)

	present := func(t *testing.T, i int) bool {
		t.Helper()
		return a.Present(t, h.Raw, i)
	}
	// begin and beginResolved roll the transaction back at cleanup, so a
	// case that fails part way never leaves it open. After a commit or a
	// rollback that rollback fails, and its error is ignored.
	begin := func(t *testing.T) (context.Context, func() error, func() error) {
		ctx, commit, rollback := h.Begin(t)
		t.Cleanup(func() { _ = rollback() })
		return ctx, commit, rollback
	}
	beginResolved := func(t *testing.T) (S, context.Context, func() error) {
		s, ctx, _, rollback := h.BeginResolved(t)
		t.Cleanup(func() { _ = rollback() })
		return s, ctx, rollback
	}

	runDurableCases(t, []durableCase{
		{
			name: "a write inside a rolled back transaction is discarded",
			assert: func(t *testing.T) {
				ctx, _, rollback := begin(t)
				require.NoError(t, a.Write(ctx, h.New(t), 1))
				assert.False(t, present(t, 1),
					"the write is visible before its transaction ended: the store did not write in it")

				require.NoError(t, rollback())
				assert.False(t, present(t, 1), "the write survived the rollback of its transaction")
			},
		},
		{
			name: "a write inside a committed transaction is kept",
			assert: func(t *testing.T) {
				ctx, commit, _ := begin(t)
				require.NoError(t, a.Write(ctx, h.New(t), 2))
				assert.False(t, present(t, 2),
					"the write is visible before its transaction ended: the store did not write in it")

				require.NoError(t, commit())
				assert.True(t, present(t, 2), "the write is missing after its transaction committed")
			},
		},
		{
			name: "a refusal inside a transaction leaves it usable",
			assert: func(t *testing.T) {
				ctx, commit, _ := begin(t)
				s := h.New(t)
				require.NoError(t, a.Write(ctx, s, 3))

				require.ErrorIs(t, a.Refuse(ctx, s), a.Refusal, "Refuse did not return the refusal")

				require.NoError(t, a.Write(ctx, s, 4), "a write after the refusal failed")
				require.NoError(t, commit(), "the transaction did not commit after the refusal")
				assert.True(t, present(t, 3), "the write before the refusal was not committed")
				assert.True(t, present(t, 4), "the write after the refusal was not committed")
			},
		},
		{
			name: "a configured resolver's transaction is used",
			assert: func(t *testing.T) {
				s, ctx, rollback := beginResolved(t)
				require.NoError(t, a.Write(ctx, s, 5))
				assert.False(t, present(t, 5),
					"the write is visible before the resolver's transaction ended: the store did not write in it")

				require.NoError(t, rollback())
				assert.False(t, present(t, 5), "the write survived the rollback of the resolver's transaction")
			},
		},
		{
			name: "a transaction attached for another backend is ignored",
			assert: func(t *testing.T) {
				ctx, rollback := h.BeginForeign(t)
				t.Cleanup(func() { _ = rollback() })
				require.NoError(t, a.Write(ctx, h.New(t), 6))
				assert.True(t, present(t, 6),
					"the write is not visible: the store wrote in another backend's transaction")

				require.NoError(t, rollback())
				assert.True(t, present(t, 6), "the write was rolled back with another backend's transaction")
			},
		},
	})
}

// requireAmbient fails t at once, naming every missing input, when h or a is
// missing one.
func requireAmbient[S any](t testing.TB, h DurableHarness[S], a Ambient[S]) {
	t.Helper()

	h.requireWith(t,
		input{"Ambient.Write", a.Write != nil},
		input{"Ambient.Present", a.Present != nil},
		input{"Ambient.Refuse", a.Refuse != nil},
		input{"Ambient.Refusal", a.Refusal != nil},
	)
}
