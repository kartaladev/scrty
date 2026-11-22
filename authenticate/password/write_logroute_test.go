package password_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// TestLogRoute_ProvisionerWrites pins where the abort record of an unwalkable
// store error goes for the ready-made writes: the logger of the chain handling
// the request, else slog.Default() at record time. It swaps the default
// logger, so it does not run in parallel.
func TestLogRoute_ProvisionerWrites(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		call   func(ctx context.Context, prov identity.UserProvisioner) error
		chain  bool
		assert func(t *testing.T, chain, def *recordingHandler)
	}

	user := &identity.Details{Username: "ada"}
	write := func(ctx context.Context, prov identity.UserProvisioner) error {
		w, err := password.ProvisionerWrite(prov)
		require.NoError(t, err)

		return w(ctx, user, []byte("h"), time.Now())
	}
	rehash := func(ctx context.Context, prov identity.UserProvisioner) error {
		w, err := password.ConditionalProvisionerRehash(prov)
		require.NoError(t, err)

		return w(ctx, user, []byte("old"), []byte("new"))
	}
	inChain := func(t *testing.T, chain, def *recordingHandler) {
		assert.Len(t, chain.all(), 1)
		assert.Empty(t, def.all(), "the default logger must see nothing")
	}
	noChain := func(t *testing.T, chain, def *recordingHandler) {
		assert.Empty(t, chain.all())
		assert.Len(t, def.all(), 1, "the default as swapped at record time")
	}

	cases := []testCase{
		{name: "ProvisionerWrite, inside a configured chain", call: write, chain: true, assert: inChain},
		{name: "ProvisionerWrite, no chain", call: write, assert: noChain},
		{name: "ConditionalProvisionerRehash, inside a configured chain", call: rehash, chain: true, assert: inChain},
		{name: "ConditionalProvisionerRehash, no chain", call: rehash, assert: noChain},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain, def := &recordingHandler{}, &recordingHandler{}

			previous := slog.Default()
			slog.SetDefault(slog.New(def))
			t.Cleanup(func() { slog.SetDefault(previous) })

			prov := NewMockUserProvisioner(gomock.NewController(t))
			prov.EXPECT().Update(gomock.Any(), "ada", gomock.Any()).Return(nil, &hostileCycleOne{})

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, slog.New(chain))
			}

			require.Error(t, tc.call(ctx, prov))
			tc.assert(t, chain, def)
		})
	}
}
