package passkey_test

// TestLogRoute_Passkeys replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/token/onetime"
)

// findFailsChallenges is a challenge store whose reads fail, so the one-time
// manager the passkey manager hands its logger to has a record to write.
type findFailsChallenges struct{ *spyChallenges }

func (findFailsChallenges) FindByID(context.Context, id.ID) (*onetime.Token, error) {
	return nil, errors.New("dial tcp: connection refused")
}

// deleteCycles is a credential store whose Delete fails with an error whose
// chain loops, so the sanitizer writes an abort record.
type deleteCycles struct{ *passkey.MemoryCredentialStore }

func (deleteCycles) Delete(context.Context, identity.UserID, id.ID) (bool, error) {
	return false, &pregCycleOne{}
}

const (
	// logRoutePasskeyMsg is a record the passkey manager writes itself.
	logRoutePasskeyMsg = "passkey: expired login challenges were not purged"
	// logRouteOnetimeMsg is a record the manager's one-time child writes.
	logRouteOnetimeMsg = "onetime: reading the token store failed"
)

func TestLogRoute_Passkeys(t *testing.T) {
	// run makes the manager and its one-time child each write a record.
	run := func(t *testing.T, ctx context.Context, opts ...passkey.Option) {
		t.Helper()

		e := newLoginEnv(t, nil)
		e.challenges.err = errors.New("dial tcp: connection refused")
		e.f.deps.Challenges = findFailsChallenges{e.challenges}
		e.m = e.f.manager(t, opts...)

		_, err := e.m.BeginLogin(ctx, e.binding)
		require.NoError(t, err)

		e.mu.Lock()
		challenge := e.requested[len(e.requested)-1].Challenge
		e.mu.Unlock()

		_, err = e.m.Authenticate(ctx, assertion(challenge, nil), e.binding)
		require.Error(t, err)
	}

	tests := []struct {
		name   string
		ctx    func(chain *slog.Logger) context.Context
		opts   func(own *slog.Logger) []passkey.Option
		assert func(t *testing.T, chain, own, def string)
	}{
		{
			name: "no option, inside a configured chain",
			ctx:  func(chain *slog.Logger) context.Context { return ctxlog.With(context.Background(), chain) },
			assert: func(t *testing.T, chain, _, def string) {
				assert.Contains(t, chain, logRoutePasskeyMsg)
				assert.Contains(t, chain, logRouteOnetimeMsg, "the one-time manager did not route")
				assert.Empty(t, def)
			},
		},
		{
			name: "own option wins",
			ctx:  func(chain *slog.Logger) context.Context { return ctxlog.With(context.Background(), chain) },
			opts: func(own *slog.Logger) []passkey.Option { return []passkey.Option{passkey.WithLogger(own)} },
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, own, logRoutePasskeyMsg)
				assert.Contains(t, own, logRouteOnetimeMsg)
				assert.Empty(t, chain)
				assert.Empty(t, def)
			},
		},
		{
			name: "no chain",
			ctx:  func(*slog.Logger) context.Context { return context.Background() },
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, def, logRoutePasskeyMsg)
				assert.Contains(t, def, logRouteOnetimeMsg)
				assert.Empty(t, chain)
				assert.Empty(t, own)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chainBuf, ownBuf, defBuf := &logBuffer{}, &logBuffer{}, &logBuffer{}

			prev := slog.Default()
			slog.SetDefault(defBuf.logger())
			t.Cleanup(func() { slog.SetDefault(prev) })

			var opts []passkey.Option
			if tt.opts != nil {
				opts = tt.opts(ownBuf.logger())
			}

			run(t, tt.ctx(chainBuf.logger()), opts...)

			tt.assert(t, chainBuf.String(), ownBuf.String(), defBuf.String())
		})
	}

	t.Run("nil option", func(t *testing.T) {
		f := newFixture(t)

		_, err := passkey.New(f.deps, passkey.WithRepudiationContact("help@example.com"), passkey.WithLogger(nil))

		require.ErrorIs(t, err, passkey.ErrConfig)
		assert.ErrorContains(t, err, "WithLogger")
	})

	// The recovery kind a manager reports reports to that manager's logger.
	t.Run("recovery kind uses the manager's logger", func(t *testing.T) {
		own := &logBuffer{}
		def := &logBuffer{}

		prev := slog.Default()
		slog.SetDefault(def.logger())
		t.Cleanup(func() { slog.SetDefault(prev) })

		f := newFixture(t)
		f.deps.Credentials = deleteCycles{passkey.NewMemoryCredentialStore()}
		m := f.manager(t, passkey.WithLogger(own.logger()))

		cid := must.Must(id.NewV7Generator().NewID())
		err := m.RecoveryKind().Remove(t.Context(), "u-1",
			[]recovery.AuthenticatorRef{{Kind: passkey.RecoveryKindName, ID: cid.String()}})

		require.Error(t, err)
		assert.NotEmpty(t, own.String(), "the abort record did not reach the manager's logger")
		assert.Empty(t, def.String())
	})

	// The sampler's summary has no request of its own: it goes to the chain
	// whose record the sampler last held back, not to slog.Default().
	t.Run("suppressed summary follows the chain", func(t *testing.T) {
		chain := &logBuffer{}
		def := &logBuffer{}

		prev := slog.Default()
		slog.SetDefault(def.logger())
		t.Cleanup(func() { slog.SetDefault(prev) })

		e := newLoginEnv(t, nil)
		e.m = e.f.manager(t)
		ctx := ctxlog.With(t.Context(), chain.logger())

		for range 3 {
			_, err := e.m.Authenticate(ctx,
				assertion(e.begin(t), func(b *assertionBody) { b.ID = "unknown-key" }), e.binding)
			require.Error(t, err)
		}

		require.NoError(t, e.m.FlushRefusalLogs())

		assert.Contains(t, chain.String(), "passkey: records suppressed")
		assert.Empty(t, def.String())
	})
}
