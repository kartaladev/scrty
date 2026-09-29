package onetime_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/onetime"
)

// errRateLimited stands for a caller's own refusal: a reason the holder can fix
// and come back from, which is exactly why it must not cost them their token.
var errRateLimited = errors.New("too many attempts, try again later")

func TestConsume(t *testing.T) {
	t.Parallel()

	t.Run("a checked token is spent, and spending it again is refused", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, store := newManager(t, clk)

		presented, tok, err := m.Issue(t.Context(), "ada@example.com")
		require.NoError(t, err)

		clk.Advance(time.Minute)
		first, err := m.Check(t.Context(), presented, "")
		require.NoError(t, err)
		require.NoError(t, m.Consume(t.Context(), first))

		spentAt := issuedAt.Add(time.Minute)
		stored, err := store.FindByID(t.Context(), tok.ID)
		require.NoError(t, err)
		assert.Equal(t, spentAt, stored.ConsumedAt)

		// A holder who kept the proof of an earlier check cannot spend the
		// token twice with it: consumption is decided in the store, not by
		// what the caller is holding.
		clk.Advance(time.Minute)
		err = m.Consume(t.Context(), first)
		require.ErrorIs(t, err, onetime.ErrInvalidToken)

		stored, err = store.FindByID(t.Context(), tok.ID)
		require.NoError(t, err)
		assert.Equal(t, spentAt, stored.ConsumedAt,
			"the second attempt moved the recorded consumption time")
	})

	t.Run("a Checked a caller declared for themselves names no record and is refused", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		// No EXPECT: an empty proof must be refused without a store round trip.
		store := NewMockStore(ctrl)

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, err := onetime.NewManager("magic-link",
			onetime.WithStore(store), onetime.WithClock(clk))
		require.NoError(t, err)

		require.ErrorIs(t, m.Consume(t.Context(), onetime.Checked{}), onetime.ErrInvalidToken)
	})

	t.Run("a store that cannot mark the token consumed is refused, not reported", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt.Add(time.Minute))
		ctrl := gomock.NewController(t)
		rec := liveRecord(t)

		store := NewMockStore(ctrl)
		store.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(&rec, nil)
		store.EXPECT().Consume(gomock.Any(), checkTokenID, gomock.Any()).Return(errStoreDown)

		var logs bytes.Buffer
		m, err := onetime.NewManager("magic-link",
			onetime.WithStore(store), onetime.WithClock(clk),
			onetime.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
		require.NoError(t, err)

		c, err := m.Check(t.Context(), checkTokenID.String()+"."+checkSecret, "")
		require.NoError(t, err)

		err = m.Consume(t.Context(), c)
		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.NotErrorIs(t, err, errStoreDown,
			"the store's own failure reached the caller, who can now tell an outage from a spent token")
		assert.Contains(t, logs.String(), "level=ERROR", "a store outage passed unreported")
	})
}

// TestCheckedCannotBeConstructedOutsideThePackage pins the one thing that makes
// check-then-consume a rule the compiler keeps rather than one a caller has to
// remember. Every field of Checked is unexported and nothing but Check returns
// one, so there is no spelling of "spend this token" that skips the check.
func TestCheckedCannotBeConstructedOutsideThePackage(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(onetime.Checked{})
	require.Positive(t, typ.NumField(),
		"Checked carries nothing, so it proves nothing about what was checked")

	for i := range typ.NumField() {
		field := typ.Field(i)
		assert.False(t, field.IsExported(),
			"Checked.%s is exported, so a caller can build one and consume without checking", field.Name)
	}
}

func TestRedeem(t *testing.T) {
	t.Parallel()

	t.Run("a valid token is checked, the caller's checks run in order, and it is spent once", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, store := newManager(t, clk)

		presented, tok, err := m.Issue(t.Context(), "ada@example.com")
		require.NoError(t, err)

		clk.Advance(time.Minute)

		var order []string
		redeemed, err := m.Redeem(t.Context(), presented, "",
			func(_ context.Context, got onetime.Token) error {
				order = append(order, "first")
				assert.Equal(t, tok.ID, got.ID, "the caller's check was handed another token")
				assert.Equal(t, "ada@example.com", got.Subject)

				return nil
			},
			nil, // a nil check is skipped rather than panicked on
			func(context.Context, onetime.Token) error {
				order = append(order, "second")

				return nil
			},
		)
		require.NoError(t, err)

		assert.Equal(t, []string{"first", "second"}, order)
		assert.Equal(t, tok.ID, redeemed.ID)
		assert.Equal(t, "ada@example.com", redeemed.Subject)
		assert.Equal(t, issuedAt.Add(time.Minute), redeemed.ConsumedAt,
			"the record handed back does not say when it was spent")

		_, err = m.Redeem(t.Context(), presented, "")
		require.ErrorIs(t, err, onetime.ErrInvalidToken, "the token was spent twice")

		assert.Equal(t, 1, store.Len())
	})

	t.Run("a caller check error is returned unchanged and spends nothing", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, store := newManager(t, clk)

		presented, tok, err := m.Issue(t.Context(), "ada@example.com")
		require.NoError(t, err)

		clk.Advance(time.Minute)

		refused, err := m.Redeem(t.Context(), presented, "",
			func(context.Context, onetime.Token) error { return errRateLimited })
		require.ErrorIs(t, err, errRateLimited, "the caller's reason was replaced")
		assert.NotErrorIs(t, err, onetime.ErrInvalidToken,
			"a refusal the holder can come back from was reported as a bad token")
		assert.Zero(t, refused)

		stored, err := store.FindByID(t.Context(), tok.ID)
		require.NoError(t, err)
		assert.True(t, stored.ConsumedAt.IsZero(), "a refused redemption marked the token consumed")

		// The whole point: the holder fixes the problem and still has a token.
		clk.Advance(time.Minute)
		redeemed, err := m.Redeem(t.Context(), presented, "")
		require.NoError(t, err, "a refusal spent the token")
		assert.Equal(t, tok.ID, redeemed.ID)
	})

	t.Run("the first refusing check stops the rest, and none of them spends the token", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, _ := newManager(t, clk)

		presented, _, err := m.Issue(t.Context(), "ada@example.com")
		require.NoError(t, err)

		clk.Advance(time.Minute)

		var reached bool
		_, err = m.Redeem(t.Context(), presented, "",
			func(context.Context, onetime.Token) error { return errRateLimited },
			func(context.Context, onetime.Token) error {
				reached = true

				return nil
			},
		)
		require.ErrorIs(t, err, errRateLimited)
		assert.False(t, reached, "a check after the refusal still ran")

		clk.Advance(time.Minute)
		_, err = m.Redeem(t.Context(), presented, "")
		require.NoError(t, err, "a refusal spent the token")
	})

	t.Run("a refused check never runs when the token itself is bad", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, _ := newManager(t, clk)

		var reached bool
		_, err := m.Redeem(t.Context(), "not-a-token", "",
			func(context.Context, onetime.Token) error {
				reached = true

				return nil
			})
		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.False(t, reached, "the caller's check was handed a token that had not passed a check")
	})

	t.Run("a consumption failure is a refusal and no subject", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt.Add(time.Minute))
		ctrl := gomock.NewController(t)
		rec := liveRecord(t)

		store := NewMockStore(ctrl)
		store.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(&rec, nil)
		store.EXPECT().Consume(gomock.Any(), checkTokenID, gomock.Any()).Return(errStoreDown)

		var logs bytes.Buffer
		m, err := onetime.NewManager("magic-link",
			onetime.WithStore(store), onetime.WithClock(clk),
			onetime.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
		require.NoError(t, err)

		tok, err := m.Redeem(t.Context(), checkTokenID.String()+"."+checkSecret, "")
		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.Zero(t, tok, "a redemption that did not happen handed back a subject")
		assert.Contains(t, logs.String(), "level=ERROR")
		assert.NotContains(t, logs.String(), checkSecret, "the log carried the presented secret")
	})
}

// TestExactlyOneOfManyRacingRedemptionsSpendsTheToken is the reason Consume is
// a compare-and-set in the store rather than a read followed by a write here.
func TestExactlyOneOfManyRacingRedemptionsSpendsTheToken(t *testing.T) {
	t.Parallel()

	const redeemers = 50

	clk := clockwork.NewFakeClockAt(issuedAt)
	m, store := newManager(t, clk)

	presented, tok, err := m.Issue(t.Context(), "ada@example.com")
	require.NoError(t, err)

	clk.Advance(time.Minute)

	var (
		succeeded atomic.Int64
		refused   atomic.Int64
		start     sync.WaitGroup
		done      sync.WaitGroup
	)
	start.Add(1)

	for range redeemers {
		done.Add(1)
		go func() {
			defer done.Done()

			start.Wait()
			if _, err := m.Redeem(t.Context(), presented, ""); err == nil {
				succeeded.Add(1)

				return
			}
			refused.Add(1)
		}()
	}

	start.Done()
	done.Wait()

	assert.Equal(t, int64(1), succeeded.Load(), "the token was spent more than once")
	assert.Equal(t, int64(redeemers-1), refused.Load())

	stored, err := store.FindByID(t.Context(), tok.ID)
	require.NoError(t, err)
	assert.Equal(t, issuedAt.Add(time.Minute), stored.ConsumedAt)
}
