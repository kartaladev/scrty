package httpsec_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/policy"
)

// errMagicLinkCheckRefused is what a consumer's own refusal check refuses with.
var errMagicLinkCheckRefused = errors.New("magiclink_test: terms not accepted")

// countingRedeemer forwards to the real redemption and counts how often it was
// reached, which is how a test pins that a throttled source never gets that
// far.
type countingRedeemer struct {
	inner httpsec.Redeemer
	calls atomic.Int64
}

func (r *countingRedeemer) Redeem(
	ctx context.Context,
	token, nonce string,
	checks ...magiclink.Check,
) (magiclink.Redemption, error) {
	r.calls.Add(1)

	return r.inner.Redeem(ctx, token, nonce, checks...)
}

// switchable is a policy a test turns from denying to allowing, standing in for
// the user who goes and does whatever the policy wanted.
type switchable struct {
	allow atomic.Bool
}

func (s *switchable) engine(t *testing.T) *policy.Engine {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("magiclink_test: switchable").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, *policy.Input) policy.Decision {
			if s.allow.Load() {
				return policy.Decision{Outcome: policy.Allow}
			}

			return policy.Decision{Outcome: policy.Deny, Reason: errMagicLinkDenied}
		})

	return engineOf(t, p)
}

// TestMagicLinkSourceAccounting pins that refused redemptions of a valid link
// cost the source its allowance. Without that, one link the policy refuses is
// an unlimited supply of store reads and policy evaluations for as long as it
// lives.
func TestMagicLinkSourceAccounting(t *testing.T) {
	t.Parallel()

	t.Run("ten policy-denied redemptions throttle the eleventh", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		counting := &countingRedeemer{inner: h.manager}
		h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkRedeemer(counting))
		h.engine = denyingEngine(t, errMagicLinkDenied)

		c := h.chain(t)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
				errMagicLinkDenied)
		}

		out := h.redeemFrom(t, c, magicLinkSource, token, nonce)
		assert.ErrorIs(t, out.err, magiclink.ErrInvalidLink,
			"a throttled source is refused with the uniform error")
		assert.Equal(t, int64(10), counting.calls.Load(),
			"and the eleventh never reaches the redeemer")
	})

	t.Run("an unattributable source is refused without redeeming", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		counting := &countingRedeemer{inner: h.manager}
		h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkRedeemer(counting))

		out := h.redeemFrom(t, h.chain(t), "", token, nonce)

		assert.ErrorIs(t, out.err, magiclink.ErrInvalidLink)
		assert.Zero(t, counting.calls.Load(),
			"an address that names no single client keys no bucket, so it is refused outright")
	})

	t.Run("another source is unaffected", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		c := h.chain(t)

		token, nonce := h.link(t, c)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, "wrong-token", nonce).err,
				magiclink.ErrInvalidLink)
		}

		require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
			magiclink.ErrInvalidLink, "the guessing source is throttled")

		require.NoError(t, h.redeemFrom(t, c, "198.51.100.4", token, nonce).err,
			"a source that guessed at nothing still redeems")
		assert.Equal(t, 1, h.activeSessions(t))
	})
}

// TestMagicLinkCountRefusalsOptOut pins what the opt-out exempts, and — more
// importantly — what it does not.
func TestMagicLinkCountRefusalsOptOut(t *testing.T) {
	t.Parallel()

	t.Run("policy refusals stop counting", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		gate := &switchable{}
		h.engine = gate.engine(t)
		h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkCountRefusals(false))

		c := h.chain(t)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
				errMagicLinkDenied)
		}

		gate.allow.Store(true)

		require.NoError(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
			"the source was never counted, so it is not throttled")
	})

	t.Run("consumer check refusals stop counting too", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		var accepted atomic.Bool

		h.linkOpts = append(h.linkOpts,
			httpsec.WithMagicLinkCountRefusals(false),
			httpsec.WithMagicLinkChecks(
				func(context.Context, identity.Principal, time.Time) error {
					if accepted.Load() {
						return nil
					}

					return errMagicLinkCheckRefused
				}))

		c := h.chain(t)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
				errMagicLinkCheckRefused, "the consumer's error reaches them unchanged")
		}

		accepted.Store(true)

		require.NoError(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err)
	})

	t.Run("invalid tokens still count", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkCountRefusals(false))
		c := h.chain(t)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, "wrong-token", nonce).err,
				magiclink.ErrInvalidLink)
		}

		assert.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
			magiclink.ErrInvalidLink, "the source is throttled")
		assert.Zero(t, h.activeSessions(t))
	})

	t.Run("a redeemer that discarded the deny and failed otherwise still counts", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		other := errors.New("magiclink_test: dial tcp: connection refused")

		h.engine = denyingEngine(t, errMagicLinkDenied)
		h.linkOpts = append(h.linkOpts,
			httpsec.WithMagicLinkCountRefusals(false),
			httpsec.WithMagicLinkRedeemer(redeemerFunc(func(
				ctx context.Context,
				_, _ string,
				checks ...magiclink.Check,
			) (magiclink.Redemption, error) {
				for _, check := range checks {
					_ = check(ctx, identity.Principal{ID: magicLinkUserID}, time.Time{})
				}

				return magiclink.Redemption{}, other
			})))

		c := h.chain(t)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err, other)
		}

		assert.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
			magiclink.ErrInvalidLink,
			"the opt-out exempts exactly the refusal the check produced, nothing else")
	})
}

// TestMagicLinkThrottleLogSampling pins that a source hammering the endpoint
// cannot also flood the log, and that what is written carries none of what was
// presented.
func TestMagicLinkThrottleLogSampling(t *testing.T) {
	t.Parallel()

	h := newMagicLinkHarness(t)
	token, nonce := h.link(t, h.chain(t))

	logs := &capturingHandler{}

	c, err := httpsec.New(
		httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableMagicLink(h.manager, h.options()...),
	)
	require.NoError(t, err)

	for range 500 {
		_ = h.redeemFrom(t, c, magicLinkSource, "wrong-token", nonce)
	}

	var throttled int

	for _, r := range logs.records() {
		if r.Message == "httpsec: source throttled" {
			throttled++
		}

		r.Attrs(func(a slog.Attr) bool {
			value := a.Value.String()
			assert.NotContains(t, value, token, "no record carries a presented token")
			assert.NotContains(t, value, nonce, "nor a binding value")
			assert.NotContains(t, value, magicLinkKnown, "nor a submitted address")

			return true
		})

		assert.NotContains(t, r.Message, token)
		assert.NotContains(t, r.Message, magicLinkKnown)
	}

	assert.Equal(t, 1, throttled,
		"one record stands for every refusal in the window")
	assert.NotContains(t, strings.Join(messagesOf(logs.records()), "\n"), nonce)
}

// messagesOf is every message the handler captured, for the assertions that are
// about the stream rather than one record.
func messagesOf(recs []slog.Record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Message)
	}

	return out
}
