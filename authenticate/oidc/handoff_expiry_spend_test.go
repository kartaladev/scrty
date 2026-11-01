package oidc_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/mock/gomock"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
)

// A code whose expiry is reached while a caller's check runs is refused at the
// spend and left unconsumed, including when the check ends exactly at the
// expiry instant.
func TestHandoff_RedeemRefusesCodeExpiredDuringChecks(t *testing.T) {
	tests := map[string]struct {
		checkTakes time.Duration
		assert     func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error)
	}{
		"check ends after the expiry": {
			checkTakes: 2 * time.Second,
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				assert.False(t, f.consumed(t), "an expired code must not be spent")
			},
		},
		"check ends exactly at the expiry instant": {
			checkTakes: time.Second,
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				assert.False(t, f.consumed(t), "a code is refused at its expiry instant")
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newHandoffRedeemFixture(t, nil)
			f.clock.Advance(handoffT0.Add(59 * time.Second).Sub(f.clock.Now()))
			f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)

			res, err := f.m.Redeem(t.Context(), f.code, func(context.Context, oidc.RedeemCandidate) error {
				f.clock.Advance(tc.checkTakes)
				return nil
			})

			tc.assert(t, f, res, err)
		})
	}
}
