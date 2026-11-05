package oidcprovider_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// endingCodes runs before as a code is written.
type endingCodes struct {
	oidcprovider.CodeStore

	before atomic.Pointer[func()]
}

func (c *endingCodes) Create(ctx context.Context, record *oidcprovider.CodeRecord) error {
	if before := c.before.Swap(nil); before != nil {
		(*before)()
	}

	return c.CodeStore.Create(ctx, record)
}

// endingBrowsers runs after once a browser session's use has been recorded.
type endingBrowsers struct {
	oidcprovider.BrowserSessionStore

	after atomic.Pointer[func()]
}

func (b *endingBrowsers) Touch(ctx context.Context, digest []byte, idleExpiresAt time.Time) error {
	err := b.BrowserSessionStore.Touch(ctx, digest, idleExpiresAt)
	if after := b.after.Swap(nil); after != nil {
		(*after)()
	}

	return err
}

// A consent answered from a browser session rests on nothing the chain could read again, so the
// provider holds the line itself: the session is looked at last, once the code is written. An end
// before that look refuses the answer, and an end after it finds the code.
func TestProvider_ResumeConsent_BrowserSessionEndsMeanwhile(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		arm    func(codes *endingCodes, browsers *endingBrowsers, end func())
		assert func(*testing.T, *exchangeFixture, parked, oidcprovider.ResumeResult, error)
	}

	cases := []testCase{
		{
			name: "an end before the code is written: the answer is refused, and nothing is handed out",
			arm:  func(codes *endingCodes, _ *endingBrowsers, end func()) { codes.before.Store(&end) },
			assert: func(t *testing.T, x *exchangeFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()

				require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)
				assert.Equal(t, oidcprovider.ResumeResult{}, res)
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, x.parkFixture, r))
			},
		},
		{
			name: "an end after the last look finds the code, which then makes no grant",
			arm:  func(_ *endingCodes, browsers *endingBrowsers, end func()) { browsers.after.Store(&end) },
			assert: func(t *testing.T, x *exchangeFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()

				require.NoError(t, err)
				code := queryOf(t, res.RedirectTo).Get("code")
				require.NotEmpty(t, code)

				_, exchangeErr := x.p.Token(t.Context(), billingExchange(issuedCode{code: code}, nil))
				assertRefused(t, exchangeErr, oidcprovider.CodeInvalidGrant)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(exchangeFixtureStart)
			codeStore, err := oidcprovider.NewMemoryCodeStore(oidcprovider.WithMemoryStoreClock(clk))
			require.NoError(t, err)
			browserStore, err := oidcprovider.NewMemoryBrowserSessionStore(oidcprovider.WithMemoryStoreClock(clk))
			require.NoError(t, err)

			codes := &endingCodes{CodeStore: codeStore}
			browsers := &endingBrowsers{BrowserSessionStore: browserStore}
			x := newExchangeFixtureOn(t, clk, oidcprovider.WithCodeStore(codes), oidcprovider.WithBrowserSessionStore(browsers))

			signIn := testSignIn(x.parkFixture, "u-1")
			r, _ := atConsent(t, x.parkFixture, nil, signIn)
			held := heldBrowserSession(t, x.parkFixture, signIn)

			tc.arm(codes, browsers, func() {
				_, endErr := x.p.EndSignIn(context.WithoutCancel(t.Context()), oidcprovider.SignInSelector{Family: signIn.Family})
				assert.NoError(t, endErr)
			})

			in := r.input(nil)
			in.BrowserSessionSecret = held
			answerWith(&in, "openid")

			res, err := x.p.Resume(t.Context(), in)
			tc.assert(t, x, r, res, err)
		})
	}
}
