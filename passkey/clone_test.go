package passkey_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/passkey"
)

// countRecords counts the log records whose message is msg.
func countRecords(logs *logBuffer, msg string) int {
	n := 0

	for _, r := range logs.records() {
		if strings.Contains(r, `"msg":"`+msg+`"`) {
			n++
		}
	}

	return n
}

const msgCloneRecord = "passkey: suspected clone"

func TestClone(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []passkey.Option
		seed    func(c *passkey.Credential)
		count   uint32 // the presented counter, over a stored 42 unless seeded
		adjust  func(b *assertionBody)
		sendErr error
		assert  func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error)
	}

	suspendedWithNotice := func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, passkey.ErrCloneSuspected)
		require.ErrorIs(t, err, mfa.ErrAuthenticatorRefused)
		assert.Nil(t, res)

		c := e.stored(t)
		assert.Equal(t, passkey.StateSuspended, c.State)
		assert.Equal(t, uint32(42), c.SignCount)

		msgs := e.f.messages()
		require.Len(t, msgs, 1)
		assert.Equal(t, "ana@example.com", msgs[0].To)
		assert.Contains(t, msgs[0].TextBody, "Security key")
		assert.Contains(t, msgs[0].TextBody, "help@example.com")
		assert.Contains(t, msgs[0].TextBody, "register a new passkey")
		assert.Equal(t, 1, countRecords(e.logs, msgCloneRecord))
	}
	allowed := func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Equal(t, passkey.StateActive, e.stored(t).State)
		assert.Empty(t, e.f.messages())
	}

	var (
		signalMu sync.Mutex
		signals  []passkey.CloneSignal
	)

	adminsOnly := func(_ context.Context, s passkey.CloneSignal) passkey.CloneAction {
		signalMu.Lock()
		signals = append(signals, s)
		signalMu.Unlock()

		if s.User == "admin" {
			return passkey.CloneRefuseSuspend
		}

		return passkey.CloneAllow
	}

	cases := []testCase{
		{
			name:   "a counter going backwards is refused, suspended and notified",
			count:  41,
			assert: suspendedWithNotice,
		},
		{
			name:   "an equal non-zero counter is refused, suspended and notified",
			count:  42,
			assert: suspendedWithNotice,
		},
		{
			name:  "a counter that stays zero is never a clone",
			seed:  func(c *passkey.Credential) { c.SignCount = 0 },
			count: 0,
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				allowed(t, e, res, err)
				assert.Equal(t, regStart, e.stored(t).LastUsedAt)
				assert.Zero(t, countRecords(e.logs, msgCloneRecord))
			},
		},
		{
			name:  "signal only allows the login, keeps the counter and warns",
			opts:  []passkey.Option{passkey.WithCloneResponse(passkey.CloneSignalOnly)},
			count: 41,
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				allowed(t, e, res, err)
				assert.Equal(t, uint32(42), e.stored(t).SignCount)

				out := e.logs.String()
				assert.Equal(t, 1, countRecords(e.logs, msgCloneRecord))
				assert.Contains(t, out, `"level":"WARN"`)
				assert.Contains(t, out, e.cred.ID.String())
			},
		},
		{
			name:  "a consumer policy allowing non-administrators lets the login proceed",
			opts:  []passkey.Option{passkey.WithClonePolicy(adminsOnly)},
			count: 41,
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				allowed(t, e, res, err)

				signalMu.Lock()
				defer signalMu.Unlock()

				require.NotEmpty(t, signals)
				assert.Contains(t, signals, passkey.CloneSignal{
					User: "u-1", Credential: e.cred.ID, Stored: 42, Presented: 41,
				})
			},
		},
		{
			name: "a consumer policy refusing without suspending refuses only",
			opts: []passkey.Option{passkey.WithClonePolicy(func(context.Context, passkey.CloneSignal) passkey.CloneAction {
				return passkey.CloneRefuse
			})},
			count: 41,
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Nil(t, res)
				assert.Equal(t, passkey.StateActive, e.stored(t).State)
				assert.Empty(t, e.f.messages())
			},
		},
		{
			name: "a consumer policy decides over the response",
			opts: []passkey.Option{
				passkey.WithCloneResponse(passkey.CloneSignalOnly),
				passkey.WithClonePolicy(func(context.Context, passkey.CloneSignal) passkey.CloneAction {
					return passkey.CloneRefuseSuspend
				}),
			},
			count:  41,
			assert: suspendedWithNotice,
		},
		{
			name:    "a refused suspension notice leaves the credential suspended",
			count:   41,
			sendErr: errors.New("queue full"),
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Nil(t, res)
				assert.Equal(t, passkey.StateSuspended, e.stored(t).State)
				assert.Equal(t, 1, countRecords(e.logs, "passkey: a notice was not queued"))
			},
		},
		{
			name:   "a changed backup-eligible flag is refused as authentication failed",
			count:  43,
			adjust: func(b *assertionBody) { b.BE = true },
			assert: func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, res)

				c := e.stored(t)
				assert.Equal(t, passkey.StateActive, c.State)
				assert.Equal(t, uint32(42), c.SignCount)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, tc.seed)
			e.f.sendErr = tc.sendErr
			e.manager(t, tc.opts...)

			challenge := e.begin(t)
			body := assertion(challenge, func(b *assertionBody) {
				b.Count = tc.count
				if tc.adjust != nil {
					tc.adjust(b)
				}
			})

			res, err := e.m.Authenticate(t.Context(), body, e.binding)
			tc.assert(t, e, res, err)
		})
	}
}

// TestCloneConcurrentAssertionsWithOneCounter pins the specification's choice:
// two assertions from two tabs, both carrying 43 over a stored 42, give one
// login and one suspected clone, which suspends the credential.
func TestCloneConcurrentAssertionsWithOneCounter(t *testing.T) {
	t.Parallel()

	e := newLoginEnv(t, nil)
	e.manager(t)

	type attempt struct {
		binding string
		body    []byte
	}

	attempts := make([]attempt, 2)
	for i := range attempts {
		e.binding = []string{"tab-1", "tab-2"}[i]
		attempts[i] = attempt{binding: e.binding, body: assertion(e.begin(t), nil)}
	}

	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make([]error, len(attempts))
	)

	for i, a := range attempts {
		wg.Go(func() {
			<-start
			_, errs[i] = e.m.Authenticate(t.Context(), a.body, a.binding)
		})
	}

	close(start)
	wg.Wait()

	var ok, clone int

	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, passkey.ErrCloneSuspected):
			clone++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}

	assert.Equal(t, 1, ok, "exactly one login")
	assert.Equal(t, 1, clone, "exactly one suspected clone")
	assert.Equal(t, passkey.StateSuspended, e.stored(t).State)
	assert.Equal(t, uint32(43), e.stored(t).SignCount)
}
