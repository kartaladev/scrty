package mfa_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
)

// failAfterReader serves n bytes from the secure source, then fails. Beginning
// an enrolment reads the 20-byte secret, so n = 20 lets a begin succeed and
// makes drawing the emailed code the read that fails.
type failAfterReader struct {
	mu sync.Mutex
	n  int
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.n <= 0 {
		return 0, errors.New("entropy pool exhausted")
	}

	p = p[:min(len(p), r.n)]
	r.n -= len(p)

	return rand.Read(p)
}

// scriptedReader serves a 20-byte enrolment secret, then the bytes a case
// scripts, so a test fixes what rand.Int draws for the emailed code.
type scriptedReader struct {
	mu   sync.Mutex
	data []byte
}

func newScriptedReader(draw ...byte) *scriptedReader {
	return &scriptedReader{data: append(bytes.Repeat([]byte{0xA5}, 20), draw...)}
}

func (r *scriptedReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.data) == 0 {
		return 0, io.EOF
	}

	n := copy(p, r.data)
	r.data = r.data[n:]

	return n, nil
}

// spyStore records the order of the calls that decide an emailed code's
// redemption, so a test can pin charge → read → complete.
type spyStore struct {
	*mfa.MemoryEnrolmentStore

	mu    sync.Mutex
	calls []string

	// afterGet, when set, runs once right after the next Get has read, so a
	// test can land a write between a caller's read and its own write.
	afterGet func()

	// hideExhausted makes Get report a code whose attempts have run out as
	// absent, as a store that clears it on exhaustion would.
	hideExhausted bool

	// hideProof makes Get also report the device proof of an exhausted code as
	// absent, as a store that cleared it would.
	hideProof bool
}

func (s *spyStore) armAfterGet(hook func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.afterGet = hook
}

func (s *spyStore) hideExhaustedCodes() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.hideExhausted = true
}

func (s *spyStore) hideExhaustedProofs() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.hideExhausted, s.hideProof = true, true
}

func (s *spyStore) note(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, name)
}

func (s *spyStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = nil
}

func (s *spyStore) Get(ctx context.Context, user identity.UserID) (mfa.Enrolment, bool, error) {
	s.note("Get")

	e, ok, err := s.MemoryEnrolmentStore.Get(ctx, user)

	s.mu.Lock()
	hook, hide, hideProof := s.afterGet, s.hideExhausted, s.hideProof
	s.afterGet = nil
	s.mu.Unlock()

	if hide && e.EmailCodeAttempts >= mfa.MaxEmailCodeFailures {
		e.EmailCode = nil
		if hideProof {
			e.DeviceProvenAt = time.Time{}
		}
	}

	if hook != nil {
		hook()
	}

	return e, ok, err
}

func (s *spyStore) ChargeEmailCode(
	ctx context.Context, user identity.UserID, gen id.ID, at time.Time,
) (int, bool, error) {
	s.note("ChargeEmailCode")

	return s.MemoryEnrolmentStore.ChargeEmailCode(ctx, user, gen, at)
}

func (s *spyStore) Complete(ctx context.Context, user identity.UserID, gen id.ID, at time.Time) (bool, error) {
	s.note("Complete")

	return s.MemoryEnrolmentStore.Complete(ctx, user, gen, at)
}

// portlessStore implements EnrolmentStore and nothing else, as a store written
// before the enrolment path existed does.
type portlessStore struct{ mfa.EnrolmentStore }

// enrolFixture is one TOTP method over a spy store, with a clock a case moves.
type enrolFixture struct {
	store *spyStore
	m     *mfa.TOTP

	mu  sync.Mutex
	now time.Time
}

func newEnrolFixture(t *testing.T, opts ...mfa.TOTPOption) *enrolFixture {
	t.Helper()

	f := &enrolFixture{
		store: &spyStore{MemoryEnrolmentStore: mfa.NewMemoryEnrolmentStore()},
		now:   time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC),
	}

	m, err := mfa.NewTOTP(f.store, "Example",
		append([]mfa.TOTPOption{mfa.WithClock(f.clock)}, opts...)...)
	require.NoError(t, err)

	f.m = m

	return f
}

func (f *enrolFixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.now
}

func (f *enrolFixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.now = f.now.Add(d)
}

// begin starts an enrolment for u-1 and returns its generation and the code
// the authenticator shows now.
func (f *enrolFixture) begin(t *testing.T) (id.ID, string) {
	t.Helper()

	p, gen, err := f.m.BeginEnrolmentGeneration(t.Context(), "u-1", "alice@example.com")
	require.NoError(t, err)

	return gen, codeForSecret(t, p.Secret, f.clock())
}

// proven begins and proves the device with email confirmation on, returning
// the generation and the emailed code.
func (f *enrolFixture) proven(t *testing.T) (id.ID, string) {
	t.Helper()

	gen, device := f.begin(t)
	emailed, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, true, 10*time.Minute)
	require.NoError(t, err)

	return gen, emailed
}

func (f *enrolFixture) stored(t *testing.T) mfa.Enrolment {
	t.Helper()

	e, ok, err := f.store.MemoryEnrolmentStore.Get(t.Context(), "u-1")
	require.NoError(t, err)
	require.True(t, ok)

	return e
}

func (f *enrolFixture) enrolled(t *testing.T) bool {
	t.Helper()

	ok, err := f.m.Enrolled(t.Context(), "u-1")
	require.NoError(t, err)

	return ok
}

// wrongCode returns a well-formed six-digit code that is not code.
func wrongCode(t *testing.T, code string) string {
	t.Helper()

	n, err := strconv.Atoi(code)
	require.NoError(t, err)

	return strconv.Itoa(100000 + (n+1)%900000)
}

func TestTOTPEnroller(t *testing.T) {
	t.Parallel()

	type outcome struct {
		code     string
		enrolled bool
		e        mfa.Enrolment
		calls    []string
	}

	type testCase struct {
		name   string
		opts   []mfa.TOTPOption
		run    func(t *testing.T, f *enrolFixture) (outcome, error)
		assert func(t *testing.T, f *enrolFixture, got outcome, err error)
	}

	notProven := func(t *testing.T, got outcome) {
		t.Helper()
		assert.True(t, got.e.DeviceProvenAt.IsZero(), "the device must not be proven")
		assert.Nil(t, got.e.EmailCode)
		assert.False(t, got.enrolled)
	}

	// redeem proves a device, presents codes in turn and reports the last
	// presentation's error.
	redeem := func(present func(t *testing.T, emailed string) []string) func(*testing.T, *enrolFixture) (outcome, error) {
		return func(t *testing.T, f *enrolFixture) (outcome, error) {
			gen, emailed := f.proven(t)

			var err error
			for _, c := range present(t, emailed) {
				err = f.m.RedeemEmailCode(t.Context(), "u-1", gen, c)
			}

			return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
		}
	}

	refusedPending := func(attempts int) func(*testing.T, *enrolFixture, outcome, error) {
		return func(t *testing.T, _ *enrolFixture, got outcome, err error) {
			require.ErrorIs(t, err, mfa.ErrEmailCodeInvalid)
			assert.False(t, got.enrolled, "a refused code completes nothing")
			assert.True(t, got.e.ConfirmedAt.IsZero())
			assert.Equal(t, attempts, got.e.EmailCodeAttempts)
		}
	}

	// confirmNow presents the authenticator's next code to the single-call
	// confirm, as a consumer's out-of-band route would.
	confirmNow := func(t *testing.T, f *enrolFixture) error {
		t.Helper()

		e := f.stored(t)
		f.advance(30 * time.Second)

		return f.m.ConfirmEnrolment(t.Context(), "u-1", codeAt(t, e.Secret, f.clock(), 6, 30*time.Second))
	}

	// exhaust spends every attempt on the emailed code with wrong codes.
	exhaust := func(t *testing.T, f *enrolFixture, gen id.ID, emailed string) {
		t.Helper()

		for range mfa.MaxEmailCodeFailures {
			require.ErrorIs(t, f.m.RedeemEmailCode(t.Context(), "u-1", gen, wrongCode(t, emailed)),
				mfa.ErrEmailCodeInvalid)
		}
	}

	// bypass runs a proof with an emailed code, spoils the code with spoil,
	// then tries to confirm without it through finish.
	bypass := func(
		spoil func(t *testing.T, f *enrolFixture, gen id.ID, emailed string),
		finish func(t *testing.T, f *enrolFixture, gen id.ID) error,
	) func(*testing.T, *enrolFixture) (outcome, error) {
		return func(t *testing.T, f *enrolFixture) (outcome, error) {
			gen, emailed := f.proven(t)
			spoil(t, f, gen, emailed)
			err := finish(t, f, gen)

			return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
		}
	}

	complete := func(t *testing.T, f *enrolFixture, gen id.ID) error {
		return f.m.CompleteEnrolment(t.Context(), "u-1", gen)
	}

	confirm := func(t *testing.T, f *enrolFixture, _ id.ID) error { return confirmNow(t, f) }

	expire := func(_ *testing.T, f *enrolFixture, _ id.ID, _ string) { f.advance(11 * time.Minute) }

	hiddenExhaust := func(t *testing.T, f *enrolFixture, gen id.ID, emailed string) {
		f.store.hideExhaustedCodes()
		exhaust(t, f, gen, emailed)
	}

	hiddenProofExhaust := func(t *testing.T, f *enrolFixture, gen id.ID, emailed string) {
		f.store.hideExhaustedProofs()
		exhaust(t, f, gen, emailed)
	}

	stillPending := func(t *testing.T, _ *enrolFixture, got outcome, err error) {
		t.Helper()
		require.ErrorIs(t, err, mfa.ErrInvalidCode)
		assert.False(t, got.enrolled, "only the emailed code completes this enrolment")
		assert.True(t, got.e.ConfirmedAt.IsZero())
	}

	cases := []testCase{
		// ProveDevice
		{
			name: "a valid device code proves the device and returns a six-digit emailed code",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				code, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, true, 10*time.Minute)

				return outcome{code: code, enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, f *enrolFixture, got outcome, err error) {
				require.NoError(t, err)
				assert.Len(t, got.code, 6)
				assert.Regexp(t, `^[0-9]{6}$`, got.code)
				assert.Equal(t, []byte(got.code), got.e.EmailCode, "the emailed code is kept on the enrolment")
				assert.Equal(t, f.clock(), got.e.DeviceProvenAt)
				assert.Equal(t, f.clock().Add(10*time.Minute), got.e.EmailCodeUntil)
				assert.Equal(t, f.clock().Unix()/30, got.e.LastStep, "the proving step is recorded")
				assert.False(t, got.enrolled, "a proven device is not an enrolment")
			},
		},
		{
			name: "email confirmation off proves the device and returns no code",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				code, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, false, 0)

				return outcome{code: code, enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, f *enrolFixture, got outcome, err error) {
				require.NoError(t, err)
				assert.Empty(t, got.code)
				assert.Equal(t, f.clock(), got.e.DeviceProvenAt)
				assert.Nil(t, got.e.EmailCode)
				assert.False(t, got.enrolled)
			},
		},
		{
			name: "a wrong device code is refused and proves nothing",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				code, err := f.m.ProveDevice(t.Context(), "u-1", gen, wrongCode(t, device), true, 10*time.Minute)

				return outcome{code: code, enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Empty(t, got.code)
				notProven(t, got)
			},
		},
		{
			name: "a device code on a replaced generation is refused",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				old, _ := f.begin(t)
				_, device := f.begin(t)
				code, err := f.m.ProveDevice(t.Context(), "u-1", old, device, true, 10*time.Minute)

				return outcome{code: code, enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Empty(t, got.code)
				notProven(t, got)
			},
		},
		{
			name: "a device already proven is not proven again",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				_, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, true, 10*time.Minute)
				require.NoError(t, err)
				first := f.stored(t)

				f.advance(30 * time.Second)
				code, err := f.m.ProveDevice(t.Context(), "u-1", gen,
					codeAt(t, first.Secret, f.clock(), 6, 30*time.Second), true, 10*time.Minute)

				return outcome{code: code, enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Empty(t, got.code)
			},
		},
		{
			name: "a random-source failure while drawing the emailed code proves nothing",
			opts: []mfa.TOTPOption{mfa.WithRandom(&failAfterReader{n: 20})},
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				code, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, true, 10*time.Minute)

				return outcome{code: code, enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, mfa.ErrInvalidCode, "an outage is not a wrong code")
				assert.Empty(t, got.code)
				notProven(t, got)
			},
		},
		{
			name: "an emailed code with no lifetime is refused before anything is written",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				code, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, true, 0)

				return outcome{code: code, enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, mfa.ErrInvalidCode)
				notProven(t, got)
			},
		},

		{
			// rand.Int over 10^6 reads three bytes and keeps the low 20 bits:
			// 0x00002A is a draw of 42.
			name: "a small draw is zero-padded to six digits",
			opts: []mfa.TOTPOption{mfa.WithRandom(newScriptedReader(0x00, 0x00, 0x2A))},
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				code, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, true, 10*time.Minute)

				return outcome{code: code}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.NoError(t, err)
				assert.Equal(t, "000042", got.code)
			},
		},
		{
			// 0x0F423F is 999999, the top of the range.
			name: "the top draw is the largest six-digit code",
			opts: []mfa.TOTPOption{mfa.WithRandom(newScriptedReader(0x0F, 0x42, 0x3F))},
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				code, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, true, 10*time.Minute)

				return outcome{code: code}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.NoError(t, err)
				assert.Equal(t, "999999", got.code)
			},
		},

		// CompleteEnrolment
		{
			name: "completion after a proof confirms the enrolment",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				_, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, false, 0)
				require.NoError(t, err)

				err = f.m.CompleteEnrolment(t.Context(), "u-1", gen)

				return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, f *enrolFixture, got outcome, err error) {
				require.NoError(t, err)
				assert.True(t, got.enrolled)
				assert.Equal(t, f.clock(), got.e.ConfirmedAt)
			},
		},
		{
			name: "completion before a proof is refused and the enrolment stays pending",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, _ := f.begin(t)
				err := f.m.CompleteEnrolment(t.Context(), "u-1", gen)

				return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.False(t, got.enrolled)
			},
		},
		{
			name: "completion while an emailed code is outstanding is refused and writes nothing",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, _ := f.proven(t)
				before := f.stored(t)
				err := f.m.CompleteEnrolment(t.Context(), "u-1", gen)

				return outcome{code: string(before.EmailCode), enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.False(t, got.enrolled, "only the emailed code completes this enrolment")
				assert.True(t, got.e.ConfirmedAt.IsZero())
				assert.Equal(t, []byte(got.code), got.e.EmailCode, "the emailed code stays outstanding")
			},
		},
		{
			name: "the single-call confirm is refused while an emailed code is outstanding",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				_, emailed := f.proven(t)
				e := f.stored(t)

				f.advance(30 * time.Second)
				err := f.m.ConfirmEnrolment(t.Context(), "u-1", codeAt(t, e.Secret, f.clock(), 6, 30*time.Second))

				return outcome{code: emailed, enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.False(t, got.enrolled, "only the emailed code completes this enrolment")
				assert.True(t, got.e.ConfirmedAt.IsZero())
				assert.Equal(t, []byte(got.code), got.e.EmailCode, "the emailed code stays outstanding")
			},
		},
		{
			name:   "completion is refused once the emailed code has expired",
			run:    bypass(expire, complete),
			assert: stillPending,
		},
		{
			name:   "the single-call confirm is refused once the emailed code has expired",
			run:    bypass(expire, confirm),
			assert: stillPending,
		},
		{
			name:   "completion is refused once the emailed code is out of attempts",
			run:    bypass(exhaust, complete),
			assert: stillPending,
		},
		{
			name:   "the single-call confirm is refused once the emailed code is out of attempts",
			run:    bypass(exhaust, confirm),
			assert: stillPending,
		},
		{
			name:   "completion is refused when the store reports an exhausted code as absent",
			run:    bypass(hiddenExhaust, complete),
			assert: stillPending,
		},
		{
			name:   "the single-call confirm is refused when the store reports an exhausted code as absent",
			run:    bypass(hiddenExhaust, confirm),
			assert: stillPending,
		},
		{
			// The record that a proof issued a code is its expiry, not the proof
			// time, so the confirm holds even if a store dropped the proof.
			name:   "the single-call confirm is refused when the store reports an exhausted proof as absent",
			run:    bypass(hiddenProofExhaust, confirm),
			assert: stillPending,
		},
		{
			name: "completion is refused when a proof with an emailed code lands between its read and its write",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				f.store.armAfterGet(func() {
					_, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, true, 10*time.Minute)
					require.NoError(t, err)
				})

				err := f.m.CompleteEnrolment(t.Context(), "u-1", gen)

				return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, f *enrolFixture, got outcome, err error) {
				stillPending(t, f, got, err)
				assert.NotNil(t, got.e.EmailCode, "the proof landed and its code is outstanding")
			},
		},
		{
			name: "the single-call confirm is refused on a device proven without email confirmation",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				_, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, false, 0)
				require.NoError(t, err)

				err = confirmNow(t, f)

				return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, f *enrolFixture, got outcome, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.False(t, got.enrolled, "a path-proven device completes only through the path")
				assert.True(t, got.e.ConfirmedAt.IsZero())

				require.NoError(t, f.m.CompleteEnrolment(t.Context(), "u-1", got.e.Generation),
					"the path still completes it")
				assert.True(t, f.enrolled(t))
			},
		},
		{
			name: "the proving code cannot then verify",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				_, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, false, 0)
				require.NoError(t, err)
				require.NoError(t, f.m.CompleteEnrolment(t.Context(), "u-1", gen))

				return outcome{enrolled: f.enrolled(t)}, f.m.Verify(t.Context(), "u-1", device)
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				assert.True(t, got.enrolled)
				require.ErrorIs(t, err, mfa.ErrInvalidCode, "a device-proving code is spent")
			},
		},

		// RedeemEmailCode
		{
			name: "the emailed code completes the enrolment and is cleared",
			run:  redeem(func(_ *testing.T, emailed string) []string { return []string{emailed} }),
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.NoError(t, err)
				assert.True(t, got.enrolled)
				assert.Nil(t, got.e.EmailCode)
			},
		},
		{
			name: "redemption charges, reads, then completes last",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, emailed := f.proven(t)
				f.store.reset()
				err := f.m.RedeemEmailCode(t.Context(), "u-1", gen, emailed)

				return outcome{calls: f.store.calls}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"ChargeEmailCode", "Get", "Complete"}, got.calls)
			},
		},
		{
			name: "a wrong emailed code is refused and charged",
			run: redeem(func(t *testing.T, emailed string) []string {
				return []string{wrongCode(t, emailed)}
			}),
			assert: refusedPending(1),
		},
		{
			name: "a wrong emailed code never reaches completion",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, emailed := f.proven(t)
				f.store.reset()
				err := f.m.RedeemEmailCode(t.Context(), "u-1", gen, wrongCode(t, emailed))

				return outcome{calls: f.store.calls}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.ErrorIs(t, err, mfa.ErrEmailCodeInvalid)
				assert.Equal(t, []string{"ChargeEmailCode", "Get"}, got.calls)
			},
		},
		{
			name: "four wrong codes and then the right one completes",
			run: redeem(func(t *testing.T, emailed string) []string {
				w := wrongCode(t, emailed)

				return []string{w, w, w, w, emailed}
			}),
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.NoError(t, err)
				assert.True(t, got.enrolled)
			},
		},
		{
			name: "five wrong codes and then the right one is refused",
			run: redeem(func(t *testing.T, emailed string) []string {
				w := wrongCode(t, emailed)

				return []string{w, w, w, w, w, emailed}
			}),
			assert: refusedPending(5),
		},
		{
			name: "the emailed code is accepted just inside its lifetime",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, emailed := f.proven(t)
				f.advance(10*time.Minute - time.Second)
				err := f.m.RedeemEmailCode(t.Context(), "u-1", gen, emailed)

				return outcome{enrolled: f.enrolled(t)}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.NoError(t, err)
				assert.True(t, got.enrolled)
			},
		},
		{
			name: "the emailed code is refused after its lifetime",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, emailed := f.proven(t)
				f.advance(11 * time.Minute)
				err := f.m.RedeemEmailCode(t.Context(), "u-1", gen, emailed)

				return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: refusedPending(0),
		},
		{
			name: "the current code presented on an older generation completes nothing",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				older, _ := f.proven(t)
				f.advance(30 * time.Second)
				_, current := f.proven(t)
				err := f.m.RedeemEmailCode(t.Context(), "u-1", older, current)

				return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: refusedPending(0),
		},
		{
			name: "a code with a leading space is charged and refused",
			run: redeem(func(_ *testing.T, emailed string) []string {
				return []string{" " + emailed[1:]}
			}),
			assert: refusedPending(1),
		},
		{
			name: "a code padded with a space is charged and refused, never trimmed",
			run: redeem(func(_ *testing.T, emailed string) []string {
				return []string{" " + emailed}
			}),
			assert: refusedPending(1),
		},
		{
			name: "a five-digit code is charged and refused",
			run: redeem(func(_ *testing.T, emailed string) []string {
				return []string{emailed[:5]}
			}),
			assert: refusedPending(1),
		},
		{
			name: "a seven-digit code is charged and refused",
			run: redeem(func(_ *testing.T, emailed string) []string {
				return []string{emailed + "0"}
			}),
			assert: refusedPending(1),
		},
		{
			name: "non-ASCII digits are charged and refused",
			run: redeem(func(_ *testing.T, _ string) []string {
				return []string{"١٢٣٤٥٦"}
			}),
			assert: refusedPending(1),
		},
		{
			name: "no emailed code outstanding is refused",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				_, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, false, 0)
				require.NoError(t, err)

				err = f.m.RedeemEmailCode(t.Context(), "u-1", gen, "123456")

				return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: refusedPending(0),
		},

		// VoidEmailCode
		{
			name: "voiding charges every attempt the emailed code has left, and it then completes nothing",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, emailed := f.proven(t)
				require.NoError(t, mfa.VoidEmailCode(t.Context(), f.m, "u-1", gen))

				err := f.m.RedeemEmailCode(t.Context(), "u-1", gen, emailed)

				return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: refusedPending(mfa.MaxEmailCodeFailures),
		},
		{
			name: "voiding after wrong attempts charges only the attempts left",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, emailed := f.proven(t)
				w := wrongCode(t, emailed)
				require.ErrorIs(t, f.m.RedeemEmailCode(t.Context(), "u-1", gen, w), mfa.ErrEmailCodeInvalid)
				require.ErrorIs(t, f.m.RedeemEmailCode(t.Context(), "u-1", gen, w), mfa.ErrEmailCodeInvalid)
				require.NoError(t, mfa.VoidEmailCode(t.Context(), f.m, "u-1", gen))

				err := f.m.RedeemEmailCode(t.Context(), "u-1", gen, emailed)

				return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: refusedPending(mfa.MaxEmailCodeFailures),
		},
		{
			name: "voiding where no emailed code is outstanding changes nothing and is not an error",
			run: func(t *testing.T, f *enrolFixture) (outcome, error) {
				gen, device := f.begin(t)
				_, err := f.m.ProveDevice(t.Context(), "u-1", gen, device, false, 0)
				require.NoError(t, err)

				err = mfa.VoidEmailCode(t.Context(), f.m, "u-1", gen)

				return outcome{enrolled: f.enrolled(t), e: f.stored(t)}, err
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.NoError(t, err)
				assert.False(t, got.enrolled)
				assert.Zero(t, got.e.EmailCodeAttempts)
				assert.False(t, got.e.DeviceProvenAt.IsZero(), "the proof stands")
			},
		},

		// SupportsEnrolmentPath
		{
			name: "a store with the device-proof port supports the path",
			run: func(_ *testing.T, f *enrolFixture) (outcome, error) {
				return outcome{enrolled: f.m.SupportsEnrolmentPath()}, nil
			},
			assert: func(t *testing.T, _ *enrolFixture, got outcome, err error) {
				require.NoError(t, err)
				assert.True(t, got.enrolled, "supported")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEnrolFixture(t, tc.opts...)
			got, err := tc.run(t, f)
			tc.assert(t, f, got, err)
		})
	}
}

// A store written against EnrolmentStore alone cannot serve the enrolment
// path; the method says so, and every path operation refuses rather than
// panics or pretends.
func TestTOTPEnrollerWithoutDeviceProofPort(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC)
	store := portlessStore{mfa.NewMemoryEnrolmentStore()}
	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(func() time.Time { return now }))
	require.NoError(t, err)

	assert.False(t, m.SupportsEnrolmentPath())

	p, gen, err := m.BeginEnrolmentGeneration(t.Context(), "u-1", "alice@example.com")
	require.NoError(t, err, "begin needs only EnrolmentStore")

	device := codeForSecret(t, p.Secret, now)

	_, err = m.ProveDevice(t.Context(), "u-1", gen, device, true, 10*time.Minute)
	require.Error(t, err)
	assert.NotErrorIs(t, err, mfa.ErrInvalidCode, "a wiring gap is not a wrong code")

	require.Error(t, m.CompleteEnrolment(t.Context(), "u-1", gen))
	require.Error(t, m.RedeemEmailCode(t.Context(), "u-1", gen, "123456"))

	enrolled, err := m.Enrolled(t.Context(), "u-1")
	require.NoError(t, err)
	assert.False(t, enrolled)
}

// TestTOTPEnrollerLogs runs a begin, a device proof and a refused emailed code,
// and finds none of the secret, the provisioning URI, the device code or the
// emailed code in any record.
func TestTOTPEnrollerLogs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	now := time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC)
	logger := slog.New(slog.NewTextHandler(&lockedWriter{w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example",
		mfa.WithClock(func() time.Time { return now }), mfa.WithTOTPLogger(logger))
	require.NoError(t, err)

	p, gen, err := m.BeginEnrolmentGeneration(t.Context(), "u-1", "alice@example.com")
	require.NoError(t, err)

	device := codeForSecret(t, p.Secret, now)
	emailed, err := m.ProveDevice(t.Context(), "u-1", gen, device, true, 10*time.Minute)
	require.NoError(t, err)

	wrong := wrongCode(t, emailed)
	require.ErrorIs(t, m.RedeemEmailCode(t.Context(), "u-1", gen, wrong), mfa.ErrEmailCodeInvalid)

	logs := buf.String()
	require.Contains(t, logs, "u-1", "the records were written")

	for name, secret := range map[string]string{
		"secret": p.Secret, "provisioning URI": p.URI, "device code": device,
		"emailed code": emailed, "presented code": wrong, "label": "alice@example.com",
	} {
		assert.NotContains(t, logs, secret, "a record carries the %s", name)
	}
}

// lockedWriter serialises writes from concurrent records.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.w.Write(p)
}

// errChargeOutage is the failure of a store that cannot charge an attempt.
var errChargeOutage = errors.New("enroller_test: enrolment store unreachable")

// chargeOutageStore is the in-memory store with its charge out of service.
type chargeOutageStore struct{ *mfa.MemoryEnrolmentStore }

func (chargeOutageStore) ChargeEmailCode(context.Context, identity.UserID, id.ID, time.Time) (int, bool, error) {
	return 0, false, errChargeOutage
}

// completingEnroller is a broken Enroller: it completes the enrolment on any
// presented code, the never-matching one included, and counts the calls.
type completingEnroller struct {
	*mfa.TOTP

	mu    sync.Mutex
	calls int
}

func (c *completingEnroller) RedeemEmailCode(context.Context, identity.UserID, id.ID, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.calls++

	return nil
}

func (c *completingEnroller) redeemed() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.calls
}

// TestVoidEmailCodeFailures pins how voiding reports what is not a refusal: a
// store that cannot charge stops it and is reported as itself, and a method
// that completes the enrolment on the never-matching code stops it and is
// reported as broken. Neither is ErrEmailCodeInvalid.
func TestVoidEmailCodeFailures(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// enroller builds the method voided and the generation named.
		enroller func(t *testing.T) (mfa.Enroller, id.ID)

		assert func(t *testing.T, e mfa.Enroller, err error)
	}

	cases := []testCase{
		{
			name: "a store that cannot charge",
			enroller: func(t *testing.T) (mfa.Enroller, id.ID) {
				t.Helper()

				now := time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC)
				m, err := mfa.NewTOTP(chargeOutageStore{mfa.NewMemoryEnrolmentStore()}, "Example",
					mfa.WithClock(func() time.Time { return now }))
				require.NoError(t, err)

				p, gen, err := m.BeginEnrolmentGeneration(t.Context(), "u-1", "alice@example.com")
				require.NoError(t, err)

				_, err = m.ProveDevice(t.Context(), "u-1", gen, codeForSecret(t, p.Secret, now), true, 10*time.Minute)
				require.NoError(t, err)

				return m, gen
			},
			assert: func(t *testing.T, _ mfa.Enroller, err error) {
				t.Helper()

				require.ErrorIs(t, err, errChargeOutage)
				assert.NotErrorIs(t, err, mfa.ErrInvalidCode)
			},
		},
		{
			name: "a method that completes on the never-matching code",
			enroller: func(t *testing.T) (mfa.Enroller, id.ID) {
				t.Helper()

				m, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
				require.NoError(t, err)

				return &completingEnroller{TOTP: m}, id.MustParse("01920000-0000-7000-8000-000000000001")
			},
			assert: func(t *testing.T, e mfa.Enroller, err error) {
				t.Helper()

				require.Error(t, err, "a completion is a broken method, not a voided code")
				assert.NotErrorIs(t, err, mfa.ErrEmailCodeInvalid)
				assert.NotErrorIs(t, err, mfa.ErrInvalidCode)

				broken, ok := e.(*completingEnroller)
				require.True(t, ok)
				assert.Equal(t, 1, broken.redeemed(), "voiding stops at the completion")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, gen := tc.enroller(t)
			tc.assert(t, e, mfa.VoidEmailCode(t.Context(), e, "u-1", gen))
		})
	}
}
