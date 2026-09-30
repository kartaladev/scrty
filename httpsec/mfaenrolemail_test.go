package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// emailCodeRequest posts code to the emailed-code endpoint as a URL-encoded
// form, so a code with spaces or non-ASCII digits reaches it as it was typed.
func emailCodeRequest(ctx context.Context, code string) *http.Request {
	return post(ctx, enrolEmailPath, url.Values{"code": {code}}.Encode())
}

// beginDoc runs a begin through c and returns the document it answered with.
func (h *enrolHarness) beginDoc(t *testing.T, c *httpsec.Chain) beginBody {
	t.Helper()

	out := serve(t, c, post(t.Context(), enrolBeginPath, ""))
	require.NoError(t, out.err)

	var body beginBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))

	return body
}

// prove proves the device through c with a code from secret, and returns the
// code the user was emailed for it, as the message they received carries it.
func (h *enrolHarness) prove(t *testing.T, c *httpsec.Chain, o *outbox, secret string) string {
	t.Helper()

	out := serve(t, c, post(t.Context(), enrolConfirmPath, "code="+h.codeFor(t, secret)))
	require.NoError(t, out.err)

	return lastEmailedCode(t, o)
}

// lastEmailedCode is the code carried by the latest message the user was sent.
func lastEmailedCode(t *testing.T, o *outbox) string {
	t.Helper()

	sent := o.messages()
	require.NotEmpty(t, sent)

	code := sixDigits.FindString(sent[len(sent)-1].TextBody)
	require.NotEmpty(t, code, "the message carries a code")

	return code
}

// otherCode is a well-formed code that is not code.
func otherCode(code string) string {
	if code == "000000" {
		return "111111"
	}

	return "000000"
}

// lenientConfirmLimiter replaces the confirmation limiter with one the case
// cannot reach, so what refuses a code is the enrolment's own attempt count
// and not the per-user limit.
func lenientConfirmLimiter(t *testing.T, h *enrolHarness) {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(1000, time.Hour)
	require.NoError(t, err)

	h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentConfirmLimiter(l))
}

// failuresRecorded replaces the confirmation limiter with a double that admits
// every request and expects exactly n failures, each recorded under a context
// that was not cancelled.
func failuresRecorded(t *testing.T, h *enrolHarness, n int) {
	t.Helper()

	key := httpsec.EnrolmentConfirmThrottleKey(testMFAUser)

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), key).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), key).Times(n).
		DoAndReturn(func(ctx context.Context, _ string) error {
			require.NoError(t, ctx.Err(), "recording is not abandoned with the request")
			return nil
		})

	h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentConfirmLimiter(l))
}

// enrolled reports whether the enrolling user now has a usable enrolment.
func (h *enrolHarness) enrolled(t *testing.T) bool {
	t.Helper()

	ok, err := h.totp.Enrolled(t.Context(), testMFAUser)
	require.NoError(t, err)

	return ok
}

// TestEnrolmentEmailCode pins the emailed-code endpoint: the code emailed when
// the device was proven completes the enrolment within 10 minutes and moves the
// session on to verification; every refusal — late, wrong, malformed, voided,
// from another generation — completes nothing, and a presented code is charged
// on the enrolment before it is compared, and a wrong one on the per-user
// limiter too.
func TestEnrolmentEmailCode(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// prepare wires the harness before the chain is built. The sender
		// accepts every message unless prepare wires it otherwise.
		prepare func(t *testing.T, h *enrolHarness, o *outbox)

		// before runs after the device was proven and before the request
		// under test; emailed is the code the proof sent.
		before func(t *testing.T, h *enrolHarness, c *httpsec.Chain, o *outbox, emailed string)

		// present is the code posted; nil posts the emailed code.
		present func(t *testing.T, o *outbox, emailed string) string

		// request builds the request under test instead of a form post.
		request func(ctx context.Context, code string) *http.Request

		ctx func(ctx context.Context) context.Context

		assert func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, doc beginBody, out served)
	}

	// refused is a refusal that completed nothing: the invalid-code error,
	// answered 401, the enrolment still pending and the session still
	// confined.
	refused := func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, mfa.ErrEmailCodeInvalid)
		require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		assert.False(t, h.enrolled(t), "nothing is enrolled")
		assert.Equal(t, session.MFAEnrolmentPending, h.stored(t, s.ID).MFA, "the session stays confined")
	}

	attempts := func(t *testing.T, h *enrolHarness) int {
		t.Helper()

		e, ok := h.enrolment(t)
		require.True(t, ok)

		return e.EmailCodeAttempts
	}

	// staleGeneration is the case of a session whose recorded generation is
	// no longer the enrolment's: another session of the same user began after
	// it, proved its own device and was emailed its own code, which this
	// session then presents.
	staleGeneration := func() testCase {
		var other *httpsec.Chain

		return testCase{
			name: "a session holding an older generation",
			before: func(t *testing.T, h *enrolHarness, _ *httpsec.Chain, o *outbox, _ string) {
				t.Helper()

				other = h.chain(t, h.enrolmentOnly(t, factor.Password))
				h.prove(t, other, o, h.beginDoc(t, other).Secret)
			},
			present: func(t *testing.T, o *outbox, _ string) string {
				t.Helper()

				return lastEmailedCode(t, o)
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, _ beginBody, out served) {
				t.Helper()

				refused(t, h, s, out)
				assert.Zero(t, attempts(t, h), "a code for another generation is not charged to it")

				// The code was good: the session that holds its generation
				// still completes with it.
				done := serve(t, other, emailCodeRequest(t.Context(), lastEmailedCode(t, o)))
				require.NoError(t, done.err)
				assert.True(t, h.enrolled(t))
			},
		}
	}

	cases := []testCase{
		{
			name: "the emailed code within 10 minutes",
			before: func(_ *testing.T, h *enrolHarness, _ *httpsec.Chain, _ *outbox, _ string) {
				h.clock.Advance(9 * time.Minute)
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, doc beginBody, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.Empty(t, out.rec.Body.String())
				assert.False(t, out.handlerRan)
				assert.True(t, h.enrolled(t), "the enrolment is confirmed")

				stored := h.stored(t, s.ID)
				assert.Equal(t, session.MFAPending, stored.MFA,
					"the session moves on to verification, not past it")
				assert.False(t, stored.EnrolmentOriginDeadline.IsZero(),
					"the marker stays until verification restores the deadline")

				sent := o.messages()
				require.Len(t, sent, 2, "the code, then the notification")

				bound := sent[1]
				assert.Equal(t, enrolUsername, bound.To)
				assert.Contains(t, bound.TextBody, h.totp.Name(), "the notification names the method")

				for _, leaked := range []string{lastEmailedCode(t, &outbox{sent: sent[:1]}), doc.Secret, doc.URI} {
					assert.NotContains(t, bound.Subject, leaked)
					assert.NotContains(t, bound.TextBody, leaked)
				}

				assert.NotRegexp(t, sixDigits, bound.TextBody, "it carries no code")
			},
		},
		{
			name: "the emailed code 11 minutes later",
			before: func(_ *testing.T, h *enrolHarness, _ *httpsec.Chain, _ *outbox, _ string) {
				h.clock.Advance(11 * time.Minute)
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, _ *outbox, _ beginBody, out served) {
				t.Helper()

				refused(t, h, s, out)
			},
		},
		{
			name:    "a wrong code is charged on the enrolment and on the limiter",
			prepare: func(t *testing.T, h *enrolHarness, _ *outbox) { t.Helper(); failuresRecorded(t, h, 1) },
			present: func(_ *testing.T, _ *outbox, emailed string) string { return otherCode(emailed) },
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, _ *outbox, _ beginBody, out served) {
				t.Helper()

				refused(t, h, s, out)
				assert.Equal(t, 1, attempts(t, h))
			},
		},
		{
			name:    "a wrong code from a caller who has hung up",
			prepare: func(t *testing.T, h *enrolHarness, _ *outbox) { t.Helper(); failuresRecorded(t, h, 1) },
			present: func(_ *testing.T, _ *outbox, emailed string) string { return otherCode(emailed) },
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, _ *outbox, _ beginBody, out served) {
				t.Helper()

				require.Error(t, out.err)
				assert.False(t, h.enrolled(t))
			},
		},
		{
			name:    "the fifth wrong code voids it",
			prepare: func(t *testing.T, h *enrolHarness, _ *outbox) { t.Helper(); lenientConfirmLimiter(t, h) },
			before: func(t *testing.T, _ *enrolHarness, c *httpsec.Chain, _ *outbox, emailed string) {
				t.Helper()

				for range 5 {
					out := serve(t, c, emailCodeRequest(t.Context(), otherCode(emailed)))
					require.ErrorIs(t, out.err, mfa.ErrEmailCodeInvalid)
				}
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, _ *outbox, _ beginBody, out served) {
				t.Helper()

				refused(t, h, s, out)
			},
		},
		{
			// Under the default limiter the same five wrong codes reach the
			// per-user limit first.
			name: "five wrong codes under the default limiter",
			before: func(t *testing.T, _ *enrolHarness, c *httpsec.Chain, _ *outbox, emailed string) {
				t.Helper()

				for range 5 {
					out := serve(t, c, emailCodeRequest(t.Context(), otherCode(emailed)))
					require.ErrorIs(t, out.err, mfa.ErrEmailCodeInvalid)
				}
			},
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, _ *outbox, _ beginBody, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrEnrolmentThrottled)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.False(t, h.enrolled(t))
			},
		},
		{
			name:    "twenty wrong codes at once",
			prepare: func(t *testing.T, h *enrolHarness, _ *outbox) { t.Helper(); lenientConfirmLimiter(t, h) },
			before: func(t *testing.T, _ *enrolHarness, c *httpsec.Chain, _ *outbox, emailed string) {
				t.Helper()

				var wg sync.WaitGroup

				errs := make([]error, 20)

				for n := range errs {
					wg.Go(func() {
						errs[n] = serve(t, c, emailCodeRequest(t.Context(), otherCode(emailed))).err
					})
				}

				wg.Wait()

				for _, err := range errs {
					require.ErrorIs(t, err, mfa.ErrEmailCodeInvalid)
				}
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, _ *outbox, _ beginBody, out served) {
				t.Helper()

				refused(t, h, s, out)
				assert.Equal(t, mfa.MaxEmailCodeFailures, attempts(t, h),
					"no more attempts are charged, so no more comparisons made, than the limit")
			},
		},
		staleGeneration(),
		{
			// Review focus 1: the session's generation moves with every
			// begin, so the code a proof sent before the second begin no
			// longer matches it.
			name: "a code from before a second begin in the same session",
			before: func(t *testing.T, h *enrolHarness, c *httpsec.Chain, _ *outbox, _ string) {
				t.Helper()

				h.beginDoc(t, c)
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, _ *outbox, _ beginBody, out served) {
				t.Helper()

				refused(t, h, s, out)
			},
		},
		{
			// Review focus 3: a malformed code is charged and refused, never
			// trimmed or normalised into a match. Four of them leave the fifth
			// attempt, which the code itself then uses.
			name:    "malformed codes are charged and never normalised",
			prepare: func(t *testing.T, h *enrolHarness, _ *outbox) { t.Helper(); failuresRecorded(t, h, 4) },
			before: func(t *testing.T, h *enrolHarness, c *httpsec.Chain, _ *outbox, emailed string) {
				t.Helper()

				fullWidth := strings.Map(func(r rune) rune { return r - '0' + '０' }, emailed)

				for n, malformed := range []string{" " + emailed, emailed[:5], emailed + "0", fullWidth} {
					out := serve(t, c, emailCodeRequest(t.Context(), malformed))
					require.ErrorIs(t, out.err, mfa.ErrEmailCodeInvalid, "%q", malformed)
					assert.Equal(t, n+1, attempts(t, h), "%q is charged", malformed)
					assert.False(t, h.enrolled(t))
				}
			},
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, _ *outbox, _ beginBody, out served) {
				t.Helper()

				require.NoError(t, out.err, "the code itself, charged fifth, still completes")
				assert.True(t, h.enrolled(t))
			},
		},
		{
			name:    "a code the endpoint cannot read",
			prepare: func(t *testing.T, h *enrolHarness, _ *outbox) { t.Helper(); failuresRecorded(t, h, 0) },
			request: func(ctx context.Context, code string) *http.Request {
				req := post(ctx, enrolEmailPath, `{"code":"`+code+`"}`)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, _ *outbox, _ beginBody, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
				assert.Zero(t, attempts(t, h), "an unread code is not charged")
				assert.False(t, h.enrolled(t))
				assert.Equal(t, session.MFAEnrolmentPending, h.stored(t, s.ID).MFA)
			},
		},
		{
			name: "a confirmation limiter that cannot decide",
			prepare: func(t *testing.T, h *enrolHarness, _ *outbox) {
				t.Helper()

				// The proof passes it; the emailed code finds it down.
				l := NewMockLimiter(gomock.NewController(t))
				gomock.InOrder(
					l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil),
					l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
						Return(false, errors.New("mfaenrolemail_test: limiter store unreachable")),
				)
				l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)

				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentConfirmLimiter(l))
			},
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, _ *outbox, _ beginBody, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrEnrolmentThrottled)
				assert.Zero(t, attempts(t, h), "a refused request is not charged")
				assert.False(t, h.enrolled(t))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			o := &outbox{}

			if tc.prepare != nil {
				tc.prepare(t, h, o)
			}

			o.accepting(h, nil)

			s := h.enrolmentOnly(t, factor.Password)
			c := h.chain(t, s)

			doc := h.beginDoc(t, c)
			emailed := h.prove(t, c, o, doc.Secret)

			if tc.before != nil {
				tc.before(t, h, c, o, emailed)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			code := emailed
			if tc.present != nil {
				code = tc.present(t, o, emailed)
			}

			req := emailCodeRequest(ctx, code)
			if tc.request != nil {
				req = tc.request(ctx, code)
			}

			tc.assert(t, h, s, o, doc, serveIn(ctx, t, c, req))
		})
	}
}

// failingNotifications wires the sender to accept the emailed code and refuse
// every later message with err, recording each.
func (o *outbox) failingNotifications(h *enrolHarness, err error) {
	h.sender.EXPECT().Send(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, m notify.Message) error {
			o.mu.Lock()
			defer o.mu.Unlock()

			o.sent = append(o.sent, m)
			if len(o.sent) == 1 {
				return nil
			}

			return err
		})
}

// boundMessages is a consumer renderer that writes its own notification.
type boundMessages struct{}

func (boundMessages) Code(code string, _ time.Time) (string, string) {
	return "code", "code " + code
}

func (boundMessages) Bound(method string, at time.Time) (string, string) {
	return "consumer subject", "consumer body: " + method + " at " + at.UTC().Format(time.RFC3339)
}

// TestEnrolmentNotification pins the notification an enrolment completed
// through the emailed code sends: on by default, to the contact resolver's
// address, naming the method; off on request; and, when the sender refuses to
// queue it, logged by a fixed reason with the completion standing.
func TestEnrolmentNotification(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		prepare func(t *testing.T, h *enrolHarness, o *outbox)
		assert  func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, logs *capturingHandler, out served)
	}

	completed := func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.Equal(t, http.StatusNoContent, out.rec.Code)
		assert.True(t, h.enrolled(t), "the enrolment stands")
		assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA)
	}

	cases := []testCase{
		{
			name:    "on by default",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) { o.accepting(h, nil) },
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, _ *capturingHandler, out served) {
				t.Helper()

				completed(t, h, s, out)

				sent := o.messages()
				require.Len(t, sent, 2)
				assert.Equal(t, enrolUsername, sent[1].To)
				assert.Contains(t, sent[1].TextBody, h.totp.Name())
			},
		},
		{
			name: "a consumer contact resolver",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithContactResolver(
					func(context.Context, *identity.Details) (string, error) { return "ana.work@example.com", nil }))
				o.accepting(h, nil)
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, _ *capturingHandler, out served) {
				t.Helper()

				completed(t, h, s, out)

				sent := o.messages()
				require.Len(t, sent, 2)
				assert.Equal(t, "ana.work@example.com", sent[0].To, "the emailed code")
				assert.Equal(t, "ana.work@example.com", sent[1].To, "the notification")
			},
		},
		{
			name: "a consumer renderer",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentMessages(boundMessages{}))
				o.accepting(h, nil)
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, _ *capturingHandler, out served) {
				t.Helper()

				completed(t, h, s, out)

				sent := o.messages()
				require.Len(t, sent, 2)
				assert.Equal(t, "consumer subject", sent[1].Subject)
				assert.True(t, strings.HasPrefix(sent[1].TextBody, "consumer body: "+h.totp.Name()))
				assert.Equal(t, enrolUsername, sent[1].To, "the library still addresses it")
			},
		},
		{
			name: "turned off",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEnrolmentNotification())
				o.accepting(h, nil)
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, _ *capturingHandler, out served) {
				t.Helper()

				completed(t, h, s, out)
				assert.Len(t, o.messages(), 1, "only the emailed code was sent")
			},
		},
		{
			name:    "a queue that refuses it",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) { o.failingNotifications(h, notify.ErrQueueFull) },
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, logs *capturingHandler, out served) {
				t.Helper()

				completed(t, h, s, out)
				require.Len(t, o.messages(), 2, "it was asked to send the notification")

				var found int

				for _, r := range logs.records() {
					if r.Message != "httpsec: the user could not be notified of a completed enrolment" {
						continue
					}

					found++

					reason, ok := attrValue(r, "reason")
					require.True(t, ok)
					assert.Equal(t, "send-refused", reason.String())
				}

				assert.Equal(t, 1, found, "the refusal is logged once")
				noRecordCarries(t, logs, enrolUsername)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			o := &outbox{}
			logs := &capturingHandler{}

			h.extra = append(h.extra, httpsec.WithLogger(slog.New(logs)))
			tc.prepare(t, h, o)

			s := h.enrolmentOnly(t, factor.Password)
			c := h.chain(t, s)
			emailed := h.prove(t, c, o, h.beginDoc(t, c).Secret)

			tc.assert(t, h, s, o, logs, serve(t, c, emailCodeRequest(t.Context(), emailed)))
		})
	}
}

// TestEnrolmentNotifiesWhenSessionUnsaved pins that the owner is told of every
// binding: once the enrolment is completed it stands, so the notification is
// sent even when the session's move on to verification cannot then be saved.
// The request still fails with the library's fixed text, and the session keeps
// the state it had.
func TestEnrolmentNotifiesWhenSessionUnsaved(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// emailOff completes the enrolment at the device proof rather than at
		// the emailed code.
		emailOff bool

		// complete runs the request that completes the enrolment, with the
		// session store's saves failing from then on.
		complete func(t *testing.T, h *enrolHarness, c *httpsec.Chain, o *outbox, failing *atomic.Bool) served

		assert func(t *testing.T, sent []notify.Message)
	}

	cases := []testCase{
		{
			name: "completed by the emailed code",
			complete: func(t *testing.T, h *enrolHarness, c *httpsec.Chain, o *outbox, failing *atomic.Bool) served {
				t.Helper()

				emailed := h.prove(t, c, o, h.beginDoc(t, c).Secret)
				failing.Store(true)

				return serve(t, c, emailCodeRequest(t.Context(), emailed))
			},
			assert: func(t *testing.T, sent []notify.Message) {
				t.Helper()

				require.Len(t, sent, 2, "the emailed code, then the notification")
				assert.Equal(t, enrolUsername, sent[1].To)
				assert.NotRegexp(t, sixDigits, sent[1].TextBody, "the notification carries no code")
			},
		},
		{
			name:     "completed by the device proof, with email confirmation off",
			emailOff: true,
			complete: func(t *testing.T, h *enrolHarness, c *httpsec.Chain, _ *outbox, failing *atomic.Bool) served {
				t.Helper()

				secret := h.beginDoc(t, c).Secret
				failing.Store(true)

				return serve(t, c, post(t.Context(), enrolConfirmPath,
					"code="+h.codeFor(t, secret)))
			},
			assert: func(t *testing.T, sent []notify.Message) {
				t.Helper()

				require.Len(t, sent, 1, "the notification, and nothing else")
				assert.Equal(t, enrolUsername, sent[0].To)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			o := &outbox{}
			o.accepting(h, nil)

			var failing atomic.Bool

			var err error
			h.sessions, err = session.NewManager(session.WithStore(
				failingSaves{Store: session.NewMemoryStore(), failing: &failing}))
			require.NoError(t, err)

			if tc.emailOff {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEmailConfirmation())
			}

			s := h.enrolmentOnly(t, factor.Password)
			c := h.chain(t, s)

			out := tc.complete(t, h, c, o, &failing)

			require.ErrorIs(t, out.err, errStoreLeaky, "the save's failure is still reachable")
			assert.Equal(t, "httpsec: the enrolling session could not be saved", out.err.Error(),
				"with the library's fixed text")
			assert.True(t, h.enrolled(t), "the binding stands")
			assert.Equal(t, session.MFAEnrolmentPending, h.stored(t, s.ID).MFA,
				"the session keeps the state it had")

			tc.assert(t, o.messages())
		})
	}
}
