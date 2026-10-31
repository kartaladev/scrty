package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// sixDigits finds a 6-digit code standing on its own in a message body.
var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// outbox records what the sender double was asked to send.
type outbox struct {
	mu   sync.Mutex
	sent []notify.Message
}

func (o *outbox) messages() []notify.Message {
	o.mu.Lock()
	defer o.mu.Unlock()

	return append([]notify.Message(nil), o.sent...)
}

// accepting wires the sender to record every message and answer err.
func (o *outbox) accepting(h *enrolHarness, err error) {
	h.sender.EXPECT().Send(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, m notify.Message) error {
			o.mu.Lock()
			defer o.mu.Unlock()

			o.sent = append(o.sent, m)

			return err
		})
}

// transportPeer is the peer address a transport's failure names.
const transportPeer = "203.0.113.7:51234"

// errTransportReset is a transport's failure to deliver or accept a body,
// which quotes the connection's addresses, as net's errors do.
var errTransportReset = errors.New("read tcp 10.0.0.1:443->" + transportPeer + ": connection reset by peer")

// errProofOutage is the failure of a store that cannot record a device proof.
var errProofOutage = errors.New("mfaenrolconfirm_test: enrolment store unreachable")

// proofOutageStore is the in-memory store with its device-proof write out of
// service, as a durable store's would be in an outage.
type proofOutageStore struct{ *mfa.MemoryEnrolmentStore }

func (proofOutageStore) ProveDevice(
	context.Context, identity.UserID, id.ID, int64, []byte, time.Time, time.Time,
) (bool, error) {
	return false, errProofOutage
}

// begin runs a begin through c and returns the secret it provisioned.
func (h *enrolHarness) begin(t *testing.T, c *httpsec.Chain) string {
	t.Helper()

	out := serve(t, c, post(t.Context(), enrolBeginPath, ""))
	require.NoError(t, out.err)

	var body beginBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))

	return body.Secret
}

// wrongCodeFor is a well-formed code that is not the one secret shows now.
func (h *enrolHarness) wrongCodeFor(t *testing.T, secret string) string {
	t.Helper()

	if h.codeFor(t, secret) == "000000" {
		return "111111"
	}

	return "000000"
}

// TestEnrolmentConfirm pins the confirm endpoint: a code from the pending
// secret proves the device on the session's own generation; with email
// confirmation on — the default — that proves the device and no more, and a
// code goes to the user's mailbox; a wrong code is counted against the user
// even when the caller has gone away; and with email confirmation off the
// proof completes the enrolment and moves the session on to verification.
func TestEnrolmentConfirm(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// prepare wires the harness before the chain is built.
		prepare func(t *testing.T, h *enrolHarness, o *outbox)

		// skipBegin leaves the session without a begun enrolment.
		skipBegin bool

		// before runs requests ahead of the one under test.
		before func(t *testing.T, h *enrolHarness, c *httpsec.Chain, secret string)

		// code is the code posted, from the provisioned secret.
		code func(t *testing.T, h *enrolHarness, secret string) string

		// request builds the confirm request carrying code, when a case sends
		// it some other way than as the URL-encoded body's form field.
		request func(ctx context.Context, code string) *http.Request

		ctx func(ctx context.Context) context.Context

		assert func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, out served)
	}

	valid := func(t *testing.T, h *enrolHarness, secret string) string {
		t.Helper()

		return h.codeFor(t, secret)
	}

	wrong := func(t *testing.T, h *enrolHarness, secret string) string {
		t.Helper()

		return h.wrongCodeFor(t, secret)
	}

	// countingLimiter is a confirmation limiter double that admits and
	// expects exactly failures recorded failures, each under a context that
	// was not cancelled.
	countingLimiter := func(failures int) func(t *testing.T, h *enrolHarness, o *outbox) {
		return func(t *testing.T, h *enrolHarness, o *outbox) {
			t.Helper()

			key := httpsec.EnrolmentConfirmThrottleKey(testMFAUser)

			l := NewMockLimiter(gomock.NewController(t))
			l.EXPECT().Exceeded(gomock.Any(), key).Return(false, nil)
			l.EXPECT().RecordFailure(gomock.Any(), key).Times(failures).
				DoAndReturn(func(ctx context.Context, _ string) error {
					require.NoError(t, ctx.Err(), "recording is not abandoned with the request")
					return nil
				})

			h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentConfirmLimiter(l))
			o.accepting(h, nil)
		}
	}

	// unread is the refusal of a code the endpoint could not read: missing
	// credentials, never a wrong code, so it is not charged — the case's
	// limiter expects no failure — and the device is not proven.
	unread := func(t *testing.T, h *enrolHarness, _ *session.Session, o *outbox, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
		require.NotErrorIs(t, out.err, mfa.ErrInvalidCode, "an unread code is not a wrong one")
		assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
		assert.Empty(t, o.messages())

		e, ok := h.enrolment(t)
		require.True(t, ok)
		assert.True(t, e.DeviceProvenAt.IsZero(), "the device is not proven")
	}

	// body is a POST of payload declared as contentType.
	body := func(contentType, payload string) func(ctx context.Context, code string) *http.Request {
		return func(ctx context.Context, code string) *http.Request {
			req := post(ctx, enrolConfirmPath, strings.ReplaceAll(payload, "{code}", code))
			req.Header.Set("Content-Type", contentType)

			return req
		}
	}

	notProven := func(t *testing.T, h *enrolHarness) {
		t.Helper()

		e, ok := h.enrolment(t)
		if ok {
			assert.True(t, e.DeviceProvenAt.IsZero(), "the device is not proven")
			assert.True(t, e.ConfirmedAt.IsZero(), "nothing is enrolled")
		}
	}

	proofOnly := func(t *testing.T, h *enrolHarness, s *session.Session) {
		t.Helper()

		e, ok := h.enrolment(t)
		require.True(t, ok)
		assert.False(t, e.DeviceProvenAt.IsZero(), "the device is proven")

		enrolled, err := h.totp.Enrolled(t.Context(), testMFAUser)
		require.NoError(t, err)
		assert.False(t, enrolled, "a proven device alone is not an enrolment")
		assert.Equal(t, session.MFAEnrolmentPending, h.stored(t, s.ID).MFA, "the session stays confined")
	}

	cases := []testCase{
		{
			name:    "a valid code with email confirmation on",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) { o.accepting(h, nil) },
			code:    valid,
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.Empty(t, out.rec.Body.String())
				assert.False(t, out.handlerRan)

				proofOnly(t, h, s)

				sent := o.messages()
				require.Len(t, sent, 1, "one code is queued")
				assert.Equal(t, enrolUsername, sent[0].To, "the default contact is the username")
				assert.NotEmpty(t, sent[0].Subject)

				e, _ := h.enrolment(t)
				require.Len(t, e.EmailCode, 6)
				assert.Contains(t, sent[0].TextBody, string(e.EmailCode), "the message carries the code")
				assert.Regexp(t, sixDigits, sent[0].TextBody)
			},
		},
		{
			name: "a consumer contact resolver",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentContactResolver(
					func(_ context.Context, d *identity.Details) (string, error) {
						if d.ID != testMFAUser {
							return "", errors.New("mfaenrolconfirm_test: resolved for the wrong user")
						}

						return "ana.work@example.com", nil
					}))
				o.accepting(h, nil)
			},
			code: valid,
			assert: func(t *testing.T, _ *enrolHarness, _ *session.Session, o *outbox, out served) {
				t.Helper()

				require.NoError(t, out.err)

				sent := o.messages()
				require.Len(t, sent, 1)
				assert.Equal(t, "ana.work@example.com", sent[0].To)
			},
		},
		{
			name:    "a wrong code",
			prepare: countingLimiter(1),
			code:    wrong,
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, o *outbox, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				notProven(t, h)
				assert.Empty(t, o.messages(), "no code is sent for a device that was not proven")
			},
		},
		{
			name:    "a wrong code from a caller who has hung up",
			prepare: countingLimiter(1),
			code:    wrong,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, _ *outbox, out served) {
				t.Helper()

				require.Error(t, out.err)
				notProven(t, h)
			},
		},
		{
			name:      "a code with no begun enrolment",
			prepare:   countingLimiter(1),
			skipBegin: true,
			code:      func(*testing.T, *enrolHarness, string) string { return "123456" },
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, _ *outbox, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				notProven(t, h)
			},
		},
		{
			// A code is read from the POST body alone: one in the URL has
			// already reached access logs, proxy logs and the Referer.
			name:    "a valid code in the query string is no code",
			prepare: countingLimiter(0),
			code:    valid,
			request: func(ctx context.Context, code string) *http.Request {
				return post(ctx, enrolConfirmPath+"?code="+code, "")
			},
			assert: unread,
		},
		{
			// Only a URL-encoded form body is read; a multipart one is not
			// parsed, and so carries no code.
			name:    "a valid code in a multipart body",
			prepare: countingLimiter(0),
			code:    valid,
			request: body("multipart/form-data; boundary=b",
				"--b\r\nContent-Disposition: form-data; name=\"code\"\r\n\r\n{code}\r\n--b--\r\n"),
			assert: unread,
		},
		{
			name:    "a valid code in a body that does not parse",
			prepare: countingLimiter(0),
			code:    valid,
			request: body("application/x-www-form-urlencoded", "code={code}&note=100%"),
			assert:  unread,
		},
		{
			// A body read as a form must say it is one: text that merely
			// looks like a form is not parsed.
			name:    "a valid code in a text/plain body",
			prepare: countingLimiter(0),
			code:    valid,
			request: body("text/plain", "code={code}"),
			assert:  unread,
		},
		{
			// A body the transport could not deliver carries no code, and its
			// failure's text — which names the peer's address — is not the
			// library's to return.
			name:    "a body the transport cannot read",
			prepare: countingLimiter(0),
			code:    valid,
			request: func(ctx context.Context, _ string) *http.Request {
				req := post(ctx, enrolConfirmPath, "")
				req.Body = io.NopCloser(iotest.ErrReader(errTransportReset))

				return req
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, out served) {
				t.Helper()

				unread(t, h, s, o, out)
				assert.Equal(t, httpsec.ErrCredentialsMissing.Error(), out.err.Error(),
					"the refusal carries the library's own text")
				assert.NotContains(t, out.err.Error(), transportPeer)
			},
		},
		{
			name:    "a valid code in a JSON body",
			prepare: countingLimiter(0),
			code:    valid,
			request: body("application/json", `{"code":"{code}"}`),
			assert:  unread,
		},
		{
			name:    "an empty body",
			prepare: countingLimiter(0),
			code:    valid,
			request: body("application/x-www-form-urlencoded", ""),
			assert:  unread,
		},
		{
			name:    "a form with no code field",
			prepare: countingLimiter(0),
			code:    valid,
			request: body("application/x-www-form-urlencoded", "note=x"),
			assert:  unread,
		},
		{
			name:    "a form with an empty code field",
			prepare: countingLimiter(0),
			code:    valid,
			request: body("application/x-www-form-urlencoded", "code="),
			assert:  unread,
		},
		{
			// An outage is not a guess: counting it would lock the user out
			// for the store's failure.
			name: "a store that cannot record the proof",
			prepare: func(t *testing.T, h *enrolHarness, o *outbox) {
				t.Helper()

				countingLimiter(0)(t, h, o)

				var err error
				h.totp, err = mfa.NewTOTP(proofOutageStore{h.store}, enrolIssuer,
					mfa.WithClock(h.clock))
				require.NoError(t, err)

				h.method = h.totp
			},
			code: valid,
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, o *outbox, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, errProofOutage)
				require.NotErrorIs(t, out.err, mfa.ErrInvalidCode)
				notProven(t, h)
				assert.Empty(t, o.messages())
			},
		},
		{
			name:    "five wrong codes, then a valid one",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) { o.accepting(h, nil) },
			before: func(t *testing.T, h *enrolHarness, c *httpsec.Chain, secret string) {
				t.Helper()

				for range 5 {
					out := serve(t, c, post(t.Context(), enrolConfirmPath,
						"code="+h.wrongCodeFor(t, secret)))
					require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				}
			},
			code: valid,
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, o *outbox, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrEnrolmentThrottled)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				notProven(t, h)
				assert.Empty(t, o.messages())
			},
		},
		{
			name: "a confirmation limiter that cannot decide",
			prepare: func(t *testing.T, h *enrolHarness, o *outbox) {
				t.Helper()

				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
					Return(true, errors.New("mfaenrolconfirm_test: limiter store unreachable"))
				l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)

				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentConfirmLimiter(l))
				o.accepting(h, nil)
			},
			code: valid,
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, o *outbox, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrEnrolmentThrottled)
				notProven(t, h)
				assert.Empty(t, o.messages())
			},
		},
		{
			name:    "a sender that refuses to queue the code",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) { o.accepting(h, notify.ErrQueueFull) },
			code:    valid,
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, notify.ErrQueueFull, "the confirm request fails")

				// The proof stands, and issued a code nobody received, so it
				// completes only with that code: never without it.
				gen := h.stored(t, s.ID).EnrolmentGeneration
				require.ErrorIs(t, h.totp.CompleteEnrolment(t.Context(), testMFAUser, gen), mfa.ErrInvalidCode)

				// Nor with it: the code the refusing sender was handed is
				// voided, so a later emailed-code request presenting it is
				// refused and completes nothing.
				drawn := lastEmailedCode(t, o)

				e, ok := h.enrolment(t)
				require.True(t, ok)
				assert.Equal(t, mfa.MaxEmailCodeAttempts, e.EmailCodeAttempts,
					"every attempt the code had left is charged")

				later := serve(t, h.chain(t, s), emailCodeRequest(t.Context(), drawn))
				require.ErrorIs(t, later.err, mfa.ErrEmailCodeInvalid)
				require.ErrorIs(t, later.err, mfa.ErrInvalidCode)
				assert.False(t, later.handlerRan)

				enrolled, err := h.totp.Enrolled(t.Context(), testMFAUser)
				require.NoError(t, err)
				assert.False(t, enrolled, "the enrolment stays pending")

				e, ok = h.enrolment(t)
				require.True(t, ok)
				assert.True(t, e.ConfirmedAt.IsZero(), "the enrolment stays pending")
				assert.Equal(t, session.MFAEnrolmentPending, h.stored(t, s.ID).MFA, "the session stays confined")
			},
		},
		{
			// The client hangs up while the sender is refusing, and the store
			// honours cancellation: the code is voided all the same.
			name: "a sender that refuses as the caller goes away",
			prepare: func(t *testing.T, h *enrolHarness, o *outbox) {
				t.Helper()

				var err error
				h.totp, err = mfa.NewTOTP(cancellableStore{h.store}, enrolIssuer,
					mfa.WithClock(h.clock))
				require.NoError(t, err)

				h.method = h.totp

				h.sender.EXPECT().Send(gomock.Any(), gomock.Any()).AnyTimes().
					DoAndReturn(func(ctx context.Context, m notify.Message) error {
						o.mu.Lock()
						defer o.mu.Unlock()

						o.sent = append(o.sent, m)

						if hangUp, ok := ctx.Value(hangUpKey{}).(context.CancelFunc); ok {
							hangUp()
						}

						return notify.ErrQueueFull
					})
			},
			code: valid,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)

				return context.WithValue(cctx, hangUpKey{}, cancel)
			},
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, o *outbox, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, notify.ErrQueueFull, "the confirm request fails")
				require.Len(t, o.messages(), 1, "the sender was asked, and hung the caller up")

				e, ok := h.enrolment(t)
				require.True(t, ok)
				assert.Equal(t, mfa.MaxEmailCodeAttempts, e.EmailCodeAttempts,
					"every attempt the code had left is charged, though the caller went away")
			},
		},
		{
			name: "email confirmation off",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEnrolmentEmailConfirmation())
				o.accepting(h, nil)
			},
			code: valid,
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)

				enrolled, err := h.totp.Enrolled(t.Context(), testMFAUser)
				require.NoError(t, err)
				assert.True(t, enrolled, "the proof completes the enrolment at once")

				stored := h.stored(t, s.ID)
				assert.Equal(t, session.MFAPending, stored.MFA,
					"the session moves on to verification, not past it")
				assert.False(t, stored.EnrolmentOriginDeadline.IsZero(),
					"the marker stays until verification restores the deadline")

				sent := o.messages()
				require.Len(t, sent, 1, "the user is notified of the binding")
				assert.Equal(t, enrolUsername, sent[0].To)
				assert.Contains(t, sent[0].TextBody, h.totp.Name(), "the notification names the method")
				assert.NotRegexp(t, sixDigits, sent[0].TextBody, "it carries no code")
			},
		},
		{
			name: "email confirmation and notification off",
			prepare: func(t *testing.T, h *enrolHarness, _ *outbox) {
				t.Helper()

				h.enrolOpts = append(h.enrolOpts,
					httpsec.WithoutEnrolmentEmailConfirmation(), httpsec.WithoutEnrolmentNotification())
				h.sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(0)
			},
			code: valid,
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, _ *outbox, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA)
			},
		},
		{
			// The session's generation was drawn by TOTP's store. Another
			// method's store has no pending enrolment of that generation, so
			// it refuses the proof as it refuses any stale generation, even
			// with a code that is right for TOTP's secret.
			name: "a generation belongs to the method that issued it",
			prepare: func(t *testing.T, h *enrolHarness, _ *outbox) {
				t.Helper()

				h.extraMethods = []mfa.Method{renamedTOTP(t, h, "totp-backup", mfa.NewMemoryEnrolmentStore())}
				h.sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(0)
			},
			code: valid,
			request: func(ctx context.Context, code string) *http.Request {
				return post(ctx, httpsec.DefaultEnrolmentConfirmPrefix+"/totp-backup", "code="+code)
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, o *outbox, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Empty(t, o.messages())

				e, ok := h.enrolment(t)
				require.True(t, ok)
				assert.True(t, e.DeviceProvenAt.IsZero(), "TOTP's device is not proven")

				backup := h.extraMethods[0].(renamedTOTPMethod)
				_, ok, err := backup.store.Get(t.Context(), testMFAUser)
				require.NoError(t, err)
				assert.False(t, ok, "the other method's store holds nothing")
				assert.Equal(t, session.MFAEnrolmentPending, h.stored(t, s.ID).MFA)
			},
		},
		{
			name: "a confirm path naming no enrollable method",
			prepare: func(_ *testing.T, h *enrolHarness, _ *outbox) {
				h.sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(0)
			},
			code: valid,
			request: func(ctx context.Context, code string) *http.Request {
				return post(ctx, httpsec.DefaultEnrolmentConfirmPrefix+"/sms", "code="+code)
			},
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, o *outbox, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
				assert.Empty(t, o.messages())

				e, ok := h.enrolment(t)
				require.True(t, ok)
				assert.True(t, e.DeviceProvenAt.IsZero(), "the device is not proven")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			o := &outbox{}

			tc.prepare(t, h, o)

			s := h.enrolmentOnly(t, factor.Password)
			c := h.chain(t, s)

			var secret string
			if !tc.skipBegin {
				secret = h.begin(t, c)
			}

			if tc.before != nil {
				tc.before(t, h, c, secret)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			req := post(ctx, enrolConfirmPath, "code="+tc.code(t, h, secret))
			if tc.request != nil {
				req = tc.request(ctx, tc.code(t, h, secret))
			}
			tc.assert(t, h, s, o, serveIn(ctx, t, c, req))
		})
	}
}

// hangUpKey carries, on a confirm request's context, the function that
// cancels it, so a sender double can hang the caller up mid-request.
type hangUpKey struct{}

// cancellableStore is the in-memory store with a charge that honours
// cancellation, as a durable store's does: under a cancelled context it
// charges nothing and fails.
type cancellableStore struct{ *mfa.MemoryEnrolmentStore }

func (s cancellableStore) ChargeEmailCode(
	ctx context.Context, user identity.UserID, gen id.ID, at time.Time,
) (int, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}

	return s.MemoryEnrolmentStore.ChargeEmailCode(ctx, user, gen, at)
}

// TestEnrolmentThrottleLeavesVerificationAlone pins that exhausted enrolment
// confirmations do not stop anyone verifying: u-1 spends every confirmation,
// and then a user already enrolled and MFA pending — another user, or u-1
// itself — verifies through the verify endpoint. The confirmation and verify
// limiters are one shared limiter, as a consumer's may be, so the two flows
// are kept apart only by their keys, which must differ for the same user.
func TestEnrolmentThrottleLeavesVerificationAlone(t *testing.T) {
	t.Parallel()

	confirmKey := httpsec.EnrolmentConfirmThrottleKey(testMFAUser)
	assert.NotEqual(t, mfa.VerifyThrottleKey(testMFAUser), confirmKey,
		"one user's confirmations and verifications are counted apart")
	assert.NotEqual(t, httpsec.EnrolmentBeginThrottleKey(testMFAUser), confirmKey,
		"one user's begins and confirmations are counted apart")

	type testCase struct {
		name string

		// enrolled leaves a user with a confirmed enrolment, after u-1 spent
		// its confirmations on the path's generation gen, and returns the user
		// and its secret.
		enrolled func(t *testing.T, h *enrolHarness, gen id.ID, secret string) (identity.UserID, string)
	}

	cases := []testCase{
		{
			name: "another user",
			enrolled: func(t *testing.T, h *enrolHarness, _ id.ID, _ string) (identity.UserID, string) {
				t.Helper()

				const other identity.UserID = "u-2"

				p, gen, err := h.totp.BeginEnrolmentGeneration(t.Context(), other, "bea@example.com")
				require.NoError(t, err)
				_, err = h.totp.ProveDevice(t.Context(), other, gen, h.codeFor(t, p.Secret), false, 0)
				require.NoError(t, err)
				require.NoError(t, h.totp.CompleteEnrolment(t.Context(), other, gen))

				return other, p.Secret
			},
		},
		{
			// u-1's own enrolment is completed outside the path, on the
			// generation the path began, so the same user then verifies.
			name: "the same user",
			enrolled: func(t *testing.T, h *enrolHarness, gen id.ID, secret string) (identity.UserID, string) {
				t.Helper()

				_, err := h.totp.ProveDevice(t.Context(), testMFAUser, gen, h.codeFor(t, secret), false, 0)
				require.NoError(t, err)
				require.NoError(t, h.totp.CompleteEnrolment(t.Context(), testMFAUser, gen))

				return testMFAUser, secret
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			o := &outbox{}
			o.accepting(h, nil)

			shared, err := ratelimit.NewMemoryLimiter(5, time.Hour)
			require.NoError(t, err)

			h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentConfirmLimiter(shared))
			h.mfaOpts = append(h.mfaOpts, httpsec.WithMFAVerifyLimiter(shared))

			issued := issuedFor(h)

			// u-1 spends every confirmation it has.
			enrolling := h.enrolmentOnly(t, factor.Password)
			c := h.chain(t, enrolling)
			secret := h.begin(t, c)

			for range 5 {
				out := serve(t, c, post(t.Context(), enrolConfirmPath,
					"code="+h.wrongCodeFor(t, secret)))
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
			}

			throttled := serve(t, c, post(t.Context(), enrolConfirmPath,
				"code="+h.codeFor(t, secret)))
			require.ErrorIs(t, throttled.err, mfa.ErrEnrolmentThrottled, "u-1's confirmations are exhausted")

			user, userSecret := tc.enrolled(t, h, h.stored(t, enrolling.ID).EnrolmentGeneration, secret)

			pending, err := h.sessions.Create(t.Context(), user, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			pending.MFA = session.MFAPending
			require.NoError(t, h.sessions.Save(t.Context(), pending))

			// The next step's code, since the one that proved the device is
			// spent.
			h.clock.Advance(30 * time.Second)

			out := serve(t, h.chain(t, pending), post(t.Context(), testMFAVerifyPath,
				"code="+h.codeFor(t, userSecret)))
			require.NoError(t, out.err, "the verification succeeds")
			assert.Equal(t, http.StatusOK, out.rec.Code)

			rotated, ok := issued.Load().(string)
			require.True(t, ok, "a credential is issued")
			assert.Equal(t, session.MFASatisfied, h.stored(t, rotated).MFA)
		})
	}
}

// beginBody is the begin endpoint's document, read back as a client would.
type beginBody struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// begun decodes a successful begin and returns its document.
func begun(t *testing.T, out served) beginBody {
	t.Helper()

	require.NoError(t, out.err)
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"),
		"the document carries the secret, which no cache may keep")
	assert.False(t, out.handlerRan, "the begin endpoint answers the request itself")

	var body beginBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.Secret)
	require.NotEmpty(t, body.URI)

	return body
}

// labelOf is the account label a provisioning URI carries: the part of its
// path after the issuer and the separator.
func labelOf(t *testing.T, uri string) string {
	t.Helper()

	u, err := url.Parse(uri)
	require.NoError(t, err)

	_, label, ok := strings.Cut(u.Path, ":")
	require.True(t, ok, "the label is issuer:account")

	return label
}

// TestEnrolmentBegin pins the begin endpoint: it begins on the MFA method for
// the session's own user, labels the secret from the user's records and never
// from the request, refuses the first factor's channel and an enrolled user
// before generating anything, and counts every call against the user.
func TestEnrolmentBegin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		first factor.Kind

		// prepare wires the harness before the chain is built.
		prepare func(t *testing.T, h *enrolHarness)

		// before runs requests or writes ahead of the one under test, on the
		// chain it will run on.
		before func(t *testing.T, h *enrolHarness, c *httpsec.Chain, s *session.Session)

		// path is where the begin is posted: TOTP's begin path unless a
		// case names another method.
		path string

		body string
		ctx  func(ctx context.Context) context.Context

		assert func(t *testing.T, h *enrolHarness, s *session.Session, out served)
	}

	beginOn := func(t *testing.T, c *httpsec.Chain) served {
		t.Helper()

		return serve(t, c, post(t.Context(), enrolBeginPath, ""))
	}

	// nothingBegun pins that the refusal generated and recorded nothing: no
	// enrolment for the user, and no generation on the session.
	nothingBegun := func(t *testing.T, h *enrolHarness, s *session.Session) {
		t.Helper()

		_, ok := h.enrolment(t)
		assert.False(t, ok, "nothing is stored")
		assert.True(t, h.stored(t, s.ID).EnrolmentGeneration.IsZero(),
			"the session records no generation")
	}

	cases := []testCase{
		{
			name:  "a begin returns provisioning and leaves the user unenrolled",
			first: factor.Password,
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				body := begun(t, out)
				assert.Equal(t, enrolUsername, labelOf(t, body.URI),
					"the default label is the user's username")

				enrolled, err := h.totp.Enrolled(t.Context(), testMFAUser)
				require.NoError(t, err)
				assert.False(t, enrolled, "a begun enrolment is pending, not enrolled")

				e, ok := h.enrolment(t)
				require.True(t, ok)

				stored := h.stored(t, s.ID)
				require.False(t, stored.EnrolmentGeneration.IsZero(), "the session records the generation")
				assert.Equal(t, e.Generation, stored.EnrolmentGeneration,
					"the generation recorded is the one the begin drew")
				assert.Equal(t, session.MFAEnrolmentPending, stored.MFA, "the session stays confined")
			},
		},
		{
			name:  "a label in the request is ignored",
			first: factor.Password,
			body:  "label=" + url.QueryEscape("attacker@example.com"),
			assert: func(t *testing.T, _ *enrolHarness, _ *session.Session, out served) {
				t.Helper()

				body := begun(t, out)
				assert.Equal(t, enrolUsername, labelOf(t, body.URI))
				assert.NotContains(t, body.URI, "attacker")
			},
		},
		{
			name:  "a consumer label resolver",
			first: factor.Password,
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithEnrolmentLabelResolver(
					func(_ context.Context, d *identity.Details) (string, error) {
						if d.ID != testMFAUser {
							return "", errors.New("mfaenrolbegin_test: resolved for the wrong user")
						}

						return "ana.work@example.com", nil
					})}
			},
			assert: func(t *testing.T, _ *enrolHarness, _ *session.Session, out served) {
				t.Helper()

				assert.Equal(t, "ana.work@example.com", labelOf(t, begun(t, out).URI))
			},
		},
		{
			name:  "a begin again replaces the pending enrolment and moves the generation",
			first: factor.Password,
			before: func(t *testing.T, _ *enrolHarness, c *httpsec.Chain, _ *session.Session) {
				t.Helper()

				begun(t, beginOn(t, c))
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				begun(t, out)

				e, ok := h.enrolment(t)
				require.True(t, ok)
				assert.Equal(t, e.Generation, h.stored(t, s.ID).EnrolmentGeneration,
					"the session follows the newest generation")
			},
		},
		{
			// A magic-link login arrived by email; a second factor emailed
			// too would be the same factor twice.
			name:  "the first factor's own channel",
			first: factor.MagicLink,
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				m := NewMockEnroller(gomock.NewController(t))
				m.EXPECT().Name().Return("email-code").AnyTimes()
				m.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
				m.EXPECT().Channel().Return(factor.Email).AnyTimes()
				m.EXPECT().SupportsEnrolmentPath().Return(true).AnyTimes()
				m.EXPECT().BeginEnrolmentGeneration(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				h.method = m
			},
			path: httpsec.DefaultEnrolmentBeginPrefix + "/email-code",
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrSameChannel)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.True(t, h.stored(t, s.ID).EnrolmentGeneration.IsZero())
			},
		},
		{
			// The same-channel test is the named method's: an emailed method
			// beside TOTP does not stop a magic-link session enrolling TOTP.
			name:  "a magic-link session begins on TOTP beside an emailed method",
			first: factor.MagicLink,
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				m := NewMockEnroller(gomock.NewController(t))
				m.EXPECT().Name().Return("email-code").AnyTimes()
				m.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
				m.EXPECT().Channel().Return(factor.Email).AnyTimes()
				m.EXPECT().SupportsEnrolmentPath().Return(true).AnyTimes()
				m.EXPECT().BeginEnrolmentGeneration(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				h.extraMethods = []mfa.Method{m}
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				begun(t, out)

				e, ok := h.enrolment(t)
				require.True(t, ok, "TOTP's store holds the pending enrolment")
				assert.Equal(t, e.Generation, h.stored(t, s.ID).EnrolmentGeneration)
			},
		},
		{
			name:  "a begin path naming no enrollable method",
			first: factor.Password,
			path:  httpsec.DefaultEnrolmentBeginPrefix + "/sms",
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
				assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(out.err))
				nothingBegun(t, h, s)
			},
		},
		{
			// The path names the method, and the begin is that method's
			// alone: its store holds the pending enrolment and draws the
			// generation the session records.
			name:  "a begin on another enrollable method",
			first: factor.Password,
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				h.extraMethods = []mfa.Method{renamedTOTP(t, h, "totp-backup", mfa.NewMemoryEnrolmentStore())}
			},
			path: httpsec.DefaultEnrolmentBeginPrefix + "/totp-backup",
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				begun(t, out)

				_, ok := h.enrolment(t)
				assert.False(t, ok, "TOTP's store holds nothing")

				backup := h.extraMethods[0].(renamedTOTPMethod)
				e, ok, err := backup.store.Get(t.Context(), testMFAUser)
				require.NoError(t, err)
				require.True(t, ok, "the named method's store holds the pending enrolment")
				assert.Equal(t, e.Generation, h.stored(t, s.ID).EnrolmentGeneration)
			},
		},
		{
			name:  "an enrolled user",
			first: factor.Password,
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				p, err := h.totp.BeginEnrolment(t.Context(), testMFAUser, enrolUsername)
				require.NoError(t, err)
				require.NoError(t, h.totp.ConfirmEnrolment(t.Context(), testMFAUser, h.codeFor(t, p.Secret)))
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrAlreadyEnrolled)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))

				enrolled, err := h.totp.Enrolled(t.Context(), testMFAUser)
				require.NoError(t, err)
				assert.True(t, enrolled, "the confirmed enrolment is left as it was")
				assert.True(t, h.stored(t, s.ID).EnrolmentGeneration.IsZero())
			},
		},
		{
			name:  "the sixth begin in an hour",
			first: factor.Password,
			before: func(t *testing.T, _ *enrolHarness, c *httpsec.Chain, _ *session.Session) {
				t.Helper()

				for range 5 {
					begun(t, beginOn(t, c))
				}
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrEnrolmentThrottled)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))

				e, ok := h.enrolment(t)
				require.True(t, ok)
				assert.Equal(t, e.Generation, h.stored(t, s.ID).EnrolmentGeneration,
					"nothing was generated: the fifth begin's generation still stands")
			},
		},
		{
			name:  "a limiter that cannot decide",
			first: factor.Password,
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
					Return(true, errors.New("mfaenrolbegin_test: limiter store unreachable"))
				l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)

				h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginLimiter(l)}
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrEnrolmentThrottled)
				nothingBegun(t, h, s)
			},
		},
		{
			// A limiter whose failure is the throttled sentinel itself is
			// still a limiter that could not decide: the refusal keeps the
			// path's own text, not the sentinel's.
			name:  "a limiter that cannot decide, failing with the throttled sentinel itself",
			first: factor.Password,
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, mfa.ErrEnrolmentThrottled)
				l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)

				h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginLimiter(l)}
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrEnrolmentThrottled)
				assert.Equal(t,
					"httpsec: the enrolment limiter could not decide, so the attempt is refused",
					out.err.Error())
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				nothingBegun(t, h, s)
			},
		},
		{
			// Every call is counted, not only failures: each begin generates
			// a secret and can lead to an email. The count survives a caller
			// who hangs up.
			name:  "a consumer limiter sees every begin, keyed by user, under a context that cannot be cancelled",
			first: factor.Password,
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				key := httpsec.EnrolmentBeginThrottleKey(testMFAUser)

				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), key).Return(false, nil)
				l.EXPECT().RecordFailure(gomock.Any(), key).
					DoAndReturn(func(ctx context.Context, _ string) error {
						require.NoError(t, ctx.Err(), "recording is not abandoned with the request")
						return nil
					})

				h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginLimiter(l)}
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, _ *enrolHarness, _ *session.Session, _ served) {
				t.Helper()
				// The limiter double pins the check and the record.
			},
		},
		{
			// The TOTP method refuses a ':' in its account label, since it
			// separates issuer from account in the URI.
			name:  "a username the default label cannot carry",
			first: factor.Password,
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.username = "ana:x"
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				require.Error(t, out.err, "the method refuses the label")
				assert.NotContains(t, out.err.Error(), "ana:x", "the refusal does not quote the username")
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				nothingBegun(t, h, s)
			},
		},
		{
			// WithEnrolmentMethods narrows what the path enrols: a second
			// enrollable method configured beside the named one is refused at
			// its own path, exactly as a method EnableMFA was never given.
			name:  "a method narrowed out by WithEnrolmentMethods",
			first: factor.Password,
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				h.extraMethods = []mfa.Method{renamedTOTP(t, h, "totp-backup", mfa.NewMemoryEnrolmentStore())}
				h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithEnrolmentMethods("totp")}
			},
			path: httpsec.DefaultEnrolmentBeginPrefix + "/totp-backup",
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
				assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(out.err))
				nothingBegun(t, h, s)

				backup := h.extraMethods[0].(renamedTOTPMethod)
				_, ok, err := backup.store.Get(t.Context(), testMFAUser)
				require.NoError(t, err)
				assert.False(t, ok, "the narrowed-out method's own store holds nothing")
			},
		},
		{
			// The path names no enrollable method at all: the limiter double
			// carries no expectations, so any call to it fails the test, and
			// this proves the name is checked before the limiter runs.
			name:  "an unknown method is refused before the limiter runs",
			first: factor.Password,
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				h.enrolOpts = []httpsec.EnrolmentOption{
					httpsec.WithEnrolmentBeginLimiter(NewMockLimiter(gomock.NewController(t))),
				}
			},
			path: httpsec.DefaultEnrolmentBeginPrefix + "/sms",
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
				nothingBegun(t, h, s)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			if tc.prepare != nil {
				tc.prepare(t, h)
			}

			s := h.enrolmentOnly(t, tc.first)
			c := h.chain(t, s)

			if tc.before != nil {
				tc.before(t, h, c, s)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			path := tc.path
			if path == "" {
				path = enrolBeginPath
			}

			tc.assert(t, h, s, serveIn(ctx, t, c, post(ctx, path, tc.body)))
		})
	}
}

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
				assert.Equal(t, mfa.MaxEmailCodeAttempts, attempts(t, h),
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
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentContactResolver(
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
//
// Not rows of TestEnrolmentNotification: its rows complete the enrolment with
// the session store's saves failing.
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
			h.sessions, err = session.New(session.WithStore(
				failingSaves{Store: must.Must(session.NewMemoryStore()), failing: &failing}))
			require.NoError(t, err)

			if tc.emailOff {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEnrolmentEmailConfirmation())
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

// gateWitnesses records which of the steps behind the enrolment gate ran: a
// consumer interceptor after it, the authorizer's rule set, and the
// password-change resolve endpoint.
type gateWitnesses struct {
	consumer   atomic.Bool
	authorizer atomic.Bool
	change     atomic.Bool
}

// passwordResolvePath is where the password-change gate's resolve endpoint
// answers in these tests.
const passwordResolvePath = "/account/password"

// options are the chain options that give each witness something to record.
func (w *gateWitnesses) options(h *enrolHarness) []httpsec.Option {
	consumer := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		w.consumer.Store(true)
		return next(ex)
	})

	everything := authorize.Rule[httpsec.Request]{
		Match: func(httpsec.Request) bool {
			w.authorizer.Store(true)
			return true
		},
		Require: authorize.PermitAll(),
	}

	change := func(*httpsec.Exchange) error {
		w.change.Store(true)
		return nil
	}

	return []httpsec.Option{
		httpsec.EnablePasswordChangeGate(h.sessions,
			httpsec.WithPasswordChangeEndpoint(passwordResolvePath, change)),
		httpsec.RegisterInterceptor(consumer, httpsec.After(httpsec.OrderPasswordChange)),
		httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(h.t)), everything),
	}
}

// TestEnrolmentGate pins what an enrolment-only session may reach: the three
// enrolment endpoints, by POST, and logout. Everything else is refused with an
// enrolment challenge carrying the session, before any step behind the gate
// runs — the verify endpoint and the password-change resolve endpoint
// included.
func TestEnrolmentGate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// state is the session's second-factor state; the zero value is
		// session.MFANone, so every case sets it.
		state session.MFAState

		enrolOpts  []httpsec.EnrolmentOption
		logoutOpts []httpsec.LogoutOption

		request func(ctx context.Context) *http.Request

		// refused marks the rows the gate refuses. Each of them is run again
		// on a chain without the gate, where it must reach what it was
		// addressed to — the handler, or the password-change resolve
		// endpoint: that is what shows the gate, and nothing else on the
		// chain, is doing the refusing.
		refused bool

		// reached asserts, on the chain without the gate, that the request
		// reached what it was addressed to. Nil means the handler, with no
		// refusal.
		reached func(t *testing.T, w *gateWitnesses, out served)

		assert func(t *testing.T, h *enrolHarness, s *session.Session, w *gateWitnesses, out served)
	}

	get := func(path string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request {
			return httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		}
	}

	postTo := func(path, body string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request { return post(ctx, path, body) }
	}

	challenged := func(t *testing.T, _ *enrolHarness, s *session.Session, w *gateWitnesses, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch)
		assert.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)
		require.NotNil(t, ch.Session, "the refusal carries the session, for the consumer to prompt on")
		assert.Equal(t, s.ID, ch.Session.ID)
		assert.Empty(t, ch.Token, "a gate challenges a session that exists, so it issues nothing")
		assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))

		assert.False(t, out.handlerRan, "the handler does not run")
		assert.False(t, w.consumer.Load(), "no consumer interceptor after the gate runs")
		assert.False(t, w.authorizer.Load(), "the authorizer does not run")
		assert.False(t, w.change.Load(), "no password is changed")
	}

	loggedOut := func(t *testing.T, h *enrolHarness, s *session.Session, _ *gateWitnesses, out served) {
		t.Helper()

		require.NoError(t, out.err, "an enrolment-only session can always log out")
		assert.Equal(t, http.StatusOK, out.rec.Code)

		_, err := h.sessions.Load(t.Context(), s.ID)
		require.Error(t, err, "the session is ended, and its handle no longer loads")
	}

	unknownMethod := func(t *testing.T, h *enrolHarness, s *session.Session, w *gateWitnesses, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
		assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(out.err))

		var ch *httpsec.ChallengeError
		assert.NotErrorAs(t, out.err, &ch, "the endpoint refuses it, not the gate")
		assert.False(t, out.handlerRan)
		assert.False(t, w.consumer.Load(), "nothing behind the gate runs")

		_, ok := h.enrolment(t)
		assert.False(t, ok, "nothing is stored")
		assert.True(t, h.stored(t, s.ID).EnrolmentGeneration.IsZero())
	}

	cases := []testCase{
		{
			name:    "a protected route",
			state:   session.MFAEnrolmentPending,
			request: postTo("/invoices", "amount=10"),
			refused: true,
			assert:  challenged,
		},
		{
			name:    "a protected route read by GET",
			state:   session.MFAEnrolmentPending,
			request: get("/invoices"),
			refused: true,
			assert:  challenged,
		},
		{
			name:    "the verify endpoint",
			state:   session.MFAEnrolmentPending,
			request: postTo(testMFAVerifyPath, "code="+testMFACode),
			refused: true,
			reached: func(t *testing.T, _ *gateWitnesses, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrMFAMethodNotUsable,
					"the verify endpoint judges the request, and refuses a method the user has not enrolled on")
			},
			assert: challenged,
		},
		{
			// The MFA begin prefix is a different endpoint from the
			// enrolment path's own begin prefix; the gate confines an
			// enrolment-only session away from it too.
			name:    "the MFA begin endpoint",
			state:   session.MFAEnrolmentPending,
			request: postTo(httpsec.DefaultMFABeginPrefix+"/totp", ""),
			refused: true,
			reached: func(t *testing.T, _ *gateWitnesses, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod,
					"the MFA slot judges the request: totp has no begin step")
			},
			assert: challenged,
		},
		{
			name:    "the password-change resolve endpoint",
			state:   session.MFAEnrolmentPending,
			request: postTo(passwordResolvePath, "password=new"),
			refused: true,
			reached: func(t *testing.T, w *gateWitnesses, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.True(t, w.change.Load(), "the resolve endpoint runs")
			},
			assert: challenged,
		},
		{
			name:    "a GET on the begin path",
			state:   session.MFAEnrolmentPending,
			request: get(enrolBeginPath),
			refused: true,
			assert:  challenged,
		},
		{
			name:    "a GET on the confirm path",
			state:   session.MFAEnrolmentPending,
			request: get(enrolConfirmPath),
			refused: true,
			assert:  challenged,
		},
		{
			// Logout is exempt as a POST alone, as every other exemption is:
			// a GET on its path is a link another site could make the
			// caller follow.
			name:    "a GET on the logout path",
			state:   session.MFAEnrolmentPending,
			request: get(httpsec.DefaultLogoutPath),
			refused: true,
			assert:  challenged,
		},
		{
			// With email confirmation off the endpoint does not exist, so
			// its path is a route like any other.
			name:      "the emailed-code path with email confirmation off",
			state:     session.MFAEnrolmentPending,
			enrolOpts: []httpsec.EnrolmentOption{httpsec.WithoutEnrolmentEmailConfirmation()},
			request:   postTo(enrolEmailPath, "code=123456"),
			refused:   true,
			assert:    challenged,
		},
		{
			// A moved endpoint takes its exemption with it: the default path
			// is then a route like any other.
			name:      "the default begin path once the begin prefix is moved",
			state:     session.MFAEnrolmentPending,
			enrolOpts: []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginPrefix("/account/2fa/start")},
			request:   postTo(enrolBeginPath, ""),
			refused:   true,
			assert:    challenged,
		},
		{
			// Every POST under an enrolment prefix is that endpoint's, so one
			// naming no enrollable method is refused by the endpoint as
			// unknown, rather than challenged by the gate or passed on.
			name:    "a begin path naming no enrollable method",
			state:   session.MFAEnrolmentPending,
			request: postTo(httpsec.DefaultEnrolmentBeginPrefix+"/sms", ""),
			assert:  unknownMethod,
		},
		{
			name:    "the bare begin prefix",
			state:   session.MFAEnrolmentPending,
			request: postTo(httpsec.DefaultEnrolmentBeginPrefix, ""),
			assert:  unknownMethod,
		},
		{
			name:    "a confirm path with an extra segment",
			state:   session.MFAEnrolmentPending,
			request: postTo(enrolConfirmPath+"/x", "code=123456"),
			assert:  unknownMethod,
		},
		{
			name:    "an emailed-code path with an empty segment",
			state:   session.MFAEnrolmentPending,
			request: postTo(httpsec.DefaultEnrolmentEmailConfirmPrefix+"/", "code=123456"),
			assert:  unknownMethod,
		},
		{
			name:    "logout",
			state:   session.MFAEnrolmentPending,
			request: postTo(httpsec.DefaultLogoutPath, ""),
			assert:  loggedOut,
		},
		{
			// EnableMFAEnrolment is applied before EnableLogout, whose path
			// is moved: the gate reads the chain's final logout path at
			// assembly, not whatever was set when it was enabled.
			name:       "a consumer logout path configured after the path",
			state:      session.MFAEnrolmentPending,
			logoutOpts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/session/end")},
			request:    postTo("/session/end", ""),
			assert:     loggedOut,
		},
		{
			name:      "a consumer begin prefix",
			state:     session.MFAEnrolmentPending,
			enrolOpts: []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginPrefix("/account/2fa/start")},
			request:   postTo("/account/2fa/start/totp", ""),
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, w *gateWitnesses, out served) {
				t.Helper()

				begun(t, out)
				assert.False(t, w.consumer.Load(), "the endpoint answers before anything behind the gate")

				_, ok := h.enrolment(t)
				assert.True(t, ok, "a pending enrolment is begun")
			},
		},
		{
			name:    "a session owing nothing",
			state:   session.MFANone,
			request: get("/invoices"),
			assert: func(t *testing.T, _ *enrolHarness, _ *session.Session, _ *gateWitnesses, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.True(t, out.handlerRan, "the gate guards the enrolment-only state alone")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			h.enrolOpts, h.logoutOpts = tc.enrolOpts, tc.logoutOpts

			s := h.sessionIn(t, factor.Password, tc.state)

			w := &gateWitnesses{}
			h.extra = w.options(h)

			tc.assert(t, h, s, w, serve(t, h.chain(t, s), tc.request(t.Context())))
		})

		if !tc.refused {
			continue
		}

		t.Run(tc.name+", without the gate", func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			h.enrolOpts, h.logoutOpts = tc.enrolOpts, tc.logoutOpts
			h.withoutGate = true

			s := h.sessionIn(t, factor.Password, tc.state)

			w := &gateWitnesses{}
			h.extra = w.options(h)

			out := serve(t, h.chain(t, s), tc.request(t.Context()))

			if tc.reached != nil {
				tc.reached(t, w, out)

				return
			}

			require.NoError(t, out.err, "without the gate nothing on the chain refuses this request")
			assert.True(t, out.handlerRan, "without the gate the handler runs")
		})
	}
}

// TestEnrolmentGateAnonymous pins that the gate guards sessions and nothing
// else: a request carrying none is the business of the authentication
// interceptors outside it.
//
// Not a row of TestEnrolmentGate: it carries no session, and builds the chain
// without that table's witnesses.
func TestEnrolmentGateAnonymous(t *testing.T) {
	t.Parallel()

	h := newEnrolHarness(t)

	out := serve(t, h.chain(t, nil),
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil))

	require.NoError(t, out.err)
	assert.True(t, out.handlerRan)
}

// errMailboxRejected is what a synchronous SMTP sender answers when the
// server refuses the recipient: the refusal quotes the address back.
var errMailboxRejected = errors.New("notify: RCPT TO: 550 5.1.1 <" + enrolUsername + ">: recipient rejected")

// errNoSuchUser is a user loader's refusal that names the username, which by
// default is the address.
var errNoSuchUser = errors.New("users: no active user " + enrolUsername)

// errAddressUnusable is a contact or label resolver's refusal that quotes the
// address it would not use.
var errAddressUnusable = errors.New("resolver: " + enrolUsername + " is not deliverable")

// loadingOnce replaces the harness's user loader with one that loads the user
// the first time and answers err on every later call: the begin's label is
// resolved, and whatever loads the user after it fails.
func loadingOnce(t *testing.T, h *enrolHarness, err error) {
	t.Helper()

	var calls atomic.Int32

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), testMFAUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			if calls.Add(1) > 1 {
				return nil, err
			}

			return &identity.Details{ID: testMFAUser, Name: "Ana", Username: h.username, Active: true}, nil
		})

	h.users = users
}

// failingResolver is a contact or label resolver that refuses with err.
func failingResolver(err error) func(context.Context, *identity.Details) (string, error) {
	return func(context.Context, *identity.Details) (string, error) { return "", err }
}

// noRecordCarries asserts that no captured record, message or attribute,
// contains secret.
func noRecordCarries(t *testing.T, logs *capturingHandler, secret string) {
	t.Helper()

	for _, r := range logs.records() {
		assert.NotContains(t, r.Message, secret)

		r.Attrs(func(a slog.Attr) bool {
			assert.NotContains(t, a.Value.String(), secret, "attribute %q", a.Key)
			return true
		})
	}
}

// TestEnrolmentNotificationLogsCarryNoAddress pins that a notification that
// cannot be sent is logged by a fixed reason, never by its cause's text: a
// synchronous sender's refusal, a user loader's and a contact resolver's can
// each quote the address back, and a contact address is never written to a
// log.
//
// Its own table: every row completes an enrolment with email confirmation off
// and reads the log record of the failed notification.
func TestEnrolmentNotificationLogsCarryNoAddress(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		prepare func(t *testing.T, h *enrolHarness, o *outbox)
		reason  string
	}

	cases := []testCase{
		{
			name:    "a sender that refuses the recipient",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) { o.accepting(h, errMailboxRejected) },
			reason:  "send-refused",
		},
		{
			name: "a user loader that cannot load the user",
			prepare: func(t *testing.T, h *enrolHarness, o *outbox) {
				t.Helper()

				loadingOnce(t, h, errNoSuchUser)
				o.accepting(h, nil)
			},
			reason: "user-unloadable",
		},
		{
			name: "a contact resolver that cannot resolve the address",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentContactResolver(failingResolver(errAddressUnusable)))
				o.accepting(h, nil)
			},
			reason: "contact-unresolved",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			o := &outbox{}
			logs := &capturingHandler{}

			h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEnrolmentEmailConfirmation())
			h.extra = append(h.extra, httpsec.WithLogger(slog.New(logs)))
			tc.prepare(t, h, o)

			s := h.enrolmentOnly(t, factor.Password)
			c := h.chain(t, s)
			secret := h.begin(t, c)

			out := serve(t, c, post(t.Context(), enrolConfirmPath, "code="+h.codeFor(t, secret)))
			require.NoError(t, out.err, "the enrolment stands, told or not")
			noRecordCarries(t, logs, enrolUsername)

			var found bool

			for _, r := range logs.records() {
				if r.Message != "httpsec: the user could not be notified of a completed enrolment" {
					continue
				}

				found = true

				reason, ok := attrValue(r, "reason")
				require.True(t, ok, "the record names why")
				assert.Equal(t, tc.reason, reason.String())
			}

			require.True(t, found, "the failure is logged")
		})
	}
}

// TestEnrolmentRefusalsCarryNoAddress pins that an enrolment refusal a
// consumer's error handler may log carries a fixed text of the library's own,
// never its cause's: a loader, a resolver, the method's label check and a
// synchronous sender can each quote the username or the address. The cause
// stays reachable through errors.Is, so its status and the consumer's own
// mapping are unchanged.
//
// Not rows of TestEnrolmentOutagesCarryNoAddress: its rows prepare the harness
// and the outbox themselves, over the harness's own stores.
func TestEnrolmentRefusalsCarryNoAddress(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		prepare func(t *testing.T, h *enrolHarness, o *outbox)

		// confirm runs a begin and then a confirm with a valid code, rather
		// than a begin alone.
		confirm bool

		// leaked is what the refusal must not carry.
		leaked string

		assert func(t *testing.T, err error)
	}

	is := func(target error) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.ErrorIs(t, err, target, "the cause is still reachable")
		}
	}

	// undecided is a limiter that cannot decide, and quotes the bucket key
	// and the address back as it refuses.
	undecided := func(t *testing.T) *MockLimiter {
		t.Helper()

		l := NewMockLimiter(gomock.NewController(t))
		l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).AnyTimes().
			DoAndReturn(func(_ context.Context, key string) (bool, error) {
				return false, errors.New("limiter: cannot read " + key + " for " + enrolUsername)
			})
		l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		return l
	}

	throttled := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, mfa.ErrEnrolmentThrottled)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err))
		assert.NotContains(t, err.Error(), string(testMFAUser), "nor the user reference")
	}

	cases := []testCase{
		{
			name: "a begin limiter that cannot decide",
			prepare: func(t *testing.T, h *enrolHarness, _ *outbox) {
				t.Helper()

				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentBeginLimiter(undecided(t)))
			},
			leaked: enrolUsername,
			assert: throttled,
		},
		{
			name: "a confirmation limiter that cannot decide",
			prepare: func(t *testing.T, h *enrolHarness, o *outbox) {
				t.Helper()

				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentConfirmLimiter(undecided(t)))
				o.accepting(h, nil)
			},
			confirm: true,
			leaked:  enrolUsername,
			assert:  throttled,
		},
		{
			name: "a begin whose user cannot be loaded",
			prepare: func(t *testing.T, h *enrolHarness, _ *outbox) {
				t.Helper()

				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), testMFAUser).Return(nil, errNoSuchUser).AnyTimes()
				h.users = users
			},
			leaked: enrolUsername,
			assert: is(errNoSuchUser),
		},
		{
			name: "a begin whose label cannot be resolved",
			prepare: func(_ *testing.T, h *enrolHarness, _ *outbox) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentLabelResolver(failingResolver(errAddressUnusable)))
			},
			leaked: enrolUsername,
			assert: is(errAddressUnusable),
		},
		{
			name:    "a begin whose label the method refuses",
			prepare: func(_ *testing.T, h *enrolHarness, _ *outbox) { h.username = "ana:x@example.com" },
			leaked:  "ana:x@example.com",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "a confirm whose user cannot be loaded",
			prepare: func(t *testing.T, h *enrolHarness, o *outbox) {
				t.Helper()

				loadingOnce(t, h, errNoSuchUser)
				o.accepting(h, nil)
			},
			confirm: true,
			leaked:  enrolUsername,
			assert:  is(errNoSuchUser),
		},
		{
			name: "a confirm whose contact cannot be resolved",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentContactResolver(failingResolver(errAddressUnusable)))
				o.accepting(h, nil)
			},
			confirm: true,
			leaked:  enrolUsername,
			assert:  is(errAddressUnusable),
		},
		{
			name: "a confirm whose code the sender refuses to send",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) {
				o.accepting(h, errMailboxRejected)
			},
			confirm: true,
			leaked:  enrolUsername,
			assert:  is(errMailboxRejected),
		},
		{
			name: "a confirm whose code cannot be queued",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) {
				o.accepting(h, notify.ErrQueueFull)
			},
			confirm: true,
			leaked:  enrolUsername,
			assert:  is(notify.ErrQueueFull),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			o := &outbox{}
			tc.prepare(t, h, o)

			s := h.enrolmentOnly(t, factor.Password)
			c := h.chain(t, s)

			out := serve(t, c, post(t.Context(), enrolBeginPath, ""))

			if tc.confirm {
				require.NoError(t, out.err)

				var body beginBody
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))

				out = serve(t, c, post(t.Context(), enrolConfirmPath,
					"code="+h.codeFor(t, body.Secret)))
			}

			tc.assert(t, out.err)
			assert.NotContains(t, out.err.Error(), tc.leaked, "the refusal's text carries no address")
			assert.False(t, strings.Contains(out.err.Error(), "@"), "nor anything that looks like one")
		})
	}
}

// TestEnrolmentLimiterLogsCarryNoUser pins that a limiter that cannot record
// an attempt is logged by a fixed reason, never by its error's text: a
// consumer's limiter may quote the bucket key back, and the key carries the
// user reference, which a deployment may have made the address.
//
// Its own table: every row wires a failing mocked limiter, then serves a begin
// and a wrong code.
func TestEnrolmentLimiterLogsCarryNoUser(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// limit wires the failing limiter l into the enrolment options.
		limit func(l *MockLimiter) httpsec.EnrolmentOption

		// path is where the request under test is posted.
		path string

		limiter string
	}

	cases := []testCase{
		{
			name:    "the begin limiter",
			limit:   func(l *MockLimiter) httpsec.EnrolmentOption { return httpsec.WithEnrolmentBeginLimiter(l) },
			path:    enrolBeginPath,
			limiter: "begin",
		},
		{
			name:    "the confirmation limiter",
			limit:   func(l *MockLimiter) httpsec.EnrolmentOption { return httpsec.WithEnrolmentConfirmLimiter(l) },
			path:    enrolConfirmPath,
			limiter: "confirm",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			logs := &capturingHandler{}

			l := NewMockLimiter(gomock.NewController(t))
			l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
			l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, key string) error {
					return errors.New("limiter: cannot write " + key + " for " + enrolUsername)
				})

			h.enrolOpts = append(h.enrolOpts, tc.limit(l))
			h.extra = append(h.extra, httpsec.WithLogger(slog.New(logs)))

			s := h.enrolmentOnly(t, factor.Password)
			c := h.chain(t, s)

			// A wrong code, which the confirmation limiter records; the begin
			// limiter records every begin.
			serve(t, c, post(t.Context(), enrolBeginPath, ""))
			serve(t, c, post(t.Context(), tc.path, "code=000000"))

			noRecordCarries(t, logs, enrolUsername)
			noRecordCarries(t, logs, string(testMFAUser))

			var found bool

			for _, r := range logs.records() {
				if r.Message != "httpsec: an enrolment attempt could not be recorded" {
					continue
				}

				found = true

				reason, ok := attrValue(r, "reason")
				require.True(t, ok, "the record names why")
				assert.Equal(t, "limiter-unavailable", reason.String())

				limiter, ok := attrValue(r, "limiter")
				require.True(t, ok, "the record names the limiter")
				assert.Equal(t, tc.limiter, limiter.String())
			}

			require.True(t, found, "the failure is logged")
		})
	}
}

// errStoreLeaky is a dependency's failure that quotes the user reference and
// the address back, as a durable store's or a driver's error may.
var errStoreLeaky = errors.New("store: write for user " + string(testMFAUser) + " <" + enrolUsername + "> failed")

// leakyEnrolmentStore is the in-memory enrolment store with any of its writes
// replaced by a failure: each field, when set, is what that write answers.
type leakyEnrolmentStore struct {
	*mfa.MemoryEnrolmentStore

	putPending, prove, complete error
}

func (s leakyEnrolmentStore) PutPending(ctx context.Context, e mfa.Enrolment) error {
	if s.putPending != nil {
		return s.putPending
	}

	return s.MemoryEnrolmentStore.PutPending(ctx, e)
}

func (s leakyEnrolmentStore) ProveDevice(
	ctx context.Context, user identity.UserID, gen id.ID, step int64, code []byte, codeUntil, at time.Time,
) (bool, error) {
	if s.prove != nil {
		return false, s.prove
	}

	return s.MemoryEnrolmentStore.ProveDevice(ctx, user, gen, step, code, codeUntil, at)
}

func (s leakyEnrolmentStore) Complete(ctx context.Context, user identity.UserID, gen id.ID, at time.Time) (bool, error) {
	if s.complete != nil {
		return false, s.complete
	}

	return s.MemoryEnrolmentStore.Complete(ctx, user, gen, at)
}

// failingSaves is a session store whose Save answers errStoreLeaky once
// failing is set, and behaves as the in-memory store otherwise.
type failingSaves struct {
	session.Store

	failing *atomic.Bool
}

func (s failingSaves) Save(ctx context.Context, sess *session.Session) error {
	if s.failing.Load() {
		return errStoreLeaky
	}

	return s.Store.Save(ctx, sess)
}

// TestEnrolmentOutagesCarryNoAddress pins that every error the enrolment path
// returns carries fixed text of the library's own, including a store's, a
// session store's and a method's failure, and a store's refusal that wraps a
// library sentinel in text of its own: each of them can quote the user
// reference or the address. The cause and any sentinel stay reachable through
// errors.Is, so the status is unchanged.
//
// Its own table: its rows rebuild the TOTP method over a leaky enrolment store
// and the session manager over failing saves.
func TestEnrolmentOutagesCarryNoAddress(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// store is the enrolment store the TOTP method is built over.
		store func(mem *mfa.MemoryEnrolmentStore) leakyEnrolmentStore

		// emailOff turns email confirmation off, so a proof completes.
		emailOff bool

		// confirm runs a begin and then a confirm with a valid code, rather
		// than a begin alone.
		confirm bool

		// failSave makes the session store's saves fail from the request
		// under test on.
		failSave bool

		// failWrite answers the request under test through a writer whose
		// transport has gone.
		failWrite bool

		assert func(t *testing.T, err error)
	}

	answers := func(target error, status int) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.ErrorIs(t, err, target, "the cause is still reachable")
			assert.Equal(t, status, httpsec.StatusForError(err), "the status is unchanged")
		}
	}

	plain := func(mem *mfa.MemoryEnrolmentStore) leakyEnrolmentStore {
		return leakyEnrolmentStore{MemoryEnrolmentStore: mem}
	}

	cases := []testCase{
		{
			name: "a begin whose store refuses as already enrolled, in its own words",
			store: func(mem *mfa.MemoryEnrolmentStore) leakyEnrolmentStore {
				return leakyEnrolmentStore{MemoryEnrolmentStore: mem,
					putPending: fmt.Errorf("%w: %w", errStoreLeaky, mfa.ErrAlreadyEnrolled)}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				answers(mfa.ErrAlreadyEnrolled, http.StatusForbidden)(t, err)
				require.ErrorIs(t, err, errStoreLeaky)
			},
		},
		{
			// The transport's failure names the connection's addresses.
			name:      "a begin whose answer the transport cannot write",
			store:     plain,
			failWrite: true,
			assert: func(t *testing.T, err error) {
				t.Helper()

				answers(errTransportReset, http.StatusInternalServerError)(t, err)
				assert.NotContains(t, err.Error(), transportPeer, "the error's text carries no address")
			},
		},
		{
			name:     "a begin whose session cannot be saved",
			store:    plain,
			failSave: true,
			assert:   answers(errStoreLeaky, http.StatusInternalServerError),
		},
		{
			name: "a confirm whose proof the store cannot write",
			store: func(mem *mfa.MemoryEnrolmentStore) leakyEnrolmentStore {
				return leakyEnrolmentStore{MemoryEnrolmentStore: mem, prove: errStoreLeaky}
			},
			confirm: true,
			assert:  answers(errStoreLeaky, http.StatusInternalServerError),
		},
		{
			name: "a confirm whose proof the store refuses as a wrong code, in its own words",
			store: func(mem *mfa.MemoryEnrolmentStore) leakyEnrolmentStore {
				return leakyEnrolmentStore{MemoryEnrolmentStore: mem,
					prove: fmt.Errorf("%w: %w", errStoreLeaky, mfa.ErrInvalidCode)}
			},
			confirm: true,
			assert:  answers(mfa.ErrInvalidCode, http.StatusUnauthorized),
		},
		{
			name: "a confirm whose completion the store cannot write",
			store: func(mem *mfa.MemoryEnrolmentStore) leakyEnrolmentStore {
				return leakyEnrolmentStore{MemoryEnrolmentStore: mem, complete: errStoreLeaky}
			},
			emailOff: true,
			confirm:  true,
			assert:   answers(errStoreLeaky, http.StatusInternalServerError),
		},
		{
			name:     "a confirm whose upgraded session cannot be saved",
			store:    plain,
			emailOff: true,
			confirm:  true,
			failSave: true,
			assert:   answers(errStoreLeaky, http.StatusInternalServerError),
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
			h.sessions, err = session.New(session.WithStore(
				failingSaves{Store: must.Must(session.NewMemoryStore()), failing: &failing}))
			require.NoError(t, err)

			h.totp, err = mfa.NewTOTP(tc.store(h.store), enrolIssuer,
				mfa.WithClock(h.clock))
			require.NoError(t, err)

			h.method = h.totp

			if tc.emailOff {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEnrolmentEmailConfirmation())
			}

			s := h.enrolmentOnly(t, factor.Password)
			c := h.chain(t, s)

			var out served

			if tc.confirm {
				secret := h.begin(t, c)
				failing.Store(tc.failSave)

				out = serve(t, c, post(t.Context(), enrolConfirmPath,
					"code="+h.codeFor(t, secret)))
			} else {
				failing.Store(tc.failSave)

				req := post(t.Context(), enrolBeginPath, "")
				if tc.failWrite {
					out = serveThrough(t, c, req, brokenWriter{})
				} else {
					out = serve(t, c, req)
				}
			}

			tc.assert(t, out.err)
			assert.NotContains(t, out.err.Error(), enrolUsername, "the error's text carries no address")
			assert.NotContains(t, out.err.Error(), string(testMFAUser), "nor the user reference")
		})
	}
}

// brokenWriter is a response writer whose connection has gone: every write
// fails with the transport's own error, which quotes the peer's address.
type brokenWriter struct{}

func (brokenWriter) SetHeader(string, string)  {}
func (brokenWriter) SetCookie(*httpsec.Cookie) {}
func (brokenWriter) WriteHeader(int)           {}
func (brokenWriter) Write([]byte) (int, error) { return 0, errTransportReset }

// serveThrough runs req through chain, answering through w.
func serveThrough(t *testing.T, chain *httpsec.Chain, req *http.Request, w httpsec.ResponseWriter) served {
	t.Helper()

	out := served{rec: httptest.NewRecorder()}
	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	out.err = run(httpsec.NewExchange(req.Context(), httpsec.NewHTTPRequest(req), w))

	return out
}

// The records the enrolment path writes, as a consumer's log pipeline would
// match them.
const (
	msgEnrolmentRefused     = "httpsec: an enrolment request was refused"
	msgEnrolmentSuppressed  = "httpsec: enrolment logs suppressed"
	msgEnrolmentNotRecorded = "httpsec: an enrolment attempt could not be recorded"
	msgVerifyThrottled      = "mfa: verification throttled"
)

// recordsNamed is every captured record with message msg.
func recordsNamed(logs *capturingHandler, msg string) []slog.Record {
	var out []slog.Record

	for _, r := range logs.records() {
		if r.Message == msg {
			out = append(out, r)
		}
	}

	return out
}

// withReason is those of recs whose reason attribute is reason.
func withReason(recs []slog.Record, reason string) []slog.Record {
	var out []slog.Record

	for _, r := range recs {
		if v, ok := attrValue(r, "reason"); ok && v.String() == reason {
			out = append(out, r)
		}
	}

	return out
}

// beginsPastTheLimit spends the default begin budget of five and then begins n
// more times, each refused as throttled.
func beginsPastTheLimit(t *testing.T, c *httpsec.Chain, n int) {
	t.Helper()

	for range 5 {
		require.NoError(t, serve(t, c, post(t.Context(), enrolBeginPath, "")).err)
	}

	for range n {
		out := serve(t, c, post(t.Context(), enrolBeginPath, ""))
		require.ErrorIs(t, out.err, mfa.ErrEnrolmentThrottled)
	}
}

// TestEnrolmentLogs pins what the enrolment path writes to the chain's
// logger: every refusal of an enrolment endpoint is recorded by a fixed
// reason, through a sampler of the path's own whose window is one minute by
// default and set by WithEnrolmentLogInterval alone, with a reporter for what
// it held back; and no record, the path's or the TOTP method's, carries a
// code, a secret, a provisioning URI or an address — nor, in the path's own
// records, the user reference.
//
// Its own table: its rows drive the chain themselves and read both the chain's
// log and the method's.
func TestEnrolmentLogs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// prepare wires the harness before the chain is built.
		prepare func(t *testing.T, h *enrolHarness)

		// run drives the chain and returns what the records must not carry.
		run func(t *testing.T, h *enrolHarness, c *httpsec.Chain, o *outbox) []string

		assert func(t *testing.T, logs, methodLogs *capturingHandler)
	}

	cases := []testCase{
		{
			name: "a run through begin, proof and refused codes",
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentLogInterval(0))
			},
			run: func(t *testing.T, h *enrolHarness, c *httpsec.Chain, o *outbox) []string {
				t.Helper()

				doc := h.beginDoc(t, c)
				emailed := h.prove(t, c, o, doc.Secret)
				wrong := otherCode(emailed)

				// A device code after the proof, which the proof already
				// spent; a wrong emailed code; and a malformed one.
				device := h.codeFor(t, doc.Secret)
				require.ErrorIs(t, serve(t, c, post(t.Context(), enrolConfirmPath,
					"code="+device)).err, mfa.ErrInvalidCode)
				require.ErrorIs(t, serve(t, c, emailCodeRequest(t.Context(), wrong)).err, mfa.ErrEmailCodeInvalid)
				require.ErrorIs(t, serve(t, c, emailCodeRequest(t.Context(), " "+emailed)).err,
					mfa.ErrEmailCodeInvalid)

				return []string{doc.Secret, doc.URI, emailed, wrong, device, enrolUsername}
			},
			assert: func(t *testing.T, logs, _ *capturingHandler) {
				t.Helper()

				refused := recordsNamed(logs, msgEnrolmentRefused)
				assert.Len(t, withReason(refused, "invalid-code"), 1, "the spent device code")
				assert.Len(t, withReason(refused, "email-code-invalid"), 2, "the two emailed codes")

				for _, r := range refused {
					endpoint, ok := attrValue(r, "endpoint")
					require.True(t, ok, "the record names the endpoint")
					assert.Contains(t, []string{"confirm", "confirm-email"}, endpoint.String())
				}

				noRecordCarries(t, logs, string(testMFAUser))
			},
		},
		{
			name: "an interval of zero writes every enrolment refusal",
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentLogInterval(0))
			},
			run: func(t *testing.T, h *enrolHarness, c *httpsec.Chain, _ *outbox) []string {
				t.Helper()

				beginsPastTheLimit(t, c, 20)

				// Verification of another session is throttled on the same
				// logger, under its own default window. The user is enrolled,
				// so each wrong code is a guess the throttle counts: a method
				// the user may not use is refused before anything is counted.
				p, err := h.totp.BeginEnrolment(t.Context(), testMFAUser, enrolUsername)
				require.NoError(t, err)
				require.NoError(t, h.totp.ConfirmEnrolment(t.Context(), testMFAUser, h.codeFor(t, p.Secret)))

				wrong := h.wrongCodeFor(t, p.Secret)
				pending := h.chain(t, h.sessionIn(t, factor.Password, session.MFAPending))

				for n := range 25 {
					out := serve(t, pending, post(t.Context(), testMFAVerifyPath, "code="+wrong))
					if n >= 5 {
						require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
					}
				}

				return []string{enrolUsername}
			},
			assert: func(t *testing.T, logs, _ *capturingHandler) {
				t.Helper()

				assert.Len(t, withReason(recordsNamed(logs, msgEnrolmentRefused), "throttled"), 20,
					"every enrolment refusal is written")
				assert.Len(t, recordsNamed(logs, msgVerifyThrottled), 1,
					"verification throttle records stay sampled")
			},
		},
		{
			// The chain's own flush is what a consumer calls at shutdown, and
			// it drains the enrolment path's window with the chain's.
			name: "a long window writes one record, and the chain's flush reports the rest",
			prepare: func(_ *testing.T, h *enrolHarness) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentLogInterval(time.Hour))
			},
			run: func(t *testing.T, _ *enrolHarness, c *httpsec.Chain, _ *outbox) []string {
				t.Helper()

				beginsPastTheLimit(t, c, 20)
				require.NoError(t, c.FlushRefusalLogs())

				return []string{enrolUsername}
			},
			assert: func(t *testing.T, logs, _ *capturingHandler) {
				t.Helper()

				assert.Len(t, withReason(recordsNamed(logs, msgEnrolmentRefused), "throttled"), 1)

				reports := recordsNamed(logs, msgEnrolmentSuppressed)
				require.Len(t, reports, 1, "what the window held back is reported")

				suppressed, ok := attrValue(reports[0], "suppressed")
				require.True(t, ok)
				assert.Equal(t, int64(19), suppressed.Int64())

				key, ok := attrValue(reports[0], "key")
				require.True(t, ok)
				assert.True(t, strings.Contains(key.String(), "throttled"), "the key names the reason")

				noRecordCarries(t, logs, string(testMFAUser))
			},
		},
		{
			name: "a limiter that cannot record is sampled too",
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
				l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
					Return(errors.New("mfaenrollogs_test: limiter store unreachable"))

				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentConfirmLimiter(l))
			},
			run: func(t *testing.T, h *enrolHarness, c *httpsec.Chain, _ *outbox) []string {
				t.Helper()

				secret := h.beginDoc(t, c).Secret

				for range 3 {
					out := serve(t, c, post(t.Context(), enrolConfirmPath,
						"code="+h.wrongCodeFor(t, secret)))
					require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				}

				return []string{enrolUsername}
			},
			assert: func(t *testing.T, logs, _ *capturingHandler) {
				t.Helper()

				assert.Len(t, recordsNamed(logs, msgEnrolmentNotRecorded), 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			o := &outbox{}
			o.accepting(h, nil)

			logs, methodLogs := &capturingHandler{}, &capturingHandler{}
			h.extra = append(h.extra, httpsec.WithLogger(slog.New(logs)))

			var err error
			h.totp, err = mfa.NewTOTP(h.store, enrolIssuer,
				mfa.WithClock(h.clock), mfa.WithLogger(slog.New(methodLogs)))
			require.NoError(t, err)

			h.method = h.totp

			if tc.prepare != nil {
				tc.prepare(t, h)
			}

			c := h.chain(t, h.enrolmentOnly(t, factor.Password))

			for _, secret := range tc.run(t, h, c, o) {
				noRecordCarries(t, logs, secret)
				noRecordCarries(t, methodLogs, secret)
			}

			tc.assert(t, logs, methodLogs)
		})
	}
}

// errChargeOutage is the failure of a store that cannot charge an emailed
// code's attempt; its text names the user, as a store's may.
var errChargeOutage = errors.New("mfaenrollogs_test: cannot charge u-1")

// chargeOutageStore is the in-memory store with its charge out of service.
type chargeOutageStore struct{ *mfa.MemoryEnrolmentStore }

func (chargeOutageStore) ChargeEmailCode(context.Context, identity.UserID, id.ID, time.Time) (int, bool, error) {
	return 0, false, errChargeOutage
}

// completingEnroller is a broken method: it completes the enrolment on any
// emailed code presented, the never-matching one voiding presents included.
type completingEnroller struct{ *mfa.TOTP }

func (completingEnroller) RedeemEmailCode(context.Context, identity.UserID, id.ID, string) error {
	return nil
}

// TestEnrolmentVoidFailureLogged pins what happens when the sender refuses to
// queue the emailed code and the code then cannot be voided, because the store
// cannot charge or the method is broken: the request still fails with the send
// failure's fixed text, and the voiding failure is logged by a fixed reason,
// never by its own text. It is a table of its own because its sender refuses
// and its method is replaced, which TestEnrolmentLogs does not wire.
//
// Its own table: its rows vary the method, under a sender that refuses to
// queue.
func TestEnrolmentVoidFailureLogged(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// method builds the method the chain is given, from the harness.
		method func(t *testing.T, h *enrolHarness) mfa.Method

		// hidden is failure text no record may carry.
		hidden string

		// cause, when set, is the voiding failure the request must not answer
		// with.
		cause error
	}

	cases := []testCase{
		{
			name: "a store that cannot charge",
			method: func(t *testing.T, h *enrolHarness) mfa.Method {
				t.Helper()

				var err error
				h.totp, err = mfa.NewTOTP(chargeOutageStore{h.store}, enrolIssuer,
					mfa.WithClock(h.clock))
				require.NoError(t, err)

				return h.totp
			},
			hidden: errChargeOutage.Error(),
			cause:  errChargeOutage,
		},
		{
			name: "a method that completes on the never-matching code",
			method: func(_ *testing.T, h *enrolHarness) mfa.Method {
				return completingEnroller{h.totp}
			},
			hidden: "voiding the emailed code completed the enrolment",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			o := &outbox{}
			o.accepting(h, notify.ErrQueueFull)

			logs := &capturingHandler{}
			h.extra = append(h.extra, httpsec.WithLogger(slog.New(logs)))

			h.method = tc.method(t, h)

			c := h.chain(t, h.enrolmentOnly(t, factor.Password))
			secret := h.beginDoc(t, c).Secret

			out := serve(t, c, post(t.Context(), enrolConfirmPath, "code="+h.codeFor(t, secret)))
			require.ErrorIs(t, out.err, notify.ErrQueueFull, "the send failure is what the request answers")
			assert.Equal(t, "httpsec: the enrolment message could not be sent", out.err.Error())

			if tc.cause != nil {
				require.NotErrorIs(t, out.err, tc.cause, "the voiding failure does not mask it")
			}

			notVoided := withReason(recordsNamed(logs, "httpsec: an undelivered enrolment code could not be voided"),
				"not-voided")
			require.Len(t, notVoided, 1, "the voiding failure is logged by a fixed reason")

			errType, ok := attrValue(notVoided[0], "error_type")
			require.True(t, ok, "the record must carry the voiding failure's Go type, "+
				"never its text")
			assert.Equal(t, "*errors.errorString", errType.String())

			noRecordCarries(t, logs, tc.hidden)
			noRecordCarries(t, logs, string(testMFAUser))
			noRecordCarries(t, logs, lastEmailedCode(t, o))
		})
	}
}

// TestEnrolmentRefusalRecordCarriesErrorType pins what the enrolment path's
// general refusal record ("httpsec: an enrolment request was refused")
// carries beyond the fixed reason: the failed dependency's Go type when a
// dependency answered the refusal, and no error type at all when the refusal
// is the library's own decision, with no dependency error behind it.
//
// Its own table: its rows vary the first factor and the begin path, and read
// the error type on the refusal record.
func TestEnrolmentRefusalRecordCarriesErrorType(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		first   factor.Kind
		prepare func(t *testing.T, h *enrolHarness)

		// path is where the begin is posted: TOTP's begin path unless a
		// case names another method.
		path string

		reason  string
		hasType bool
	}

	cases := []testCase{
		{
			name:  "a limiter outage is a dependency failure",
			first: factor.Password,
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
					Return(true, errors.New("mfaenrollogs_test: limiter store unreachable"))
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentBeginLimiter(l))
			},
			reason:  "limiter-unavailable",
			hasType: true,
		},
		{
			// A magic-link login arrived by email; a second factor emailed too
			// would be the same factor twice. No dependency is asked before
			// this refusal.
			name:  "the same-channel refusal is the library's own decision",
			first: factor.MagicLink,
			prepare: func(t *testing.T, h *enrolHarness) {
				t.Helper()

				m := NewMockEnroller(gomock.NewController(t))
				m.EXPECT().Name().Return("email-code").AnyTimes()
				m.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
				m.EXPECT().Channel().Return(factor.Email).AnyTimes()
				m.EXPECT().SupportsEnrolmentPath().Return(true).AnyTimes()
				m.EXPECT().BeginEnrolmentGeneration(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				h.method = m
			},
			path:    httpsec.DefaultEnrolmentBeginPrefix + "/email-code",
			reason:  "same-channel",
			hasType: false,
		},
		{
			name:    "a path naming no enrollable method is the library's own decision",
			first:   factor.Password,
			prepare: func(*testing.T, *enrolHarness) {},
			path:    httpsec.DefaultEnrolmentBeginPrefix + "/sms",
			reason:  "unknown-method",
			hasType: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			logs := &capturingHandler{}
			h.extra = append(h.extra, httpsec.WithLogger(slog.New(logs)))

			tc.prepare(t, h)

			path := tc.path
			if path == "" {
				path = enrolBeginPath
			}

			c := h.chain(t, h.enrolmentOnly(t, tc.first))
			serve(t, c, post(t.Context(), path, ""))

			refused := withReason(recordsNamed(logs, msgEnrolmentRefused), tc.reason)
			require.Len(t, refused, 1, "the refusal is recorded under its reason")

			_, ok := attrValue(refused[0], "error_type")
			assert.Equal(t, tc.hasType, ok,
				"a dependency-caused refusal must carry the cause's Go type; "+
					"a library refusal with no dependency behind it must not")
		})
	}
}

// moveTo sets the harness's timeline, shared by the session manager, its store
// and the TOTP method, to at.
func moveTo(h *enrolHarness, at time.Time) { h.clock.Advance(at.Sub(h.clock.Now())) }

// failingCreates is a session store whose inserts, Create and Supersede,
// answer errStoreLeaky once failing is set, and which behaves as the store it
// wraps otherwise.
type failingCreates struct {
	session.Store

	failing *atomic.Bool
}

func (s failingCreates) Create(ctx context.Context, sess *session.Session) error {
	if s.failing.Load() {
		return errStoreLeaky
	}

	return s.Store.Create(ctx, sess)
}

func (s failingCreates) Supersede(ctx context.Context, op session.Supersession) error {
	if s.failing.Load() {
		return errStoreLeaky
	}

	return s.Store.Supersede(ctx, op)
}

// upgradeDay is the morning the enrolment timelines run on.
var upgradeDay = time.Date(2026, time.September, 28, 0, 0, 0, 0, time.UTC)

// clockAt is hh:mm on upgradeDay.
func clockAt(hh, mm int) time.Time {
	return upgradeDay.Add(time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute)
}

// onTimeline rebuilds the harness's session manager and TOTP method on one
// shared clock, starting at 09:00, with a 12-hour absolute timeout. Inserts
// into the session store, Create and the Supersede a rotation writes through,
// fail while failing is set.
func onTimeline(t *testing.T, h *enrolHarness, failing *atomic.Bool) {
	t.Helper()

	// A fresh fake rather than a move: the timeline's instants are UTC, and a
	// move would keep the harness clock's location.
	h.clock = clockwork.NewFakeClockAt(clockAt(9, 0))

	store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(h.clock)))

	var err error
	h.sessions, err = session.New(
		session.WithStore(failingCreates{Store: store, failing: failing}),
		session.WithClock(h.clock),
		session.WithAbsoluteTimeout(12*time.Hour),
	)
	require.NoError(t, err)

	h.totp, err = mfa.NewTOTP(h.store, enrolIssuer, mfa.WithClock(h.clock))
	require.NoError(t, err)

	h.method = h.totp
}

// issuedFor records the session identifier every token was issued for.
func issuedFor(h *enrolHarness) *atomic.Value {
	var issued atomic.Value

	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			issued.Store(id)

			return "token-for-" + id, nil
		})

	return &issued
}

// TestVerifyUpgradesEnrolmentSession pins the last step of the path: a session
// that entered it at 09:00, with its absolute deadline lowered to 09:15,
// becomes a full session only by verifying a fresh code at the verify
// endpoint, which restores the deadline it would have had and rotates it; a
// session already past its lowered deadline is refused as ended and never
// rotated, and a rotation that fails leaves it exactly as it was.
func TestVerifyUpgradesEnrolmentSession(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// before runs after the emailed code was redeemed at 09:08, and before
		// the verification.
		before func(t *testing.T, h *enrolHarness, s *session.Session, failing *atomic.Bool)

		assert func(t *testing.T, h *enrolHarness, s *session.Session, issued *atomic.Value, out served)
	}

	// untouched is a refusal that changed nothing: the pinned session is as
	// verification found it, and no credential was issued.
	untouched := func(t *testing.T, h *enrolHarness, issued *atomic.Value) {
		t.Helper()

		assert.Nil(t, issued.Load(), "no credential is issued")

		kept := h.pinned
		assert.Equal(t, session.MFAPending, kept.MFA, "the challenge stays pending")
		assert.True(t, kept.MFASatisfiedAt.IsZero())
		assert.Equal(t, clockAt(9, 15), kept.AbsoluteExpiresAt, "the lowered deadline stays")
		assert.Equal(t, clockAt(21, 0), kept.EnrolmentOriginDeadline, "the marker stays")
		assert.False(t, kept.EnrolmentGeneration.IsZero(), "the generation stays")
	}

	cases := []testCase{
		{
			name: "a fresh code at 09:09",
			before: func(_ *testing.T, h *enrolHarness, _ *session.Session, _ *atomic.Bool) {
				moveTo(h, clockAt(9, 9))
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, issued *atomic.Value, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)

				id, ok := issued.Load().(string)
				require.True(t, ok, "a credential is issued")
				require.NotEqual(t, s.ID, id, "for the rotated session")

				rotated := h.stored(t, id)
				assert.Equal(t, session.MFASatisfied, rotated.MFA)
				assert.Equal(t, clockAt(21, 0), rotated.AbsoluteExpiresAt,
					"the deadline a login at 09:00 would have had")
				assert.Equal(t, clockAt(9, 39), rotated.IdleExpiresAt,
					"the default 30-minute idle deadline, counted from the verification at 09:09")
				assert.True(t, rotated.EnrolmentOriginDeadline.IsZero(), "the marker is cleared")
				assert.True(t, rotated.EnrolmentGeneration.IsZero(), "the generation is cleared")

				_, err := h.sessions.Load(t.Context(), s.ID)
				require.Error(t, err, "the old handle no longer loads")
			},
		},
		{
			// A session the store loaded at 09:14 reaches verification at
			// 09:16, past the deadline it was lowered to.
			name: "a session past its lowered deadline",
			before: func(t *testing.T, h *enrolHarness, s *session.Session, _ *atomic.Bool) {
				t.Helper()

				moveTo(h, clockAt(9, 14))
				h.pinned = h.stored(t, s.ID)
				moveTo(h, clockAt(9, 16))
			},
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, issued *atomic.Value, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired, "the session has ended")
				require.ErrorIs(t, out.err, session.ErrExpired)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				untouched(t, h, issued)
			},
		},
		{
			name: "a rotation that fails",
			before: func(t *testing.T, h *enrolHarness, s *session.Session, failing *atomic.Bool) {
				t.Helper()

				moveTo(h, clockAt(9, 9))
				h.pinned = h.stored(t, s.ID)
				failing.Store(true)
			},
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, issued *atomic.Value, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, errStoreLeaky)
				untouched(t, h, issued)
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

			onTimeline(t, h, &failing)
			issued := issuedFor(h)

			s := h.enrolmentOnly(t, factor.Password)
			require.Equal(t, clockAt(9, 15), s.AbsoluteExpiresAt)

			c := h.chain(t, s)
			secret := h.beginDoc(t, c).Secret

			moveTo(h, clockAt(9, 7))
			emailed := h.prove(t, c, o, secret)

			moveTo(h, clockAt(9, 8))
			require.NoError(t, serve(t, c, emailCodeRequest(t.Context(), emailed)).err)
			require.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA)

			tc.before(t, h, s, &failing)

			tc.assert(t, h, s, issued, serve(t, c, post(t.Context(), testMFAVerifyPath,
				"code="+h.codeFor(t, secret))))
		})
	}
}

// TestConfirmationIsNotASecondFactor pins that completing an enrolment is not
// verifying it: a session whose enrolment was just confirmed through the path
// is refused a protected route with the ordinary MFA challenge, and the
// handler never runs.
//
// Stands alone: it completes an enrolment through a sequence of requests on one
// chain before the request it pins.
func TestConfirmationIsNotASecondFactor(t *testing.T) {
	t.Parallel()

	h := newEnrolHarness(t)
	o := &outbox{}
	o.accepting(h, nil)

	s := h.enrolmentOnly(t, factor.Password)
	c := h.chain(t, s)
	emailed := h.prove(t, c, o, h.beginDoc(t, c).Secret)
	require.NoError(t, serve(t, c, emailCodeRequest(t.Context(), emailed)).err)
	require.True(t, h.enrolled(t))

	out := serve(t, c, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil))

	var challenge *httpsec.ChallengeError
	require.True(t, errors.As(out.err, &challenge), "got %v", out.err)
	assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
	assert.False(t, out.handlerRan)
}
