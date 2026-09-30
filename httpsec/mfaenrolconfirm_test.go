package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
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
				h.enrolOpts = append(h.enrolOpts, httpsec.WithContactResolver(
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
				assert.Equal(t, mfa.MaxEmailCodeFailures, e.EmailCodeAttempts,
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
				assert.Equal(t, mfa.MaxEmailCodeFailures, e.EmailCodeAttempts,
					"every attempt the code had left is charged, though the caller went away")
			},
		},
		{
			name: "email confirmation off",
			prepare: func(_ *testing.T, h *enrolHarness, o *outbox) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEmailConfirmation())
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
					httpsec.WithoutEmailConfirmation(), httpsec.WithoutEnrolmentNotification())
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
