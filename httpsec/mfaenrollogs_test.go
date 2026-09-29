package httpsec_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
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
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

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
		require.NoError(t, serve(t, c, post(t.Context(), httpsec.DefaultEnrolmentBeginPath, "")).err)
	}

	for range n {
		out := serve(t, c, post(t.Context(), httpsec.DefaultEnrolmentBeginPath, ""))
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
				require.ErrorIs(t, serve(t, c, post(t.Context(), httpsec.DefaultEnrolmentConfirmPath,
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
				c.FlushRefusalLogs()

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
					out := serve(t, c, post(t.Context(), httpsec.DefaultEnrolmentConfirmPath,
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
				mfa.WithClock(h.clock), mfa.WithTOTPLogger(slog.New(methodLogs)))
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

			out := serve(t, c, post(t.Context(), httpsec.DefaultEnrolmentConfirmPath, "code="+h.codeFor(t, secret)))
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
func TestEnrolmentRefusalRecordCarriesErrorType(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		first   factor.Kind
		prepare func(t *testing.T, h *enrolHarness)
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
			reason:  "same-channel",
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

			c := h.chain(t, h.enrolmentOnly(t, tc.first))
			serve(t, c, post(t.Context(), httpsec.DefaultEnrolmentBeginPath, ""))

			refused := withReason(recordsNamed(logs, msgEnrolmentRefused), tc.reason)
			require.Len(t, refused, 1, "the refusal is recorded under its reason")

			_, ok := attrValue(refused[0], "error_type")
			assert.Equal(t, tc.hasType, ok,
				"a dependency-caused refusal must carry the cause's Go type; "+
					"a library refusal with no dependency behind it must not")
		})
	}
}
