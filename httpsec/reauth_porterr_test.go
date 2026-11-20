package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// reauthPortErrRowEnv names the row a child process of
// TestPortErrors_ReauthEnrolled runs. It is empty in the parent.
const reauthPortErrRowEnv = "SCRTY_HTTPSEC_REAUTH_PORTERR_ROW"

// reauthPortErrRan is what a child prints, as a line of its own followed by
// the row's name, once it has run its row to the end.
const reauthPortErrRan = "reauth-porterr-row-ran:"

// reauthEnrolledThrough serves request on a re-authentication chain whose
// user is not enrolled on TOTP, and whose second method's enrolment lookup
// fails with portErr. A hostile error read as "not enrolled" would leave the
// user holding no second factor and so downgrade the re-proof to the
// password: the authenticator is strict, so a password check fails the test.
func reauthEnrolledThrough(
	request func(ctx context.Context) *http.Request,
) func(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	return func(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
		t.Helper()

		ctx, onCall := requestContext(t, run.cancelDuring)

		h := newReauthHarness(t)
		h.totpUnenrolled = true
		h.neverVerifies()

		m := emailCodeMethod(t)
		m.EXPECT().Enrolled(gomock.Any(), testMFAUser).AnyTimes().
			DoAndReturn(func(context.Context, identity.UserID) (bool, error) {
				onCall()

				return false, portErr
			})
		m.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
		h.extra = []mfa.Method{m}

		h.limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()

		charges := &stepUpCharges{}
		h.limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
			DoAndReturn(func(context.Context, string) error {
				charges.add()

				return nil
			})

		logs := &capturingHandler{}
		returned := &stepUpReturned{}
		h.chainOpts = append(h.chainOpts, httpsec.WithLogger(slog.New(logs)), stepUpObserver(returned, run.swallow))

		s := h.fullSession(t, factor.Password)

		chain, err := h.build(s)
		require.NoError(t, err)

		rec, panicked := stepUpServeWithin(t, chain, request(ctx))

		return stepUpOutcomeOf(rec, panicked, charges, reauthState(t, h, s.ID), logs, returned)
	}
}

// TestPortErrors_ReauthEnrolled pins that a hostile error from a second-factor
// method's enrolment lookup, at the re-authentication listing, the password
// re-proof and the re-proof verify's named method, is answered exactly as a
// plain outage of that lookup is: the same refusal, byte for byte, nothing
// charged, and the session untouched. It never reads as "not enrolled", which
// would offer or accept the weaker password in place of the second factor. It
// is reported once, to the chain's logger, and not to slog.Default().
func TestPortErrors_ReauthEnrolled(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runStepUpPortErrors(t, reauthPortErrRowEnv, reauthPortErrRan, []stepUpPortSite{
		{
			name: "the method listing",
			through: reauthEnrolledThrough(func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, reauthMethodsPath, nil)
			}),
		},
		{
			name: "the password re-proof",
			through: reauthEnrolledThrough(func(ctx context.Context) *http.Request {
				return formRequest(ctx, reauthPasswordPath, "password=s3cret")
			}),
		},
		{
			name: "the re-proof verify's named method",
			through: reauthEnrolledThrough(func(ctx context.Context) *http.Request {
				return post(ctx, httpsec.DefaultReauthenticationPrefix+"/verify/email-code", "code="+testMFACode)
			}),
		},
	}, errors.New("enrolment store: connection refused"))
}
