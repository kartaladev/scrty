package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/session"
)

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

		body string
		ctx  func(ctx context.Context) context.Context

		assert func(t *testing.T, h *enrolHarness, s *session.Session, out served)
	}

	beginOn := func(t *testing.T, c *httpsec.Chain) served {
		t.Helper()

		return serve(t, c, post(t.Context(), httpsec.DefaultEnrolmentBeginPath, ""))
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
				h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithLabelResolver(
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
				m.EXPECT().Channel().Return(factor.Email).AnyTimes()
				m.EXPECT().SupportsEnrolmentPath().Return(true).AnyTimes()
				m.EXPECT().BeginEnrolmentGeneration(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				h.method = m
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, mfa.ErrSameChannel)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.True(t, h.stored(t, s.ID).EnrolmentGeneration.IsZero())
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

			tc.assert(t, h, s, serveIn(ctx, t, c, post(ctx, httpsec.DefaultEnrolmentBeginPath, tc.body)))
		})
	}
}
