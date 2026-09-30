package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

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
				h.enrolOpts = append(h.enrolOpts, httpsec.WithContactResolver(failingResolver(errAddressUnusable)))
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

			h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEmailConfirmation())
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
				h.enrolOpts = append(h.enrolOpts, httpsec.WithLabelResolver(failingResolver(errAddressUnusable)))
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
				h.enrolOpts = append(h.enrolOpts, httpsec.WithContactResolver(failingResolver(errAddressUnusable)))
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
			h.sessions, err = session.NewManager(session.WithStore(
				failingSaves{Store: session.NewMemoryStore(), failing: &failing}))
			require.NoError(t, err)

			h.totp, err = mfa.NewTOTP(tc.store(h.store), enrolIssuer,
				mfa.WithClock(h.clock))
			require.NoError(t, err)

			h.method = h.totp

			if tc.emailOff {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEmailConfirmation())
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
