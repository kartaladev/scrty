package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
)

// recoveryHoldDelay is the fixed delay the hold cases configure.
const recoveryHoldDelay = time.Hour

// errRecordStoreDown is what a failing record store answers, with text a
// response must never carry.
var errRecordStoreDown = errors.New("records: connection to 10.0.0.9 refused")

// errRecoveryLoginDenied is what a consumer's policy denies a login with.
var errRecoveryLoginDenied = errors.New("recovery test: the policy denied the login")

// heldRecovery is what a held recovery handed its two parties: the client's
// completion token and the instant it can be presented, and the cancel token
// the notice's link carried.
type heldRecovery struct {
	completion    string
	completableAt time.Time
	cancel        string
}

// withHold configures the fixed delay and the cancel link a hold needs.
func (h *recoveryHarness) withHold() {
	h.coreOpts = append(h.coreOpts,
		recovery.WithDelay(recoveryHoldDelay), recovery.WithCancelLink("https://app.example.com/cancel"))
}

// hold completes a recovery that the configured delay holds, and returns what
// the hold handed out.
func (h *recoveryHarness) hold(t *testing.T) heldRecovery {
	t.Helper()

	out := h.complete(t, recoveryForm(
		httpsec.RecoverySavedCodeParam, h.saved(t),
		httpsec.RecoveryIssuedCodeParam, h.issued(t)))
	require.NoError(t, out.err)
	require.Equal(t, http.StatusAccepted, out.rec.Code)

	var doc struct {
		CompletionToken string    `json:"completion_token"`
		CompletableAt   time.Time `json:"completable_at"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.CompletionToken)

	held := h.sender.last(t)
	require.Equal(t, "held", held.Subject, "the hold sent no notice")

	link, err := url.Parse(held.TextBody)
	require.NoError(t, err)

	cancel := link.Query().Get(recovery.CancelLinkParam)
	require.NotEmpty(t, cancel, "the notice's link carries no cancel token")

	return heldRecovery{completion: doc.CompletionToken, completableAt: doc.CompletableAt, cancel: cancel}
}

// finish posts a completion token to the finish endpoint.
func (h *recoveryHarness) finish(t *testing.T, completion string) served {
	t.Helper()

	return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource,
		url.Values{httpsec.RecoveryCompletionTokenParam: {completion}}))
}

// cancelHold posts a cancel token to the cancel endpoint.
func (h *recoveryHarness) cancelHold(t *testing.T, cancel string) served {
	t.Helper()

	return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCancelPath, e2eSource,
		url.Values{httpsec.RecoveryCancelTokenParam: {cancel}}))
}

// passwordLogin logs the user in with their password through form login.
func (h *recoveryHarness) passwordLogin(t *testing.T) served {
	t.Helper()

	return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	}))
}

// withMagicLink adds magic-link login for the harness's user to the chain.
func (h *recoveryHarness) withMagicLink(t *testing.T) {
	t.Helper()

	onetimes, err := onetime.NewManager("magic-link", onetime.WithTTL(magicLinkTTL))
	require.NoError(t, err)

	links, err := magiclink.NewManager(onetimes, h.users, h.sender, "https://app.example.com")
	require.NoError(t, err)

	h.chainOpts = append(h.chainOpts, httpsec.EnableMagicLink(links,
		httpsec.WithMagicLinkSessions(h.sessions), httpsec.WithMagicLinkTokens(h.tokens)))
}

// magicLinkLogin asks for a link for the harness's user and follows it.
func (h *recoveryHarness) magicLinkLogin(t *testing.T) served {
	t.Helper()

	asked := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath, e2eSource,
		url.Values{httpsec.DefaultMagicLinkAddressParam: {e2eAddress}, httpsec.DefaultMagicLinkNextParam: {"/"}}))
	require.NoError(t, asked.err)

	cookie := cookieNamed(asked.rec, httpsec.DefaultBindingCookieName)
	require.NotNil(t, cookie)

	req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, e2eSource,
		url.Values{httpsec.DefaultMagicLinkTokenParam: {h.sender.lastToken(t)}})
	req.AddCookie(bindingCookie(cookie.Value))

	return serve(t, h.chain, req)
}

// sentWithSubject counts the messages sent with subject.
func (s *capturingSender) sentWithSubject(subject string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for _, m := range s.sent {
		if m.Subject == subject {
			n++
		}
	}

	return n
}

// activeSessions counts the user's live sessions.
func (h *recoveryHarness) activeSessions(t *testing.T) int {
	t.Helper()

	n, err := h.sessions.CountActiveByUser(t.Context(), e2eUser)
	require.NoError(t, err)

	return n
}

// cancelledNothing asserts out is the cancel endpoint's one answer: 204, an
// empty body, and the application never reached.
func cancelledNothing(t *testing.T, out served) {
	t.Helper()

	require.NoError(t, out.err)
	assert.False(t, out.handlerRan, "the cancel endpoint passed the request on")
	assert.Equal(t, http.StatusNoContent, out.rec.Code)
	assert.Empty(t, out.rec.Body.Bytes())
}

// refusedFinish asserts out refused a finish as a refused recovery.
func refusedFinish(t *testing.T, out served) {
	t.Helper()

	require.ErrorIs(t, out.err, recovery.ErrRefused)
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	assert.False(t, out.handlerRan)
}

// recordsCancelPendingFails is a record store that keeps records in memory
// and fails every CancelPending with errRecordStoreDown.
func recordsCancelPendingFails(t *testing.T) recovery.RecordStore {
	t.Helper()

	mem := recovery.NewMemoryRecordStore()
	m := NewMockRecordStore(gomock.NewController(t))

	m.EXPECT().Insert(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.Insert)
	m.EXPECT().Find(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.Find)
	m.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.Complete)
	m.EXPECT().Cancel(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.Cancel)
	m.EXPECT().LatestCompletion(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.LatestCompletion)
	m.EXPECT().CancelPending(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID, time.Time) (int, error) { return 0, errRecordStoreDown })

	return m
}

// TestRecoveryHold pins held recoveries over HTTP: the hold's answer, the
// finish endpoint before and after the hold, the cancel endpoint's one
// answer, a login's cancellation of a held recovery, and the race between a
// cancel and a finish.
func TestRecoveryHold(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		arrange func(t *testing.T, h *recoveryHarness)
		act     func(t *testing.T, h *recoveryHarness) served
		assert  func(t *testing.T, h *recoveryHarness, out served)
	}

	cases := []testCase{
		{
			name:    "a fixed delay answers 202 with the completion token and the instant, and creates no session",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryIssuedCodeParam, h.issued(t)))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusAccepted, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

				var doc map[string]any
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				assert.ElementsMatch(t, []string{"completion_token", "completable_at"}, keysOf(doc))

				at, err := time.Parse(time.RFC3339Nano, doc["completable_at"].(string))
				require.NoError(t, err)
				assert.True(t, at.Equal(h.clock.Now().Add(recoveryHoldDelay)))

				assert.Zero(t, h.activeSessions(t), "a held recovery creates no session")
				assert.Equal(t, 1, h.sender.sentWithSubject("held"), "the hold's notice is sent")
			},
		},
		{
			name:    "a finish before the hold is over is 409, and the same token finishes once it is",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay / 2)

				early := h.finish(t, held.completion)
				require.ErrorIs(t, early.err, recovery.ErrNotYetCompletable)
				assert.Equal(t, http.StatusConflict, httpsec.StatusForError(early.err))
				assert.False(t, early.handlerRan)
				assert.Zero(t, h.activeSessions(t), "an early finish creates no session")

				h.clock.Advance(recoveryHoldDelay / 2)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
			},
		},
		{
			name:    "a finish after the hold answers 200 with a recovery-pending credential and the new codes",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay + time.Minute)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				doc := recovered(t, h, out)
				assert.Len(t, doc.RecoveryCodes, 10, "the spent saved code's set is replaced at the finish")
				assert.Equal(t, 1, h.sender.sentWithSubject("recovered"))
			},
		},
		{
			name:    "a finish token spent once is refused the second time",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)
				recovered(t, h, h.finish(t, held.completion))

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { refusedFinish(t, out) },
		},
		{
			name:    "an unknown finish token is 401",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.finish(t, "not-a-token")
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { refusedFinish(t, out) },
		},
		{
			name:    "a finish with no completion token is malformed",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource,
					url.Values{}))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrMalformed)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
			},
		},
		{
			name:    "a completion token given twice is malformed, and the token still finishes",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)

				twice := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource,
					url.Values{httpsec.RecoveryCompletionTokenParam: {held.completion, "other"}}))
				require.ErrorIs(t, twice.err, recovery.ErrMalformed)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(twice.err))

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) { recovered(t, h, out) },
		},
		{
			name:    "a completion token in the query is not read",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)

				return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryFinishPath+"?"+
					url.Values{httpsec.RecoveryCompletionTokenParam: {held.completion}}.Encode(), e2eSource,
					url.Values{}))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, recovery.ErrMalformed)
				assert.Zero(t, h.activeSessions(t))
			},
		},
		{
			name:    "a finish body over 16 KiB is 413",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource,
					url.Values{httpsec.RecoveryCompletionTokenParam: {strings.Repeat("a", 17<<10)}}))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, http.StatusRequestEntityTooLarge, httpsec.StatusForError(out.err))
			},
		},
		{
			name:    "a GET to the finish path reaches the application",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return serve(t, h.chain, getFrom(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
		{
			name: "a consumer finish path is answered there",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.withHold()
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryFinishPath("/account/recover/finish")}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)

				return serve(t, h.chain, postValues(t.Context(), "/account/recover/finish", e2eSource,
					url.Values{httpsec.RecoveryCompletionTokenParam: {held.completion}}))
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) { recovered(t, h, out) },
		},
		{
			name: "a consumer responder answers the finish",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.withHold()
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryResponder(
					func(ex *httpsec.Exchange, res httpsec.RecoveryResult) error {
						if res.Token == "" || res.Recovery == nil || res.Recovery.Session == nil {
							return errors.New("recovery test: the finish carries no credential")
						}

						ex.Writer.WriteHeader(http.StatusCreated)

						return nil
					})}
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusCreated, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name:    "a garbage cancel token is answered 204",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.cancelHold(t, "garbage")
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				cancelledNothing(t, out)
				assert.Zero(t, h.sender.sentWithSubject("cancelled"))
			},
		},
		{
			name:    "a cancel with no body is answered 204",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
					httpsec.DefaultRecoveryCancelPath, nil)
				req.RemoteAddr = e2eSource + ":51000"

				return serve(t, h.chain, req)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { cancelledNothing(t, out) },
		},
		{
			name:    "a cancel body that is not a form, or over 16 KiB, is answered 204",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				notForm := serve(t, h.chain, postBody(t.Context(), httpsec.DefaultRecoveryCancelPath,
					"application/json", strings.NewReader(`{"cancel_token":"x"}`)))
				cancelledNothing(t, notForm)

				return h.cancelHold(t, strings.Repeat("a", 17<<10))
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { cancelledNothing(t, out) },
		},
		{
			// A valid token outside the form body — as JSON, in the query, or
			// given twice — must be read as no token at all, exactly as a
			// garbage one is: readHoldToken reads only a URL-encoded body, by
			// the same rules as the complete and finish endpoints, and never
			// the query. Each of the three must cancel nothing, so the same
			// token still finishes the recovery once the hold is over.
			name:    "a valid cancel token sent as JSON, in the query, or duplicated in the form cancels nothing",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				asJSON := serve(t, h.chain, postBody(t.Context(), httpsec.DefaultRecoveryCancelPath,
					"application/json", strings.NewReader(`{"`+httpsec.RecoveryCancelTokenParam+`":"`+held.cancel+`"}`)))
				cancelledNothing(t, asJSON)

				inQuery := serve(t, h.chain, postValues(t.Context(),
					httpsec.DefaultRecoveryCancelPath+"?"+
						url.Values{httpsec.RecoveryCancelTokenParam: {held.cancel}}.Encode(),
					e2eSource, url.Values{}))
				cancelledNothing(t, inQuery)

				duplicated := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCancelPath, e2eSource,
					url.Values{httpsec.RecoveryCancelTokenParam: {held.cancel, held.cancel}}))
				cancelledNothing(t, duplicated)

				assert.Zero(t, h.sender.sentWithSubject("cancelled"), "none of the three cancelled anything")

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) { recovered(t, h, out) },
		},
		{
			name:    "the cancel link cancels: 204, one notice, and the finish is refused after the hold",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				cancelledNothing(t, h.cancelHold(t, held.cancel))
				assert.Equal(t, 1, h.sender.sentWithSubject("cancelled"))

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				refusedFinish(t, out)
				assert.Zero(t, h.activeSessions(t))
			},
		},
		{
			name:    "a finish token posted to cancel is 204, cancels nothing, and still finishes",
			arrange: func(_ *testing.T, h *recoveryHarness) { h.withHold() },
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				cancelledNothing(t, h.cancelHold(t, held.completion))

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				recovered(t, h, out)
				assert.Zero(t, h.sender.sentWithSubject("cancelled"), "nothing was cancelled")
			},
		},
		{
			name: "a password login cancels a held recovery",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.withHold()
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				login := h.passwordLogin(t)
				require.NoError(t, login.err)
				require.Equal(t, http.StatusOK, login.rec.Code)
				require.Equal(t, 1, h.activeSessions(t), "the login created its session")

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { refusedFinish(t, out) },
		},
		{
			name: "a magic-link login cancels a held recovery",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.withHold()
				h.withMagicLink(t)
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				login := h.magicLinkLogin(t)
				require.NoError(t, login.err)
				require.NotNil(t, login.rec)
				require.Equal(t, 1, h.activeSessions(t), "the magic-link login created its session")

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { refusedFinish(t, out) },
		},
		{
			// Unlike form login, a magic-link redemption applies the policy
			// inside its own check, before the credential is spent: a denied
			// check never reaches the login completion step that cancels held
			// recoveries, and never consumes the token either.
			name: "a magic-link login the policy denies cancels nothing, and its token stays redeemable",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.withHold()
				h.withMagicLink(t)
				h.chainOpts = append(h.chainOpts, httpsec.WithPolicyEngine(deniesOnceThenAllows(t)))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				asked := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath, e2eSource,
					url.Values{
						httpsec.DefaultMagicLinkAddressParam: {e2eAddress},
						httpsec.DefaultMagicLinkNextParam:    {"/"},
					}))
				require.NoError(t, asked.err)

				cookie := cookieNamed(asked.rec, httpsec.DefaultBindingCookieName)
				require.NotNil(t, cookie)

				tok := h.sender.lastToken(t)
				consume := func() served {
					req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, e2eSource,
						url.Values{httpsec.DefaultMagicLinkTokenParam: {tok}})
					req.AddCookie(bindingCookie(cookie.Value))

					return serve(t, h.chain, req)
				}

				denied := consume()
				require.ErrorIs(t, denied.err, errMagicLinkDenied)
				require.Zero(t, h.activeSessions(t), "the denied redemption created no session")

				h.clock.Advance(recoveryHoldDelay)

				finished := h.finish(t, held.completion)
				require.NoError(t, finished.err, "the denied redemption cancelled nothing")
				require.Equal(t, http.StatusOK, finished.rec.Code)

				redone := consume()
				require.NoError(t, redone.err, "the token was never consumed by the denied redemption")
				assert.Equal(t, 2, h.activeSessions(t),
					"the finish's session and the retried, allowed redemption's own session")

				return finished
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) { recovered(t, h, out) },
		},
		{
			name: "a login the policy phase denies still cancels, and the finish is refused",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.withHold()
				h.chainOpts = append(h.chainOpts, httpsec.WithPolicyEngine(engineOf(t, policyAnswering(t,
					policy.Decision{Outcome: policy.Deny, Reason: errRecoveryLoginDenied}))))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				// The first factor authenticated, which is the evidence the
				// real user still has access, whatever the policy then decides.
				login := h.passwordLogin(t)
				require.ErrorIs(t, login.err, errRecoveryLoginDenied)
				require.Zero(t, h.activeSessions(t), "the denied login created no session")

				h.clock.Advance(recoveryHoldDelay)

				return h.finish(t, held.completion)
			},
			assert: func(t *testing.T, _ *recoveryHarness, out served) { refusedFinish(t, out) },
		},
		{
			name: "a login without a hold configured never touches the record store",
			arrange: func(t *testing.T, h *recoveryHarness) {
				// A strict double: any call fails the test.
				h.records = NewMockRecordStore(gomock.NewController(t))
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.passwordLogin(t)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, 1, h.activeSessions(t))
			},
		},
		{
			name: "a record store outage at login refuses the login, and no session is created",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.withHold()
				h.records = recordsCancelPendingFails(t)
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				return h.passwordLogin(t)
			},
			assert: func(t *testing.T, h *recoveryHarness, out served) {
				require.Error(t, out.err)
				require.ErrorIs(t, out.err, errRecordStoreDown)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.NotContains(t, out.err.Error(), "10.0.0.9", "the store's text is not the library's")
				assert.False(t, out.handlerRan)
				assert.Empty(t, out.rec.Body.Bytes(), "no credential is written")
				assert.Zero(t, h.activeSessions(t), "the refused login created no session")
			},
		},
		{
			name: "a racing cancel and finish over HTTP: exactly one takes effect",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.withHold()
			},
			act: func(t *testing.T, h *recoveryHarness) served {
				held := h.hold(t)

				h.clock.Advance(recoveryHoldDelay)

				const each = 8

				var (
					wg       sync.WaitGroup
					mu       sync.Mutex
					finishes []served
					cancels  []served
					start    = make(chan struct{})
				)

				for range each {
					wg.Add(2)

					go func() {
						defer wg.Done()
						<-start

						out := h.finish(t, held.completion)

						mu.Lock()
						finishes = append(finishes, out)
						mu.Unlock()
					}()

					go func() {
						defer wg.Done()
						<-start

						out := h.cancelHold(t, held.cancel)

						mu.Lock()
						cancels = append(cancels, out)
						mu.Unlock()
					}()
				}

				close(start)
				wg.Wait()

				// Every cancel answers exactly as a solo one does, whatever it
				// raced against; asserted here, on the test goroutine, once
				// every goroutine above has returned.
				for _, out := range cancels {
					cancelledNothing(t, out)
				}

				won := 0
				for _, out := range finishes {
					if out.err == nil && out.rec.Code == http.StatusOK {
						won++
						continue
					}

					require.ErrorIs(t, out.err, recovery.ErrRefused)
				}

				cancelled := h.sender.sentWithSubject("cancelled")
				assert.Equal(t, 1, won+cancelled,
					"exactly one of the finishes and cancels takes effect (finishes %d, cancels %d)", won, cancelled)
				assert.LessOrEqual(t, won, 1)
				assert.LessOrEqual(t, cancelled, 1)

				return served{rec: httptest.NewRecorder()}
			},
			assert: func(*testing.T, *recoveryHarness, served) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)
			if tc.arrange != nil {
				tc.arrange(t, h)
			}

			h.build(t)

			tc.assert(t, h, tc.act(t, h))
		})
	}
}

// TestRecoveryHold_EndpointsOnlyWithAHold pins that the finish and cancel
// endpoints exist only when the core may hold a recovery: without a hold a
// POST to either path reaches the application like any other request.
func TestRecoveryHold_EndpointsOnlyWithAHold(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		values url.Values
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name:   "finish",
			path:   httpsec.DefaultRecoveryFinishPath,
			values: url.Values{httpsec.RecoveryCompletionTokenParam: {"x"}},
			assert: func(t *testing.T, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
		{
			name:   "cancel",
			path:   httpsec.DefaultRecoveryCancelPath,
			values: url.Values{httpsec.RecoveryCancelTokenParam: {"x"}},
			assert: func(t *testing.T, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t).build(t)

			tc.assert(t, serve(t, h.chain, postValues(t.Context(), tc.path, e2eSource, tc.values)))
		})
	}
}

// keysOf lists a decoded JSON object's member names.
func keysOf(doc map[string]any) []string {
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}

	return keys
}

// TestRecoveryHold_OIDCLogin pins that a federated login cancels the user's
// held recoveries, as form login and magic link do, exactly when its own
// login succeeds. Its handoff redemption ends through the same login
// completion, so a redemption a consumer policy denies — refused by
// guardRedemption before completeLogin ever runs — never reaches that step:
// it cancels nothing, and the held recovery still completes once its delay is
// over, the same way a denied magic-link redemption leaves its own held
// recovery alone.
//
// The chain is the OIDC harness's, with account recovery held beside it; the
// held recovery is a pending record placed in the store directly, since the
// federated user has no saved set to recover with, and another user's pending
// record shows the allowed case's cancellation is the user's alone.
func TestRecoveryHold_OIDCLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		arrange func(t *testing.T, h *oidcHarness)
		assert  func(t *testing.T, h *oidcHarness, out served, records recovery.RecordStore, held, other recovery.Record)
	}

	cases := []testCase{
		{
			name: "an allowed login cancels the user's held recovery",
			assert: func(t *testing.T, h *oidcHarness, out served, records recovery.RecordStore, held, other recovery.Record) {
				require.NoError(t, out.err)
				require.Equal(t, http.StatusOK, out.rec.Code)
				require.Equal(t, 1, h.activeSessions(t), "the federated login created its session")

				got, err := records.Find(t.Context(), held.ID)
				require.NoError(t, err)
				assert.False(t, got.CancelledAt.IsZero(), "the federated login cancelled the user's held recovery")

				untouched, err := records.Find(t.Context(), other.ID)
				require.NoError(t, err)
				assert.True(t, untouched.CancelledAt.IsZero(), "another user's held recovery stands")
			},
		},
		{
			name: "a denied login cancels nothing, and the held recovery still completes",
			arrange: func(t *testing.T, h *oidcHarness) {
				h.chainOpts = append(h.chainOpts,
					httpsec.WithPolicyEngine(denyingEngine(t, errRecoveryLoginDenied)))
			},
			assert: func(t *testing.T, h *oidcHarness, out served, records recovery.RecordStore, held, other recovery.Record) {
				require.ErrorIs(t, out.err, errRecoveryLoginDenied)
				assert.Zero(t, h.activeSessions(t), "the denied login created no session")

				got, err := records.Find(t.Context(), held.ID)
				require.NoError(t, err)
				assert.True(t, got.CancelledAt.IsZero(), "the denied login cancelled nothing")

				completed, err := records.Complete(t.Context(), held.ID, held.NotBefore)
				require.NoError(t, err)
				assert.True(t, completed, "the held recovery still completes")

				untouched, err := records.Find(t.Context(), other.ID)
				require.NoError(t, err)
				assert.True(t, untouched.CancelledAt.IsZero(), "another user's held recovery stands")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			h.issueTokens()

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
				Return(&identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}, nil)

			totpMethod, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
			require.NoError(t, err)

			kind, err := recovery.MFAEnrolments(totpMethod)
			require.NoError(t, err)

			codes, err := recovery.NewCodes()
			require.NoError(t, err)

			records := recovery.NewMemoryRecordStore()
			now := time.Now()

			held := recovery.Record{
				ID: id.MustParse("01900000-0000-7000-8000-000000000001"), User: oidcTestUserID,
				StartedAt: now, NotBefore: now.Add(recoveryHoldDelay),
			}
			other := recovery.Record{
				ID: id.MustParse("01900000-0000-7000-8000-000000000002"), User: "u-other",
				StartedAt: now, NotBefore: now.Add(recoveryHoldDelay),
			}
			require.NoError(t, records.Insert(t.Context(), held))
			require.NoError(t, records.Insert(t.Context(), other))

			if tc.arrange != nil {
				tc.arrange(t, h)
			}

			h.chainOpts = append(h.chainOpts,
				httpsec.EnablePasswordChangeGate(h.sessions,
					httpsec.WithChangePasswordEndpoint(passwordResolvePath, func(*httpsec.Exchange) error { return nil })),
				httpsec.EnableAccountRecovery(httpsec.RecoveryDeps{
					Users: users, Sessions: h.sessions, Sender: &capturingSender{}, Codes: codes, Records: records,
				},
					httpsec.WithRecoveryTokens(h.tokens),
					httpsec.WithRecoveryCore(
						recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
						recovery.WithRepudiationContact("Write to security@example.com if this was not you."),
						recovery.WithAuthenticatorKinds(kind),
						recovery.WithMessages(recoveryMessages{}),
						recovery.WithDelay(recoveryHoldDelay),
						recovery.WithCancelLink("https://app.example.com/cancel"),
					)),
			)

			chain := h.chain(t)

			out := serve(t, chain, handoffRequest(t.Context(), oidcTestSource, h.issueHandoff(t, "")))
			tc.assert(t, h, out, records, held, other)
		})
	}
}
