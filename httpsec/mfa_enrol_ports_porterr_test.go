package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
)

// enrolPortsRowEnv names the row a child process of
// TestPortErrors_EnrolmentPorts runs. It is empty in the parent.
const enrolPortsRowEnv = "SCRTY_HTTPSEC_ENROL_PORTS_PORTERR_ROW"

// enrolPortsRan is what a child prints, as a line of its own followed by the
// row's name, once it has run its row to the end.
const enrolPortsRan = "enrol-ports-porterr-row-ran:"

// The ports of the enrolment path a row makes fail.
const (
	enrolPortLoad     = "user loader"
	enrolPortLabel    = "label resolver"
	enrolPortContact  = "contact resolver"
	enrolPortBegin    = "method's begin"
	enrolPortProve    = "method's proof"
	enrolPortSend     = "sender"
	enrolPortComplete = "method's completion"
	enrolPortRedeem   = "method's redemption"
)

// enrolPortFlow is the requests a site's row serves: the last of them is the
// one whose port fails.
type enrolPortFlow int

const (
	// enrolFlowBegin is a begin.
	enrolFlowBegin enrolPortFlow = iota

	// enrolFlowConfirm is a healthy begin, then a confirm with a valid code
	// under email confirmation, which emails the code.
	enrolFlowConfirm

	// enrolFlowConfirmDirect is a healthy begin, then a confirm with a valid
	// code with email confirmation off, which completes the enrolment and
	// notifies the user.
	enrolFlowConfirmDirect

	// enrolFlowRedeem is a healthy begin and confirm, then the redemption of
	// the emailed code, which completes the enrolment.
	enrolFlowRedeem
)

// enrolPortRig makes one port of the enrolment path fail with err while it is
// armed, cancelling cancel first when it is set, and counts what the armed
// request did.
type enrolPortRig struct {
	port   string
	err    error
	cancel context.CancelFunc

	armed atomic.Bool

	mu sync.Mutex

	// hits is how many times the armed request reached the failing port, and
	// redeems how many emailed-code redemptions it made, voiding included.
	hits, redeems int

	// handed is every error the enrolment interceptor handed outward, to the
	// interceptors around it and the chain's dispatch.
	handed []error
}

// fail is the failure of port: err when the rig is armed for port, and
// otherwise nil.
func (r *enrolPortRig) fail(port string) error {
	if !r.armed.Load() || r.port != port {
		return nil
	}

	r.mu.Lock()
	r.hits++
	r.mu.Unlock()

	if r.cancel != nil {
		r.cancel()
	}

	return r.err
}

func (r *enrolPortRig) counts() (hits, redeems int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.hits, r.redeems
}

// witness is a consumer interceptor outside the enrolment interceptor that
// keeps every error handed out through it.
func (r *enrolPortRig) witness() httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		err := next(ex)
		if err != nil {
			r.mu.Lock()
			r.handed = append(r.handed, err)
			r.mu.Unlock()
		}

		return err
	}), httpsec.After(httpsec.OrderBearerToken))
}

// walksToEnd reports whether err's chain can be read to its end through its
// Unwrap methods within a budget, as a consumer's code reading it with stdlib
// errors.Is would need: no cycle, no fan-out past the budget, no panicking
// Unwrap. It is the test's own bounded probe, so it cannot hang or crash.
func walksToEnd(err error) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()

	pending := []error{err}

	for seen := 0; len(pending) > 0; seen++ {
		if seen > 1000 {
			return false
		}

		e := pending[len(pending)-1]
		pending = pending[:len(pending)-1]

		switch u := e.(type) {
		case interface{ Unwrap() error }:
			if next := u.Unwrap(); next != nil {
				pending = append(pending, next)
			}
		case interface{ Unwrap() []error }:
			for _, next := range u.Unwrap() {
				if next != nil {
					pending = append(pending, next)
				}
			}
		}
	}

	return true
}

// handedWalkable reports whether every error handed outward walks to its end.
func (r *enrolPortRig) handedWalkable() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, err := range r.handed {
		if !walksToEnd(err) {
			return false
		}
	}

	return true
}

// resolver is a label or contact resolver that fails as port, and otherwise
// answers the default.
func (r *enrolPortRig) resolver(port string) func(context.Context, *identity.Details) (string, error) {
	return func(ctx context.Context, d *identity.Details) (string, error) {
		if err := r.fail(port); err != nil {
			return "", err
		}

		return mfa.UsernameAsAddress(ctx, d)
	}
}

// enrolPortMethod is the harness's TOTP method with its enrolment steps
// failing as the rig says.
type enrolPortMethod struct {
	*mfa.TOTP

	rig *enrolPortRig
}

func (m enrolPortMethod) BeginEnrolmentGeneration(
	ctx context.Context, user identity.UserID, label string,
) (mfa.Provisioning, id.ID, error) {
	if err := m.rig.fail(enrolPortBegin); err != nil {
		return mfa.Provisioning{}, id.ID{}, err
	}

	return m.TOTP.BeginEnrolmentGeneration(ctx, user, label)
}

func (m enrolPortMethod) ProveDevice(
	ctx context.Context, user identity.UserID, gen id.ID, code string, emailCode bool, ttl time.Duration,
) (string, error) {
	if err := m.rig.fail(enrolPortProve); err != nil {
		return "", err
	}

	return m.TOTP.ProveDevice(ctx, user, gen, code, emailCode, ttl)
}

func (m enrolPortMethod) CompleteEnrolment(ctx context.Context, user identity.UserID, gen id.ID) error {
	if err := m.rig.fail(enrolPortComplete); err != nil {
		return err
	}

	return m.TOTP.CompleteEnrolment(ctx, user, gen)
}

func (m enrolPortMethod) RedeemEmailCode(ctx context.Context, user identity.UserID, gen id.ID, code string) error {
	if m.rig.armed.Load() {
		m.rig.mu.Lock()
		m.rig.redeems++
		m.rig.mu.Unlock()
	}

	if err := m.rig.fail(enrolPortRedeem); err != nil {
		return err
	}

	return m.TOTP.RedeemEmailCode(ctx, user, gen, code)
}

var _ mfa.Enroller = enrolPortMethod{}

// enrolPortSite is one port call of the enrolment path whose error the library
// reads.
type enrolPortSite struct {
	name string
	flow enrolPortFlow
	port string

	// claims is the library refusal the site's branch tests the port's error
	// for, nil for none.
	claims error
}

func enrolPortSites() []enrolPortSite {
	return []enrolPortSite{
		{name: "begin's user loader", flow: enrolFlowBegin, port: enrolPortLoad},
		{name: "begin's label resolver", flow: enrolFlowBegin, port: enrolPortLabel},
		{name: "begin's method", flow: enrolFlowBegin, port: enrolPortBegin, claims: mfa.ErrAlreadyEnrolled},
		{name: "confirm's user loader", flow: enrolFlowConfirm, port: enrolPortLoad},
		{name: "confirm's contact resolver", flow: enrolFlowConfirm, port: enrolPortContact},
		{name: "confirm's proof", flow: enrolFlowConfirm, port: enrolPortProve, claims: mfa.ErrInvalidCode},
		{name: "confirm's sender of the code", flow: enrolFlowConfirm, port: enrolPortSend},
		{
			name: "confirm's completion", flow: enrolFlowConfirmDirect, port: enrolPortComplete,
			claims: mfa.ErrInvalidCode,
		},
		{name: "notification's user loader", flow: enrolFlowConfirmDirect, port: enrolPortLoad},
		{name: "notification's contact resolver", flow: enrolFlowConfirmDirect, port: enrolPortContact},
		{name: "redemption's method", flow: enrolFlowRedeem, port: enrolPortRedeem, claims: mfa.ErrInvalidCode},
	}
}

// enrolClaimingCycle is a self-cycle through Unwrap() error whose own Is
// claims to be claims: stdlib errors.Is answers true for claims at once, and
// loops for ever for anything else.
type enrolClaimingCycle struct{ claims error }

func (*enrolClaimingCycle) Error() string { return hostileSecret }

func (c *enrolClaimingCycle) Unwrap() error { return c }

func (c *enrolClaimingCycle) Is(target error) bool { return target == c.claims } //nolint:errorlint // identity of a sentinel

// enrolPortErrKinds are the hostile errors an enrolment port may return at a
// site whose branch tests for claims (nil for none). Rows that overflow the
// stack on an unsanitized error run in a child process.
func enrolPortErrKinds(claims error) []loginPortErrKind {
	kinds := []loginPortErrKind{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: loginFanOut(25), reason: "budget"},
		{
			name:   "cycle wrapping context.Canceled",
			err:    &throttleCycleWrapping{sentinel: context.Canceled},
			reason: "budget", child: true, ctx: "cancelled",
		},
		// Walked to the end, so it passes unchanged and is answered as any
		// plain port error.
		{name: "typed-nil root", err: (*loginTypedNil)(nil)},
	}

	if claims != nil {
		kinds = append(kinds,
			loginPortErrKind{
				name: "cycle wrapping the branch's sentinel",
				err:  &throttleCycleWrapping{sentinel: claims}, reason: "budget", child: true,
			},
			loginPortErrKind{
				name: "cycle whose Is claims the branch's sentinel",
				err:  &enrolClaimingCycle{claims: claims}, reason: "budget",
			},
		)
	}

	return kinds
}

// enrolPortOutcome is everything one enrolment flow through a failing port
// produced that a client or the account can observe, and the records the
// chain's logger received.
type enrolPortOutcome struct {
	status int
	header http.Header
	body   string

	hits, redeems  int
	asked, charged int

	stored, enrolled bool

	// handedWalkable is whether every error handed outward can be read to its
	// end: nothing hostile travels past the port's call site.
	handedWalkable bool

	// sent is the recipient and subject of every message the sender was
	// handed, over the whole flow.
	sent []string

	logs []slog.Record
}

// enrolPortThrough serves site's flow through the chain's net/http middleware,
// as a server does, with the site's port failing with portErr on the last
// request. When cancelDuring is set that request is cancelled inside the port.
func enrolPortThrough(t *testing.T, site enrolPortSite, portErr error, cancelDuring bool) enrolPortOutcome {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rig := &enrolPortRig{port: site.port, err: portErr}
	if cancelDuring {
		rig.cancel = cancel
	}

	h := newEnrolHarness(t)
	logs := &capturingHandler{}
	ask := &limiterAsk{}
	limiter := hostileLimiter(t, ask, nil, nil)

	h.enrolOpts = append(h.enrolOpts,
		httpsec.WithEnrolmentBeginLimiter(limiter),
		httpsec.WithEnrolmentConfirmLimiter(limiter),
		httpsec.WithEnrolmentLabelResolver(rig.resolver(enrolPortLabel)),
		httpsec.WithEnrolmentContactResolver(rig.resolver(enrolPortContact)),
	)
	if site.flow == enrolFlowConfirmDirect {
		h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEnrolmentEmailConfirmation())
	}

	h.extra = append(h.extra, httpsec.WithLogger(slog.New(logs)), rig.witness())
	h.method = enrolPortMethod{TOTP: h.totp, rig: rig}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), testMFAUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			if err := rig.fail(enrolPortLoad); err != nil {
				return nil, err
			}

			return &identity.Details{ID: testMFAUser, Name: "Ana", Username: h.username, Active: true}, nil
		})
	h.users = users

	o := &outbox{}

	h.sender.EXPECT().Send(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, m notify.Message) error {
			o.mu.Lock()
			o.sent = append(o.sent, m)
			o.mu.Unlock()

			return rig.fail(enrolPortSend)
		})

	c := h.chain(t, h.enrolmentOnly(t, factor.Password))

	var last *http.Request

	switch site.flow {
	case enrolFlowBegin:
		last = post(ctx, enrolBeginPath, "")
	case enrolFlowConfirm, enrolFlowConfirmDirect, enrolFlowRedeem:
		begin := loginServeWithin(t, c, post(t.Context(), enrolBeginPath, ""))
		require.Equal(t, http.StatusOK, begin.Code, "the begin before the confirm")

		var doc beginBody
		require.NoError(t, json.Unmarshal(begin.Body.Bytes(), &doc))

		confirm := post(ctx, enrolConfirmPath, "code="+h.codeFor(t, doc.Secret))
		if site.flow != enrolFlowRedeem {
			last = confirm

			break
		}

		confirm = post(t.Context(), enrolConfirmPath, "code="+h.codeFor(t, doc.Secret))
		proof := loginServeWithin(t, c, confirm)
		require.Less(t, proof.Code, http.StatusBadRequest, "the proof before the redemption")

		last = emailCodeRequest(ctx, lastEmailedCode(t, o))
	}

	rig.armed.Store(true)

	out := loginServeWithin(t, c, last)

	rig.armed.Store(false)

	hits, redeems := rig.counts()
	asked, charged := ask.counts()
	_, stored := h.enrolment(t)

	sent := make([]string, 0, len(o.messages()))
	for _, m := range o.messages() {
		sent = append(sent, m.To+"|"+m.Subject)
	}

	return enrolPortOutcome{
		status: out.Code, header: out.Header(), body: out.Body.String(),
		hits: hits, redeems: redeems, asked: asked, charged: charged,
		stored: stored, enrolled: h.enrolled(t), handedWalkable: rig.handedWalkable(), sent: sent,
		logs: logs.records(),
	}
}

// TestPortErrors_EnrolmentPorts pins that a hostile error from a port the
// enrolment path reads (the user loader, the label and contact resolvers, the
// method's begin, proof, completion and redemption, and the sender of the
// emailed code) is answered exactly as a plain outage of that port: the same
// response, byte for byte, the same limiter charges, voids, sends and stored
// enrolment, and the same records. It is never the invalid-code or
// already-enrolled refusal, whatever it claims to be. It is reported once, to
// the chain's logger, and not to slog.Default().
//
// Its rows are one invariant over sites, contexts and hostile errors, so the
// table holds data and one shared assertion rather than a closure per row.
func TestPortErrors_EnrolmentPorts(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(enrolPortsRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	contexts := []struct {
		name         string
		cancelDuring bool
	}{
		{name: "live"},
		{name: "cancelled", cancelDuring: true},
	}

	plainOutage := errors.New("enrolment dependency: connection refused")

	for _, site := range enrolPortSites() {
		for _, c := range contexts {
			for _, kind := range enrolPortErrKinds(site.claims) {
				row := site.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				if kind.ctx != "" && kind.ctx != c.name {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						limiterPortErrInChild(t, enrolPortsRowEnv, enrolPortsRan, row)

						return
					}

					defaults := swapDefaultLogger(t)

					plain := enrolPortThrough(t, site, plainOutage, c.cancelDuring)
					require.Empty(t, abortRecords(plain.logs), "the plain outage writes no abort record")
					require.Equal(t, 1, plain.hits, "the port was reached once")
					require.True(t, plain.handedWalkable, "the plain outage hands out a walkable error")

					got := enrolPortThrough(t, site, kind.err, c.cancelDuring)

					assert.Equal(t, plain.status, got.status, "status")
					assert.Equal(t, plain.header, got.header, "headers")
					assert.Equal(t, plain.body, got.body, "body")
					assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")
					assert.Equal(t, plain.hits, got.hits, "calls of the failing port")
					assert.Equal(t, plain.redeems, got.redeems, "redemptions, voiding included")
					assert.Equal(t, plain.asked, got.asked, "checks of the limiters")
					assert.Equal(t, plain.charged, got.charged, "charges to the limiters")
					assert.Equal(t, plain.stored, got.stored, "the stored enrolment")
					assert.Equal(t, plain.enrolled, got.enrolled, "a usable enrolment")
					assert.True(t, got.handedWalkable, "the port's hostile error was handed out past its call site")
					assert.Equal(t, plain.sent, got.sent, "messages handed to the sender")
					assert.Equal(t, nonAbortMessages(plain.logs), nonAbortMessages(got.logs), "the chain's records")
					noRecordCarries(t, &capturingHandler{recs: got.logs}, hostileSecret)

					aborts := abortRecords(got.logs)
					if kind.reason == "" {
						assert.Empty(t, aborts, "a walk that completes writes no abort record")
					} else {
						require.Len(t, aborts, 1, "one abort record, on the chain's logger")
						assertAbortRecord(t, aborts[0], kind.reason)
					}

					assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

					if childRow != "" && !t.Failed() {
						fmt.Fprintln(os.Stdout, enrolPortsRan+row)
					}
				})
			}
		}
	}
}
