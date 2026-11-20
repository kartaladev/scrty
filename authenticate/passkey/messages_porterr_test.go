package passkey_test

// TestPortErrors_Notices replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found. The hostile error
// types, the outage, the failing-port switch and the default-logger capture are
// those of the login and registration port-error tests; the panic(nil) rows
// rely on the //go:debug panicnil=1 directive in login_porterr_test.go.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/notify"
)

// pmsgRowEnv names the row a child process runs. It is empty in the parent.
const pmsgRowEnv = "SCRTY_PASSKEY_NOTICE_PORTERR_ROW"

// pmsgRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pmsgRanMarker = "SCRTY_PASSKEY_NOTICE_PORTERR_RAN: "

// pmsgNotQueued is the manager's record of a notice it could not queue.
const pmsgNotQueued = "passkey: a notice was not queued"

// The port calls a row fails. The notice sites are reached by a registration
// from a full session, whose passkey is active at once and so owes the binding
// notice; the emailed-code sites by one from an enrolment-only session that
// awaits an emailed code.
const (
	pmsgNotice        plogSite = "the binding notice's Send"
	pmsgNoticeLoad    plogSite = "the binding notice's LoadByUserID"
	pmsgNoticeResolve plogSite = "the binding notice's contact resolver"
	pmsgCodeLoad      plogSite = "the emailed code's LoadByUserID"
	pmsgCodeResolve   plogSite = "the emailed code's contact resolver"
)

// pmsgSender fails the notice's Send, and is non-blocking as a queued sender
// is.
type pmsgSender struct {
	notify.Sender

	ports *plogPorts
}

func (s pmsgSender) Send(ctx context.Context, msg notify.Message) error {
	if err := s.ports.fails(pmsgNotice); err != nil {
		return err
	}

	return s.Sender.Send(ctx, msg)
}

func (pmsgSender) NonBlocking() bool { return true }

// pmsgUsers is the consumer's user loader. Armed at site, it fails with the
// row's error, or, when noUser is set, answers no user and no error.
type pmsgUsers struct {
	identity.UserLoader

	ports  *plogPorts
	site   plogSite
	noUser bool
}

func (u pmsgUsers) LoadByUserID(ctx context.Context, user identity.UserID) (*identity.Details, error) {
	if u.ports.site == u.site && u.ports.armed.Load() && u.noUser {
		return nil, nil //nolint:nilnil // the broken port contract under test
	}

	if err := u.ports.fails(u.site); err != nil {
		return nil, err
	}

	return u.UserLoader.LoadByUserID(ctx, user)
}

// pmsgResolver is a consumer contact resolver that fails at site, and reads
// the details it is handed as a consumer's resolver would: it dereferences
// them. sawNil records that it was handed no details.
func pmsgResolver(ports *plogPorts, site plogSite, sawNil *atomic.Bool) mfa.ContactResolver {
	return func(_ context.Context, details *identity.Details) (string, error) {
		if err := ports.fails(site); err != nil {
			return "", err
		}

		if details == nil {
			sawNil.Store(true)
		}

		return details.Username, nil
	}
}

// pmsgOutcome is what one registration whose message failed produced.
type pmsgOutcome struct {
	err          error
	text         string
	panicked     bool
	userNotFound bool // the returned error is identity.ErrUserNotFound
	activated    bool // the finish returned an activated passkey
	active       int  // active passkeys the user holds afterwards
	stored       int  // passkeys the user holds afterwards, in any state
	sent         int  // messages the sender queued
	sawNil       bool // the consumer's resolver was handed no details

	// notQueued are the manager's "notice was not queued" records.
	notQueued []map[string]any
	// aborts are the sanitizer's records on the manager's logger.
	aborts []map[string]any
}

// runMessagesSite finishes a registration whose message fails at site with
// portErr, or, when noUser is set, whose user loader answers no user and no
// error there. A notice site finishes from a full session, whose passkey is
// active at once and so owes the binding notice; an emailed-code site from an
// enrolment-only session awaiting an emailed code. When cancelDuring is set the
// failing call cancels the caller's context first. It fails the test when the
// finish, or the classification of what it returned, hangs or panics.
func runMessagesSite(t *testing.T, site plogSite, portErr error, noUser, cancelDuring bool) pmsgOutcome {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ports := &plogPorts{site: site, err: portErr}
	if cancelDuring {
		ports.cancel = cancel
	}

	codeFlow := site == pmsgCodeLoad || site == pmsgCodeResolve
	loadSite := pmsgNoticeLoad

	if codeFlow {
		loadSite = pmsgCodeLoad
	}

	var sawNil atomic.Bool

	f := newFixture(t)
	f.deps.Sender = pmsgSender{Sender: f.deps.Sender, ports: ports}
	f.deps.Users = pmsgUsers{UserLoader: f.deps.Users, ports: ports, site: loadSite, noUser: noUser}

	logs := &logBuffer{}
	opts := []passkey.Option{passkey.WithLogger(logs.logger())}

	s := fullSession("sess-a", "u-1")
	rc := passkey.RegistrationContext{}

	if codeFlow {
		s = enrolmentSession("sess-a", "u-1")
		rc = passkey.RegistrationContext{
			EmailConfirmation: true, ContactResolver: pmsgResolver(ports, pmsgCodeResolve, &sawNil),
		}
	} else {
		opts = append(opts, passkey.WithContactResolver(pmsgResolver(ports, pmsgNoticeResolve, &sawNil)))
	}

	m := f.manager(t, opts...)
	challenge := f.begin(t, m, s)

	ports.armed.Store(true)

	done := make(chan pmsgOutcome, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				_ = recover()
				done <- pmsgOutcome{panicked: true}
			}
		}()

		res, err := m.FinishRegistration(ctx, s, regBody(challenge, "cred-a", ""), rc)

		// Classified inside the bound: a hostile chain that reaches the caller
		// raw hangs here, and fails the run as a hang.
		out := pmsgOutcome{err: err, activated: res != nil && res.Activated}
		if err != nil {
			out.text = err.Error()
			out.userNotFound = errors.Is(err, identity.ErrUserNotFound)
		}

		returned = true
		done <- out
	}()

	var out pmsgOutcome

	select {
	case out = <-done:
		require.False(t, out.panicked, "a hostile port error escaped as a panic")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the finish, or its classification")
	}

	held, err := f.creds.List(t.Context(), "u-1")
	require.NoError(t, err)

	out.stored = len(held)

	for _, c := range held {
		if c.State == passkey.StateActive {
			out.active++
		}
	}

	out.sent = len(f.messages())
	out.sawNil = sawNil.Load()

	for _, rec := range plogRecords(t, logs.String()) {
		switch rec["msg"] {
		case pmsgNotQueued:
			out.notQueued = append(out.notQueued, rec)
		case porterr.MsgClassificationAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// TestPortErrors_Notices pins that a consumer sender, user loader or contact
// resolver failing a passkey notice or the emailed code with an error whose
// chain cannot be walked is answered exactly as a plain outage is:
//
//   - a failed notice leaves the change it reports standing, and is logged by
//     a fixed reason without the error's text;
//   - a failed emailed code fails the finish, and the stored passkey is
//     removed again, with nothing sent.
//
// The sanitizer writes one record to the manager's own logger and none to
// slog.Default(). A user loader answering no user and no error is answered as
// the user not being found, and the consumer's resolver is never handed no
// details.
func TestPortErrors_Notices(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pmsgRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name string
		site plogSite
		err  error

		// plainErr is what the parity run fails with: plogOutage when nil.
		plainErr error
		// noUser makes the user loader answer no user and no error.
		noUser bool
		// cancelDuring makes the failing call cancel the caller's context.
		cancelDuring bool

		// child runs the row in a child process.
		child bool

		// assert receives the parity run's outcome and the row's.
		assert func(t *testing.T, plain, got pmsgOutcome)
	}

	sameAsPlain := func(t *testing.T, site plogSite, plain, got pmsgOutcome) {
		t.Helper()

		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Equal(t, plain.userNotFound, got.userNotFound)
		assert.Equal(t, plain.activated, got.activated)
		assert.Equal(t, plain.active, got.active)
		assert.Equal(t, plain.stored, got.stored, "the same stored state")
		assert.Equal(t, plain.sent, got.sent, "the same messages queued")
		assert.Len(t, got.notQueued, len(plain.notQueued))
		assert.False(t, got.sawNil, "the consumer's resolver was handed no details")
		assert.NotContains(t, got.text, plogSecret)

		for _, rec := range got.notQueued {
			for _, v := range rec {
				if s, ok := v.(string); ok {
					assert.NotContains(t, s, plogSecret, "the record quotes the error")
				}
			}
		}

		switch site {
		case pmsgCodeLoad, pmsgCodeResolve:
			require.Error(t, got.err, "an emailed code that cannot be queued fails the finish")
			assert.False(t, got.activated)
			assert.Zero(t, got.stored, "the stored passkey is removed again")
			assert.Zero(t, got.sent, "nothing is sent")
			assert.Empty(t, got.notQueued)
		default:
			require.NoError(t, got.err, "a notice that fails does not fail the finish")
			assert.True(t, got.activated, "the passkey is active")
			assert.Equal(t, 1, got.active, "the passkey stays stored and active")
			require.Len(t, got.notQueued, 1, "the failed notice is logged")
			assert.Equal(t, "registered", got.notQueued[0]["reason"])
			assert.Equal(t, plain.notQueued[0]["reason"], got.notQueued[0]["reason"])
		}
	}

	asOutage := func(site plogSite, reason string) func(t *testing.T, plain, got pmsgOutcome) {
		return func(t *testing.T, plain, got pmsgOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

			require.Len(t, got.aborts, 1, "one abort record, on the manager's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			for _, v := range got.aborts[0] {
				if s, ok := v.(string); ok {
					assert.NotContains(t, s, plogSecret, "the record quotes the error")
				}
			}
		}
	}

	var cases []testCase

	for _, site := range []plogSite{pmsgNotice, pmsgNoticeLoad, pmsgNoticeResolve, pmsgCodeResolve} {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &plogCycleOne{},
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &plogCycleMany{}, child: true,
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: plogPanicUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: plogPanicNilUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: plogFanOut(25),
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle on a context the failing call cancelled is an outage", site: site,
				err: &plogCycleOne{}, cancelDuring: true, assert: asOutage(site, "budget")},
			testCase{name: prefix + "a typed-nil root walks to the end and is answered as an outage", site: site,
				err: (*plogTypedNil)(nil),
				assert: func(t *testing.T, plain, got pmsgOutcome) {
					t.Helper()

					sameAsPlain(t, site, plain, got)
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				}},
		)
	}

	// The load sites answer a not-found user as the loader's own refusal, so a
	// hostile error claiming it must still read as an outage.
	cases = append(cases, testCase{
		name: string(pmsgNoticeLoad) + ": a cycle claiming " + identity.ErrUserNotFound.Error(),
		site: pmsgNoticeLoad, err: &plogClaim{claims: identity.ErrUserNotFound},
		assert: asOutage(pmsgNoticeLoad, "budget"),
	})

	// A walkable error keeps its outcome and writes no abort record.
	for _, site := range []plogSite{pmsgNoticeLoad, pmsgNoticeResolve, pmsgCodeResolve} {
		cases = append(cases, testCase{
			name: string(site) + ": a walkable error keeps its outcome", site: site,
			err: fmt.Errorf("consumer: %w", plogOutage),
			assert: func(t *testing.T, plain, got pmsgOutcome) {
				t.Helper()

				sameAsPlain(t, site, plain, got)
				assert.Empty(t, got.aborts, "a walkable error writes no abort record")
			},
		})
	}

	// A loader answering no user and no error is answered as the user not being
	// found, and the consumer's resolver is never handed no details.
	for _, site := range []plogSite{pmsgNoticeLoad, pmsgCodeLoad} {
		cases = append(cases, testCase{
			name: string(site) + ": no user and no error is an unknown user", site: site,
			noUser: true, plainErr: identity.ErrUserNotFound,
			assert: func(t *testing.T, plain, got pmsgOutcome) {
				t.Helper()

				sameAsPlain(t, site, plain, got)
				assert.Empty(t, got.aborts)

				if site == pmsgCodeLoad {
					assert.True(t, got.userNotFound, "answered as the user not being found")
				}
			},
		})
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				portErrInChild(t, pmsgRowEnv, pmsgRanMarker, tc.name)

				return
			}

			defaults := pregDefaultRecords(t)

			plainErr := tc.plainErr
			if plainErr == nil {
				plainErr = plogOutage
			}

			plain := runMessagesSite(t, tc.site, plainErr, false, tc.cancelDuring)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runMessagesSite(t, tc.site, tc.err, tc.noUser, tc.cancelDuring)
			tc.assert(t, plain, got)

			for _, rec := range plogRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pmsgRanMarker + tc.name + "\n")
			}
		})
	}
}
