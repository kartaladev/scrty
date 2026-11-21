package oidc_test

// TestPortErrors_Broker replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found. It reuses the
// hostile error types of login_porterr_test.go (pe6a*), read-only.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
)

// pe6bRowEnv names the row a child process runs. It is empty in the parent.
const pe6bRowEnv = "SCRTY_OIDC_BROKER_PORTERR_ROW"

// pe6bRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe6bRanMarker = "SCRTY_OIDC_BROKER_PORTERR_RAN: "

// errPe6bPortDown is the plain outage every parity run fails with.
var errPe6bPortDown = errors.New("port-6b: connection refused")

// pe6bSite names the port call a row fails.
type pe6bSite string

const (
	pe6bFind      pe6bSite = "LinkStore.FindByExternal in Broker"
	pe6bLoad      pe6bSite = "UserLoader.LoadByUserID in resolveLinked"
	pe6bProvision pe6bSite = "UserProvisioner.Provision in provision"
	pe6bInsert    pe6bSite = "LinkStore.Insert in provision"
	pe6bUpdate    pe6bSite = "UserProvisioner.Update in mirror"
	pe6bNewID     pe6bSite = "id.Generator.NewID in provision"
	pe6bProbe     pe6bSite = "password.Encoder.Encode probe in NewBroker"
)

// pe6bClass is the returned error as every check downstream reads it, taken
// inside the run's time bound.
type pe6bClass struct {
	nilErr, unwalkable, linkNotFound, userNotFound, userExists, noLinked, provisioningRefused, config bool

	// quotes is set when the error's text quotes the run's port error.
	quotes bool
}

// pe6bRecord is one record the broker's logger wrote, other than an abort
// record, reduced to what a consumer routes on.
type pe6bRecord struct {
	level, msg, provider string

	// quotes is set when the record's error attribute quotes the run's port
	// error.
	quotes bool
}

// pe6bOutcome is what one call through a failing port produced.
type pe6bOutcome struct {
	class pe6bClass

	// principal is the user the login resolved to, empty when it failed;
	// built is whether NewBroker returned a broker.
	principal identity.UserID
	built     bool

	// The state the call left behind: users provisioned, links inserted and
	// mirror updates written.
	provisions, inserts, updates int64

	records []pe6bRecord
	raw     string
	aborts  []map[string]any
}

// pe6bRun calls the broker on a login whose site port fails with portErr, or
// builds a broker whose encoder probe fails with it. When cancel is set the
// port cancels the caller's context before it fails. It fails the test when
// the call, or the checks of its error, hang or let a panic escape.
func pe6bRun(t *testing.T, site pe6bSite, portErr error, cancel bool) pe6bOutcome {
	t.Helper()

	// Identity, not errors.Is: the hostile errors cannot be walked.
	portText := pe6aSecret
	if portErr == errPe6bPortDown { //nolint:errorlint // identity of the parity error
		portText = errPe6bPortDown.Error()
	}

	ctx, stop := context.WithCancel(t.Context())
	defer stop()

	fail := func() error {
		if cancel {
			stop()
		}

		return portErr
	}

	var provisions, inserts, updates atomic.Int64

	ctrl := gomock.NewController(t)
	links := NewMockLinkStore(ctrl)
	users := NewMockUserLoader(ctrl)
	prov := NewMockUserProvisioner(ctrl)
	ids := NewMockHandoffIDGenerator(ctrl)

	linked := &oidc.Link{
		ID: id.MustParse("01926a4e-0000-7000-8000-0000000006b1"), Provider: "corp", Issuer: brokerCorpIssuer, Subject: "s-1",
		UserID: "u-1", Username: "alice", Email: "alice@corp.example",
	}

	links.EXPECT().FindByExternal(gomock.Any(), "corp", brokerCorpIssuer, "s-1").
		DoAndReturn(func(context.Context, string, string, string) (*oidc.Link, error) {
			switch site {
			case pe6bFind:
				return nil, fail()
			case pe6bLoad, pe6bUpdate:
				return linked, nil
			default:
				return nil, oidc.ErrLinkNotFound
			}
		}).AnyTimes()
	links.EXPECT().Insert(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, oidc.Link) error {
		if site == pe6bInsert {
			return fail()
		}
		inserts.Add(1)

		return nil
	}).AnyTimes()
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			if site == pe6bLoad {
				return nil, fail()
			}

			return mirrorStored(), nil
		}).AnyTimes()
	prov.EXPECT().Provision(gomock.Any(), "alice@corp.example", gomock.Any()).
		DoAndReturn(func(context.Context, string, ...identity.UserOption) (*identity.Details, error) {
			if site == pe6bProvision {
				return nil, fail()
			}
			provisions.Add(1)

			return &identity.Details{ID: "u-new", Username: "alice@corp.example", Active: true}, nil
		}).AnyTimes()
	prov.EXPECT().Update(gomock.Any(), "alice", gomock.Any()).
		DoAndReturn(func(context.Context, string, ...identity.UserOption) (*identity.Details, error) {
			if site == pe6bUpdate {
				return nil, fail()
			}
			updates.Add(1)

			return mirrorStored(), nil
		}).AnyTimes()
	ids.EXPECT().NewID().DoAndReturn(func() (id.ID, error) {
		if site == pe6bNewID {
			return id.Nil, fail()
		}

		return id.MustParse("01926a4e-0000-7000-8000-0000000006b2"), nil
	}).AnyTimes()

	logs := &bytes.Buffer{}
	opts := []oidc.BrokerOption{
		oidc.WithBrokerLogger(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		oidc.WithBrokerClock(clockwork.NewFakeClockAt(provisionClock)),
		oidc.WithBrokerIDGenerator(ids),
		oidc.WithBrokerProvisioner(prov),
		oidc.WithBrokerJIT("corp"),
		oidc.WithBrokerNameClaim("corp", "name"),
		oidc.WithBrokerClaimMirror("corp", true),
	}

	if site == pe6bProbe {
		enc := NewMockEncoder(ctrl)
		enc.EXPECT().Encode(gomock.Any()).DoAndReturn(func(string) ([]byte, error) {
			return nil, fail()
		}).Times(1)
		opts = append(opts, oidc.WithBrokerPasswordEncoder(enc))
	}

	type result struct {
		out      pe6bOutcome
		panicked bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				done <- result{panicked: true, value: recover()}
			}
		}()

		var (
			out  pe6bOutcome
			rerr error
		)

		b, err := oidc.NewBroker(links, users, opts...)
		out.built = b != nil
		rerr = err

		if site != pe6bProbe && err == nil {
			// The linked corp identity presenting a changed display name, so a
			// linked login mirrors it.
			var p *identity.Principal
			p, rerr = b.Broker(ctx, mirrorIdentity("Alice B.", hashCost12))
			if p != nil {
				out.principal = p.ID
			}
		}

		// Every check a caller makes of the error, inside the bound.
		out.class = pe6bClass{
			nilErr:              rerr == nil,
			unwalkable:          errors.Is(rerr, porterr.ErrUnwalkable),
			linkNotFound:        errors.Is(rerr, oidc.ErrLinkNotFound),
			userNotFound:        errors.Is(rerr, identity.ErrUserNotFound),
			userExists:          errors.Is(rerr, identity.ErrUserExists),
			noLinked:            errors.Is(rerr, oidc.ErrNoLinkedAccount),
			provisioningRefused: errors.Is(rerr, oidc.ErrProvisioningRefused),
			config:              errors.Is(rerr, oidc.ErrConfig),
		}
		if rerr != nil {
			out.class.quotes = strings.Contains(rerr.Error(), portText)
		}

		returned = true
		done <- result{out: out}
	}()

	var out pe6bOutcome

	select {
	case res := <-done:
		require.False(t, res.panicked, "a hostile port error escaped as a panic: %v", res.value)
		out = res.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the broker or a check of its error")
	}

	out.provisions, out.inserts, out.updates = provisions.Load(), inserts.Load(), updates.Load()
	out.raw = logs.String()

	for _, rec := range pe6aJSONRecords(t, out.raw) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)

			continue
		}

		provider, _ := rec["provider"].(string)
		errText, _ := rec["error"].(string)
		out.records = append(out.records, pe6bRecord{
			level: rec["level"].(string), msg: rec["msg"].(string), provider: provider,
			quotes: strings.Contains(errText, portText),
		})
	}

	return out
}

// pe6bSiteShape pins what a plain outage of site produces, so a parity row
// cannot pass by two equally wrong outcomes.
func pe6bSiteShape(t *testing.T, site pe6bSite, plain pe6bOutcome) {
	t.Helper()

	c := plain.class
	// Only a link insert fails after the user was provisioned: the user is
	// left with no link, as broker_provision.go documents.
	wantProvisions := int64(0)
	if site == pe6bInsert {
		wantProvisions = 1
	}
	require.Equal(t, wantProvisions, plain.provisions, "precondition: users a plain outage provisions")
	require.Zero(t, plain.inserts, "precondition: no plain outage inserts a link")
	require.Zero(t, plain.updates, "precondition: no plain outage writes a mirror update")
	require.False(t, c.linkNotFound || c.userNotFound || c.userExists || c.noLinked || c.provisioningRefused,
		"precondition: a plain outage is no refusal")

	switch site {
	case pe6bUpdate:
		require.True(t, c.nilErr, "precondition: a failed mirror update does not fail the login")
		require.Equal(t, identity.UserID("u-1"), plain.principal)
		require.Contains(t, plain.records, pe6bRecord{
			level: "ERROR", msg: "oidc: claim mirroring could not update the user; the login continues with the stored values",
			provider: "corp", quotes: true,
		})
	case pe6bProbe:
		require.True(t, c.config, "precondition: a failed probe is a configuration error")
		require.False(t, plain.built, "precondition: no broker is built")
	case pe6bInsert:
		require.False(t, c.nilErr)
		require.Len(t, plain.records, 1, "precondition: the unlinked user is logged")
		require.Equal(t, "ERROR", plain.records[0].level)
	default:
		require.False(t, c.nilErr, "precondition: a plain outage fails the login")
		require.Empty(t, plain.principal)
	}
}

// TestPortErrors_Broker pins that each port call of the identity broker — the
// link store's FindByExternal and Insert, the user loader, the provisioner's
// Provision and Update, the link identifier generator, and the password
// encoder's construction probe — failing with an error whose chain cannot be
// walked is answered exactly as a plain outage of that port: the same result,
// the same answer to every sentinel check a caller makes, the same state
// (users provisioned, links inserted, mirror updates written), the same
// records, and nothing quoting the port's error. A chain that claims the
// sentinel the site branches on (ErrLinkNotFound, which would provision a
// duplicate user; identity.ErrUserNotFound; identity.ErrUserExists) is an
// outage, never that branch. The sanitizer writes one record, to the broker's
// logger, and none to slog.Default().
func TestPortErrors_Broker(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe6bRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name string
		site pe6bSite
		err  error

		// cancel makes the port cancel the caller's context before it fails,
		// in both runs of the row.
		cancel bool

		// child runs the row in a child process: unsanitized, it may
		// overflow the stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got pe6bOutcome)
	}

	sameAsPlain := func(t *testing.T, plain, got pe6bOutcome) {
		t.Helper()

		wantClass := plain.class
		wantClass.unwalkable = got.class.unwalkable // asserted by the caller
		wantClass.quotes = got.class.quotes         // asserted by the caller
		assert.Equal(t, wantClass, got.class, "the same answer to every check of the error")
		assert.Equal(t, plain.principal, got.principal, "the same principal")
		assert.Equal(t, plain.built, got.built, "the same construction result")
		assert.Equal(t, plain.provisions, got.provisions, "the same users provisioned")
		assert.Equal(t, plain.inserts, got.inserts, "the same links inserted")
		assert.Equal(t, plain.updates, got.updates, "the same mirror updates")
		require.Len(t, got.records, len(plain.records), "the same records")

		for i := range plain.records {
			want := plain.records[i]
			want.quotes = got.records[i].quotes // asserted by the caller
			assert.Equal(t, want, got.records[i], "the same record, level and provider")
		}
	}

	asOutage := func(reason string) func(t *testing.T, plain, got pe6bOutcome) {
		return func(t *testing.T, plain, got pe6bOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)
			assert.False(t, got.class.quotes, "the returned error quotes the port's")
			assert.NotContains(t, got.raw, pe6aSecret, "a record quotes the port's error")

			if !plain.class.nilErr {
				assert.True(t, got.class.unwalkable, "the error is the sanitizer's fault")
			}

			require.Len(t, got.aborts, 1, "one abort record, on the broker's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
		}
	}

	var cases []testCase

	sites := []pe6bSite{pe6bFind, pe6bLoad, pe6bProvision, pe6bInsert, pe6bUpdate, pe6bNewID, pe6bProbe}
	for _, site := range sites {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &pe6aCycleOne{},
				assert: asOutage("budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &pe6aCycleMany{}, child: true,
				assert: asOutage("budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: pe6aPanicUnwrap{},
				assert: asOutage("panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: pe6aPanicNilUnwrap{},
				assert: asOutage("panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: pe6aFanOut(25),
				assert: asOutage("budget")},
			testCase{
				name: prefix + "a typed-nil root walks to the end and is answered as an outage",
				site: site, err: (*pe6aTypedNil)(nil),
				assert: func(t *testing.T, plain, got pe6bOutcome) {
					t.Helper()

					// A walkable error passes unchanged, so its text comes back
					// exactly where a plain outage's does.
					sameAsPlain(t, plain, got)
					assert.Equal(t, plain.class.quotes, got.class.quotes, "the port's text comes back where it did")

					for i := range plain.records {
						assert.Equal(t, plain.records[i].quotes, got.records[i].quotes, "a record quotes the port's text where it did")
					}

					assert.False(t, got.class.unwalkable, "a walkable error passes unchanged")
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				},
			},
		)

		// NewBroker takes no context: there is none to cancel.
		if site != pe6bProbe {
			cases = append(cases, testCase{
				name: prefix + "a cycle after the port cancelled the caller's context", site: site,
				err: &pe6aCycleOne{}, cancel: true, assert: asOutage("budget"),
			})
		}
	}

	// The sentinels each site branches on, claimed by a chain that cannot be
	// walked.
	claims := map[pe6bSite][]error{
		pe6bFind:      {oidc.ErrLinkNotFound},
		pe6bLoad:      {identity.ErrUserNotFound},
		pe6bProvision: {identity.ErrUserExists},
	}

	for _, site := range sites {
		for _, claim := range claims[site] {
			prefix := string(site) + ": "
			cases = append(cases,
				testCase{
					name: prefix + "a cycle whose Is claims " + claim.Error() + " is an outage",
					site: site, err: &pe6aClaimCycle{claim: claim}, assert: asOutage("budget"),
				},
				testCase{
					name: prefix + "a cycle wrapping " + claim.Error() + " beside itself is an outage",
					site: site, err: &pe6aClaimCycleMany{claim: claim}, child: true, assert: asOutage("budget"),
				},
			)
		}
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe6bInChild(t, tc.name)

				return
			}

			defaults := pe6aDefaultRecords(t)

			plain := pe6bRun(t, tc.site, errPe6bPortDown, tc.cancel)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			pe6bSiteShape(t, tc.site, plain)

			got := pe6bRun(t, tc.site, tc.err, tc.cancel)
			tc.assert(t, plain, got)

			for _, rec := range pe6aJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe6bRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe6bInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// line that shows it ran the row: a stack overflow is fatal and only a child
// can watch for one.
func pe6bInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe6bRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe6bRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
