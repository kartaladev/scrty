package httpsec_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// failingSelectorStore is a session store whose selection write fails with err.
type failingSelectorStore struct {
	session.Store

	err error
}

func (s failingSelectorStore) SelectRole(context.Context, string, string) error { return s.err }

// switchSetup is what a role-switch fixture varies.
type switchSetup struct {
	// off builds the chain without WithSwitchableRoles.
	off bool

	// store, when set, wraps the memory store the session manager uses.
	store func(session.Store) session.Store

	// publishOther adds a consumer interceptor, after the built-in bearer,
	// that publishes the fixture's other session (another user's) once a
	// test has set it.
	publishOther bool

	// anonymous sends the request without credentials, so the chain resolves
	// no session itself.
	anonymous bool
}

// switchFixture is a session-bearer chain over a memory session store on a fake
// clock, with a live session of ada, who holds sales (primary) and audit.
type switchFixture struct {
	clk      *clockwork.FakeClock
	sessions *session.Sessions
	session  *session.Session
	rec      *eventRecorder
	chain    *httpsec.Chain

	// user is what the user loader returns for ada; a test replaces it to
	// change her grants between requests.
	user func() *identity.Details

	// other is bob's live session, which a consumer interceptor publishes when
	// set; anonymous drops the request's credentials.
	other     *session.Session
	anonymous bool
}

// adaWithGrants is ada holding sales, primary, and audit, both undated.
func adaWithGrants() *identity.Details {
	d := storedUser()
	d.Roles = []*identity.AssignedRole{
		{ID: "r-sales", Name: "sales", Primary: true},
		{ID: "r-audit", Name: "audit"},
	}

	return d
}

func newSwitchFixture(t *testing.T, setup switchSetup) *switchFixture {
	t.Helper()

	f := &switchFixture{
		clk:  clockwork.NewFakeClockAt(time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)),
		rec:  &eventRecorder{},
		user: adaWithGrants,

		anonymous: setup.anonymous,
	}

	var store session.Store = must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(f.clk)))
	if setup.store != nil {
		store = setup.store(store)
	}

	var err error

	f.sessions, err = session.New(session.WithClock(f.clk), session.WithStore(store))
	require.NoError(t, err)

	f.session, err = f.sessions.Create(t.Context(), testUserID, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), testUserID).AnyTimes().
		DoAndReturn(func(ctx context.Context, _ identity.UserID) (*identity.Details, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			return f.user(), nil
		})

	opts := []httpsec.Option{
		httpsec.WithClock(f.clk),
		httpsec.WithLogger(discardLogger()),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: users}),
		httpsec.EnableSecurityEvents(f.rec.sink),
	}
	if setup.publishOther {
		opts = append(opts, httpsec.RegisterInterceptor(
			httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				if o := f.other; o != nil {
					a := &authenticate.Authentication{Principal: &identity.Principal{ID: o.UserID, Username: "bob"}}
					if err := ex.PublishSession(a, o); err != nil {
						return err
					}
				}

				return next(ex)
			}), httpsec.OrderBearerToken))
	}

	if !setup.off {
		opts = append(opts, httpsec.WithSwitchableRoles())
	}

	f.chain, err = httpsec.New(opts...)
	require.NoError(t, err)

	return f
}

// request runs one request on ada's session, with handler as the
// application's handler, and returns the chain's answer.
func (f *switchFixture) request(t *testing.T, handler func(ex *httpsec.Exchange) error) error {
	t.Helper()

	req := bearerRequest(t.Context(), "Bearer "+f.session.ID)
	if f.anonymous {
		req.Header.Del("Authorization")
	}

	run := f.chain.Assemble(handler)

	return run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req),
		httpsec.NewHTTPResponseWriter(httptest.NewRecorder())))
}

// switchTo switches ada's active role to role from inside a request on her
// session, once during has run, on the request's context as ctx modifies it,
// and returns what the switch returned.
func (f *switchFixture) switchTo(
	t *testing.T,
	during func(t *testing.T, f *switchFixture),
	ctx func(context.Context) context.Context,
	role string,
) error {
	t.Helper()

	var switched error

	ran := false

	require.NoError(t, f.request(t, func(ex *httpsec.Exchange) error {
		ran = true

		if during != nil {
			during(t, f)
		}

		c := ex.Context()
		if ctx != nil {
			c = ctx(c)
		}

		switched = f.chain.SwitchActiveRole(c, role)

		return nil
	}))
	require.True(t, ran, "the request reached the handler")

	return switched
}

// active is the name of the active role of ada's next request, "" for none.
func (f *switchFixture) active(t *testing.T) string {
	t.Helper()

	var name string

	require.NoError(t, f.request(t, func(ex *httpsec.Exchange) error {
		p, ok := identity.PrincipalFromContext(ex.Context())
		require.True(t, ok, "the request is authenticated")

		if p.ActiveRole != nil {
			name = p.ActiveRole.Name
		}

		return nil
	}))

	return name
}

// selected is the selected role ada's stored session records.
func (f *switchFixture) selected(t *testing.T) string {
	t.Helper()

	s, err := f.sessions.Load(t.Context(), f.session.ID)
	require.NoError(t, err)

	return s.SelectedRole
}

// switched is every role-switch event reported so far.
func (f *switchFixture) switched() []event.Event {
	var out []event.Event

	for _, e := range f.rec.all() {
		if e.Name == event.ActiveRoleSwitched {
			out = append(out, e)
		}
	}

	return out
}

// TestChain_SwitchActiveRole pins switching the active role: a held, valid
// grant is recorded on the session and becomes active on the next request,
// with one event; anything else is refused with the session unchanged.
func TestChain_SwitchActiveRole(t *testing.T) {
	t.Parallel()

	errStoreDown := errors.New("the session store holds row 7 and cannot reach it")

	// unchanged asserts the refusal left the session as it was and reported
	// nothing.
	unchanged := func(t *testing.T, f *switchFixture) {
		t.Helper()

		assert.Empty(t, f.selected(t), "the session records no selection")
		assert.Equal(t, "sales", f.active(t), "the primary grant stays active")
		assert.Empty(t, f.switched(), "a refused switch reports nothing")
	}

	type testCase struct {
		name   string
		setup  switchSetup
		before func(t *testing.T, f *switchFixture)
		during func(t *testing.T, f *switchFixture)
		ctx    func(ctx context.Context) context.Context
		role   string
		assert func(t *testing.T, f *switchFixture, err error)
	}

	cases := []testCase{
		{
			name: "switching to a held role makes it active on the next request and reports it",
			role: "audit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.NoError(t, err)
				assert.Equal(t, "audit", f.selected(t))
				assert.Equal(t, "audit", f.active(t))

				got := f.switched()
				require.Len(t, got, 1)
				assert.Equal(t, event.OutcomeSuccess, got[0].Outcome)
				assert.Equal(t, testUserID, got[0].User)
				assert.Equal(t, string(testUserID), got[0].Actor, "the user switched her own role")
				assert.Equal(t, "audit", got[0].Target, "the role switched to")
				assert.Equal(t, []string{"active_role"}, got[0].Changed)
				assert.Equal(t, factor.Password, got[0].Factor)
				assert.Equal(t, digestOf(f.session.ID), got[0].Session)
			},
		},
		{
			name: "a role not held is refused and the session is unchanged",
			role: "admin",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, httpsec.ErrRoleNotHeld)
				require.ErrorIs(t, err, authorize.ErrAccessDenied)
				require.ErrorIs(t, err, authorize.ErrNoActiveRole)
				assert.NotContains(t, err.Error(), "admin", "the text does not echo the role")
				unchanged(t, f)
			},
		},
		{
			name: "a held grant that has ended is not held",
			before: func(t *testing.T, f *switchFixture) {
				t.Helper()

				f.user = func() *identity.Details {
					d := adaWithGrants()
					d.Roles[1].ValidUntil = f.clk.Now()

					return d
				}
			},
			role: "audit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, httpsec.ErrRoleNotHeld)
				unchanged(t, f)
			},
		},
		{
			name: "a held grant that has not started is not held",
			before: func(t *testing.T, f *switchFixture) {
				t.Helper()

				f.user = func() *identity.Details {
					d := adaWithGrants()
					d.Roles[1].StartDate = f.clk.Now().Add(time.Second)

					return d
				}
			},
			role: "audit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, httpsec.ErrRoleNotHeld)
				unchanged(t, f)
			},
		},
		{
			name: "a role name over the bound is refused as not held",
			role: strings.Repeat("a", 257),
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, httpsec.ErrRoleNotHeld)
				unchanged(t, f)
			},
		},
		{
			name: "a role name the store could not hold is refused as not held",
			before: func(t *testing.T, f *switchFixture) {
				t.Helper()

				f.user = func() *identity.Details {
					d := adaWithGrants()
					d.Roles[1].Name = "au\x00dit"

					return d
				}
			},
			role: "au\x00dit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, httpsec.ErrRoleNotHeld)
				unchanged(t, f)
			},
		},
		{
			name:  "switching is off by default",
			setup: switchSetup{off: true},
			role:  "audit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, httpsec.ErrRoleSwitchingDisabled)
				assert.NotErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				unchanged(t, f)
			},
		},
		{
			name: "the empty role clears the selection",
			before: func(t *testing.T, f *switchFixture) {
				t.Helper()

				require.NoError(t, f.sessions.SelectRole(t.Context(), f.session.ID, "audit"))
				require.Equal(t, "audit", f.active(t))
			},
			role: "",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.NoError(t, err)
				assert.Empty(t, f.selected(t))
				assert.Equal(t, "sales", f.active(t))

				got := f.switched()
				require.Len(t, got, 1)
				assert.Equal(t, "sales", got[0].Target, "the role active once the selection is cleared")
				assert.Equal(t, []string{"active_role"}, got[0].Changed)
			},
		},
		{
			name: "a user no longer active is refused as authentication required",
			before: func(t *testing.T, f *switchFixture) {
				t.Helper()

				// Active for the request's own resolution, inactive for the
				// switch's reload.
				loads := 0
				f.user = func() *identity.Details {
					loads++
					d := adaWithGrants()
					d.Active = loads == 1

					return d
				}
			},
			role: "audit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				f.user = adaWithGrants
				unchanged(t, f)
			},
		},
		{
			name: "a session that ended during the request is refused as authentication required",
			during: func(t *testing.T, f *switchFixture) {
				t.Helper()

				// The session is deleted between its resolution and the switch.
				require.NoError(t, f.sessions.Delete(t.Context(), f.session.ID))
			},
			role: "audit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				assert.Empty(t, f.switched())

				_, loadErr := f.sessions.Load(t.Context(), f.session.ID)
				require.ErrorIs(t, loadErr, session.ErrNotFound, "the switch does not bring the session back")
			},
		},
		{
			name: "a store that fails to record is a dependency failure, not a refusal",
			setup: switchSetup{store: func(s session.Store) session.Store {
				return failingSelectorStore{Store: s, err: errStoreDown}
			}},
			role: "audit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, errStoreDown)
				assert.NotErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				assert.NotErrorIs(t, err, httpsec.ErrRoleNotHeld)
				assert.NotContains(t, err.Error(), "row 7", "the store's text stays behind fixed text")
				assert.Empty(t, f.switched())
			},
		},
		{
			name:  "a session another interceptor published after the chain resolved hers is refused",
			setup: switchSetup{publishOther: true},
			before: func(t *testing.T, f *switchFixture) {
				t.Helper()

				bob, err := f.sessions.Create(t.Context(), "u-bob", session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				f.other = bob
			},
			role: "audit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)

				bob, loadErr := f.sessions.Load(t.Context(), f.other.ID)
				require.NoError(t, loadErr)
				assert.Empty(t, bob.SelectedRole, "the session the request is on is not written")
				assert.Empty(t, f.selected(t), "the session the chain resolved is not written")
				assert.Empty(t, f.switched())
			},
		},
		{
			name:  "a session only a consumer interceptor published is refused as a configuration error",
			setup: switchSetup{publishOther: true, anonymous: true},
			before: func(t *testing.T, f *switchFixture) {
				t.Helper()

				bob, err := f.sessions.Create(t.Context(), "u-bob", session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				f.other = bob
			},
			role: "audit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.NotErrorIs(t, err, httpsec.ErrAuthenticationRequired)

				bob, loadErr := f.sessions.Load(t.Context(), f.other.ID)
				require.NoError(t, loadErr)
				assert.Empty(t, bob.SelectedRole)
				assert.Empty(t, f.switched())
			},
		},
		{
			name: "a context that carries no authenticated request is refused as authentication required",
			ctx: func(context.Context) context.Context {
				return context.Background()
			},
			role: "audit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				assert.Empty(t, f.selected(t))
				assert.Empty(t, f.switched())
			},
		},
		{
			name: "a request that ended is a hang-up, not a refusal",
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()

				return c
			},
			role: "audit",
			assert: func(t *testing.T, f *switchFixture, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				assert.NotErrorIs(t, err, httpsec.ErrRoleNotHeld)
				unchanged(t, f)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSwitchFixture(t, tc.setup)
			if tc.before != nil {
				tc.before(t, f)
			}

			tc.assert(t, f, f.switchTo(t, tc.during, tc.ctx, tc.role))
		})
	}
}

// TestWithSwitchableRoles pins the option's construction check: a chain with
// no session manager to record a selection in is refused before it serves
// anything.
func TestWithSwitchableRoles(t *testing.T) {
	t.Parallel()

	manager := func(t *testing.T) *session.Sessions {
		t.Helper()

		m, err := session.New(session.WithStore(must.Must(session.NewMemoryStore())))
		require.NoError(t, err)

		return m
	}

	bearer := func(m *session.Sessions) httpsec.Option {
		return httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
			Sessions: m, Users: NewMockUserLoader(gomock.NewController(t)),
		})
	}

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			name: "a manager that records a selection builds",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{bearer(manager(t)), httpsec.WithSwitchableRoles()}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				require.NotNil(t, chain)
			},
		},
		{
			name: "the option given twice builds and behaves as once",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					bearer(manager(t)), httpsec.WithSwitchableRoles(), httpsec.WithSwitchableRoles(),
				}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				require.NotNil(t, chain)
			},
		},
		{
			name: "the option given before the manager builds",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.WithSwitchableRoles(),
					bearer(manager(t)),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: manager(t)}),
				}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				require.NotNil(t, chain)
			},
		},
		{
			name: "a chain with no session manager is refused",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.WithSwitchableRoles()}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, chain)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.opts(t)...)
			tc.assert(t, chain, err)
		})
	}
}
