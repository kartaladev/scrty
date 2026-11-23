package test

// The two scenarios here share one stack builder and differ in what they
// exercise (a grant matrix reaching a guard, an imported hash reaching a
// login), so they are separate functions and not table rows.

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/migrate"
	"github.com/kartaladev/scrty/store/pgxstore"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	adminE2EPassword = "correct horse battery staple 42!"
	adminE2EOwned    = "lead-owned"
	adminE2EOther    = "lead-other"
)

// adminE2EEvents records every event the administration services report.
type adminE2EEvents struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *adminE2EEvents) sink(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, e)
}

func (r *adminE2EEvents) count(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := 0

	for _, e := range r.events {
		if e.Name == name {
			n++
		}
	}

	return n
}

// adminE2EStack is the real wiring: a migrated database, the pgx identity
// store as every identity and administration port, and a net/http chain
// logging in through a username and password provider and resolving the
// session reference it issues on every later request.
type adminE2EStack struct {
	store  *pgxstore.IdentityStore
	events *adminE2EEvents
	chain  *httpsec.Chain
	authz  authorize.Authorizer

	// refused is the refusal the last request ended in, nil when it was served.
	refusedMu sync.Mutex
	refused   error
}

func (s *adminE2EStack) lastRefusal() error {
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()

	return s.refused
}

func (s *adminE2EStack) refuse(w http.ResponseWriter, _ *http.Request, err error) {
	s.refusedMu.Lock()
	s.refused = err
	s.refusedMu.Unlock()

	w.WriteHeader(httpsec.StatusForError(err))
}

func (s *adminE2EStack) reset() {
	s.refusedMu.Lock()
	s.refused = nil
	s.refusedMu.Unlock()
}

// newAdminE2EStack builds the stack. encoder, when not nil, is the password
// encoder of the login provider.
func newAdminE2EStack(t *testing.T, encoder password.Encoder) *adminE2EStack {
	t.Helper()

	ss, is := migrate.SecurityState(), migrate.Identity()
	conn := RunTestPostgres(t,
		WithTestPostgresMigrations(ss.FS(), ss.Dir, ss.VersionTable),
		WithTestPostgresMigrations(is.FS(), is.Dir, is.VersionTable),
	)

	cfg, err := pgxpool.ParseConfig(conn.DSN)
	require.NoError(t, err)

	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	store, err := pgxstore.NewIdentityStore(pool)
	require.NoError(t, err)

	var opts []authenticate.PasswordOption
	if encoder != nil {
		opts = append(opts, authenticate.WithPasswordEncoder(encoder))
	}

	provider, err := authenticate.NewUsernamePasswordAuthenticator(store, opts...)
	require.NoError(t, err)

	sessions, err := session.New(session.WithStore(must.Must(session.NewMemoryStore())))
	require.NoError(t, err)

	authz, err := authorize.NewPrivilegeAuthorizer(store)
	require.NoError(t, err)

	stack := &adminE2EStack{store: store, events: &adminE2EEvents{}, authz: authz}

	stack.chain, err = httpsec.New(
		httpsec.WithErrorHandler(stack.refuse),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: store}),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: provider,
			Sessions:      sessions,
			Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
		}),
	)
	require.NoError(t, err)

	return stack
}

// loginStatus posts the credentials through the chain and returns the status.
func (s *adminE2EStack) loginStatus(t *testing.T, username, pw string) int {
	t.Helper()

	body := url.Values{
		httpsec.DefaultLoginUsernameParam: {username},
		httpsec.DefaultLoginPasswordParam: {pw},
	}.Encode()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultLoginPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	s.chain.Middleware()(http.NotFoundHandler()).ServeHTTP(rec, req)

	return rec.Code
}

// login posts the credentials through the chain and returns the session
// reference the response carries.
func (s *adminE2EStack) login(t *testing.T, username, pw string) string {
	t.Helper()

	body := url.Values{
		httpsec.DefaultLoginUsernameParam: {username},
		httpsec.DefaultLoginPasswordParam: {pw},
	}.Encode()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultLoginPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	s.chain.Middleware()(http.NotFoundHandler()).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "the login is served; refusal: %v", s.lastRefusal())

	var doc struct {
		AccessToken string `json:"access_token"`
	}

	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.AccessToken, "the login issues a session reference")

	return doc.AccessToken
}

// serve sends one request with the session reference through the chain and the
// mux, and returns the status. The refusal, if any, is in lastRefusal.
func (s *adminE2EStack) serve(t *testing.T, handler http.Handler, ref, target string) int {
	t.Helper()

	s.reset()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer "+ref)

	rec := httptest.NewRecorder()
	s.chain.Middleware()(handler).ServeHTTP(rec, req)

	return rec.Code
}

// TestAdministration_EndToEnd covers the whole administration path against
// PostgreSQL: a catalogue, a role granted view on all and update on own, a user
// created and given the role and a password through the services, a login
// through the chain, the privileges the login holds, a route guard that
// refuses the own-only update, an ownership check that tells an owned record
// from another, and the deactivation taking effect on the next request.
func TestAdministration_EndToEnd(t *testing.T) {
	t.Parallel()

	stack := newAdminE2EStack(t, nil)
	ctx := admin.WithSystemActor(t.Context(), "e2e")
	sink := admin.WithEventSink(stack.events.sink)

	catalogue, err := authorize.NewCatalogue(authorize.CatalogueResource{
		Group: "crm", Name: "lead",
		Privileges: []authorize.CataloguePrivilege{{Name: "view"}, {Name: "update"}},
	})
	require.NoError(t, err)

	roles, err := admin.NewRoles(stack.store, sink)
	require.NoError(t, err)

	grants, err := admin.NewGrants(stack.store, catalogue, sink)
	require.NoError(t, err)

	users, err := admin.NewUsers(stack.store, sink)
	require.NoError(t, err)

	assignments, err := admin.NewAssignments(stack.store, sink)
	require.NoError(t, err)

	role, err := roles.Create(ctx, admin.Role{Name: "partner", DisplayName: "Partner"})
	require.NoError(t, err)

	grantsVersion, err := grants.Replace(ctx, role.Name, role.Version, admin.ResourceGrants{
		Group: "crm", Resource: "lead",
		Grants: []admin.Grant{
			{Privilege: "view", Granted: true, Scope: identity.ScopeAll},
			{Privilege: "update", Granted: true, Scope: identity.ScopeOwn},
		},
	})
	require.NoError(t, err)

	user, err := users.Create(ctx, admin.NewUser{Username: "pat", Name: "Pat Partner", Email: "pat@example.com"})
	require.NoError(t, err)

	version, err := assignments.Add(ctx, user.ID, user.Version, admin.Assignment{Role: "partner", Primary: true})
	require.NoError(t, err)

	user, err = users.SetPassword(ctx, user.ID, version, []byte(adminE2EPassword))
	require.NoError(t, err)

	guards, err := httpsec.NewGuards(stack.authz, httpsec.WithGuardErrorHandler(stack.refuse))
	require.NoError(t, err)

	requireView, err := guards.Require(authorize.HasPrivilege("crm", "lead", "view"))
	require.NoError(t, err)

	requireUpdate, err := guards.Require(authorize.HasPrivilege("crm", "lead", "update"))
	require.NoError(t, err)

	owners := map[string]identity.UserID{adminE2EOwned: user.ID}

	var (
		heldMu  sync.Mutex
		held    authorize.Holdings
		heldErr error
		forErr  = map[string]error{}
	)

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	mux := http.NewServeMux()
	mux.Handle("GET /leads", requireView(ok))
	mux.Handle("GET /leads/update", requireUpdate(ok))
	mux.HandleFunc("GET /held", func(w http.ResponseWriter, r *http.Request) {
		h, err := authorize.HeldPrivileges(authorize.WithAuthorizer(r.Context(), stack.authz), "crm", "lead", "view", "update")

		heldMu.Lock()
		held, heldErr = h, err
		heldMu.Unlock()

		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /leads/{id}", func(w http.ResponseWriter, r *http.Request) {
		leadID := r.PathValue("id")
		check := authorize.HasPrivilegeFor("crm", "lead", authorize.OwnershipAttributes{
			Group: "crm", Resource: "lead",
			ResolveID: func(context.Context) (string, error) { return leadID, nil },
			OwnedBy: func(_ context.Context, subject *identity.Principal, id string) (bool, error) {
				return owners[id] == subject.ID, nil
			},
		}, "update")
		err := check(authorize.WithAuthorizer(r.Context(), stack.authz))

		heldMu.Lock()
		forErr[leadID] = err
		heldMu.Unlock()

		w.WriteHeader(http.StatusNoContent)
	})

	ref := stack.login(t, "pat", adminE2EPassword)

	// The privileges the login holds are exactly the grants: view all, update own.
	assert.Equal(t, http.StatusNoContent, stack.serve(t, mux, ref, "/held"))

	heldMu.Lock()
	require.NoError(t, heldErr)
	view, viewOK := held.Lookup("view")
	update, updateOK := held.Lookup("update")
	heldMu.Unlock()

	require.True(t, viewOK)
	require.True(t, updateOK)
	assert.Equal(t, authorize.Holding{Privilege: "view", Held: true, Scope: identity.ScopeAll}, view)
	assert.Equal(t, authorize.Holding{Privilege: "update", Held: true, Scope: identity.ScopeOwn}, update)

	// view on all passes its guard.
	assert.Equal(t, http.StatusNoContent, stack.serve(t, mux, ref, "/leads"))
	assert.NoError(t, stack.lastRefusal())

	// update on own only does not pass a route guard that demands all: the
	// handler would otherwise show an own-only caller every record.
	assert.Equal(t, http.StatusForbidden, stack.serve(t, mux, ref, "/leads/update"))
	require.ErrorIs(t, stack.lastRefusal(), authorize.ErrWrongScope)
	assert.ErrorIs(t, stack.lastRefusal(), authorize.ErrAccessDenied)

	// the ownership check passes the owned lead and refuses another.
	assert.Equal(t, http.StatusNoContent, stack.serve(t, mux, ref, "/leads/"+adminE2EOwned))
	assert.Equal(t, http.StatusNoContent, stack.serve(t, mux, ref, "/leads/"+adminE2EOther))

	heldMu.Lock()
	assert.NoError(t, forErr[adminE2EOwned], "the owned lead is updatable")
	require.Error(t, forErr[adminE2EOther])
	assert.True(t, errors.Is(forErr[adminE2EOther], authorize.ErrNotOwner), "another's lead is refused as not owned: %v", forErr[adminE2EOther])
	heldMu.Unlock()

	// the services reported their changes.
	assert.Equal(t, 1, stack.events.count(event.UserCreated))
	assert.Equal(t, 1, stack.events.count(event.PrivilegePermissionsChanged))

	// a privilege the catalogue does not list is refused and nothing is written.
	beforeGrants, beforeVersion, err := grants.Get(ctx, role.Name)
	require.NoError(t, err)
	require.Equal(t, grantsVersion, beforeVersion)

	_, err = grants.Replace(ctx, role.Name, grantsVersion, admin.ResourceGrants{
		Group: "crm", Resource: "lead",
		Grants: []admin.Grant{{Privilege: "purge", Granted: true, Scope: identity.ScopeAll}},
	})
	require.ErrorIs(t, err, admin.ErrUnknownPrivilege)

	afterGrants, afterVersion, err := grants.Get(ctx, role.Name)
	require.NoError(t, err)
	assert.Equal(t, beforeGrants, afterGrants, "a refused replace leaves the grants as they were")
	assert.Equal(t, beforeVersion, afterVersion, "a refused replace does not bump the version")
	assert.Equal(t, 1, stack.events.count(event.PrivilegePermissionsChanged), "a refused replace reports nothing")

	// deactivating the user ends their session at the next request.
	_, err = users.Deactivate(ctx, user.ID, user.Version)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, stack.serve(t, mux, ref, "/leads"))
	assert.ErrorIs(t, stack.lastRefusal(), httpsec.ErrAuthenticationRequired)
}

// TestAdministration_ImportBcrypt covers a user imported with a bcrypt hash:
// the user logs in with the password through a provider whose encoder verifies
// bcrypt, and importing the same payload again changes nothing and reports
// nothing.
func TestAdministration_ImportBcrypt(t *testing.T) {
	t.Parallel()

	bcrypt, err := password.NewBcryptEncoder()
	require.NoError(t, err)

	hash, err := bcrypt.Encode(adminE2EPassword)
	require.NoError(t, err)

	stack := newAdminE2EStack(t, bcrypt)
	ctx := admin.WithSystemActor(t.Context(), "e2e-import")

	importer, err := admin.NewImporter(stack.store, bcrypt, admin.WithEventSink(stack.events.sink))
	require.NoError(t, err)

	payload := admin.ImportedUser{
		ID:           "0192f1e2-3c4d-7e5f-8a9b-0c1d2e3f4a5b",
		Username:     "legacy",
		Name:         "Legacy User",
		Email:        "legacy@example.com",
		PasswordHash: hash,
		Active:       true,
	}

	out, err := importer.Import(ctx, payload)
	require.NoError(t, err)
	assert.Equal(t, admin.ImportCreated, out)
	assert.Equal(t, 1, stack.events.count(event.UserImported))

	// a wrong password is refused as an authentication failure.
	assert.Equal(t, http.StatusUnauthorized, stack.loginStatus(t, "legacy", "not-the-password"))

	// the imported hash verifies through the bcrypt provider.
	assert.NotEmpty(t, stack.login(t, "legacy", adminE2EPassword))

	out, err = importer.Import(ctx, payload)
	require.NoError(t, err)
	assert.Equal(t, admin.ImportUnchanged, out)
	assert.Equal(t, 1, stack.events.count(event.UserImported), "an unchanged import reports nothing")

	// the re-import did not clobber the hash.
	assert.NotEmpty(t, stack.login(t, "legacy", adminE2EPassword))
	assert.Equal(t, http.StatusUnauthorized, stack.loginStatus(t, "legacy", "not-the-password"))
}
