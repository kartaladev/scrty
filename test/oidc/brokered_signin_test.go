package oidctest_test

// The subtests of TestBrokeredSignIn_AdoptsImportedUser are consecutive steps
// of one story over one store, each depending on the state the one before left.
// They are not rows of a table: they do not share a call shape, so the table
// form does not apply.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/store/migrate"
	"github.com/kartaladev/scrty/store/pgxstore"
	scrtytest "github.com/kartaladev/scrty/test"
	oidctest "github.com/kartaladev/scrty/test/oidc"
)

const (
	brokeredProvider = "corp"
	brokeredDomain   = "corp.example"
)

// syncBuffer is a log sink several goroutines may write to.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// brokeredHarness is a relying party over a real user store, with a consumer's
// sign-in hook that adopts an imported user by verified e-mail, or provisions
// a new one, and writes only through admin.Importer, in Apply.
type brokeredHarness struct {
	idp      *oidctest.IdentityProvider
	store    *pgxstore.IdentityStore
	users    *admin.Users
	importer *admin.Importer
	links    *oidc.MemoryLinkStore
	logs     *syncBuffer
	logger   *slog.Logger
	hooked   *oidc.RelyingParty

	// secrets collects every value that must never reach a log: hashes and
	// the members of every UserInfo body the test set.
	secrets []string

	// linkedSeen is the linked argument the hook received on each sign-in, in
	// order, until takeLinked drains it.
	linkedMu   sync.Mutex
	linkedSeen []identity.UserID
}

// takeLinked returns the linked arguments the hook received since the last
// call, and forgets them.
func (h *brokeredHarness) takeLinked() []identity.UserID {
	h.linkedMu.Lock()
	defer h.linkedMu.Unlock()

	seen := h.linkedSeen
	h.linkedSeen = nil

	return seen
}

func newBrokeredHarness(t *testing.T) *brokeredHarness {
	t.Helper()

	ss, is := migrate.SecurityState(), migrate.Identity()
	conn := scrtytest.RunTestPostgres(t,
		scrtytest.WithTestPostgresMigrations(ss.FS(), ss.Dir, ss.VersionTable),
		scrtytest.WithTestPostgresMigrations(is.FS(), is.Dir, is.VersionTable),
	)

	cfg, err := pgxpool.ParseConfig(conn.DSN)
	require.NoError(t, err)

	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	store, err := pgxstore.NewIdentityStore(pool)
	require.NoError(t, err)

	bcrypt, err := password.NewBcryptEncoder()
	require.NoError(t, err)

	importer, err := admin.NewImporter(store, bcrypt)
	require.NoError(t, err)

	users, err := admin.NewUsers(store)
	require.NoError(t, err)

	roles, err := admin.NewRoles(store)
	require.NoError(t, err)

	actor := admin.WithSystemActor(t.Context(), "brokered-test")
	for _, name := range []string{"staff", "manager"} {
		_, err = roles.Create(actor, admin.Role{Name: name, DisplayName: name})
		require.NoError(t, err)
	}

	logs := &syncBuffer{}

	h := &brokeredHarness{
		idp:      oidctest.NewIdentityProvider(t),
		store:    store,
		users:    users,
		importer: importer,
		links:    oidc.NewMemoryLinkStore(),
		logs:     logs,
		logger:   slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	h.hooked = h.relyingParty(t, oidc.WithBrokerSignInHook(brokeredProvider, h.hook))

	return h
}

// relyingParty builds a relying party for the fixture provider over the
// harness's stores and logger, with the given broker options.
func (h *brokeredHarness) relyingParty(t *testing.T, opts ...oidc.BrokerOption) *oidc.RelyingParty {
	t.Helper()

	broker, err := oidc.NewBroker(h.links, h.store, append(opts, oidc.WithBrokerLogger(h.logger))...)
	require.NoError(t, err)

	registry, err := oidc.NewRegistry(h.idp.Provider(brokeredProvider, oidc.ClientSecretPost))
	require.NoError(t, err)

	rp, err := oidc.NewRelyingParty(registry, broker,
		oidc.WithOutboundClient(h.idp.Outbound(t)), oidc.WithLogger(h.logger))
	require.NoError(t, err)

	return rp
}

// userInfo is the members the provider answers for one subject.
type userInfo struct {
	email, name, dept, role, hash string
	verified                      bool
}

// setUserInfo makes the provider answer info for subject, and records every
// value of it as a secret the logs must not hold.
func (h *brokeredHarness) setUserInfo(t *testing.T, subject string, info userInfo) {
	t.Helper()

	h.idp.SetUserInfo(subject, map[string]any{
		"email":          info.email,
		"email_verified": info.verified,
		"name":           info.name,
		"dept":           info.dept,
		"role":           info.role,
		"pw_hash":        info.hash,
	})
	h.secrets = append(h.secrets, info.email, info.name, info.dept, info.hash)
}

// read is the consumer's view of a UserInfo answer.
func read(m map[string]any, key string) string {
	s, _ := m[key].(string)

	return s
}

// hook decides, and writes nothing: it matches an existing user by verified
// e-mail and adopts it, or provisions a new user under a fresh UUID for an
// unmatched e-mail at the provider's own domain. The writes are in Apply.
func (h *brokeredHarness) hook(
	ctx context.Context, _ oidc.ExternalIdentity, up oidc.Upstream, linked identity.UserID,
) (oidc.SignInDecision, error) {
	h.linkedMu.Lock()
	h.linkedSeen = append(h.linkedSeen, linked)
	h.linkedMu.Unlock()

	info, err := up.UserInfo(ctx)
	if err != nil {
		return oidc.SignInDecision{}, err
	}

	email := read(info, "email")
	if verified, _ := info["email_verified"].(bool); !verified || email == "" {
		return oidc.SignInDecision{}, oidc.ErrNoLinkedAccount
	}

	found, err := h.store.LoadByEmail(ctx, email)

	switch {
	case err == nil:
		return oidc.SignInDecision{
			User:  found.ID,
			Apply: h.apply(found.ID, found.Username, info, false),
		}, nil

	case errors.Is(err, identity.ErrUserNotFound):
		if !strings.HasSuffix(email, "@"+brokeredDomain) {
			return oidc.SignInDecision{}, oidc.ErrProvisioningRefused
		}

		user := linked
		if user == "" {
			fresh, genErr := id.NewV7Generator().NewID()
			if genErr != nil {
				return oidc.SignInDecision{}, genErr
			}
			user = identity.UserID(fresh.String())
		}

		return oidc.SignInDecision{
			User:      user,
			Provision: true,
			Apply:     h.apply(user, email, info, linked == ""),
		}, nil

	default:
		return oidc.SignInDecision{}, err
	}
}

// apply writes the user from info through the importer, as a system actor.
// With createOnly it fails unless the user was created, which is what a first
// provisioning sign-in must do (the importer would otherwise adopt silently).
func (h *brokeredHarness) apply(
	user identity.UserID, username string, info map[string]any, createOnly bool,
) func(context.Context) error {
	return func(ctx context.Context) error {
		outcome, err := h.importer.Import(admin.WithSystemActor(ctx, "sso-sync"), admin.ImportedUser{
			ID:              user,
			Username:        username,
			Name:            read(info, "name"),
			Email:           read(info, "email"),
			EmailVerifiedAt: time.Now(),
			PasswordHash:    []byte(read(info, "pw_hash")),
			Active:          true,
			Roles:           []string{read(info, "role")},
			Attributes:      map[string]string{"dept": read(info, "dept")},
		})
		if err != nil {
			return err
		}
		if createOnly && outcome != admin.ImportCreated {
			return errors.New("the provisioned user already existed")
		}

		return nil
	}
}

// signIn runs one login of subject through rp, up to and including the
// callback, and returns what the callback returned.
func (h *brokeredHarness) signIn(t *testing.T, rp *oidc.RelyingParty, subject string) (oidc.CallbackResult, error) {
	t.Helper()

	authz, err := rp.Authorize(t.Context(), brokeredProvider, "/")
	require.NoError(t, err)

	callback := h.idp.Login(t, authz.RedirectURL, map[string]any{"sub": subject})

	u, err := url.Parse(callback)
	require.NoError(t, err)

	return rp.Callback(t.Context(), brokeredProvider, u.Query().Get("code"), u.Query().Get("state"), authz.Handle)
}

// importUser seeds a user as another system would have exported it.
func (h *brokeredHarness) importUser(t *testing.T, active bool, email, name, hash string) identity.UserID {
	t.Helper()

	fresh, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	user := identity.UserID(fresh.String())

	outcome, err := h.importer.Import(admin.WithSystemActor(t.Context(), "seed"), admin.ImportedUser{
		ID:              user,
		Username:        email,
		Name:            name,
		Email:           email,
		EmailVerifiedAt: time.Now(),
		PasswordHash:    []byte(hash),
		Active:          active,
		Roles:           []string{"staff"},
		Attributes:      map[string]string{"dept": "legacy"},
	})
	require.NoError(t, err)
	require.Equal(t, admin.ImportCreated, outcome)

	return user
}

func (h *brokeredHarness) countUsers(t *testing.T) int {
	t.Helper()

	page, err := h.users.List(t.Context(), admin.UserFilter{PageSize: 100})
	require.NoError(t, err)
	require.Empty(t, page.Next, "the store holds more users than one page")

	return len(page.Users)
}

func (h *brokeredHarness) user(t *testing.T, user identity.UserID) admin.User {
	t.Helper()

	u, err := h.users.Get(t.Context(), user)
	require.NoError(t, err)

	return u
}

func (h *brokeredHarness) hashOf(t *testing.T, user identity.UserID) string {
	t.Helper()

	d, err := h.store.LoadByUserID(t.Context(), user)
	require.NoError(t, err)

	return string(d.Password)
}

func (h *brokeredHarness) linksOf(t *testing.T, user identity.UserID) []oidc.Link {
	t.Helper()

	l, err := h.links.ListByUser(t.Context(), user)
	require.NoError(t, err)

	return l
}

// primaryRole is the name of the user's primary role, "" when it has none.
func primaryRole(u admin.User) string {
	for _, r := range u.Roles {
		if r.Primary {
			return r.Name
		}
	}

	return ""
}

// TestBrokeredSignIn_AdoptsImportedUser drives a sign-in hook end to end over a
// real user store and a provider that answers UserInfo: an imported user with
// no link is adopted by verified e-mail and updated through admin in Apply
// only; the next sign-in goes through the link and refreshes; a conflicting
// e-mail and an inactive account are refused with nothing written; a new
// verified identity is provisioned; with the hook off nothing changes; and no
// token, UserInfo value or hash reaches a log.
func TestBrokeredSignIn_AdoptsImportedUser(t *testing.T) {
	t.Parallel()

	h := newBrokeredHarness(t)

	bcrypt, err := password.NewBcryptEncoder()
	require.NoError(t, err)

	encode := func(plain string) string {
		hash, encErr := bcrypt.Encode(plain)
		require.NoError(t, encErr)

		return string(hash)
	}

	hashImported, hashFirst, hashSecond := encode("imported-pw-1"), encode("first-pw-2"), encode("second-pw-3")
	hashMallory, hashNew := encode("mallory-pw-4"), encode("new-pw-5")
	h.secrets = append(h.secrets, hashImported)

	adopted := h.importUser(t, true, "a@"+brokeredDomain, "Alice Imported", hashImported)
	usersBefore := h.countUsers(t)

	t.Run("imported", func(t *testing.T) {
		h.setUserInfo(t, "sub-a", userInfo{
			email: "a@" + brokeredDomain, verified: true, name: "Alice Adopted",
			dept: "dept-finance", role: "manager", hash: hashFirst,
		})

		res, err := h.signIn(t, h.hooked, "sub-a")
		require.NoError(t, err)
		assert.Equal(t, adopted, res.Principal.ID)
		assert.Equal(t, []identity.UserID{""}, h.takeLinked(), "the first sign-in has no link, so the hook matches by e-mail")

		u := h.user(t, adopted)
		assert.Equal(t, "Alice Adopted", u.Name)
		assert.Equal(t, map[string]string{"dept": "dept-finance"}, u.Attributes)
		assert.Equal(t, "manager", primaryRole(u))
		assert.Equal(t, hashFirst, h.hashOf(t, adopted), "the hash is stored as given")
		assert.True(t, u.Active)

		assert.Equal(t, usersBefore, h.countUsers(t), "adopting creates no second user")

		links := h.linksOf(t, adopted)
		require.Len(t, links, 1)
		assert.Equal(t, "sub-a", links[0].Subject)
		assert.Equal(t, h.idp.Issuer(), links[0].Issuer)
	})

	t.Run("second", func(t *testing.T) {
		h.setUserInfo(t, "sub-a", userInfo{
			email: "a@" + brokeredDomain, verified: true, name: "Alice Refreshed",
			dept: "dept-ops", role: "staff", hash: hashSecond,
		})

		before := h.user(t, adopted)

		res, err := h.signIn(t, h.hooked, "sub-a")
		require.NoError(t, err)
		assert.Equal(t, adopted, res.Principal.ID)
		assert.Equal(t, []identity.UserID{adopted}, h.takeLinked(), "the second sign-in resolves through the link")

		u := h.user(t, adopted)
		assert.Equal(t, "Alice Refreshed", u.Name, "Apply runs again through the link")
		assert.Equal(t, map[string]string{"dept": "dept-ops"}, u.Attributes)
		assert.Equal(t, "staff", primaryRole(u))
		assert.Equal(t, hashSecond, h.hashOf(t, adopted))
		assert.Greater(t, u.Version, before.Version)

		assert.Len(t, h.linksOf(t, adopted), 1, "the link is reused, not duplicated")
		assert.Equal(t, usersBefore, h.countUsers(t))
	})

	t.Run("conflict", func(t *testing.T) {
		other := h.importUser(t, true, "b@"+brokeredDomain, "Bob Imported", hashImported)

		h.setUserInfo(t, "sub-b", userInfo{
			email: "b@" + brokeredDomain, verified: true, name: "Bob Adopted",
			dept: "dept-sales", role: "staff", hash: hashFirst,
		})
		_, err := h.signIn(t, h.hooked, "sub-b")
		require.NoError(t, err, "the other identity is linked to its own user first")
		require.Len(t, h.linksOf(t, other), 1)

		// The provider now asserts a's e-mail for the identity linked to b.
		h.setUserInfo(t, "sub-b", userInfo{
			email: "a@" + brokeredDomain, verified: true, name: "Mallory",
			dept: "dept-takeover", role: "manager", hash: hashMallory,
		})

		before := h.user(t, adopted)
		beforeHash := h.hashOf(t, adopted)
		beforeOther := h.user(t, other)
		beforeOtherHash := h.hashOf(t, other)
		usersNow := h.countUsers(t)

		_, err = h.signIn(t, h.hooked, "sub-b")
		require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)

		after := h.user(t, adopted)
		assert.Equal(t, before, after, "a refused decision writes nothing to the matched user")
		assert.Equal(t, beforeHash, h.hashOf(t, adopted))
		assert.Equal(t, beforeOther, h.user(t, other), "a refused decision writes nothing to the identity's own user")
		assert.Equal(t, beforeOtherHash, h.hashOf(t, other))
		assert.Len(t, h.linksOf(t, adopted), 1)
		assert.Len(t, h.linksOf(t, other), 1, "the identity stays linked to its own user")
		assert.Equal(t, usersNow, h.countUsers(t))
	})

	t.Run("inactive", func(t *testing.T) {
		inactive := h.importUser(t, false, "c@"+brokeredDomain, "Carol Imported", hashImported)

		h.setUserInfo(t, "sub-c", userInfo{
			email: "c@" + brokeredDomain, verified: true, name: "Carol Adopted",
			dept: "dept-hr", role: "manager", hash: hashFirst,
		})

		before := h.user(t, inactive)
		usersNow := h.countUsers(t)

		_, err := h.signIn(t, h.hooked, "sub-c")
		require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)

		after := h.user(t, inactive)
		assert.False(t, after.Active)
		assert.Equal(t, before, after, "a deactivated account is refused before anything is written")
		assert.Empty(t, h.linksOf(t, inactive), "no link is made to a deactivated account")
		assert.Equal(t, usersNow, h.countUsers(t))
	})

	t.Run("provision", func(t *testing.T) {
		h.setUserInfo(t, "sub-x", userInfo{
			email: "x@" + brokeredDomain, verified: true, name: "Xavier New",
			dept: "dept-legal", role: "staff", hash: hashNew,
		})

		usersNow := h.countUsers(t)

		res, err := h.signIn(t, h.hooked, "sub-x")
		require.NoError(t, err)

		created := res.Principal.ID
		_, parseErr := id.Parse(string(created))
		require.NoError(t, parseErr, "the new user's reference is a fresh UUID")
		assert.NotEqual(t, adopted, created)

		u := h.user(t, created)
		assert.True(t, u.Active)
		assert.Equal(t, "x@"+brokeredDomain, u.Email)
		assert.Equal(t, "Xavier New", u.Name)
		assert.Equal(t, hashNew, h.hashOf(t, created))

		assert.Equal(t, usersNow+1, h.countUsers(t))

		links := h.linksOf(t, created)
		require.Len(t, links, 1)
		assert.Equal(t, "sub-x", links[0].Subject)
	})

	t.Run("hook-off", func(t *testing.T) {
		plain := h.relyingParty(t)

		h.setUserInfo(t, "sub-y", userInfo{
			email: "y@" + brokeredDomain, verified: true, name: "Yara Unlinked",
			dept: "dept-it", role: "staff", hash: hashNew,
		})

		usersNow := h.countUsers(t)
		before := h.user(t, adopted)

		_, err := h.signIn(t, plain, "sub-y")
		require.ErrorIs(t, err, oidc.ErrNoLinkedAccount, "an unlinked identity is refused without a hook")
		assert.Equal(t, usersNow, h.countUsers(t))

		// A linked identity still resolves through its link alone, writing nothing.
		res, err := h.signIn(t, plain, "sub-a")
		require.NoError(t, err)
		assert.Equal(t, adopted, res.Principal.ID)
		assert.Equal(t, before, h.user(t, adopted))
	})

	t.Run("no-secret-in-logs", func(t *testing.T) {
		require.NoError(t, h.hooked.FlushRefusalLogs())

		logs := h.logs.String()
		require.NotEmpty(t, logs, "the refusals above were logged; an empty log proves nothing")

		tokens := h.idp.AccessTokens()
		require.NotEmpty(t, tokens)
		for _, token := range tokens {
			assert.NotContains(t, logs, token, "an access token reached a log")
		}

		for _, secret := range h.secrets {
			assert.NotContains(t, logs, secret, "a UserInfo value or hash reached a log")
		}
	})
}
