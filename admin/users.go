package admin

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/id"
)

// Bounds the service enforces before the store is called.
const (
	// MaxSearchBytes bounds a search text and a role filter.
	MaxSearchBytes = 256
	// MaxTextBytes bounds a username, a display name, an email and an identifier.
	MaxTextBytes = 256
	// MaxPasswordBytes bounds a plain password before it is converted and
	// checked; a longer one is refused as too long whatever the policy's own
	// maximum.
	MaxPasswordBytes = 1 << 16
)

// Users administers users: it lists, reads, creates, updates, deactivates,
// reactivates and deletes them, and sets their passwords.
//
// Users does not authorize. The application guards the routes that reach it,
// and the rules for who may administer whom are the application's. Every write
// requires an actor (ActorFrom) and is refused with ErrNoActor without one,
// before the store is called. Each committed write is reported to the event
// sink and the audit sink, when given: event.UserCreated, event.UserUpdated,
// event.UserArchived, event.UserReactivated, event.UserDeleted and
// event.AuthnPasswordChange. Deactivating an inactive user, or reactivating an
// active one, writes and reports nothing. A Users is safe for concurrent use
// when its store is.
type Users struct {
	store UserStore
	// renamer is the store as a UsernameUpdater, nil when it cannot rename.
	renamer UsernameUpdater
	// pager is the store as a UserPager, nil when it cannot list from an
	// offset or count.
	pager UserPager
	cfg   usersConfig
}

// NewUsers returns a Users over store. With only a store it works: pages of 50
// up to 500, the attribute bounds of the Default constants, the default
// password policy and Argon2id encoder, the system clock, version 7
// identifiers, no event sink, no audit sink, no session revocation and the
// routing logger; each option replaces one of those. It records whether store
// implements UsernameUpdater, which Update needs to rename a user, and
// UserPager, which List needs for a non-zero offset (up to
// DefaultMaxListOffset) and Count needs.
//
// A nil store, or an option that cannot work, fails with an error matching
// ErrConfig. A nil option is ignored.
func NewUsers(store UserStore, opts ...UsersOption) (*Users, error) {
	if nilcheck.IsNil(store) {
		return nil, fmt.Errorf("%w: user store is nil", ErrConfig)
	}

	cfg := usersConfig{
		pageDefault: DefaultPageSize, pageMax: DefaultMaxPageSize,
		attributeLimits: defaultAttributeLimits(), offsetMax: DefaultMaxListOffset,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		if err := opt.applyUsers(&cfg); err != nil {
			return nil, err
		}
	}

	if err := cfg.finish(); err != nil {
		return nil, err
	}

	if cfg.encoder != nil && cfg.policy != nil {
		return nil, fmt.Errorf("%w: WithPasswordEncoder and WithPasswordPolicy were both given; the policy "+
			"encodes the new password, so build it with password.WithEncoder and give only the policy", ErrConfig)
	}

	if cfg.encoder == nil {
		enc, err := password.NewArgon2idEncoder()
		if err != nil {
			return nil, fmt.Errorf("%w: default password encoder: %w", ErrConfig, err)
		}

		cfg.encoder = enc
	}

	if cfg.policy == nil {
		// The default policy is built with the configured encoder, after every
		// option, so it knows the encoder's input limit and, should a consumer
		// later compare hashes with it, matches the encoder's own hashes.
		p, err := password.NewPolicy(password.WithEncoder(cfg.encoder), password.WithClock(cfg.clock))
		if err != nil {
			return nil, fmt.Errorf("%w: default password policy: %w", ErrConfig, err)
		}

		cfg.policy = p
	}

	if cfg.ids == nil {
		cfg.ids = id.NewV7Generator()
	}

	renamer, _ := store.(UsernameUpdater)

	if cfg.revoker != nil && renamer == nil {
		return nil, fmt.Errorf("%w: admin.WithSessionRevocation was given, but the user store does not implement "+
			"admin.UsernameUpdater, so it can never rename and the revoker would never run", ErrConfig)
	}

	pager, _ := store.(UserPager)

	if cfg.offsetGiven && pager == nil {
		return nil, fmt.Errorf("%w: admin.WithMaxListOffset was given, but the user store does not implement "+
			"admin.UserPager, so it can never list from an offset and the bound would never apply", ErrConfig)
	}

	return &Users{store: store, renamer: renamer, pager: pager, cfg: cfg}, nil
}

// List returns a page of live users matching the filter, ordered by
// (lower(username), id). A page size of zero is the default; one above the
// maximum, or below zero, is ErrInvalidInput, as is a search or filter beyond
// its bound and a cursor that does not decode. Next is set when the page is
// full and continues the list.
//
// A filter may instead name an Offset, to jump to a page. A negative offset,
// one above the maximum (default DefaultMaxListOffset, WithMaxListOffset) and
// one together with a Cursor are ErrInvalidInput, decided before the store is
// called. A non-zero offset over a store that does not implement UserPager is
// an error matching ErrConfig. Offset zero is the first page: it lists as
// above and carries Next, while a page from a non-zero offset has an empty
// Next. Offset paging can skip or repeat a user when users are created or
// deleted between two requests; walk a whole list by cursor, which is
// consistent. A count and a page are separate reads (Count).
func (u *Users) List(ctx context.Context, filter UserFilter) (UserPage, error) {
	if filter.Attribute != nil {
		m := *filter.Attribute
		filter.Attribute = &m
	}

	q, err := u.query(filter)
	if err != nil {
		return UserPage{}, err
	}

	if filter.Offset > 0 {
		return u.listFrom(ctx, q, filter.Offset)
	}

	users, err := u.store.ListUsers(ctx, q)
	if err != nil {
		return UserPage{}, fmt.Errorf("admin: list users: %w", err)
	}

	if len(users) > q.Limit {
		users = users[:q.Limit]
	}

	page := UserPage{Users: users}

	if len(users) == q.Limit {
		next, err := encodeCursor(users[len(users)-1])
		if err != nil {
			return UserPage{}, err
		}

		page.Next = next
	}

	return page, nil
}

// listFrom lists a page that starts offset users in. Such a page carries no
// Next: the cursor continues a keyed list, not a position.
func (u *Users) listFrom(ctx context.Context, q UserQuery, offset int) (UserPage, error) {
	if u.pager == nil {
		return UserPage{}, fmt.Errorf("admin: list users: %w: the filter names an offset, but the user store "+
			"does not implement admin.UserPager", ErrConfig)
	}

	users, err := u.pager.ListUsersFrom(ctx, q, offset)
	if err != nil {
		return UserPage{}, fmt.Errorf("admin: list users: %w", err)
	}

	if len(users) > q.Limit {
		users = users[:q.Limit]
	}

	return UserPage{Users: users}, nil
}

// Count returns how many live users match the filter's Search, Active, Role
// and Attribute, validated as List validates them. PageSize, Offset and Cursor
// describe a page, not a match, so they are ignored and never refuse a count.
// A store without UserPager is an error matching ErrConfig, and a store
// answering below zero is an error matching no administration reason. The
// count and a page are separate reads: users created or deleted between them
// make the two disagree, so treat the count as an estimate while a list is
// being walked.
func (u *Users) Count(ctx context.Context, filter UserFilter) (int64, error) {
	if filter.Attribute != nil {
		m := *filter.Attribute
		filter.Attribute = &m
	}

	filter.PageSize, filter.Offset, filter.Cursor = 0, 0, ""

	q, err := u.query(filter)
	if err != nil {
		return 0, err
	}

	// A count has no page: the store receives the filters alone.
	q.Limit = 0

	if u.pager == nil {
		return 0, fmt.Errorf("admin: count users: %w: the user store does not implement admin.UserPager", ErrConfig)
	}

	n, err := u.pager.CountUsers(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("admin: count users: %w", err)
	}

	if n < 0 {
		return 0, errors.New("admin: count users: the user store returned a negative count")
	}

	return n, nil
}

// query validates a filter and turns it into the store's query.
func (u *Users) query(f UserFilter) (UserQuery, error) {
	limit := f.PageSize

	switch {
	case limit == 0:
		limit = u.cfg.pageDefault
	case limit < 0 || limit > u.cfg.pageMax:
		return UserQuery{}, invalid("page size must be between 1 and %d", u.cfg.pageMax)
	}

	switch {
	case f.Offset < 0:
		return UserQuery{}, invalid("offset must not be negative")
	case f.Offset > u.cfg.offsetMax:
		return UserQuery{}, invalid("offset must be at most %d", u.cfg.offsetMax)
	case f.Offset != 0 && f.Cursor != "":
		return UserQuery{}, invalid("offset and cursor are alternatives; give one")
	}

	if err := noNUL("search", f.Search, MaxSearchBytes); err != nil {
		return UserQuery{}, err
	}

	if err := text("role filter", f.Role, MaxSearchBytes); err != nil {
		return UserQuery{}, err
	}

	if m := f.Attribute; m != nil {
		if err := u.cfg.attributeName(m.Name); err != nil {
			return UserQuery{}, err
		}

		if err := noNUL("attribute value", m.Value, u.cfg.attrValueBytes); err != nil {
			return UserQuery{}, err
		}
	}

	q := UserQuery{Search: f.Search, Active: f.Active, Role: f.Role, Attribute: f.Attribute, Limit: limit}

	if f.Cursor != "" {
		after, afterID, err := decodeCursor(f.Cursor)
		if err != nil {
			return UserQuery{}, invalid("cursor does not decode")
		}

		q.AfterUsername, q.AfterID = after, afterID
	}

	return q, nil
}

// Get returns the live user with the identifier, with its roles, email,
// attributes and version. An unknown or deleted user is ErrNotFound.
func (u *Users) Get(ctx context.Context, userID identity.UserID) (User, error) {
	if err := userIDValid(userID); err != nil {
		return User{}, err
	}

	got, err := u.store.GetUser(ctx, userID)
	if err != nil {
		return User{}, fmt.Errorf("admin: get user: %w", err)
	}

	return got, nil
}

// Create generates the identifier and creates an active user with no password
// and no roles. A username with leading or trailing white space is
// ErrInvalidInput; an invisible format character at its edge, such as U+200B,
// is not refused. A taken username, or an email taken by a live user, is an
// error matching ErrAlreadyExists that names the field, decided by the store's
// write so concurrent creations produce one user. An empty email stores none.
func (u *Users) Create(ctx context.Context, nu NewUser) (User, error) {
	actor, err := ActorFrom(ctx)
	if err != nil {
		return User{}, err
	}

	nu.Attributes = maps.Clone(nu.Attributes)

	if err := u.validateNew(nu); err != nil {
		return User{}, err
	}

	uid, err := u.cfg.ids.NewID()
	if err != nil {
		return User{}, fmt.Errorf("admin: generate user identifier: %w", err)
	}

	if uid.IsZero() {
		return User{}, errors.New("admin: the identifier generator returned the zero identifier")
	}

	nu.ID = identity.UserID(uid.String())

	created, err := u.store.CreateUser(ctx, nu)
	if err != nil {
		return User{}, fmt.Errorf("admin: create user: %w", err)
	}

	report := changeReport{actor: actor, name: event.UserCreated, user: nu.ID, target: string(nu.ID)}
	if u.cfg.auditing() {
		report.after = cloneUser(created)
	}

	u.cfg.report(ctx, report)

	return created, nil
}

func (u *Users) validateNew(nu NewUser) error {
	if err := exactName("username", nu.Username, MaxTextBytes); err != nil {
		return err
	}

	if err := text("display name", nu.Name, MaxTextBytes); err != nil {
		return err
	}

	if err := emailValid(nu.Email, nu.EmailVerifiedAt); err != nil {
		return err
	}

	if err := u.cfg.validateAttributes(nu.Attributes); err != nil {
		return err
	}

	return organizationValid(nu.Organization)
}

// Update changes the fields the change names, conditional on version. A change
// that names the email but no verification time keeps the stored verification
// time when the email equals the stored one ignoring case, so re-sending the
// current address does not unverify it, and clears it otherwise, so a new or
// cleared address is unverified until the caller says otherwise. The store
// makes that comparison under its row lock (see UserStore.UpdateUser). The
// event lists the fields the change names, and email_verified_at also when a
// named email leaves the user with no verification time. A verification time
// named for a user with no email, and an empty change, or a version below one,
// are ErrInvalidInput; a version that differs from the stored one is
// ErrStaleUpdate and changes nothing.
//
// A change naming a username renames the user through the store's
// UsernameUpdater (see UserChange.Username); over a store without it, the
// change is refused with an error matching ErrConfig after the input is
// validated and before the store is called. The event lists username first.
// With WithSessionRevocation, a rename the store reports as a change of the
// stored username then revokes the user's sessions; when that fails, Update
// returns the renamed user together with an error matching
// ErrSessionsNotRevoked.
func (u *Users) Update(ctx context.Context, userID identity.UserID, version int64, change UserChange) (User, error) {
	actor, err := ActorFrom(ctx)
	if err != nil {
		return User{}, err
	}

	if err := userWrite(userID, version); err != nil {
		return User{}, err
	}

	change.Attributes = maps.Clone(change.Attributes)

	if err := u.validateChange(change); err != nil {
		return User{}, err
	}

	// A store without the capability would otherwise be handed a username it
	// may ignore; refuse before anything is read or written.
	if change.Username != nil && u.renamer == nil {
		return User{}, fmt.Errorf("admin: update user: %w: the change names a username, but the user store "+
			"does not implement admin.UsernameUpdater", ErrConfig)
	}

	before, err := u.auditBefore(ctx, userID, version)
	if err != nil {
		return User{}, fmt.Errorf("admin: update user: %w", err)
	}

	var (
		updated User
		renamed bool
	)

	if change.Username != nil {
		updated, renamed, err = u.renamer.UpdateUserRenaming(ctx, userID, version, change)
	} else {
		updated, err = u.store.UpdateUser(ctx, userID, version, change)
	}

	if err != nil {
		return User{}, fmt.Errorf("admin: update user: %w", err)
	}

	report := changeReport{
		actor: actor, name: event.UserUpdated, user: userID, target: string(userID),
		changed: changedUserFields(change, updated),
	}
	if before != nil {
		report.before, report.after = *before, cloneUser(updated)
	}

	u.cfg.report(ctx, report)

	// The update has committed and been reported; a failed revocation cannot
	// undo it, so the caller gets the renamed user and an error to retry on.
	if renamed && u.cfg.revoker != nil {
		if err := u.cfg.revoker.DeleteByUser(ctx, userID); err != nil {
			return updated, fmt.Errorf("%w: %w", ErrSessionsNotRevoked, err)
		}
	}

	return updated, nil
}

func (u *Users) validateChange(c UserChange) error {
	if c.Username == nil && c.Name == nil && c.Email == nil && c.EmailVerifiedAt == nil && c.Attributes == nil && c.Organization == nil {
		return invalid("the change names no field")
	}

	if c.Username != nil {
		if err := exactName("username", *c.Username, MaxTextBytes); err != nil {
			return err
		}
	}

	if c.Name != nil {
		if err := text("display name", *c.Name, MaxTextBytes); err != nil {
			return err
		}
	}

	if c.Email != nil {
		var verifiedAt time.Time
		if c.EmailVerifiedAt != nil {
			verifiedAt = *c.EmailVerifiedAt
		}

		if err := emailValid(*c.Email, verifiedAt); err != nil {
			return err
		}
	}

	if err := u.cfg.validateAttributes(c.Attributes); err != nil {
		return err
	}

	if c.Organization != nil {
		return organizationValid(*c.Organization)
	}

	return nil
}

// Deactivate clears the active flag, conditional on version. A user already
// inactive succeeds without a write.
func (u *Users) Deactivate(ctx context.Context, userID identity.UserID, version int64) (User, error) {
	return u.setActive(ctx, userID, version, false)
}

// Reactivate sets the active flag, conditional on version. A user already
// active succeeds without a write.
func (u *Users) Reactivate(ctx context.Context, userID identity.UserID, version int64) (User, error) {
	return u.setActive(ctx, userID, version, true)
}

func (u *Users) setActive(ctx context.Context, userID identity.UserID, version int64, active bool) (User, error) {
	actor, err := ActorFrom(ctx)
	if err != nil {
		return User{}, err
	}

	if err := userWrite(userID, version); err != nil {
		return User{}, err
	}

	before, err := u.auditBefore(ctx, userID, version)
	if err != nil {
		return User{}, fmt.Errorf("admin: set active: %w", err)
	}

	got, changed, err := u.store.SetActive(ctx, userID, version, active)
	if err != nil {
		return User{}, fmt.Errorf("admin: set active: %w", err)
	}

	// A flag already at the requested value is a success with nothing to
	// report: nothing was written.
	if !changed {
		return got, nil
	}

	name := event.UserArchived
	if active {
		name = event.UserReactivated
	}

	report := changeReport{
		actor: actor, name: name, user: userID, target: string(userID), changed: []string{userFieldActive},
	}
	if before != nil {
		report.before, report.after = *before, cloneUser(got)
	}

	u.cfg.report(ctx, report)

	return got, nil
}

// Delete soft-deletes the user, conditional on version: the record and its
// username stay, the email is released, and the attributes and password
// history are removed. Deleting a deleted user is ErrNotFound.
func (u *Users) Delete(ctx context.Context, userID identity.UserID, version int64) error {
	actor, err := ActorFrom(ctx)
	if err != nil {
		return err
	}

	if err := userWrite(userID, version); err != nil {
		return err
	}

	before, err := u.auditBefore(ctx, userID, version)
	if err != nil {
		return fmt.Errorf("admin: delete user: %w", err)
	}

	if err := u.store.DeleteUser(ctx, userID, version); err != nil {
		return fmt.Errorf("admin: delete user: %w", err)
	}

	report := changeReport{actor: actor, name: event.UserDeleted, user: userID, target: string(userID)}
	if before != nil {
		report.before = *before
	}

	u.cfg.report(ctx, report)

	return nil
}

// SetPassword sets the user's password, conditional on version, through the
// configured policy's Change: the plain password is checked against the
// policy's rules (length, common passwords, context words, breach and reuse),
// encoded with the policy's encoder, the replaced hash is retired through the
// reuse rule's history when the policy has one, and the store then writes the
// new hash with the service clock's time. A refusal changes nothing and returns
// the policy's error unchanged (errors.Is password.ErrPasswordRejected,
// password.ErrReused, password.ErrHistoryUnavailable, ...). A user whose stored
// version is not version is ErrStaleUpdate before the policy runs or a hash is
// made.
//
// Retiring and writing are two calls. When the store's write fails after the
// retire, the history holds a copy of the still-current hash; a retry does not
// count it twice (password.History.RetirePassword).
//
// SetPassword does not modify or retain plain: the caller owns it and wipes
// it. The policy and the encoder take a string, so a copy of the password
// exists until the garbage collector frees it; that copy cannot be wiped.
func (u *Users) SetPassword(ctx context.Context, userID identity.UserID, version int64, plain []byte) (User, error) {
	actor, err := ActorFrom(ctx)
	if err != nil {
		return User{}, err
	}

	if err := userWrite(userID, version); err != nil {
		return User{}, err
	}

	if len(plain) > MaxPasswordBytes {
		return User{}, password.RejectedError{Rule: password.RuleTooLong}
	}

	current, err := u.store.GetUser(ctx, userID)
	if err != nil {
		return User{}, fmt.Errorf("admin: set password: %w", err)
	}

	// A user already changed since the caller read it would be refused by the
	// store's conditional write anyway; refuse it before the policy and the
	// encoder spend their work.
	if current.Version != version {
		return User{}, fmt.Errorf("admin: set password: %w", ErrStaleUpdate)
	}

	// The current hash feeds the reuse rule only, as Details.Password, where the
	// policy compares the candidate against it and the retired hashes. It never
	// reaches a User, an error or a log. The store retires it when it writes
	// the new hash.
	currentHash, err := u.store.CurrentPasswordHash(ctx, userID)
	if err != nil {
		return User{}, fmt.Errorf("admin: set password: %w", err)
	}

	details := &identity.Details{
		ID: current.ID, Name: current.Name, Username: current.Username,
		Email: current.Email, Active: current.Active, Password: currentHash,
	}

	// The policy checks, encodes, retires the replaced hash through its reuse
	// rule's history, and only then calls write, which stores the new hash and
	// the service clock's time. The policy returns write's error unchanged, so
	// the store's failure is told apart by identity.
	var (
		updated  User
		writeErr error
	)

	write := func(ctx context.Context, _ *identity.Details, hash []byte, _ time.Time) error {
		updated, writeErr = u.store.SetPassword(ctx, userID, version, hash, u.cfg.clock.Now())

		return writeErr
	}

	if err := u.cfg.policy.Change(ctx, details, string(plain), write); err != nil {
		switch {
		case writeErr != nil && errors.Is(err, writeErr):
			return User{}, fmt.Errorf("admin: set password: %w", err)
		case errors.Is(err, password.ErrTooLong):
			// The policy already answers an encoder's ErrTooLong as a
			// rejection; this keeps the outcome if a policy ever does not.
			return User{}, password.RejectedError{Rule: password.RuleTooLong}
		default:
			return User{}, err
		}
	}

	report := changeReport{
		actor: actor, name: event.AuthnPasswordChange, user: userID, target: string(userID),
		changed: []string{userFieldPassword},
	}
	if u.cfg.auditing() {
		report.before, report.after = cloneUser(current), cloneUser(updated)
	}

	u.cfg.report(ctx, report)

	return updated, nil
}

func (l *attributeLimits) validateAttributes(attrs map[string]string) error {
	if len(attrs) > l.attrN {
		return invalid("more than %d attributes", l.attrN)
	}

	for name, value := range attrs {
		if err := l.attributeName(name); err != nil {
			return err
		}

		if err := noNUL("attribute value", value, l.attrValueBytes); err != nil {
			return err
		}
	}

	return nil
}

func (l *attributeLimits) attributeName(name string) error {
	if name == "" {
		return invalid("attribute name is empty")
	}

	return text("attribute name", name, l.attrNameBytes)
}

// The field names a user event's Changed lists.
const (
	userFieldUsername        = "username"
	userFieldName            = "name"
	userFieldEmail           = "email"
	userFieldEmailVerifiedAt = "email_verified_at"
	userFieldAttributes      = "attributes"
	userFieldOrganization    = "organization"
	userFieldActive          = "active"
	userFieldPassword        = "password"
)

// changedUserFields names the fields a change sets, never their values.
func changedUserFields(c UserChange, updated User) []string {
	var changed []string

	if c.Username != nil {
		changed = append(changed, userFieldUsername)
	}

	if c.Name != nil {
		changed = append(changed, userFieldName)
	}

	if c.Email != nil {
		changed = append(changed, userFieldEmail)
	}

	// A named email with no verification time leaves the verification to the
	// store, which clears it only for a different address. Without the stored
	// value the service cannot tell a cleared verification from one that was
	// already absent, so it reports the field whenever none is left.
	if c.EmailVerifiedAt != nil || (c.Email != nil && updated.EmailVerifiedAt.IsZero()) {
		changed = append(changed, userFieldEmailVerifiedAt)
	}

	if c.Attributes != nil {
		changed = append(changed, userFieldAttributes)
	}

	if c.Organization != nil {
		changed = append(changed, userFieldOrganization)
	}

	return changed
}

// auditBefore reads the user before a write when an audit sink will receive
// the change, and nothing otherwise. The read is not locked with the write, so
// the version read is compared with the one the caller named: a user already
// at another version is ErrStaleUpdate before anything is written, and a
// before record is only ever delivered for the version the write replaces.
func (u *Users) auditBefore(ctx context.Context, userID identity.UserID, version int64) (*User, error) {
	if !u.cfg.auditing() {
		return nil, nil //nolint:nilnil // no audit sink: no before record and no error
	}

	got, err := u.store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	if got.Version != version {
		return nil, ErrStaleUpdate
	}

	before := cloneUser(got)

	return &before, nil
}

// cloneUser copies a user's map, slice and pointers so an audit sink may keep
// or change it without touching what the caller received.
func cloneUser(u User) User {
	u.Attributes = maps.Clone(u.Attributes)

	if u.Roles != nil {
		roles := make([]*identity.AssignedRole, 0, len(u.Roles))
		for _, r := range u.Roles {
			if r != nil {
				c := *r
				r = &c
			}

			roles = append(roles, r)
		}

		u.Roles = roles
	}

	if u.Organization != nil {
		o := *u.Organization
		if o.Group != nil {
			g := *o.Group
			o.Group = &g
		}

		u.Organization = &o
	}

	return u
}

func organizationValid(o *identity.Organization) error {
	if o == nil {
		return nil
	}

	return nonBlank("organization identifier", o.ID, MaxTextBytes)
}

func userIDValid(userID identity.UserID) error {
	return nonBlank("user identifier", string(userID), MaxTextBytes)
}

// userWrite checks the identifier and version every write names. Versions
// start at one, so a zero is a caller that never read the user.
func userWrite(userID identity.UserID, version int64) error {
	if err := userIDValid(userID); err != nil {
		return err
	}

	if version < 1 {
		return invalid("version must be at least 1")
	}

	return nil
}
