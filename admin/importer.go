package admin

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/id"
)

// ImporterOption configures NewImporter. Every Option, such as WithEventSink,
// is one, and so is WithAttributeLimits.
type ImporterOption interface {
	applyImporter(c *importerConfig) error
}

type importerConfig struct {
	common
	attributeLimits
}

// maxImportRoles bounds the roles of one imported user, and maxHashBytes the
// password hash, before the recogniser reads it.
const (
	maxImportRoles = 1024
	maxHashBytes   = 4096
)

// Importer writes users from another system by identifier: it creates a user
// whose identifier is unknown, updates one whose values differ, and writes
// nothing when every value is equal. It matches by identifier only, so an
// import never takes over another account: a username or email held by a
// different identifier is ErrAlreadyExists.
//
// The password hash is stored as given, and must be one the recogniser given
// to NewImporter recognises, so a hash scrty could never verify is refused
// rather than locking a user out silently. The password policy is not applied:
// an import holds a hash, not a password, and cannot judge it.
//
// Importer does not authorize; every import requires an actor (ActorFrom),
// such as WithSystemActor for a synchronisation job. An Importer is safe for
// concurrent use when its store is.
type Importer struct {
	store      ImportStore
	recognizer password.Recognizer
	cfg        importerConfig
}

// NewImporter returns an Importer over store that accepts the hashes
// recognizer recognises. Pass the login's encoder (the Argon2id, bcrypt and
// scrypt encoders are recognisers), or a recogniser of the consumer's own
// that accepts every encoding its login verifies.
//
// With only a store and a recogniser it works: the attribute bounds of the
// Default constants, no event sink, no audit sink and the system clock; each
// option replaces one of those. A nil store or recogniser, or an option that
// cannot work, fails with an error matching ErrConfig. A nil option is ignored.
func NewImporter(store ImportStore, recognizer password.Recognizer, opts ...ImporterOption) (*Importer, error) {
	if nilcheck.IsNil(store) {
		return nil, fmt.Errorf("%w: import store is nil", ErrConfig)
	}

	if nilcheck.IsNil(recognizer) {
		return nil, fmt.Errorf("%w: password hash recogniser is nil", ErrConfig)
	}

	cfg := importerConfig{attributeLimits: defaultAttributeLimits()}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		if err := opt.applyImporter(&cfg); err != nil {
			return nil, err
		}
	}

	if err := cfg.finish(); err != nil {
		return nil, err
	}

	return &Importer{store: store, recognizer: recognizer, cfg: cfg}, nil
}

// Import writes the user by its identifier and reports whether it was
// created, updated or unchanged. A created or updated user is reported as
// event.UserImported; an unchanged one reports nothing.
//
// The identifier must be a canonical lower-case UUID, the username not blank,
// the text fields, roles and attributes within the service's bounds, and a
// non-empty password hash one the recogniser recognises; otherwise the call
// fails with ErrInvalidInput before the store is called. An empty hash
// imports a user with no password. A zero CreatedAt or UpdatedAt means "not
// given" and reaches the store as zero, which fills it only when it creates
// the user (see ImportStore), so a payload imported twice stays unchanged; an
// UpdatedAt before CreatedAt, when both are given, is ErrInvalidInput. The
// store's AlreadyExistsError passes through unchanged. Import keeps no
// reference to the caller's slices and map.
func (im *Importer) Import(ctx context.Context, u ImportedUser) (ImportOutcome, error) {
	actor, err := ActorFrom(ctx)
	if err != nil {
		return 0, err
	}

	u = copyImported(u)

	if err := im.validate(u); err != nil {
		return 0, err
	}

	out, err := im.store.ImportUser(ctx, u)
	if err != nil {
		return 0, fmt.Errorf("admin: import user: %w", err)
	}

	switch out {
	case ImportUnchanged:
		return out, nil
	case ImportCreated, ImportUpdated:
	default:
		return 0, fmt.Errorf("admin: import user: the store reported outcome %d, which is none of the defined outcomes", out)
	}

	r := changeReport{actor: actor, name: event.UserImported, user: u.ID, target: string(u.ID)}
	if im.cfg.auditing() {
		r.after = importedRecord(u)
	}

	im.cfg.report(ctx, r)

	return out, nil
}

func (im *Importer) validate(u ImportedUser) error {
	if err := canonicalUserID(u.ID); err != nil {
		return err
	}

	if err := exactName("username", u.Username, MaxTextBytes); err != nil {
		return err
	}

	if err := text("display name", u.Name, MaxTextBytes); err != nil {
		return err
	}

	if err := emailValid(u.Email, u.EmailVerifiedAt); err != nil {
		return err
	}

	if err := im.cfg.validateAttributes(u.Attributes); err != nil {
		return err
	}

	if !u.CreatedAt.IsZero() && !u.UpdatedAt.IsZero() && u.UpdatedAt.Before(u.CreatedAt) {
		return invalid("the update time is before the creation time")
	}

	if len(u.Roles) > maxImportRoles {
		return invalid("more than %d roles", maxImportRoles)
	}

	for _, r := range u.Roles {
		if err := roleName(r); err != nil {
			return err
		}
	}

	if len(u.PasswordHash) == 0 {
		return nil
	}

	if len(u.PasswordHash) > maxHashBytes || !im.recognizer.Recognizes(u.PasswordHash) {
		return invalid("the password hash is in no encoding the recogniser recognises")
	}

	return nil
}

// canonicalUserID checks an identifier is a canonical lower-case UUID other
// than the nil UUID, the form the default store's column holds.
func canonicalUserID(userID identity.UserID) error {
	parsed, err := id.Parse(string(userID))
	if err != nil || parsed.IsZero() || parsed.String() != string(userID) {
		return invalid("user identifier is not a canonical UUID")
	}

	return nil
}

func copyImported(u ImportedUser) ImportedUser {
	u.PasswordHash = bytes.Clone(u.PasswordHash)
	u.Roles = slices.Clone(u.Roles)
	u.Attributes = maps.Clone(u.Attributes)

	return u
}

// importedRecord is the audit record of an import: the user as imported,
// without its hash.
func importedRecord(u ImportedUser) User {
	roles := make([]*identity.AssignedRole, 0, len(u.Roles))
	for _, name := range u.Roles {
		roles = append(roles, &identity.AssignedRole{Name: name})
	}

	return User{
		ID: u.ID, Username: u.Username, Name: u.Name, Email: u.Email,
		EmailVerifiedAt: u.EmailVerifiedAt, Active: u.Active,
		Attributes: maps.Clone(u.Attributes), Roles: roles,
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
}
