// Package admin offers the administration of users, roles, grants and role
// assignments as services an application calls. scrty serves no administration
// endpoint: the application decides which of its routes reach a service.
//
// # Services
//
//   - Users lists, reads, creates, updates, deactivates, reactivates and
//     deletes users, and sets their passwords through the password policy.
//   - Importer writes users from another system by identifier, idempotently,
//     with the password hash as given.
//   - Roles lists, reads, creates, updates and deletes roles. A role's name is
//     its immutable key; a "rename" changes its display name.
//   - Grants reads a role's grants and replaces them per resource, checking
//     every grant against the application's authorize.Catalogue.
//   - Assignments lists a user's role grants, adds and removes one, and marks
//     one primary.
//
// Each is built from its store port and works with nothing else, except
// Grants, which also requires the catalogue and fails construction without
// one, and Importer, which requires the recogniser of the hashes it accepts.
// Every default is replaced by an option; each option's godoc names the
// default it replaces. A wiring mistake fails the constructor with an error
// matching ErrConfig.
//
// # Services do not authorize
//
// A service never decides whether the caller may make the change. The
// application already guards its routes with scrty's requirements, and the
// rules for who may administer whom are the application's own. Every service
// documents this, and none of them reads a role or a privilege of the caller.
//
// # Every write names its actor
//
// A write takes its actor from the context: the authenticated principal
// (identity.WithPrincipal), or a named system actor the caller attaches with
// WithSystemActor for a job that has no principal. A write with neither fails
// with ErrNoActor before the store is called. ActorFrom reads the actor.
//
// # Events and audit
//
// Each committed change is reported to the event sink given with
// WithEventSink, under the OWASP Logging Vocabulary name where it has one
// (event.UserCreated, event.UserUpdated, event.UserArchived,
// event.UserDeleted, event.AuthnPasswordChange,
// event.PrivilegePermissionsChanged, event.AuthzChange, event.AuthzAdmin) and
// under the scrty_ prefix otherwise (event.UserReactivated,
// event.UserImported). The event names the actor, the target and the changed
// fields, never a value. A refused or failed call, and a call that changed
// nothing, reports nothing. A committed change whose follow-up session
// revocation fails is the exception: it still emits its event and returns
// ErrSessionsNotRevoked. The default is no sink; on a request whose chain
// reports security events, the services report through the chain.
//
// WithAudit adds an audit sink that receives each committed change with the
// records before and after it (Change), which have no password hash field.
// When one is configured, a service reads the record before writing, one extra
// read, and Grants and Assignments read it after writing too, since their
// stores return only the new version. A record read at a version other than the
// one the caller named is ErrStaleUpdate and nothing is written, so a before
// record is only ever the version the write replaced. A failing or panicking
// audit sink is logged with the action and the target only, and the call still
// succeeds.
//
// Events and audit records are delivered after the store call returns, so a
// crash between the commit and the delivery loses them. A consumer that needs
// them transactionally puts an outbox behind the audit sink.
//
// # Paging
//
// Users.List pages by cursor: each full page carries Next, which continues the
// list after the last user seen, so a walk of the whole list is consistent
// while users come and go. A page picker jumps to page n instead with
// UserFilter.Offset, up to DefaultMaxListOffset (WithMaxListOffset), and shows
// the total from Users.Count. Offset zero is the first page and carries Next; a
// page from a non-zero offset does not. Offset pages and counts are separate
// reads and can skip or repeat a user, or disagree with each other, when users
// are created or deleted in between. Both need a store that implements
// UserPager, which scrty's stores do; over one that does not, they fail with an
// error matching ErrConfig and cursor listing works as before.
//
// # Errors
//
// Every failure an application can act on matches exactly one of ErrNotFound,
// ErrAlreadyExists, ErrStillAssigned, ErrStaleUpdate, ErrUnknownPrivilege,
// ErrInvalidInput, ErrNoActor, ErrConfig and ErrSessionsNotRevoked. ErrConfig
// is also returned at call time when a call needs a store capability the store
// lacks, such as a rename asked of a store that does not implement
// UsernameUpdater, or an offset listing or a count asked of one that does not
// implement UserPager. ErrSessionsNotRevoked reports a committed rename whose
// opted-in session revocation failed; the error also wraps the revoker's cause,
// so the change is stored and only the sign-out is in doubt. A storage failure
// matches none of them. Error text never contains a username, an email, an
// attribute value or a password hash.
//
// # Stores
//
// The services work over ports (UserStore, ImportStore, RoleStore, GrantStore
// and AssignmentStore). scrty's identity stores implement them; a consumer may
// supply its own. The rules a service enforces before reaching the store
// (input bounds, catalogue, actor, events, audit) stay with the service, so a
// consumer store inherits them. The rules only a store can enforce, versions,
// serialisation and uniqueness, belong to the store.
package admin
