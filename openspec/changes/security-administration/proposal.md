# Proposal

## Why

scrty authenticates users and checks their privileges, but an application that keeps its users and
roles in scrty's identity store has no way to manage them: no listing, no role or grant editing, no
assignment, no import. Each consumer writes that layer itself, against tables it does not own, and
re-solves the same security questions: stale writes, takeover through usernames, audit, and
grants that only apply to the caller's own records. Runtime checks are also costly: a request that
checks a route and then several "allowed actions" loads the same role's privileges once per check.

This change gives scrty ready-to-use, generic security administration: services and stores for
users, roles, grants and assignments, scoped grants, efficient runtime checks, login by email, and an
optional switch of the active role. scrty still serves no administration endpoint: the application
builds its own API on the services and maps their typed errors to its own responses.

It ships in **v0.3.0**, together with the table prefix and the device grant already on `main`, so a
consumer takes one upgrade.

## What Changes

**Authorization at runtime**
- A role's privileges are loaded at most once per request. The memo lives in the request context,
  is safe for concurrent checks, and is never reused across requests. The chain installs it by
  default; a consumer can turn it off or install it outside the chain.
- `authorize.AllOf`, beside the existing `AnyOf`.
- Every adapter (net/http, gin, fiber) gains a guard that takes any `authorize.Requirement`.
- A bulk check answers which of N privileges the caller holds on one resource, and with which scope.

**Scoped grants and a resource catalogue**
- A grant carries a scope: `all` or `own`, open to more. A grant stored without one reads as `all`.
- A privilege granted only with `own` does not satisfy a plain privilege check. Separate checks ask
  for "any scope" (and report the scope) and for "this record" (with an ownership check).
- A resource catalogue is registered in code at start-up and readable through a service. Grant
  administration refuses a privilege or scope the catalogue does not list.

**Administration services** (new `admin` package, defaults on scrty's identity stores, ports for a
consumer's own store)
- Users: list with search, filters and paging; get with roles; create; update; deactivate and
  reactivate; soft delete; set and reset a password through the existing policy and history.
- Import with given values (identifier, password hash, active flag, times), by identifier only,
  idempotent.
- Email as a user field, unique ignoring case among users that are not deleted, with a recorded
  verification time.
- Profile attributes the application defines, stored, returned and searchable by exact match.
- Roles: create, update, delete (refused while assigned unless forced), list and get. A role carries
  a display name, a description and labels. The role name is an immutable key.
- Grants: read a role's grants and replace them per resource in one transaction.
- Assignments: add, remove, list, mark primary, with optional start and end dates.
- Writes to one role's grants or one user's roles are serialised, and a stale version is refused.
- Every administrative change emits an event naming the actor, the target and the changed fields.
  Before and after values go to an optional audit port and never carry a password hash.
- One typed error per reason, so the application can render its own problem types.

**Login and sessions**
- Login by email, off by default. Only a verified email logs in. The lockout counts against the
  resolved account, so the username and the email share one budget.
- Assignment start and end dates are enforced when the chain builds the principal.
- An optional switch of the active role, recorded in the session and re-checked on every request.

**Behaviour changes** (none breaks the Go API; each is called out in the v0.3.0 CHANGELOG entry)
- **BREAKING (behaviour):** a soft-deleted user loads as not found, by username and by identifier.
- **BREAKING (behaviour):** a role grant outside its start and end dates no longer reaches the
  principal, so it no longer authorizes. Before, the dates were carried and never checked.
- The identity migration adds an `email` column and a unique index on live users' emails. A
  database where the consumer already added an `email` column of their own fails the migration,
  which then changes nothing.
- **BREAKING (behaviour):** provisioning refuses a username equal to another live user's email,
  ignoring case. A federated first login whose username is a local user's email now fails instead
  of creating a second user that the email would also name.
- The identity ports still discard an email given to `Provision` or `Update`; only the
  administration services and import set it, so just-in-time provisioning cannot fail on an
  email collision.

## Capabilities

### New Capabilities
- `security-administration`: the administration services for users, roles, grants and assignments,
  user import, profile attributes, optimistic concurrency, administration errors, audit, and the
  store ports behind them.
- `resource-catalogue`: resources, their privileges and the scopes each privilege may be granted
  with, registered in code and readable at run time.

### Modified Capabilities
- `authorization`: grant scopes and the checks that read them, the request memo, `AllOf`, the bulk
  check, and the denial reasons (no role, not granted, wrong scope, not the owner).
- `identity-model`: scope on a privilege, email and its verification on user details, soft deletion,
  the optional email loader port.
- `default-identity-store`: stores email, scope, profile attributes, versions and soft deletion;
  loaders skip deleted users; implements the administration and email-loader ports.
- `authentication`: the password provider can resolve an identifier as a verified email.
- `security-policy`: lockout keys a resolved identifier on the account it resolved to.
- `framework-adapters`: a guard for any requirement in gin and fiber.
- `http-security-chain`: a guard for any requirement in net/http, the per-request memo, assignment
  dates and the selected active role applied when the principal is built.
- `sessions`: a session can record a selected active role.
- `schema-migrations`: the identity set adds the administration columns and tables; the
  security-state set adds the selected-role column.
- `security-events`: administration events and the active-role switch.

## Impact

- **Code:** `authorize`, `identity`, new `admin`, `authenticate` (password provider), `policy/lockout`,
  `session`, `httpsec` and its gin and fiber adapters, `event`, `store/sqlstore`, `store/pgxstore`,
  `store/gormstore`, `store/migrate`, and the conformance suites in `test`.
- **Migrations:** one new identity migration and one new security-state migration, both with a Down
  section, after `20261124000000_scrty_prefix`. The version tables stay `goose_identity` and
  `goose_security_state`.
- **Dependencies:** none added.
- **Release:** v0.3.0, one CHANGELOG entry together with the table prefix and the device grant.
  All of it lands on `main` in one pull request, which leaves `main` green.
- **Out of scope:** HTTP endpoints and user interfaces for administration; any application's mapping
  of its own legacy roles; email delivery or verification flows; magic link and recovery by email.
- **Follow-up map:** this change covers the identity-model and default-identity-store parts of the
  planned `user-email` follow-up. The `oidc-provider-userinfo` part (an `email` claim) stays with it.
