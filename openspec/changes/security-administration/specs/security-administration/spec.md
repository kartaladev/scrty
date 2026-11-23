# Spec Delta

## Purpose

Lets an application manage users, roles, grants and role assignments through ready-to-use services
over scrty's identity store, or over its own store behind the same ports, without scrty serving any
administration endpoint.

## ADDED Requirements

### Requirement: Administration is offered as services, never as endpoints
The library SHALL offer user, role, grant and assignment administration as services an application calls, and SHALL NOT serve any administration endpoint. The services SHALL work over the default identity store with no other configuration than the store, and SHALL accept any implementation of their store ports in its place.

#### Scenario: Default store
- **WHEN** an application builds the user administration service over the default identity store and creates a user
- **THEN** the user is stored and can be loaded by the identity loaders

#### Scenario: Consumer store
- **WHEN** an application builds the user administration service over its own implementation of the user administration port
- **THEN** every call reaches that implementation, and the service's rules and errors are unchanged

### Requirement: Construction refuses a missing store or a missing catalogue
Building an administration service without its store SHALL fail with a configuration error. Building the grant administration service without a resource catalogue SHALL fail with a configuration error, because grants could otherwise name privileges nobody declared.

#### Scenario: Grant service without a catalogue
- **WHEN** the grant administration service is built with a store and no catalogue
- **THEN** construction fails with a configuration error

### Requirement: Every administrative call names its actor
Each administrative write SHALL take its actor from the request context: the authenticated principal, or a system actor the caller attached explicitly. A write with neither SHALL be refused with a no-actor error before anything is written. The services SHALL NOT decide whether the actor may make the change; that is the application's authorization.

#### Scenario: No actor
- **WHEN** a user is deactivated with a context that carries no principal and no system actor
- **THEN** the call fails with the no-actor error and the user stays active

#### Scenario: System actor
- **WHEN** an import runs with a context carrying the system actor `sync`
- **THEN** the write succeeds and its event names `sync` as the actor

### Requirement: Users can be listed with search, filters and bounded pages
Listing users SHALL accept a search text, an active filter, a role filter, an attribute filter by exact match, and a page size. Search SHALL match username, display name and email, ignoring case, with the search text's wildcard characters taken literally. Pages SHALL be continued by an opaque cursor. Deleted users SHALL NOT be listed.

#### Scenario: Search is literal
- **WHEN** users `a_b` and `axb` exist and the list is searched for `a_b`
- **THEN** only `a_b` is listed

#### Scenario: Filter by role and attribute
- **WHEN** the list is filtered to role `sales` and attribute `job_title` equal to `Manager`
- **THEN** only live users holding a `sales` grant and that attribute value are listed

#### Scenario: Paging
- **WHEN** 120 users match and the page size is 50
- **THEN** three pages are returned in a stable order, and the third holds 20 users and no cursor

### Requirement: Page sizes are bounded
A page size of zero SHALL use the default of 50. A page size above the maximum of 500, or below zero, SHALL be refused with an invalid-input error. A consumer SHALL be able to change the default and the maximum at construction, and a default above the maximum SHALL fail construction.

#### Scenario: Oversized page
- **WHEN** a list asks for 10 000 users per page
- **THEN** the call fails with the invalid-input error

#### Scenario: Consumer maximum
- **WHEN** the service is built with a maximum page size of 1000 and a list asks for 800
- **THEN** up to 800 users are returned

#### Scenario: A malformed cursor
- **WHEN** a list is continued with a cursor that does not decode
- **THEN** the call fails with the invalid-input error, not with a storage failure

### Requirement: A user is read with its roles, email and attributes
Getting a user by identifier SHALL return the user's details, email, email verification time, profile attributes, version, creation and update times, and every role grant with its dates and primary mark. An unknown or deleted user SHALL fail with the not-found error.

#### Scenario: Get with roles
- **WHEN** a user with grants `sales` (primary) and `audit` (ending 2027-01-01) is read
- **THEN** both grants are returned with their primary mark and dates

#### Scenario: Deleted user
- **WHEN** a soft-deleted user is read by identifier
- **THEN** the call fails with the not-found error

### Requirement: Creating a user generates its identifier and refuses a taken name or email
Creating a user SHALL generate the identifier, and SHALL fail with the already-exists error, naming the field, when the username is taken by any user, deleted or not, or the email is taken by a live user, ignoring case. The collision SHALL be decided by the write, so concurrent creations produce one user.

#### Scenario: Deleted user's username
- **WHEN** user `ada` was soft-deleted and a new user `ada` is created
- **THEN** the call fails with the already-exists error for the username

#### Scenario: Deleted user's email
- **WHEN** a deleted user had email `ada@example.com` and a new user is created with `ADA@example.com`
- **THEN** the user is created

#### Scenario: Concurrent creations
- **WHEN** eight callers create a user with the same email at once
- **THEN** exactly one succeeds and every other call fails with the already-exists error

### Requirement: A username and another user's email never coincide
A write SHALL be refused with the already-exists error when it sets a username equal to the email of another live user, or an email equal to another user's username, ignoring case. Concurrent writes that would create such a pair SHALL NOT both succeed.

#### Scenario: Username equal to another email
- **WHEN** user `bob` has email `carol@example.com` and a user `carol@example.com` is created
- **THEN** the call fails with the already-exists error and no user is created

#### Scenario: Racing pair
- **WHEN** one caller creates user `x@example.com` while another sets the email `x@example.com` on a different user
- **THEN** at most one of the two writes succeeds

### Requirement: Updates are conditional on the version the caller read
Every update of a user or a role SHALL name the version the caller read. When the stored version differs, the update SHALL change nothing and fail with the stale-update error. A successful update SHALL increase the version. Only the fields the caller names SHALL change.

#### Scenario: Stale update
- **WHEN** two administrators read user `ada` at version 3, and the first renames her
- **THEN** the second's update fails with the stale-update error and changes nothing

#### Scenario: Unnamed fields kept
- **WHEN** an update names only the display name
- **THEN** the email, attributes, roles and password are unchanged

### Requirement: Deactivation and reactivation change only the active flag
Deactivating a user SHALL clear the active flag, and reactivating SHALL set it, each conditional on the version. Deactivating an inactive user, or reactivating an active one, SHALL succeed without a write or an event.

#### Scenario: Deactivated user cannot authenticate
- **WHEN** user `ada` is deactivated and her session is used on the next request
- **THEN** that request is refused as unauthenticated

#### Scenario: Repeat deactivation
- **WHEN** an inactive user is deactivated again
- **THEN** the call succeeds and no event is emitted

### Requirement: Soft deletion hides the user and keeps the username
Deleting a user SHALL mark the user deleted and inactive, keep the record and its username, release its email, and remove its profile attributes and password history. A deleted user SHALL load as not found and SHALL NOT be undeleted.

#### Scenario: Deleted user cannot log in
- **WHEN** user `ada` is deleted and her username and correct password are presented
- **THEN** the uniform authentication failure is returned

#### Scenario: Delete twice
- **WHEN** an already deleted user is deleted again
- **THEN** the call fails with the not-found error

### Requirement: Passwords are set through the configured policy and history
Setting a user's password SHALL take a plain password, check it against the configured password policy and the reuse guard, encode it with the configured encoder, record the replaced hash in the password history and record the change time, in one transaction. A refused password SHALL change nothing.

#### Scenario: Reused password
- **WHEN** an administrator resets `ada`'s password to the one she had before
- **THEN** the call fails with the policy's reuse error and the stored hash is unchanged

#### Scenario: Reset records the change
- **WHEN** an administrator resets `ada`'s password to an acceptable one
- **THEN** her password-changed time is the service clock's time and her old hash is in the history

### Requirement: Import writes given values by identifier and is idempotent
Importing a user SHALL take an identifier, username, display name, email, email verification time, password hash, active flag, creation and update times, roles and attributes. It SHALL create the user when the identifier is unknown and update it when known, and SHALL report created, updated or unchanged. Equal values SHALL write nothing and emit no event.

#### Scenario: First import
- **WHEN** a user with identifier `0192…01`, a bcrypt hash and creation time 2021-03-04 is imported
- **THEN** the user is created with exactly that identifier, hash and creation time, and the outcome is created

#### Scenario: Re-import of equal values
- **WHEN** the same user is imported again with equal values
- **THEN** the outcome is unchanged, nothing is written and the update time is unchanged

#### Scenario: Imported hash logs in
- **WHEN** an imported bcrypt hash's password is presented at login, with bcrypt among the recognised encodings
- **THEN** the login succeeds

### Requirement: Import never takes over another user
Import SHALL match users by identifier only. A username or email that belongs to a different identifier SHALL fail with the already-exists error and write nothing. Import SHALL NOT check the password policy, because it stores a hash it is given, and SHALL store the hash unchanged.

#### Scenario: Username held by another identifier
- **WHEN** a user is imported with username `ada` and a new identifier while `ada` exists under another identifier
- **THEN** the import fails with the already-exists error and both users are unchanged

### Requirement: Profile attributes belong to the application
A user SHALL carry named profile attributes with text values that the application defines. They SHALL be stored and returned unchanged, replaced as a set when named in an update, and searchable by exact match of name and value. Names SHALL be non-empty, at most 64 bytes; values at most 1024 bytes; at most 64 attributes per user. Larger input SHALL be refused with the invalid-input error.

#### Scenario: Attributes round-trip
- **WHEN** a user is created with attributes `phone` = `+62 21 555` and `job_title` = `Manager`
- **THEN** reading the user returns both values exactly

#### Scenario: Too many attributes
- **WHEN** a user is created with 65 attributes
- **THEN** the call fails with the invalid-input error and no user is created

### Requirement: Roles carry a display name, a description and labels under an immutable name
Creating a role SHALL take a name, a display name, a description, labels and the super-role flag. The name SHALL be unique and SHALL NOT change after creation. Updating a role SHALL change its display name, description, labels or super-role flag, conditional on its version.

#### Scenario: Rename changes the display name
- **WHEN** role `sales` is updated with display name `Sales (Partner)`
- **THEN** its name stays `sales`, every grant and assignment still applies, and listing shows the new display name

#### Scenario: Duplicate role
- **WHEN** a role `sales` is created while one exists
- **THEN** the call fails with the already-exists error

### Requirement: Roles can be listed and read
Listing roles SHALL return every role with its display name, description, labels, super-role flag, version and the number of live users assigned to it, filterable by label. Reading a role by name SHALL return the same; an unknown role SHALL fail with the not-found error.

#### Scenario: Filter by label
- **WHEN** roles are listed with label `Partner`
- **THEN** only roles carrying that label are returned

### Requirement: Deleting an assigned role is refused unless forced
Deleting a role that is assigned to any live user SHALL fail with the still-assigned error and change nothing. A forced delete SHALL remove the role, its grants and its assignments in one transaction, keep each affected user's remaining grants, and make another remaining grant primary where the removed one was.

#### Scenario: Assigned role
- **WHEN** role `sales` is assigned to two users and is deleted without force
- **THEN** the call fails with the still-assigned error and the role and assignments remain

#### Scenario: Forced delete
- **WHEN** role `sales` is primary for `ada`, who also holds `audit`, and `sales` is deleted with force
- **THEN** `sales`, its grants and its assignments are gone, and `audit` is `ada`'s primary role

### Requirement: A role's grants are read and replaced per resource in one transaction
Reading a role's grants SHALL return every privilege with its group, resource, granted flag and scope. Replacing grants SHALL take one or more resources with their complete privilege lists and the role version, and SHALL replace exactly those resources' grants in one transaction, leaving other resources unchanged.

#### Scenario: Replace one resource
- **WHEN** role `sales` holds grants on `crm/lead` and `crm/deal`, and `crm/lead` is replaced with `view` (all) and `update` (own)
- **THEN** `crm/lead` holds exactly those two grants and `crm/deal` is unchanged

#### Scenario: Failure mid-write
- **WHEN** the store fails after deleting a resource's old grants and before writing the new ones
- **THEN** the role's grants are exactly as they were before the call

### Requirement: Grants are checked against the catalogue
Replacing grants SHALL be refused with the unknown-privilege error, writing nothing, when it names a resource the catalogue does not list, a privilege the catalogue does not list for that resource, or a scope that privilege may not be granted with.

#### Scenario: Unlisted privilege
- **WHEN** a grant names privilege `purge` on `crm/lead`, which the catalogue does not list
- **THEN** the call fails with the unknown-privilege error and no grant is written

#### Scenario: Scope not allowed
- **WHEN** the catalogue allows `create` on `crm/lead` only with scope `all`, and a grant names it with `own`
- **THEN** the call fails with the unknown-privilege error

### Requirement: Assignments are added, removed, listed and marked primary
A user's role grants SHALL be listed, added with an optional start and end date, removed, and one SHALL be marked primary, each conditional on the user's version. Adding a role the role catalogue of the store does not hold SHALL fail with the not-found error. An end date not after the start date SHALL be refused with the invalid-input error.

#### Scenario: Primary grant with no dates
- **WHEN** `sales` is assigned to `ada` as primary with neither a start nor an end date
- **THEN** the assignment is stored with no dates and authorizes `ada` until it is removed

#### Scenario: Mark primary
- **WHEN** `ada` holds `sales` (primary) and `audit`, and `audit` is marked primary
- **THEN** `audit` is her only primary grant and her primary role is `audit`

#### Scenario: Remove the primary grant
- **WHEN** `ada`'s primary grant `sales` is removed while she holds `audit`
- **THEN** `audit` becomes primary

#### Scenario: Unknown role
- **WHEN** role `ghost` is assigned to `ada` and no role `ghost` exists
- **THEN** the call fails with the not-found error

### Requirement: Writes to one role's grants or one user's roles are serialised
Concurrent writes to the same role's grants, or to the same user's role grants, SHALL be applied one after another, and each SHALL be checked against the version current when it is applied.

#### Scenario: Concurrent grant replacements
- **WHEN** two callers replace `sales`'s grants at once, both naming version 4
- **THEN** exactly one succeeds and the other fails with the stale-update error

### Requirement: Administration errors carry one reason each
Every administration failure the application can act on SHALL be identifiable by exactly one reason: not found, already exists (naming the field), still assigned, stale update, unknown privilege, invalid input, or no actor. A storage failure SHALL match none of them. Error text SHALL NOT contain a username, email, attribute value or password hash.

#### Scenario: Storage outage
- **WHEN** the store's connection fails during an update
- **THEN** the error matches none of the administration reasons

#### Scenario: No identifiers in text
- **WHEN** creating `ada@example.com` fails because the email is taken
- **THEN** the error text does not contain `ada@example.com`

### Requirement: Every administrative change emits an event
Each change a service makes SHALL emit one event naming the actor, the target and the names of the fields that changed, after the change commits. A refused or failed call, and a call that changed nothing, SHALL emit none. An event SHALL never carry a password, a hash or an attribute value.

#### Scenario: Update event
- **WHEN** an administrator changes `ada`'s email
- **THEN** one user-updated event names the administrator, `ada`'s identifier and the field `email`, and not the address

### Requirement: Before and after values go only to an optional audit port
A consumer MAY give the services an audit port. When given, each change SHALL also be delivered to it with the record before and after the change, with every password hash removed. Without one, no before or after values SHALL leave the service. An audit port failure SHALL be logged and SHALL NOT undo the change.

#### Scenario: Audit port
- **WHEN** an audit port is configured and `ada`'s password is reset
- **THEN** the port receives before and after records in which the password hash is absent

#### Scenario: Audit port fails
- **WHEN** the audit port returns an error for a committed change
- **THEN** the change stays committed and the failure is logged without the record's values
