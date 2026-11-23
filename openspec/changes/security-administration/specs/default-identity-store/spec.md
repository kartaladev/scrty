# Spec Delta

## MODIFIED Requirements

### Requirement: Loading a user returns the complete stored record
Loading a user by username SHALL return:
- the user's identifier as the canonical lowercase UUID string;
- display name, username and the stored password hash, byte for byte;
- the email and its verification time, each empty when none is stored;
- the active flag, the primary role name and the password-changed-at time (zero when none is stored);
- the organization, with its group when it has one;
- every assigned role grant.

Grants SHALL be returned primary first, then in their stored order. Each grant SHALL carry its identifier, name, primary flag, super-role flag and validity window unchanged. The store SHALL NOT filter grants by validity window, and SHALL NOT interpret the active flag; those decisions belong to authentication and authorization.

#### Scenario: Fully populated user
- **WHEN** a user `ada` with an organization in a group, two role grants (the second one primary, with a validity window), a stored password-changed-at time and a verified email is loaded by username
- **THEN** the result carries all of those values as stored
- **AND** the primary grant is listed first and names the primary role

#### Scenario: Organization without a group
- **WHEN** a user whose organization belongs to no group is loaded
- **THEN** the result carries the organization with no group

#### Scenario: Organization reference that resolves to nothing
- **WHEN** a user whose stored organization reference names no stored organization is loaded
- **THEN** the result has no organization and loading does not fail

#### Scenario: Inactive user is returned, not hidden
- **WHEN** a user whose active flag is false is loaded
- **THEN** the store returns the record with the active flag false and no error

## ADDED Requirements

### Requirement: Provisioning refuses a username that is another user's email
Provisioning, and an update that names a username, SHALL fail with the user-already-exists error when the username equals the email of another live user, ignoring case, and SHALL write nothing. The identity ports SHALL still not store an email they are given; only the administration services set it.

#### Scenario: Federated username equal to a local email
- **WHEN** local user `bob` has email `carol@example.com` and a federated login provisions the username `carol@example.com`
- **THEN** provisioning fails with the user-already-exists error and no user is created

#### Scenario: Email named to provisioning
- **WHEN** a user is provisioned naming the email `ada@example.com`
- **THEN** the stored user has no email

### Requirement: The store never returns a deleted user to a loader
Loading by username and by user reference SHALL report a soft-deleted user as not found. The MFA requirement lookup SHALL report a deleted user as the lookup reports an unknown one.

#### Scenario: Deleted by username
- **WHEN** `ada` is soft-deleted and loaded by username
- **THEN** the store returns the user-not-found error

### Requirement: The store loads a user by verified email
The store SHALL implement the email loader: it SHALL match the email ignoring case among live users whose email is verified, and return the complete stored record as loading by username does.

#### Scenario: Verified email
- **WHEN** `ada`'s email `ada@example.com` was verified and the store is asked for `ADA@example.com`
- **THEN** it returns `ada`'s complete record

### Requirement: Privilege scopes are stored with the grant
The store SHALL store each privilege's scope and return it from loading role privileges. A privilege written before scopes existed SHALL load with scope `all`.

#### Scenario: Stored scope
- **WHEN** `update` on `crm/lead` is granted to `sales` with scope `own` and the role's privileges are loaded
- **THEN** the entry for `crm/lead` carries `update` granted with scope `own`

#### Scenario: Grant from before the migration
- **WHEN** a privilege row written before the administration migration is loaded
- **THEN** it carries scope `all`

### Requirement: The store implements every administration port
The store SHALL implement the user, import, role, grant and assignment administration ports, and SHALL pass the administration conformance suite, as every shipped adapter does.

#### Scenario: Adapters pass the suite
- **WHEN** the administration conformance suite runs against the sqlstore, pgxstore and gormstore identity stores
- **THEN** every case passes on the oldest and newest supported PostgreSQL versions

### Requirement: The administration conformance suite tests any implementation
The test module SHALL publish an administration conformance suite a consumer can run against their own implementation of the administration ports, covering versions, serialisation, soft deletion, email and username uniqueness, import idempotence and the catalogue check.

#### Scenario: Consumer implementation
- **WHEN** a consumer runs the suite against an implementation that ignores the version on update
- **THEN** the stale-update case fails
