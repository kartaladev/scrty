## Purpose

Provides an optional, ready-to-use PostgreSQL implementation of scrty's identity ports (user loading, role privilege loading, user provisioning and MFA requirement lookup) and of the optional password-history port, plus a public conformance suite that proves any implementation of those ports, the consumer's included, keeps the same rules.

## ADDED Requirements

### Requirement: Loading a user returns the complete stored record
Loading a user by username SHALL return:
- the user's identifier as the canonical lowercase UUID string;
- display name, username and the stored password hash, byte for byte;
- the active flag, the primary role name and the password-changed-at time (zero when none is stored);
- the organization, with its group when it has one;
- every assigned role grant.

Grants SHALL be returned primary first, then in their stored order. Each grant SHALL carry its identifier, name, primary flag, super-role flag and validity window unchanged. The store SHALL NOT filter grants by validity window, and SHALL NOT interpret the active flag; those decisions belong to authentication and authorization.

#### Scenario: Fully populated user
- **WHEN** a user `ada` with an organization in a group, two role grants (the second one primary, with a validity window) and a stored password-changed-at time is loaded by username
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

### Requirement: An unknown user is reported distinctly from a storage failure
Loading an unknown username SHALL fail with the identity model's user-not-found error. A storage failure SHALL fail with an error that does not match user-not-found and that wraps the underlying cause. The store SHALL NOT return a partial record when any part of the record fails to load.

#### Scenario: Unknown username
- **WHEN** a username that has no stored user is loaded
- **THEN** loading fails with the user-not-found error

#### Scenario: Database unavailable
- **WHEN** a user is loaded while the users table cannot be read
- **THEN** loading fails with an error that is not the user-not-found error
- **AND** no record is returned

#### Scenario: Grants or organization cannot be read
- **WHEN** the user row is readable but the assigned roles, the organization or the group cannot be read
- **THEN** loading fails with an error and no record is returned

### Requirement: Usernames are matched exactly as given
The store SHALL store and match usernames exactly as supplied, with no case folding, trimming or Unicode normalization. A consumer that normalizes usernames before calling the store gets matching on the normalized form.

#### Scenario: Case differs
- **WHEN** a user is provisioned as `Alice` and then loaded as `alice`
- **THEN** loading fails with the user-not-found error

#### Scenario: Consumer normalizes usernames
- **WHEN** a consumer lowercases every username before provisioning and before loading, and provisions `Alice` then loads `ALICE`
- **THEN** both calls use `alice` and the load returns the provisioned user

### Requirement: Loading role privileges groups them by resource
Loading privileges for a role name SHALL return every stored privilege entry for that role, grouped by resource group and resource, with groups ordered by resource group and then resource. Each entry SHALL carry its privilege name and granted flag; entries whose granted flag is false SHALL be returned, not dropped. When the role has no stored privilege entries, loading SHALL fail with the identity model's privileges-not-found error. A storage failure SHALL fail with a different error.

#### Scenario: Grouped privileges
- **WHEN** role `auditor` has privileges `read` (granted) and `export` (not granted) on resource `invoice` in group `billing`, and `read` (granted) on resource `ledger` in group `accounts`
- **THEN** loading returns the `accounts/ledger` group first and the `billing/invoice` group second
- **AND** the `billing/invoice` group carries both `read` granted and `export` not granted

#### Scenario: Role with no privileges
- **WHEN** privileges are loaded for a role name with no stored entries
- **THEN** loading fails with the privileges-not-found error

### Requirement: Provisioning is create-only and a collision is a refusal
Provisioning SHALL create a new user and SHALL fail with the identity model's user-already-exists error when the username is taken. A refused provision SHALL leave the stored user and their grants exactly as they were. Detecting the collision SHALL be part of the write itself, so that concurrent provisions of the same new username produce exactly one user, and every other caller receives the user-already-exists error rather than a driver or constraint error.

#### Scenario: Taken username
- **WHEN** `bob` is provisioned with name `Original` and role `admin`, and `bob` is provisioned again with name `Impostor` and role `root`
- **THEN** the second call fails with the user-already-exists error
- **AND** loading `bob` returns name `Original` with the single grant `admin`

#### Scenario: Concurrent double submit
- **WHEN** eight callers provision the same new username at the same moment
- **THEN** exactly one call succeeds and returns the created record
- **AND** every other call fails with the user-already-exists error, and none fails with a driver or constraint error

### Requirement: A provisioned user starts from safe defaults
A newly provisioned user SHALL:
- be active;
- have no password-changed-at time, unless the caller names one;
- have the MFA-required flag false;
- have the password hash stored verbatim and never hashed by the store, with an empty hash stored when none is given;
- have the organization reference stored as given.

Role names SHALL produce one grant per occurrence, in the order given, with only the first grant primary, the first name as the primary role, and no super role or validity window. An email address passed to provisioning SHALL NOT be stored by this store and SHALL never be used as a lookup key. Provisioning SHALL return the complete stored record.

#### Scenario: Provision with every field
- **WHEN** a user is provisioned with a name, roles `admin` then `auditor`, an organization and a password hash
- **THEN** the returned record is active, carries each supplied value, names `admin` as primary, and has a zero password-changed-at time
- **AND** a requirement lookup for the user reports not required

#### Scenario: Repeated role name
- **WHEN** a user is provisioned with roles `admin`, `admin`
- **THEN** the record holds two grants named `admin` with distinct identifiers, and only the first is primary

### Requirement: An empty username is refused
Provisioning and updating SHALL both refuse an empty username with an error that is neither user-already-exists nor user-not-found, and SHALL write nothing.

#### Scenario: Empty username on provision
- **WHEN** a user is provisioned with the username `""`
- **THEN** provisioning fails with an error and no user row is created

#### Scenario: Empty username on update
- **WHEN** an update is requested for the username `""`
- **THEN** the update fails with an error that is not user-not-found

### Requirement: Updating amends only the fields the caller names
Updating SHALL amend an existing user, writing only the fields the caller explicitly named. A field the caller did not name SHALL be left as stored, whatever its value. Updating an unknown username SHALL fail with the user-not-found error and SHALL NOT create a user. A successful update SHALL return the complete stored record after the change, not only the amended fields. An update that names no field SHALL write nothing and SHALL return the complete stored record.

#### Scenario: Rename only
- **WHEN** a user provisioned with name `Original`, roles `admin` and `auditor`, an organization and password hash `h1` is updated naming only the name `Renamed`
- **THEN** the returned record has name `Renamed` and still carries both grants, the primary role, the organization, password hash `h1`, the active flag and the identifier

#### Scenario: Unknown user
- **WHEN** an update names the name `Ghost` for a username that is not stored
- **THEN** the update fails with the user-not-found error
- **AND** a subsequent load of that username fails with the user-not-found error

#### Scenario: Update naming nothing
- **WHEN** an update names no field
- **THEN** no stored value changes and the complete stored record is returned

### Requirement: The password-age clock moves only when the caller names it
Provisioning and updating SHALL write the password-changed-at time only when the caller names it, and SHALL store the named value as given. Naming a zero time SHALL clear the stored value. A password hash written without naming the time SHALL leave the stored time unchanged. This keeps a password mirrored from an external identity provider on every login from exempting that user from password-age policy, while a local change records itself by naming both. The store SHALL return whatever value it holds.

#### Scenario: Password write on a user with no password change recorded
- **WHEN** a user with no password-changed-at time is updated naming only a new password hash
- **THEN** the new hash is stored
- **AND** the stored password-changed-at time is still zero

#### Scenario: Recorded rotation survives a mirrored password write
- **WHEN** a user's password-changed-at time was recorded 400 days ago, and the user is then updated naming only a new password hash
- **THEN** the stored password-changed-at time is still 400 days ago

#### Scenario: Local change names the time
- **WHEN** a user is updated naming a new password hash and a password-changed-at time `T`
- **THEN** the new hash is stored and the returned and stored password-changed-at time is `T`

#### Scenario: Provisioning names the time
- **WHEN** a user is provisioned naming a password-changed-at time `T`
- **THEN** the returned record's password-changed-at time is `T`

#### Scenario: Naming a zero time clears it
- **WHEN** a user with a stored password-changed-at time is updated naming the zero time
- **THEN** the stored password-changed-at time is zero

### Requirement: A role list that names nothing leaves grants untouched
An update SHALL leave the stored grants, including their identifiers, super-role flags and validity windows, and the primary role, completely untouched when the caller does not name roles, names an empty role list, or names only empty role names. There SHALL be no way to remove every grant through an update.

#### Scenario: Roles not named
- **WHEN** a user with grants `admin` and `auditor` is updated naming only the name
- **THEN** both grants keep their identifiers, order and primary flags

#### Scenario: Empty role list from a filtered claim
- **WHEN** a user whose `admin` grant is a super role is updated naming an empty role list
- **THEN** the user still holds the `admin` grant with its super-role flag and validity window, and `admin` is still the primary role

#### Scenario: Only empty role names
- **WHEN** a user with grants `admin` and `auditor` is updated naming roles `""`, `""`
- **THEN** both grants are unchanged and `admin` is still the primary role

### Requirement: Naming roles rebuilds grants without escalating privilege
When an update names at least one non-empty role name, the store SHALL rebuild the grant list as follows:
- **Order and primary:** grants follow the order given; the first surviving name is primary and becomes the primary role.
- **Empty and repeated names:** empty names are skipped, and a repeated name collapses to its first occurrence.
- **A name with an existing grant:** the grant keeps its identifier, super-role flag and validity window. Only its primary flag moves.
- **A name with no existing grant:** it gets a new grant with a new identifier, no super role and no validity window.
- **Duplicate stored grants:** when the user holds more than one grant with the same name, the first in stored order is kept, and the attributes of later duplicates are discarded, never promoted.

#### Scenario: Reorder preserves a super role
- **WHEN** a user holding `admin` (a super role with a validity window) then `auditor` is updated naming roles `auditor`, `admin`
- **THEN** `auditor` is first, primary and the primary role
- **AND** `admin` keeps its identifier, super-role flag and validity window, and is not primary

#### Scenario: New role does not inherit privileges
- **WHEN** a user holding super-role grant `admin` is updated naming roles `admin`, `viewer`
- **THEN** `viewer` has a new identifier, no super role and no validity window

#### Scenario: Empty and repeated names
- **WHEN** a user holding `admin` is updated naming roles `""`, `viewer`, `viewer`, `""`
- **THEN** the user holds exactly one grant, `viewer`, and it is primary

#### Scenario: Stored duplicates collapse to the first
- **WHEN** a user holding two `admin` grants, the first a super role and the second not, is updated naming role `admin`
- **THEN** the user holds one `admin` grant carrying the first grant's identifier, super-role flag and validity window

### Requirement: Grant order does not depend on identifier order
The stored order of a user's grants SHALL be the order in which they were given, independent of the identifiers assigned to them, including when the identifier generator is replaced by one whose identifiers do not sort in creation order.

#### Scenario: Consumer generator with descending identifiers
- **WHEN** the store is configured with a consumer identifier generator that returns identifiers in descending order, and a user is provisioned with roles `admin`, `auditor`, `viewer`
- **THEN** loading the user returns the grants in the order `admin`, `auditor`, `viewer`

#### Scenario: First stored duplicate under a consumer generator
- **WHEN** the store uses a generator with descending identifiers, a user is provisioned with roles `admin`, `admin`, the first `admin` grant is made a super role, and the user is updated naming role `admin`
- **THEN** the surviving grant is the first one, carrying the super-role flag

### Requirement: Store-owned identifiers come from a replaceable generator
The store SHALL assign identifiers to the users and grants it creates, using the default UUIDv7 generator when none is configured. A consumer-configured generator's identifiers SHALL be used exactly as returned. When the generator fails, the operation SHALL fail with an error wrapping the generator's error and SHALL write nothing. A user's identifier SHALL be exposed to the rest of scrty as its canonical lowercase UUID string.

#### Scenario: Default generator
- **WHEN** a user is provisioned with no generator configured
- **THEN** the user's identifier is a canonical lowercase UUID string whose version field is `7`

#### Scenario: Consumer generator
- **WHEN** the store is configured with a generator that returns `00000000-0000-4000-8000-000000000001` for the next user
- **THEN** the provisioned user's identifier is exactly `00000000-0000-4000-8000-000000000001`

#### Scenario: Generator fails mid-provision
- **WHEN** the generator succeeds for the user and fails for the user's second grant
- **THEN** provisioning fails with an error wrapping the generator's error
- **AND** loading that username fails with the user-not-found error

### Requirement: Concurrent updates of one user serialise
Concurrent updates that rebuild the same user's grants SHALL be applied one after another, so the final grant set is exactly the one named by the update that committed last. Updates to different users SHALL NOT block each other.

#### Scenario: Revoke races re-assert
- **WHEN** a user holds `admin`, one update naming `viewer` has rebuilt the grants but not committed, and a second update naming `admin` starts, and the first then commits before the second
- **THEN** the user finally holds exactly `admin`
- **AND** does not also hold `viewer`

### Requirement: MFA requirement lookup reads the user's flag and fails closed
Looking up whether a user must use a second factor SHALL return the user's stored MFA-required flag.
- **Unknown user:** fails with the user-not-found error, never "not required".
- **Reference that is not a valid UUID string:** fails with the user-not-found error, not a driver error.
- **Storage failure:** fails with an error, never "not required".

The flag SHALL be read fresh on each lookup. Losing a user's MFA enrolment SHALL NOT change it. No port call SHALL write the flag; the consumer's own user management owns it.

#### Scenario: Flag set by the consumer
- **WHEN** the consumer's user management sets the MFA-required flag for a user and the requirement is then looked up
- **THEN** the lookup reports required

#### Scenario: Unknown or malformed user reference
- **WHEN** the requirement is looked up for `not-a-uuid`, or for a well-formed UUID with no stored user
- **THEN** the lookup fails with the user-not-found error

#### Scenario: Identity tables missing
- **WHEN** the requirement is looked up while the users table does not exist
- **THEN** the lookup fails with an error that is not the user-not-found error
- **AND** it does not report "not required"

### Requirement: Errors do not carry user-supplied identifiers
Errors returned by the store SHALL NOT include the username or password hash in their message text, and SHALL NOT pass through driver detail text that echoes stored values. On the provisioning path a username is often an email address, and errors are routinely logged.

#### Scenario: Collision error text
- **WHEN** provisioning `ada@example.test` fails because the username is taken
- **THEN** the error matches the user-already-exists error
- **AND** its message does not contain `ada@example.test`

### Requirement: The store takes part in the caller's transaction
Every port operation SHALL read and write through the caller's ambient transaction when the context carries one, following the `security-state-stores` capability's ambient transaction contract, including a consumer-supplied transaction resolver. A provisioning or update call that fails inside a caller's transaction SHALL undo only its own writes and SHALL leave the caller's transaction usable, with the caller's earlier writes intact. Outside a caller's transaction, provisioning and updating SHALL each be atomic across all tables they touch.

#### Scenario: Loaders see uncommitted rows
- **WHEN** a user, a grant, a privilege entry and the MFA-required flag are written inside a caller's transaction that is not committed
- **THEN** the user loader, role loader and requirement lookup see them when called with that transaction's context
- **AND** report not-found when called with a context that carries no transaction

#### Scenario: Failed provision inside a caller's transaction
- **WHEN** a caller writes an unrelated row in its transaction, then a provision in the same transaction fails partway through writing grants, then the caller commits
- **THEN** provisioning fails with an error and no part of the provisioned user is stored
- **AND** the commit succeeds and the unrelated row is stored

#### Scenario: Consumer transaction manager
- **WHEN** the store is configured with a consumer transaction resolver that returns the consumer's current transaction handle, and a user is provisioned inside a transaction the consumer's manager later rolls back
- **THEN** loading that username after the rollback fails with the user-not-found error

### Requirement: Wiring mistakes fail at construction
Constructing a store SHALL fail with a configuration error when it is given no database handle, or an explicitly passed absent identifier generator, transaction resolver or clock. No such mistake SHALL surface first at a port call.

#### Scenario: Missing database handle
- **WHEN** a store is constructed without a database handle
- **THEN** construction returns a configuration error and no store

### Requirement: The identity migration set is independent of security state
The identity tables SHALL ship as their own migration set, recorded in a version table distinct from the security-state set's.
- **Independence:** applying the identity set SHALL NOT require the security-state set, and applying the security-state set SHALL NOT require it.
- **No foreign keys:** no identity table SHALL declare a foreign key, to another identity table or to a security-state table.
- **Rollback:** rolling back the identity set SHALL remove only the identity tables and their version records.
- **Version table:** its name SHALL be replaceable through the migration runner's options.

#### Scenario: Identity set alone
- **WHEN** only the identity migration set is applied to an empty database
- **THEN** the users, roles, assigned roles, organizations, groups, resource privileges and password history tables exist
- **AND** no security-state table exists

#### Scenario: Consumer with their own user tables
- **WHEN** a consumer applies only the security-state migration set
- **THEN** no identity table and no identity version table is created

#### Scenario: Rollback leaves security state intact
- **WHEN** both sets are applied and the identity set is rolled back
- **THEN** every identity table is gone and every security-state table and its version records remain

#### Scenario: Consumer-named version table
- **WHEN** the identity set is applied with the version table name overridden to `app_identity_versions`
- **THEN** the applied versions are recorded in `app_identity_versions`

### Requirement: Every shipped adapter passes the identity-port conformance suite
The `database/sql`, `pgx` and `gorm` implementations of the store SHALL each pass the full identity-port conformance suite against PostgreSQL, including its ambient-transaction part and its password-history part, with every case run and none skipped.

#### Scenario: Adapter parity
- **WHEN** the conformance suite, including its password-history part, runs against each of the three adapters
- **THEN** every case passes for all three

### Requirement: The conformance suite is usable against any port implementation
The identity-port conformance suite SHALL be public and SHALL test any implementation of the user loader, role loader, user provisioner and MFA requirement lookup, not only scrty's. It SHALL be the identity ports' one public suite, and SHALL drive the implementation only through the ports, plus hooks the implementer supplies for state the ports cannot create or faults they cannot cause:
- a user's role grants with their identifiers, super-role flags and validity windows;
- an organization with its group;
- privilege entries;
- the MFA-required flag;
- a failing user load and a failing requirement lookup.

The suite SHALL NOT assume scrty's table layout, and SHALL support a single database hosting a whole run. Every hook SHALL be required. A missing hook SHALL fail the suite immediately with a message naming it, rather than skip the cases that need it. The ambient-transaction part SHALL additionally require hooks that begin a caller-owned transaction, write an unrelated row inside it, report whether that row was stored, and make a grant write fail.

#### Scenario: Consumer verifies their own store
- **WHEN** a consumer runs the suite against their own implementation of the four ports over their own user tables, supplying every hook
- **THEN** the suite exercises every rule in this capability that is observable through the ports and reports each rule as its own named case

#### Scenario: Missing seeding hook
- **WHEN** the suite is run without the MFA-required seeding hook
- **THEN** the suite fails before running any case, naming the missing hook

#### Scenario: Known defects are caught
- **WHEN** the suite is run against an implementation with any one of these defects:
  - it stamps the password-changed-at time on a password write that does not name it;
  - it ignores a named password-changed-at time;
  - it overwrites an existing user on a username collision;
  - it returns only the amended fields from an update;
  - it rebuilds grants from scratch, dropping super roles;
  - it keeps the last of duplicate stored grants;
  - it reports an unknown user as not requiring MFA
- **THEN** at least one case fails by assertion for that defect

### Requirement: The store keeps password history for the reuse guard
The store SHALL implement the password-history port, keeping each user's retired password hashes in their own table:
- **Reading:** returns up to the requested number of the user's retired hashes, newest first, byte for byte. A well-formed user reference with no entries returns none and no error.
- **Retiring:** records the hash as the user's newest entry, then removes every entry of that user beyond the newest number the caller keeps. A hash identical to the user's newest entry adds nothing. Keeping zero records nothing and removes every entry.
- **Order:** the order of entries is the order in which they were retired, independent of the identifier generator and of clock ties.
- **Bound:** after a retire that does not overlap another retire of the same user, that user holds no more entries than the caller asked to keep. Overlapping retires of one user may leave one extra entry, which that user's next retire prunes.
- **Malformed reference:** a user reference that is not a valid UUID string fails reading with an error, never with an empty history.
- **Storage failure:** fails with an error, never with an empty history.

#### Scenario: Newest first and bounded
- **WHEN** hashes `h1`, `h2`, `h3` and `h4` are retired for a user in that order, each keeping 3
- **THEN** reading 3 entries returns `h4`, `h3`, `h2`
- **AND** the store holds exactly those three rows for the user

#### Scenario: Order under a consumer generator
- **WHEN** the store uses a generator with descending identifiers, and `h1` then `h2` are retired for a user
- **THEN** reading returns `h2` before `h1`

#### Scenario: Same bytes retired twice
- **WHEN** `h1` is retired for a user, and `h1` is retired again, each keeping 3
- **THEN** the user holds exactly one entry, `h1`

#### Scenario: Keeping zero
- **WHEN** a user holds entries `h1` and `h2`, and `h3` is retired keeping 0
- **THEN** the user holds no entries

#### Scenario: Malformed reference or unavailable table
- **WHEN** history is read for `not-a-uuid`, or while the password history table does not exist
- **THEN** reading fails with an error and returns no entries

### Requirement: No port call of the identity store records password history
Provisioning and updating SHALL NOT read, record or prune password history, including when a password hash is written. Only the password-history port writes history, so a password mirrored from an identity provider on every login never enters it.

#### Scenario: Mirrored password write
- **WHEN** a user's password hash is updated through the provisioner five times
- **THEN** the user has no password history entries

### Requirement: Password history is credential material and is removed with the user
The store SHALL keep history hashes with the same handling as the stored password hash. It SHALL NOT write them to a log record, SHALL NOT include them in error text, and SHALL return them only through the port's read. It SHALL remove every entry of a user when asked to forget that user's history. Because the identity tables declare no foreign keys, the consumer's user deletion is responsible for asking, and the store's documentation SHALL say so beside the grants the deletion also removes.

#### Scenario: History deleted with the user
- **WHEN** the consumer's user deletion removes a user holding three history entries, and asks the store to forget that user's history in the same transaction
- **THEN** reading that user's history returns none
- **AND** another user's history is unchanged

#### Scenario: Error text carries no hash
- **WHEN** retiring a hash fails because the table cannot be written
- **THEN** the error's text contains no part of the hash and not the user reference

### Requirement: Password history takes part in the caller's transaction
The password-history port SHALL read and write through the caller's ambient transaction under the same rules as the identity ports. Retiring SHALL be atomic: the insert and the pruning SHALL both happen or neither SHALL. A retire that fails inside a caller's transaction SHALL undo only its own writes and SHALL leave the caller's transaction usable.

#### Scenario: Password write and history commit together
- **WHEN** a caller, in one transaction, retires a user's current hash and updates the user's password through the provisioner, then rolls back
- **THEN** the user's password and history are both as they were before the transaction

### Requirement: The conformance suite tests any password-history implementation
The identity-port conformance suite SHALL include a separate, public password-history part that tests any implementation of the password-history port through the port alone, plus a hook that begins a caller-owned transaction. It SHALL cover newest-first order, the read bound, pruning, the same-bytes rule, keeping zero, forgetting a user, the per-user boundary and ambient-transaction rollback. Running the identity-port part SHALL NOT require the password-history part's hooks.

#### Scenario: Consumer verifies their own history store
- **WHEN** a consumer runs the password-history part against their own implementation over their own table
- **THEN** each rule runs as its own named case

#### Scenario: Known history defect is caught
- **WHEN** the password-history part is run against an implementation that returns entries oldest first, or that never prunes
- **THEN** at least one case fails by assertion
