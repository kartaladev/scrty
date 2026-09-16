## Purpose

Defines who a caller is inside scrty: the principal and user details, roles, privileges, organizations, credential types and first-factor kinds. It also defines the contracts of the ports through which a consumer supplies users, role privileges, user creation and amendment, and the MFA requirement from their own data.

## ADDED Requirements

### Requirement: The user reference is opaque and consumer-owned
The library SHALL treat a user reference as an opaque string: it SHALL store, compare and return it byte-for-byte, and SHALL NOT parse it, change its case, trim it or derive meaning from its format. Role, organization and group identifiers SHALL follow the same rules.

#### Scenario: Arbitrary format round trip
- **WHEN** user details whose reference is `Tenant-7/ÅSA:0042 ` are mapped to a principal
- **THEN** the principal carries exactly `Tenant-7/ÅSA:0042 `, including the trailing space

#### Scenario: References differing only in case
- **WHEN** user references `abc` and `ABC` are compared
- **THEN** they are different users

### Requirement: A principal carries no password hash
Mapping user details to a principal SHALL carry the user reference, display name, username, roles and organization. It SHALL set the active role to the primary role when one is present, and SHALL NOT carry the password hash. Mapping absent user details SHALL yield no principal.

#### Scenario: Password hash is dropped
- **WHEN** user details holding a password hash are mapped to a principal
- **THEN** no field of the principal holds the hash

#### Scenario: Active role defaults to primary
- **WHEN** user details with roles `viewer` and `admin`, where `admin` is primary, are mapped to a principal
- **THEN** the principal's active role is `admin`

#### Scenario: No details
- **WHEN** absent user details are mapped
- **THEN** no principal is returned

### Requirement: Principals distinguish human users from services
Every principal SHALL have a kind that is either a human user or a service. A principal whose kind was not set SHALL be a human user. Service principals SHALL carry their granted scopes.

#### Scenario: Default kind
- **WHEN** a principal is created without a kind
- **THEN** it reports that it is not a service

#### Scenario: Service principal
- **WHEN** a service principal is created with scope `reports:read`
- **THEN** it reports that it is a service and carries `reports:read`

### Requirement: Roles, privileges and organizations are carried as data
An assigned role SHALL carry an identifier, a name, whether it is primary, whether it is a super role, a start date and a valid-until date. A resource privilege entry SHALL carry a group, a resource and named privileges, each granted or not. An organization SHALL carry an identifier, a name and an optional group, which carries an identifier, a name and whether it is internal. The identity model SHALL carry these values unchanged and SHALL NOT decide access from them. The library SHALL NOT supply any default organization.

#### Scenario: Role attributes preserved
- **WHEN** a loader returns a role `ops` that is a super role, valid from 2030-01-01 until 2030-06-01, and the details are mapped to a principal
- **THEN** the principal's role `ops` reports super role, start 2030-01-01 and valid-until 2030-06-01

#### Scenario: No default organization
- **WHEN** user details with no organization are mapped to a principal
- **THEN** the principal has no organization

### Requirement: Inactive is the zero state of user details
User details SHALL report a user as active only when the loader explicitly marks them active.

#### Scenario: Loader omits the active state
- **WHEN** a loader returns user details without setting the active state
- **THEN** the details report the user as inactive

### Requirement: Principal travels through a request context
The library SHALL attach a principal to a request context and read it back. An optional read of a context without a principal SHALL report that none is present. A mandatory read of such a context SHALL panic with a "no principal" error value that a recovering caller can identify.

#### Scenario: Attach and read
- **WHEN** a principal for user `u-1` is attached to a context and read from a child context
- **THEN** the principal read is for `u-1`

#### Scenario: Optional read without a principal
- **WHEN** the optional read is used on a context with no principal
- **THEN** it reports that no principal is present

#### Scenario: Mandatory read without a principal
- **WHEN** the mandatory read is used on a context with no principal and the panic is recovered
- **THEN** the recovered value is identifiable as the "no principal" error

### Requirement: Presented credentials report their type and can be cleaned up
Every presented credential SHALL report its credential type and SHALL provide a cleanup operation that wipes its sensitive material and reports any failure. The credential types `username-password` and `jwt` SHALL be named.

#### Scenario: Password credential cleanup
- **WHEN** a username-and-password credential is cleaned up
- **THEN** its password material is wiped and cleanup reports no error

### Requirement: First-factor kinds map to channels and exemptions
The library SHALL name the first-factor kinds `password`, `magic-link`, `oidc`, `basic` and `api-key`, and the channels `knowledge`, `email`, `authenticator-app`, `federated` and `machine`. It SHALL map kinds to channels as follows:
- `password` and `basic` report `knowledge`;
- `magic-link` reports `email`;
- `oidc` reports `federated`;
- `api-key` reports `machine`.

The `authenticator-app` channel SHALL be the channel of second factors that use an authenticator app, such as TOTP, and `email` SHALL also be the channel of email-delivered second factors. These kinds and channels SHALL be the complete vocabulary scrty uses. Other capabilities, including multi-factor authentication and security policy, SHALL reference these values and SHALL NOT define kinds or channels of their own.

Only `oidc` and `api-key` SHALL report themselves as exempt from an MFA requirement. The empty kind and every kind the library does not name SHALL report no channel and SHALL NOT be exempt.

#### Scenario: Authenticator-app channel
- **WHEN** the channel vocabulary is listed
- **THEN** it contains `authenticator-app` for authenticator-app second factors such as TOTP
- **AND** no first-factor kind reports `authenticator-app`

#### Scenario: Password login
- **WHEN** the kind `password` is examined
- **THEN** it reports channel `knowledge` and is not exempt

#### Scenario: Exempt kinds
- **WHEN** the kinds `oidc` and `api-key` are examined
- **THEN** `oidc` reports `federated` and is exempt
- **AND** `api-key` reports `machine` and is exempt

#### Scenario: Forgotten kind fails closed
- **WHEN** the empty kind is examined
- **THEN** it reports no channel and is not exempt

#### Scenario: Consumer-defined kind
- **WHEN** a consumer's kind `smart-card` is examined
- **THEN** it reports no channel and is not exempt

### Requirement: User loader contract
A user loader SHALL load user details by username. The library SHALL pass the username exactly as presented. When no user matches, the loader SHALL return a "user not found" error that callers can identify. Any other failure SHALL be returned as an error that is not identifiable as "user not found".

#### Scenario: Username passed unchanged
- **WHEN** a login presents the username ` Alice@Example.COM`
- **THEN** the loader receives exactly ` Alice@Example.COM`

#### Scenario: Unknown user
- **WHEN** a conforming loader is asked for a username that does not exist
- **THEN** it returns an error identifiable as "user not found"

### Requirement: Role loader contract
A role loader SHALL return the resource privileges effective for a role name. When the role has no privileges, it SHALL return a "privileges not found" error that callers can identify.

#### Scenario: Role with privileges
- **WHEN** a conforming role loader is asked for a role granting `read` on resource `invoice` in group `billing`
- **THEN** it returns an entry for `billing`/`invoice` with `read` granted

#### Scenario: Role without privileges
- **WHEN** a conforming role loader is asked for a role with no privileges
- **THEN** it returns an error identifiable as "privileges not found"

### Requirement: Provisioning is create-only and the collision is enforced by the write
A user provisioner SHALL create a user from a required username and optional display name, email, role names, organization and already-hashed password. It SHALL return the created details, which SHALL be active.
- A taken username SHALL return a "user exists" error that callers can identify, and SHALL leave the existing user unchanged.
- The collision SHALL be decided by the write itself, so concurrent requests for one username create exactly one user.
- The first role name SHALL be the primary role, and each occurrence of a name SHALL create its own grant.
- The password hash SHALL be stored exactly as given.
- The email SHALL NOT be used to look up or match a user.
- An empty username SHALL be refused.
- Error messages SHALL NOT include the username.

#### Scenario: Username taken
- **WHEN** a conforming provisioner is asked to create `alice` while `alice` exists
- **THEN** it returns an error identifiable as "user exists"
- **AND** the existing `alice` is unchanged

#### Scenario: Concurrent creation
- **WHEN** two requests to create `bob` reach a conforming provisioner at the same time
- **THEN** exactly one succeeds
- **AND** the other returns an error identifiable as "user exists"

#### Scenario: Roles and hash
- **WHEN** `carol` is created with roles `editor`, `viewer` and a password hash `H`
- **THEN** her details hold `editor` as primary and `viewer` as not primary, with password exactly `H`

#### Scenario: Error does not reveal the username
- **WHEN** creating `dave@example.com` fails because the username is taken
- **THEN** the error message does not contain `dave@example.com`

### Requirement: Updating amends only named fields of an existing user
A user provisioner SHALL amend an existing user by username, writing only the fields the caller named, whatever values they hold. Every other stored field SHALL be left unchanged. Updating an unknown username SHALL return a "user not found" error and SHALL NOT create a user. A successful update SHALL return the complete stored record. Neither creating nor updating SHALL change the stored password-changed time, including when the password is written. Concurrent updates of the same user SHALL be serialized, so the final state equals the last writer's result.

#### Scenario: Unnamed field untouched
- **WHEN** a user with organization `acme` and password `H1` is updated naming only the password `H2`
- **THEN** the user's password is `H2` and the organization is still `acme`

#### Scenario: Unknown user
- **WHEN** a conforming provisioner updates `nobody`
- **THEN** it returns an error identifiable as "user not found"
- **AND** no user `nobody` exists afterwards

#### Scenario: Complete record returned
- **WHEN** a user with roles and an organization is updated naming only the display name
- **THEN** the returned details include the user's roles and organization as stored

#### Scenario: Password-changed time preserved
- **WHEN** a user whose password-changed time is 2030-01-01 is updated naming a new password
- **THEN** the stored password-changed time is still 2030-01-01

### Requirement: Role updates never silently strip grants
When an update names roles, empty names SHALL be skipped and repeated names SHALL collapse to their first occurrence. When no name survives, the stored grants SHALL be left untouched. When names survive, the grants SHALL be rebuilt in the given order, with the first name primary. A surviving name that matches an existing grant SHALL keep that grant's identifier, super-role flag, start date and valid-until date. When stored grants contain a repeated name, the first stored grant SHALL be the one kept.

#### Scenario: Empty role list
- **WHEN** a user with super role `admin` is updated naming an empty role list, or only the name `""`
- **THEN** the user's grants are unchanged

#### Scenario: Existing grant keeps its attributes
- **WHEN** a user holding super role `admin` and role `viewer` is updated naming roles `viewer`, `admin`
- **THEN** `viewer` is primary
- **AND** `admin` is still a super role with its original identifier and validity dates

#### Scenario: Concurrent role rebuilds
- **WHEN** one update revokes `admin` in favour of `viewer` while another re-asserts `admin` on the same user
- **THEN** the final grants equal exactly one of the two requested role sets

### Requirement: MFA requirement is looked up by user reference and lives with the user
The MFA requirement lookup SHALL report, for a user reference, whether that user is required to use a second factor. The requirement SHALL be recorded with the user, not with any MFA enrolment, so removing an enrolment does not change it. The requirement SHALL NOT be part of the user details produced at authentication. A lookup failure SHALL be returned as an error, not as "not required".

#### Scenario: Enrolment removed
- **WHEN** a user marked as requiring MFA loses their MFA enrolment
- **THEN** the lookup still reports the user as required

#### Scenario: Lookup failure
- **WHEN** a conforming lookup cannot reach its backend
- **THEN** it returns an error and no answer

### Requirement: Identity ports have no silent defaults
A library component that needs a user loader, role loader, user provisioner or MFA requirement lookup SHALL NOT substitute an in-memory or empty implementation when none is supplied. When the component cannot work without the port, it SHALL fail at construction with a configuration error. An in-memory provisioner that also loads users SHALL be available to tests only.

#### Scenario: Missing user loader
- **WHEN** a component that requires a user loader is constructed without one
- **THEN** construction returns a configuration error naming the user loader

#### Scenario: Consumer implementation
- **WHEN** a consumer supplies their own user loader backed by their user table
- **THEN** the component loads users only through it
