# Spec Delta

## ADDED Requirements

### Requirement: An update may change the username under the rules of creation
An update SHALL change the username when the caller names one, alone or with other fields, under the version check every update makes. A username SHALL be refused with the invalid-input error as creation refuses one, and with the already-exists error for the username when another user holds it, deleted or not, compared exactly, or when it equals another live user's email ignoring case. The user's own username and email SHALL NOT count as a clash.

#### Scenario: Rename
- **WHEN** an administrator updates `ada` at her current version with the username `ada.lovelace` and no other field
- **THEN** she loads as `ada.lovelace`, her version has increased, and the username `ada` names no live user

#### Scenario: Username held by a deleted user
- **WHEN** user `bob` was soft-deleted and `ada` is renamed to `bob`
- **THEN** the call fails with the already-exists error for the username and nothing is written

#### Scenario: Username equal to another user's email
- **WHEN** user `carol` has email `carol@example.com` and `ada` is renamed to `CAROL@example.com`
- **THEN** the call fails with the already-exists error for the username and nothing is written

#### Scenario: Only the case changes
- **WHEN** `ada` is renamed to `Ada`
- **THEN** the update succeeds and the username is stored as `Ada`

#### Scenario: Stale rename
- **WHEN** an administrator deactivates `ada` after another caller read her, and that caller then renames her at the version it read
- **THEN** the rename fails with the stale-update error, and `ada` stays inactive with her username unchanged

#### Scenario: Surrounding white space
- **WHEN** `ada` is renamed to ` ada.lovelace`
- **THEN** the call fails with the invalid-input error and the store is not called

### Requirement: A username and an email change in one write
An update that names both the username and the email SHALL apply both or neither, in one write under one version check. The email's verification SHALL follow the rules of an email update. A user MAY take a username equal to the email set in the same update, in any case. Concurrent writes that would leave two live users with a clashing username and email SHALL NOT both succeed.

#### Scenario: Username follows a new email
- **WHEN** `ada@example.com`, whose username is her email, is updated with username and email `ada@lovelace.dev`
- **THEN** both are stored, the new email is unverified, and the version has increased once

#### Scenario: One field clashes
- **WHEN** an update names a free username and an email another live user holds
- **THEN** the call fails with the already-exists error for the email, and neither the username nor the email changes

#### Scenario: Racing rename
- **WHEN** one caller renames `ada` to `x@example.com` while another sets the email `x@example.com` on a different user
- **THEN** at most one of the two writes succeeds

### Requirement: A rename is reported as an update
A committed rename SHALL emit one user-updated event naming the actor, the target and the field `username` among the changed fields, never the old or the new username. An audit port, when configured, SHALL receive the records before and after the rename. A refused rename SHALL emit nothing.

#### Scenario: Rename event
- **WHEN** an administrator renames `ada` to `ada.lovelace` and changes her email in the same update
- **THEN** one user-updated event names the fields `username` and `email`, and contains neither username nor the address

#### Scenario: Refused rename
- **WHEN** a rename fails with the already-exists error
- **THEN** no event is emitted and the error text contains neither username

### Requirement: Import is unchanged by renames
Import SHALL keep matching users by identifier and writing the given username, with the rules it has today. A rename through an update SHALL NOT change how a later import of the same identifier behaves.

#### Scenario: Import after a rename
- **WHEN** `ada` is renamed through an update to `ada.lovelace` and her identifier is then imported with the username `ada.lovelace` and otherwise equal values
- **THEN** the import reports unchanged and emits no event

### Requirement: A rename can end the user's sessions when the consumer opts in
By default a rename SHALL end no session. With a session revoker configured, a committed update that changed the stored username SHALL then revoke every session of the user; any other update SHALL revoke nothing. A failed revocation SHALL return the updated user with an error matching the sessions-not-revoked error and its cause, the update committed and its event emitted. A nil revoker, or one given over a store that cannot change usernames, SHALL fail construction.

#### Scenario: Default
- **WHEN** `ada`, signed in with a live session, is renamed to `ada.lovelace` by a service configured with defaults
- **THEN** her session still loads

#### Scenario: Consumer opts in
- **WHEN** the service is configured with a session revoker and `ada`, signed in on two devices, is renamed
- **THEN** neither session loads after the update returns

#### Scenario: No username in the update
- **WHEN** the service is configured with a session revoker and an update changes only `ada`'s display name
- **THEN** the revoker is not called and her sessions still load

#### Scenario: Current username re-sent
- **WHEN** the service is configured with a session revoker and `ada` is updated with the username `ada` and a new display name
- **THEN** the update succeeds, the revoker is not called, and her sessions still load

#### Scenario: Refused rename revokes nothing
- **WHEN** the service is configured with a session revoker and a rename of `ada` fails with the already-exists error
- **THEN** the revoker is not called

#### Scenario: Revocation fails
- **WHEN** the revoker returns an error after `ada` is renamed
- **THEN** the call returns `ada` as `ada.lovelace` with an error matching the sessions-not-revoked error and the revoker's error, `ada` loads as `ada.lovelace`, and one user-updated event was emitted

#### Scenario: Nil revoker
- **WHEN** the service is constructed with a nil session revoker
- **THEN** construction fails with an error matching the configuration error

#### Scenario: Revoker with a store that cannot rename
- **WHEN** the service is constructed with a session revoker over a store that does not support username changes
- **THEN** construction fails with an error matching the configuration error

### Requirement: A store that cannot change usernames refuses a rename before writing
An update naming a username SHALL be refused with an error matching the configuration error, before the store is called, when the store does not support username changes. Every user store scrty ships SHALL support them. Updates that name no username SHALL be unaffected. The store conformance suite SHALL run its rename cases against every store that supports them, and SHALL skip them, saying why, for a store that does not.

#### Scenario: Consumer store without support
- **WHEN** a consumer store that does not support username changes is given an update renaming `ada`
- **THEN** the call fails with an error matching the configuration error, the store's update is not called, and `ada` is unchanged

#### Scenario: Other fields on the same store
- **WHEN** the same store is given an update changing only `ada`'s display name
- **THEN** the update succeeds

#### Scenario: Library stores
- **WHEN** the `database/sql`, pgx and GORM user stores are each given a rename
- **THEN** each applies it

#### Scenario: Conformance suite on a store without rename support
- **WHEN** the store conformance suite runs against a store that does not support username changes
- **THEN** the rename cases are skipped with a message naming the capability, and the rest of the suite runs

#### Scenario: Conformance suite on a store that claims but ignores renames
- **WHEN** the store conformance suite runs against a store that claims username changes but leaves the username unchanged
- **THEN** the rename cases fail

### Requirement: Users can be listed from an offset
Listing users SHALL accept an offset: the number of users to skip, in the list's order, before the page starts. The order SHALL match cursor listing, so consecutive offsets of an unchanged list neither overlap nor leave a gap. A non-zero offset SHALL NOT be combined with a cursor, and its page SHALL carry no cursor. An offset of zero SHALL leave the listing as it is without one. An offset past the last match SHALL give an empty page.

#### Scenario: Jump to a page
- **WHEN** 120 users match, the page size is 50 and the list is asked for offset 100
- **THEN** the 20 users that the third cursor page would hold are returned, in the same order, and the page carries no cursor

#### Scenario: Offset past the end
- **WHEN** 120 users match and the list is asked for offset 500
- **THEN** an empty page is returned without error

#### Scenario: Offset zero
- **WHEN** 120 users match, the page size is 50 and the list is asked for offset 0
- **THEN** the first 50 users are returned with a cursor, as the first cursor page is

#### Scenario: Offset and cursor together
- **WHEN** a list names both an offset and a cursor
- **THEN** the call fails with the invalid-input error

#### Scenario: Negative offset
- **WHEN** a list asks for offset -1
- **THEN** the call fails with the invalid-input error

### Requirement: Offsets are bounded
An offset above the maximum of 10 000 SHALL be refused with the invalid-input error; an offset equal to the maximum SHALL be accepted. A consumer SHALL be able to change the maximum at construction. A maximum below zero, or a maximum given with a store that cannot list from an offset, SHALL fail construction.

#### Scenario: Offset beyond the maximum
- **WHEN** a list asks for offset 10 001 from a service built with defaults
- **THEN** the call fails with the invalid-input error and the store is not called

#### Scenario: Offset at the maximum
- **WHEN** a list asks for offset 10 000 from a service built with defaults
- **THEN** the list is returned from that offset

#### Scenario: Consumer maximum
- **WHEN** the service is built with a maximum offset of 50 000 and a list asks for offset 40 000
- **THEN** the list is returned from that offset

#### Scenario: Negative maximum
- **WHEN** the service is built with a maximum offset of -1
- **THEN** construction fails with an error matching the configuration error

### Requirement: Matching users can be counted
The service SHALL count the live users that match a filter's search, active, role and attribute criteria, by the same rules as listing. A filter's page size, offset and cursor SHALL NOT affect the count. Deleted users SHALL NOT be counted.

#### Scenario: Count beside a page
- **WHEN** 999 live users match a search and the list is asked for offset 0 with a page size of 10
- **THEN** the page holds 10 users and the count of the same filter is 999

#### Scenario: Deleted users are not counted
- **WHEN** 3 users match a search and one of them is soft-deleted
- **THEN** the count is 2

### Requirement: Offset listing and counting need a store that supports them
A listing from a non-zero offset, and every count, SHALL be refused with an error matching the configuration error, after input validation and before the store is called, when the store does not support them. Cursor listing SHALL be unaffected. Every user store scrty ships SHALL support them. The store conformance suite SHALL run its offset and count cases against every store that supports them, and skip them, saying why, otherwise.

#### Scenario: Consumer store without support
- **WHEN** a consumer store without offset support is asked to list from offset 50, or to count
- **THEN** the call fails with an error matching the configuration error and the store is not called

#### Scenario: Cursor listing on the same store
- **WHEN** the same store is asked for a cursor listing
- **THEN** the page is returned as before

#### Scenario: Library stores
- **WHEN** the `database/sql`, pgx and GORM user stores are each asked to list from an offset and to count
- **THEN** each answers by the same rules as the cursor listing

#### Scenario: Conformance suite on a store without support
- **WHEN** the store conformance suite runs against a store without offset support
- **THEN** the offset and count cases are skipped with a message naming the capability, and the rest of the suite runs

## MODIFIED Requirements

### Requirement: Users can be listed with search, filters and bounded pages
Listing users SHALL accept a search text, an active filter, a role filter, an attribute filter by exact match, and a page size. Search SHALL match username, display name and email, ignoring case, with the search text's wildcard characters taken literally. By default, pages SHALL be continued by an opaque cursor; a caller MAY instead page by offset. Deleted users SHALL NOT be listed.

#### Scenario: Search is literal
- **WHEN** users `a_b` and `axb` exist and the list is searched for `a_b`
- **THEN** only `a_b` is listed

#### Scenario: Filter by role and attribute
- **WHEN** the list is filtered to role `sales` and attribute `job_title` equal to `Manager`
- **THEN** only live users holding a `sales` grant and that attribute value are listed

#### Scenario: Paging
- **WHEN** 120 users match and the page size is 50
- **THEN** three pages are returned in a stable order, and the third holds 20 users and no cursor

### Requirement: Administration errors carry one reason each
Every administration failure the application can act on SHALL be identifiable by exactly one reason: not found, already exists (naming the field), still assigned, stale update, unknown privilege, invalid input, no actor, configuration (for a rename asked of a store that does not support username changes, and for an offset listing or a count asked of a store that does not support them), or sessions not revoked (for a committed rename whose opted-in session revocation failed). A storage failure SHALL match none of them. Error text SHALL NOT contain a username, email, attribute value or password hash.

#### Scenario: Storage outage
- **WHEN** the store's connection fails during an update
- **THEN** the error matches none of the administration reasons

#### Scenario: No identifiers in text
- **WHEN** creating `ada@example.com` fails because the email is taken
- **THEN** the error text does not contain `ada@example.com`

#### Scenario: Sessions not revoked
- **WHEN** a rename commits and the configured session revoker then fails
- **THEN** the error matches the sessions-not-revoked reason and the revoker's error, and the text contains neither username

### Requirement: Every administrative change emits an event
Each change a service makes SHALL emit one event naming the actor, the target and the names of the fields that changed, after the change commits. A refused or failed call, and a call that changed nothing, SHALL emit none. A call whose change committed SHALL emit its event even when a follow-up step after the commit fails, such as an opted-in session revocation after a rename. An event SHALL never carry a password, a hash or an attribute value.

#### Scenario: Update event
- **WHEN** an administrator changes `ada`'s email
- **THEN** one user-updated event names the administrator, `ada`'s identifier and the field `email`, and not the address

#### Scenario: Committed change with a failed follow-up
- **WHEN** a rename of `ada` commits and the configured session revoker then fails
- **THEN** one user-updated event names the field `username`, and the call returns the sessions-not-revoked error
