## Purpose

Maps a verified external identity to an internal user without letting one identity claim another's account. It covers the link key and link store contract, how linked users are resolved, gated just-in-time provisioning through the create-only user provisioner, claim mirroring on later logins, and roles derived from provider claims.

## ADDED Requirements

### Requirement: Links are keyed by provider, issuer and subject, never by email
A link SHALL associate one external identity with one internal user. The identity is the provider name, the verified issuer and the verified subject. The user is recorded by the user reference and the username that existed when the link was created. Resolving an external identity SHALL use exactly the provider, issuer and subject. An email address, a username or any other claim SHALL NOT be used to find a link or to match an existing internal user. A link SHALL record the email as presented by the provider, without normalization, for operator visibility only.

#### Scenario: Same email at an attacker's provider
- **WHEN** user `u-1` is linked to subject `s-1` at issuer `https://corp.example` with email `alice@corp.example`, and a verified identity with subject `s-2` at issuer `https://social.example` presents email `alice@corp.example`
- **THEN** the second identity does not resolve to `u-1`

#### Scenario: Same subject at another issuer
- **WHEN** user `u-1` is linked to subject `12345` at issuer `https://a.example`, and a verified identity with subject `12345` at issuer `https://b.example` logs in
- **THEN** the identity does not resolve to `u-1`

### Requirement: Link store contract
A link store SHALL:
- find a link by provider, issuer and subject, reporting "link not found" when none matches;
- insert a link, refusing with a "link exists" outcome when a link for the same provider, issuer and subject exists, even when the new link is identical, and leaving the stored link unchanged;
- delete every link for a user reference, returning how many were removed.

Any failure other than "not found" or "link exists" SHALL be returned as an error distinguishable from both. Refusal errors SHALL NOT contain the subject, email, username or user reference. User references and usernames SHALL be stored and returned byte for byte. The in-memory link store SHALL be the default, and any implementation of the contract SHALL be usable in its place.

#### Scenario: Conflicting insert
- **WHEN** a link for `corp`, `https://corp.example` and `s-1` names user `u-1`, and an insert for the same key names user `u-2`
- **THEN** the insert is refused with the "link exists" outcome
- **AND** finding the key returns user `u-1`

#### Scenario: Identical re-insert
- **WHEN** a link is inserted and the same link is inserted again
- **THEN** the second insert is refused with the "link exists" outcome

#### Scenario: Deleting a user's links
- **WHEN** user `u-1` has links from two providers and the links for `u-1` are deleted
- **THEN** 2 is returned and neither identity resolves afterwards

#### Scenario: Consumer link store
- **WHEN** the broker is configured with a consumer's link store
- **THEN** every link lookup and insert is served by that store

### Requirement: A linked identity resolves only to the user it was created for
When a link exists for a verified identity, the library SHALL load the user by the link's username through the user loader. The login SHALL succeed only when:
- the loader returns details whose user reference equals the link's user reference exactly; and
- the user is enabled.

A "user not found" result, no details, a user reference that differs from the link's, and a disabled user SHALL each fail the login as an authentication failure, with the same outcome as an unlinked identity. A loader failure other than "user not found" SHALL be returned as an error that is not an authentication failure.

#### Scenario: Dangling link
- **WHEN** a link names username `alice` and the user loader reports "user not found" for `alice`
- **THEN** the login fails as an authentication failure, not as a server error

#### Scenario: Recycled username
- **WHEN** a link was created for user reference `u-1` with username `alice`, `u-1` was deleted, and a different user `u-2` now holds username `alice`
- **THEN** the login fails as an authentication failure
- **AND** it does not resolve to `u-2`

#### Scenario: Disabled user
- **WHEN** a link names user `u-1` and `u-1` is disabled
- **THEN** the login fails as an authentication failure

### Requirement: Just-in-time provisioning is off by default
An identity with no link SHALL fail the login as an authentication failure unless just-in-time provisioning is enabled for the provider that asserted it. Provisioning SHALL be enabled per provider, and enabling it for one provider SHALL NOT enable it for another. Links created outside the library, such as by an operator before a user's first login, SHALL resolve like any other link.

#### Scenario: Unlinked identity by default
- **WHEN** a verified identity with no link logs in through provider `corp` with no provisioning configured
- **THEN** the login fails as an authentication failure
- **AND** the user provisioner is not called

#### Scenario: Consumer enables provisioning for one provider
- **WHEN** provisioning is enabled for provider `corp` only, and unlinked identities log in through `corp` and through `social`
- **THEN** a user is provisioned for the `corp` identity
- **AND** the `social` login fails as an authentication failure

#### Scenario: Pre-created link
- **WHEN** an operator inserts a link for subject `s-1` naming existing user `u-1` through the link store, and `s-1` logs in with provisioning off
- **THEN** the login resolves to `u-1`

### Requirement: Provisioning requires a verified email and an allowed domain
When provisioning is enabled for a provider, an unlinked identity SHALL be provisioned only when its verified email claim is true. The consumer can explicitly allow unverified email for that provider, but allowing it SHALL NOT bypass a domain allowlist.

When the consumer configures an email domain allowlist for the provider:
- the domain part of the email SHALL exactly match an entry, compared case-insensitively;
- subdomains SHALL NOT match their parent;
- an allowlist configured with no entries SHALL admit no one.

An identity with no email SHALL NOT be provisioned. A refused provisioning SHALL fail the login as an authentication failure, and SHALL create neither a user nor a link.

#### Scenario: Unverified email
- **WHEN** provisioning is enabled for `corp` and an unlinked identity presents `email_verified` false
- **THEN** the login fails as an authentication failure and no user is created

#### Scenario: Consumer allows unverified email
- **WHEN** provisioning for `corp` is configured to allow unverified email and an unlinked identity presents `email_verified` false
- **THEN** a user is provisioned

#### Scenario: Subdomain does not match
- **WHEN** the allowlist for `corp` is `example.com` and a verified identity presents `bob@mail.example.com`
- **THEN** the login fails as an authentication failure

#### Scenario: Case-insensitive domain
- **WHEN** the allowlist for `corp` is `example.com` and a verified identity presents `Bob@EXAMPLE.com`
- **THEN** a user is provisioned

#### Scenario: Empty allowlist
- **WHEN** an allowlist with no entries is configured for `corp`
- **THEN** every unlinked identity from `corp` is refused

### Requirement: Provisioning creates a user and never adopts one
Provisioning SHALL create the user through the create-only user provisioner of the `identity-model` capability. The request SHALL name:
- the identity's email, exactly as presented, as the username and as the email;
- a display name, which is the mapped display-name claim when one is configured and resolves, and otherwise the email;
- the roles derived for the identity;
- a password hash, only when a password-hash claim is mapped and accepted.

The link SHALL then be inserted for the user reference and the username that the provisioner returned. These may differ from what was requested when the provisioner normalizes usernames.

A username that already exists SHALL fail the login as an authentication failure, with no link created and the existing user unchanged. When the link insert fails after the user was created, the login SHALL fail. An error SHALL be logged naming the provider, saying that later logins of that identity will be refused until an operator inserts the link. Enabling provisioning for any provider without a user provisioner SHALL fail construction.

#### Scenario: Username already taken
- **WHEN** local user `alice@corp.example` exists and an unlinked, verified identity with that email logs in through `corp` with provisioning enabled
- **THEN** the login fails as an authentication failure
- **AND** no link is created and `alice@corp.example` is unchanged

#### Scenario: Provisioner normalizes the username
- **WHEN** an identity with email `Bob@Corp.example` is provisioned and the provisioner creates username `bob@corp.example`
- **THEN** the link records username `bob@corp.example`
- **AND** the next login of that identity resolves to the created user

#### Scenario: Consumer display-name claim
- **WHEN** the display-name claim path for `corp` is `name` and an unlinked identity presents `name` `Bob B.` and email `bob@corp.example`
- **THEN** the provisioner is asked to create username `bob@corp.example` with display name `Bob B.`

#### Scenario: Missing provisioner
- **WHEN** provisioning is enabled for `corp` and no user provisioner is supplied
- **THEN** construction fails with a configuration error naming the missing provisioner

### Requirement: A password hash can be mapped from a claim only in a verifiable, bounded form
A consumer SHALL be able to map a dotted claim path to the user's stored password hash for a provider. It is off by default. The mapped value SHALL be accepted only when it is a well-formed bcrypt hash whose cost factor, read from the hash itself, lies within the accepted cost band. The band SHALL be 10 to 15 inclusive by default, and the consumer SHALL be able to replace it with any band inside bcrypt's own range of 4 to 31. Any other value, and a value that is absent or not a string, SHALL be ignored: nothing is written, and the login is not failed.

An ignored value SHALL be logged without the value. The log SHALL say whether the value was not a bcrypt hash, or had a cost outside the band, naming the observed cost and the band. It SHALL be at warning level the first time each reason occurs for a provider in a process, and at debug level afterwards.

Construction SHALL fail with a configuration error when:
- a password-hash claim is mapped for any provider and no password encoder is supplied;
- the supplied encoder's own output is not a bcrypt hash;
- the cost band is outside 4 to 31, or its minimum exceeds its maximum;
- the mapping is keyed by an empty provider name;
- a provider's display-name claim path or role claim path equals its password-hash claim path.

A mapped hash SHALL never appear in a log or an error. Errors from the user provisioner or user loader SHALL have any bcrypt-hash-shaped text redacted before they are logged or returned. The documentation SHALL state:
- that the application's password authentication must use the same bcrypt encoder;
- that a hash mapped only at provisioning keeps accepting a password the user later retires at the provider, unless claim mirroring is enabled.

#### Scenario: Hash mapped at provisioning
- **WHEN** the password-hash claim path for `corp` is `credentials.password_hash`, a bcrypt encoder is supplied, and an unlinked identity presents a cost-12 bcrypt hash there
- **THEN** the user is provisioned with exactly that hash

#### Scenario: Plaintext refused
- **WHEN** the mapped claim carries `hunter2`
- **THEN** the user is provisioned without a password hash
- **AND** the log record does not contain `hunter2`

#### Scenario: Cost outside the band
- **WHEN** the mapped claim carries a well-formed bcrypt hash at cost 31 with the default band
- **THEN** no password hash is written
- **AND** a warning names observed cost 31 and the band 10 to 15

#### Scenario: Consumer widens the band
- **WHEN** the cost band is configured as 4 to 15 and the mapped claim carries a cost-4 bcrypt hash
- **THEN** the hash is accepted

#### Scenario: Encoder does not produce bcrypt
- **WHEN** a password-hash claim is mapped and the supplied password encoder produces Argon2id hashes
- **THEN** construction fails with a configuration error

#### Scenario: Hash mapped into the display name
- **WHEN** provider `corp` maps both its display-name claim and its password-hash claim to `credentials.password_hash`
- **THEN** construction fails with a configuration error

### Requirement: Claim mirroring refreshes mapped fields on later logins through an update
A consumer SHALL be able to enable claim mirroring per provider. It is off by default. With mirroring enabled, every login that resolves through a link SHALL first resolve the provider's mapped display-name and password-hash claims under the same rules as provisioning. When at least one mapped field resolves to a value that differs from the stored value, the library SHALL amend the user through the user provisioner's update operation of the `identity-model` capability. The update SHALL name only the mapped fields that resolved. When nothing resolves, or nothing differs, no update SHALL be made.

After a successful update, the principal for that login SHALL carry the mirrored values for the mirrored fields only. Every other field SHALL keep the value loaded before the update, whatever the update returned.

A failed update, or an update that returns no user, SHALL be logged at error level with any hash-shaped text redacted. It SHALL NOT fail the login, which proceeds with the values loaded before the update.

Construction SHALL fail with a configuration error when mirroring is enabled for a provider:
- without a user provisioner; or
- with neither a display-name nor a password-hash claim path.

Mirroring SHALL never change roles, which only role sync derives. The documentation SHALL state:
- that a provider which re-hashes the password on every token produces a write on every login and should not be mirrored;
- that a mirrored credential is not revoked by disabling the user at the provider.

#### Scenario: Changed hash is refreshed
- **WHEN** mirroring and a password-hash claim are enabled for `corp`, a linked user's stored hash is `H1`, and a login presents an accepted hash `H2`
- **THEN** the user is updated naming only the password hash `H2`

#### Scenario: Unchanged claims write nothing
- **WHEN** mirroring is enabled for `corp` and a login presents a display name and hash equal to the stored ones
- **THEN** no update is made

#### Scenario: Update failure does not fail the login
- **WHEN** mirroring is enabled for `corp`, the mapped display name changed, and the update fails because the store is unavailable
- **THEN** the login succeeds with the previously stored display name
- **AND** an error is logged

#### Scenario: Partial update result does not strip roles
- **WHEN** a mirrored update succeeds but the provisioner returns details with no roles, for a user whose loaded details hold role `editor`
- **THEN** the principal for that login still holds role `editor`

#### Scenario: Mirroring off by default
- **WHEN** a password-hash claim is mapped for `corp` without mirroring, and a linked user logs in with a different accepted hash
- **THEN** no update is made

#### Scenario: Mirroring without a claim path
- **WHEN** mirroring is enabled for `corp` with a user provisioner but no display-name or password-hash claim path
- **THEN** construction fails with a configuration error naming `corp`

### Requirement: Roles can be derived from a claim path at provisioning
By default a provisioned user SHALL receive the single default role the consumer configured, or no role when none is configured. A consumer SHALL be able to configure a dotted role claim path for a provider, which SHALL resolve through nested objects to a string or an array of strings. When a path is configured, the provisioned user's roles SHALL be the values at that path. They SHALL NOT fall back to the default role, even when the path is empty or resolves to nothing. A path that resolves to any other type SHALL yield no roles and a sampled log record, and SHALL NOT fail the login.

A consumer SHALL be able to configure, per provider:
- a role mapping from claim values to local role names, under which values with no entry are dropped;
- a role allowlist of local names, under which any other name is dropped, including the default role.

A mapping or allowlist configured with no entries SHALL drop every role. Matching SHALL be exact and case-sensitive.

#### Scenario: No claim path
- **WHEN** a user is provisioned through `corp` with default role `member` and no role claim path
- **THEN** the user is created with role `member`

#### Scenario: Nested claim path
- **WHEN** the role claim path for `corp` is `realm_access.roles` and the ID token carries `{"realm_access": {"roles": ["editor", "viewer"]}}`
- **THEN** the user is created with roles `editor` and `viewer`

#### Scenario: Explicitly empty claim path
- **WHEN** the role claim path for `corp` is configured as empty and the default role is `member`
- **THEN** the user is created with no role

#### Scenario: Self-assigned administrative role
- **WHEN** the role allowlist for `corp` is `editor` and `viewer`, and the claim path yields `admin` and `viewer`
- **THEN** the user is created with role `viewer` only

#### Scenario: Unmapped value is dropped
- **WHEN** the role mapping for `corp` maps `corp-editors` to `editor`, and the claim path yields `corp-editors` and `corp-admins`
- **THEN** the user is created with role `editor` only

### Requirement: Role sync applies claim-derived roles to each login without persisting them
A consumer SHALL be able to enable role sync for a provider. With role sync enabled, every login through that provider SHALL derive roles from the claim path, applying the provider's mapping and allowlist. The derived roles SHALL replace the user's stored roles on the principal the callback produces, carrying only each role's name and the primary position. They SHALL NOT be written to the user store, and the next login SHALL derive them again.

Construction SHALL fail with a configuration error when:
- role sync is enabled for a provider without a non-empty role claim path;
- role sync is enabled while the login is conveyed by the handoff code rather than by a consumer callback success handler, because redemption rebuilds the principal from stored roles and would silently drop the synced ones.

The documentation SHALL state that a provider misconfiguration removes roles from every federated user of that provider on their next login.

#### Scenario: Synced roles reach the consumer's conveyance
- **WHEN** role sync is enabled for `corp` with a callback success handler, user `u-1` has stored role `viewer`, and a login's claim path yields `editor`
- **THEN** the handler receives a principal with role `editor` and not `viewer`
- **AND** `u-1`'s stored roles are still `viewer`

#### Scenario: Stored super role does not survive sync
- **WHEN** role sync is enabled for `corp`, user `u-1` holds `admin` as a super role, and a login's claim path yields `admin`
- **THEN** the principal's `admin` role is not a super role

#### Scenario: Role sync with the handoff conveyance
- **WHEN** role sync is enabled for `corp` and no callback success handler is configured
- **THEN** construction fails with a configuration error naming `corp`

#### Scenario: Role sync without a claim path
- **WHEN** role sync is enabled for `corp` and no role claim path is configured for `corp`
- **THEN** construction fails with a configuration error naming `corp`

### Requirement: The library does not interpret claims it was not told to read
The library SHALL read only the claims its verification and provisioning need, plus the claim paths the consumer configured. The claims it needs are issuer, subject, audience, authorized party, times, nonce, session id, email and email verified. Claim values SHALL NOT be written to logs or placed in error text. A logged username or email SHALL be redacted to its domain.

A consumer broker SHALL be able to replace the library's linking, provisioning and mirroring entirely. It SHALL receive the verified identity with all its claims unchanged, and its result SHALL be used as the login's principal.

#### Scenario: Consumer broker
- **WHEN** a consumer broker is configured and a callback verifies an identity whose token carries claim `department` `R&D`
- **THEN** the broker receives the identity with claim `department` equal to `R&D`
- **AND** the library's link store and provisioner are not called
