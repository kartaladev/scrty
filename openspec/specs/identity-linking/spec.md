# identity-linking Specification

## Purpose

Maps a verified external identity to an internal user without letting one identity claim another's account. It covers the link key and link store contract, how linked users are resolved, gated just-in-time provisioning through the create-only user provisioner, claim mirroring on later logins, and roles derived from provider claims.

## Requirements

### Requirement: Links are keyed by provider, issuer and subject, never by email
A link SHALL associate one external identity with one internal user. The identity is the provider name, the verified issuer and the verified subject. The user is recorded by the user reference and the username that existed when the link was created, which is empty for a user a sign-in hook provisions. Resolving an external identity SHALL use exactly the provider, issuer and subject. The library SHALL NOT use an email address, a username or any other claim to find a link or to match an existing internal user. A consumer's sign-in hook MAY decide by any rule, email included, which user an identity with no link belongs to; the library then links that user by provider, issuer and subject, and later logins resolve through the link alone. A link SHALL record the email as presented by the provider, without normalization, for operator visibility only.

#### Scenario: Same email at an attacker's provider
- **WHEN** user `u-1` is linked to subject `s-1` at issuer `https://corp.example` with email `alice@corp.example`, and a verified identity with subject `s-2` at issuer `https://social.example` presents email `alice@corp.example`
- **THEN** the second identity does not resolve to `u-1`

#### Scenario: Same subject at another issuer
- **WHEN** user `u-1` is linked to subject `12345` at issuer `https://a.example`, and a verified identity with subject `12345` at issuer `https://b.example` logs in
- **THEN** the identity does not resolve to `u-1`

#### Scenario: Consumer hook matches by email
- **WHEN** a sign-in hook for `corp` decides that the unlinked identity with subject `s-1` and email `alice@corp.example` belongs to user `u-1`, found by that email
- **THEN** a link from `corp`, the verified issuer and `s-1` to `u-1` is stored, and a later login of `s-1` resolves through that link without the hook's email rule

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
When a link exists for a verified identity, the library SHALL load the user by the link's user reference through the user loader, never by the link's username. The login SHALL succeed only when:
- the loader returns details whose user reference equals the link's user reference exactly; and
- the user is enabled.

A "user not found" result, no details, a user reference that differs from the link's, and a disabled user SHALL each fail the login as an authentication failure, with the same outcome as an unlinked identity. A loader failure other than "user not found" SHALL be returned as an error that is not an authentication failure. A missing user loader or link store SHALL fail construction with a configuration error naming the missing port.

#### Scenario: Dangling link
- **WHEN** a link names user reference `u-1` and the user loader reports "user not found" for `u-1`
- **THEN** the login fails as an authentication failure, not as a server error

#### Scenario: Recycled username
- **WHEN** a link was created for user reference `u-1` with username `alice`, `u-1` was deleted, and a different user `u-2` now holds username `alice`
- **THEN** the login fails as an authentication failure
- **AND** the user loader is never asked for username `alice`

#### Scenario: Non-conforming loader returns another user
- **WHEN** a link names user reference `u-1` and the loader, asked for `u-1`, returns details for `u-2`
- **THEN** the login fails as an authentication failure

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
- the domain part of the email SHALL exactly match an entry, compared ignoring ASCII letter case only, so a character that matches an ASCII letter only under Unicode case folding never matches it;
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

#### Scenario: Unicode look-alike of an allowed domain
- **WHEN** the allowlist for `corp` is `kartala.id` and a verified identity presents `bob@Kartala.id`, with the Kelvin sign in place of `k`
- **THEN** the login fails as an authentication failure and no user is created

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
- **THEN** construction fails with a configuration error that is identifiable as a missing port and names the user provisioner

### Requirement: A password hash can be mapped from a claim only in a verifiable, bounded form
A consumer SHALL be able to map a dotted claim path to the user's stored password hash for a provider. It is off by default. The mapped value SHALL be accepted only when it is a well-formed bcrypt hash whose cost factor, read from the hash itself, lies within the accepted cost band. The band SHALL be 10 to 15 inclusive by default, and the consumer SHALL be able to replace it with any band from 4 up to the bcrypt record ceiling of 16, so that no accepted hash is one password matching would refuse. Any other value, and a value that is absent or not a string, SHALL be ignored: nothing is written, and the login is not failed.

An ignored value SHALL be logged without the value. The log SHALL say whether the value was not a bcrypt hash, or had a cost outside the band, naming the observed cost and the band. It SHALL be at warning level the first time each reason occurs for a provider in a process, and at debug level afterwards.

Construction SHALL fail with a configuration error when:
- a password-hash claim is mapped for any provider and no password encoder is supplied;
- the supplied encoder's own output is not a bcrypt hash;
- the cost band is outside 4 to 16, or its minimum exceeds its maximum;
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

#### Scenario: Band beyond the record ceiling
- **WHEN** the cost band is configured as 10 to 20
- **THEN** construction fails with a configuration error

### Requirement: Claim mirroring refreshes mapped fields on later logins through an update
A consumer SHALL be able to enable claim mirroring per provider. It is off by default. With mirroring enabled, every login that resolves through a link SHALL first resolve the provider's mapped display-name and password-hash claims under the same rules as provisioning. When at least one mapped field resolves to a value that differs from the stored value, the library SHALL amend the user through the user provisioner's update operation of the `identity-model` capability. The update SHALL name only the mapped fields that resolved to a value differing from the stored one, and "named" SHALL mean exactly what that capability reports as the fields a caller named. When nothing resolves, or nothing differs, no update SHALL be made.

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

### Requirement: A consumer sign-in hook decides which user a provider's identity belongs to
A consumer SHALL be able to set a sign-in hook for a provider. It is off by default and applies to that provider only. On every login through it, after the ID token is verified, the hook SHALL receive the verified identity, the upstream access of the `oidc-login` capability, and the user the identity is already linked to, or none. It SHALL return a decision naming one user and an optional apply step, or an error. The decision SHALL change no stored data by itself.

#### Scenario: Default has no hook
- **WHEN** no sign-in hook is set for provider `corp` and a verified identity with no link logs in, with provisioning off
- **THEN** the login fails as an unlinked identity, as without this change

#### Scenario: Hook sees the existing link
- **WHEN** a sign-in hook is set for `corp` and an identity linked to `u-7` logs in
- **THEN** the hook receives `u-7` as the linked user

#### Scenario: Hook is per provider
- **WHEN** a sign-in hook is set for `corp` and an identity logs in through provider `partner`
- **THEN** the hook is not called

#### Scenario: No upstream access
- **WHEN** a sign-in hook is set for `corp` and the broker is asked to resolve a `corp` identity without upstream access
- **THEN** the login fails as a broker failure and the hook is not called

### Requirement: A hook decision is accepted before its apply step runs
After the hook decides, for a decision that does not provision a new user, the library SHALL check that the decision names a user, no link names another user, the user loads with that reference and is active, and, unless allowed, the user has no other link from that provider and issuer. It SHALL then insert any missing link and confirm it. Only then SHALL it run the apply step, load the user again, require it still active, and resolve the login through the link.

#### Scenario: Imported account adopted on first login
- **WHEN** the hook decides `u-7` with an apply step that stores a password hash, and no link exists for the identity or for `u-7`
- **THEN** the apply step runs once, a link from the identity to `u-7` is stored, the login resolves to `u-7`, and no other user is created

#### Scenario: Later login refreshes through the link
- **WHEN** the identity is linked to `u-7` and the hook decides `u-7` with an apply step
- **THEN** the apply step runs, no link is inserted, and the login resolves to `u-7`

#### Scenario: Inactive user
- **WHEN** the hook decides `u-7` and `u-7` loads as disabled
- **THEN** the login fails as an unlinked identity and the apply step does not run

#### Scenario: Hook names a missing user
- **WHEN** the hook decides `u-404` and the loader reports no such user
- **THEN** the login fails as an unlinked identity and the apply step does not run

#### Scenario: Apply step deactivates the user
- **WHEN** the hook decides `u-7`, which is active, and its apply step leaves `u-7` disabled
- **THEN** the login fails as an unlinked identity, and the link to `u-7` remains for later logins

#### Scenario: Concurrent first logins
- **WHEN** two first logins of the same identity race, both decide `u-7`, and one link insert finds the other's link to `u-7`
- **THEN** exactly one link exists and both logins resolve to `u-7`

### Requirement: A hook can provision a new user, linked before it is created
A decision SHALL be able to provision a user reference that does not exist yet, through an apply step that creates it. The library SHALL insert and confirm the link to that reference, with the same conflict re-read and one-link checks as any other decision, before it runs the apply step. It SHALL then load the user, require it to exist, match and be active, and resolve the login through the link. A provisioned user's link SHALL record an empty username.

#### Scenario: New user provisioned on first login
- **WHEN** the hook decides to provision `u-new`, which does not exist, with an apply step that creates it, and no link exists for the identity
- **THEN** a link from the identity to `u-new` is stored before the apply step runs, the apply step runs once, and the login resolves to `u-new`

#### Scenario: Apply step does not create the user
- **WHEN** the hook decides to provision `u-new`, the link is stored, and the apply step fails or returns without creating `u-new`
- **THEN** the login fails as a broker failure, and the link to `u-new` remains

#### Scenario: Provisioning resumed on a later login
- **WHEN** the identity is linked to `u-new`, `u-new` does not exist, and the hook decides to provision `u-new` again with an apply step that creates it
- **THEN** no link is inserted, the apply step runs, and the login resolves to `u-new`

#### Scenario: Provisioning resumed after another provider linked the user
- **WHEN** the identity is linked to `u-new`, `u-new` exists and is active, another provider's identity has since been linked to `u-new`, and the hook decides to provision `u-new` again
- **THEN** the apply step runs and the login resolves to `u-new`

#### Scenario: Concurrent first logins both provision
- **WHEN** two first logins of the same identity race, one decides to provision `u-a` and the other `u-b`, and the insert for `u-b` finds the link to `u-a`
- **THEN** exactly one link exists, naming `u-a`; the login that decided `u-b` fails as an unlinked identity and its apply step does not run, so `u-b` is never created

### Requirement: A provisioning decision never adopts an existing user
Before anything is written, the library SHALL refuse a provisioning decision as an unlinked identity when the named user loads and the identity's link does not name it, and as a broker failure when the decision has no apply step.

#### Scenario: Provisioning names an existing user
- **WHEN** the hook decides to provision `u-7`, which exists, and no link of the identity names `u-7`
- **THEN** the login fails as an unlinked identity, the apply step does not run, and no link is stored

#### Scenario: Provisioning without an apply step
- **WHEN** the hook decides to provision `u-new` with no apply step
- **THEN** the login fails as a broker failure and no link is stored

### Requirement: A hook cannot re-point an existing link
When a link exists for the identity and names a user other than the decision's, the library SHALL refuse the login as an unlinked identity, SHALL NOT run the apply step, SHALL leave the link unchanged, and SHALL log a warning naming the provider but neither user reference. The same SHALL hold when a concurrent insert leaves a link to another user.

#### Scenario: Hook disagrees with the link
- **WHEN** a link maps the identity to `u-7` and the hook decides `u-9` with an apply step
- **THEN** the login fails as an unlinked identity, the apply step does not run, `u-9` is unchanged, the link still names `u-7`, and a warning is logged

#### Scenario: Race lost to another user
- **WHEN** the hook decides `u-9`, the insert finds a link created meanwhile, and that link names `u-7`
- **THEN** the login fails as an unlinked identity and the link still names `u-7`

### Requirement: A hooked provider links each user at most once by default
By default, the library SHALL refuse, as an unlinked identity and before the apply step, a decision that would link a second identity of the same provider and issuer to a user. A link that an insert makes while another identity of that provider and issuer links the same user SHALL be removed again and the login refused. A consumer SHALL be able to allow several such links per user for a provider.

#### Scenario: Second subject for an already linked user
- **WHEN** `s-1` at `https://corp.example` is linked to `u-7` and the hook decides `u-7` for `s-2` at the same issuer
- **THEN** the login fails as an unlinked identity, the apply step does not run, and no link for `s-2` exists

#### Scenario: Consumer allows several links
- **WHEN** the consumer allows several links per user for `corp`, `s-1` is linked to `u-7`, and the hook decides `u-7` for `s-2`
- **THEN** a link for `s-2` to `u-7` is stored and the login resolves to `u-7`

#### Scenario: User already holding two links
- **WHEN** several links per user are not allowed for `corp`, `s-1` and `s-2` at `https://corp.example` are both linked to `u-7`, and `s-1` logs in
- **THEN** the login fails as an unlinked identity, the apply step does not run, and both links remain

#### Scenario: Two new subjects race for one user
- **WHEN** `s-1` and `s-2` at the same issuer both decide `u-7` concurrently, neither linked before
- **THEN** at most one link to `u-7` from that issuer remains, every login whose link was removed fails as an unlinked identity, and no refused login's apply step runs

### Requirement: A link store can remove one link
A link store SHALL be able to remove one stored link, identified by its link identifier and its provider, issuer and subject together, as an optional capability beside the link store contract, and report whether it removed one. It SHALL NOT remove any other link. Every link store the library ships SHALL provide it. A hooked provider that refuses several links per user SHALL require it.

#### Scenario: Removing one of a user's links
- **WHEN** links from `corp` subject `s-1` and `partner` subject `p-1` both name `u-7`, and the `corp` link is removed by its identifier and external identity
- **THEN** the `partner` link to `u-7` remains, and the removal reports one link removed

#### Scenario: Identifier and identity disagree
- **WHEN** a removal names the identifier of the `corp` link with the subject `s-2`
- **THEN** nothing is removed and the removal reports none

### Requirement: A link store can list a user's links
A link store SHALL be able to list every link that names a user reference, as an optional capability beside the link store contract. Every link store the library ships SHALL provide it, returning the links with their stored fields byte for byte, and an empty list for a user with none.

#### Scenario: Listing a user's links
- **WHEN** links from `corp` subjects `s-1` and `s-2` and from `partner` subject `p-1` name `u-7`, and one link names `u-8`
- **THEN** listing `u-7`'s links returns the three links naming `u-7` and not the one naming `u-8`

#### Scenario: User with no links
- **WHEN** no link names `u-9`
- **THEN** listing `u-9`'s links returns an empty list and no error

### Requirement: Hook refusals and failures are reported like the broker's own
A decision error that is the unlinked-identity or refused-provisioning outcome SHALL fail the login as that authentication failure. A decision error that is the UserInfo-failure outcome SHALL fail the login as that provider failure. Any other decision or apply error, and a decision naming no user, SHALL fail the login as a broker failure, and SHALL NOT be reported as any other library outcome it wraps. Each outcome passed through SHALL carry none of the hook's own error. Before an error reaches the caller or a log, the library SHALL scrub the identity's subject and email and the upstream access token from its text.

#### Scenario: Consumer refuses an inactive account
- **WHEN** the hook returns the unlinked-identity outcome because the consumer's account is inactive
- **THEN** the login fails as an unlinked identity and is reported as an authentication failure

#### Scenario: UserInfo outage inside the hook
- **WHEN** the hook reads the upstream UserInfo, the provider's UserInfo endpoint cannot be reached, and the hook returns that error
- **THEN** the login fails as a UserInfo failure, and the returned error carries none of the hook's text

#### Scenario: Hook failure
- **WHEN** the hook returns an error that is neither refusal outcome nor the UserInfo-failure outcome
- **THEN** the login fails as a broker failure and no link is inserted

#### Scenario: Apply step failure
- **WHEN** the decision is accepted and its apply step returns an error
- **THEN** the login fails as a broker failure, and the link to the decided user remains for later logins

#### Scenario: Wrapped library outcome
- **WHEN** the hook returns an error wrapping the provider-failure outcome
- **THEN** the login fails as a broker failure, not as a provider failure

#### Scenario: Secrets scrubbed from the error
- **WHEN** the hook returns an error whose text contains the identity's email and the upstream access token
- **THEN** neither the returned error's text nor any log record contains either

### Requirement: Sign-in hook wiring mistakes fail at construction
Building the broker SHALL fail with a configuration error when a sign-in hook has no function or no provider name, shares its provider with just-in-time provisioning, claim mirroring or role sync (two writers of one user's data), or sits over a link store that cannot list a user's links or remove one link while several links per user are not allowed. A hook naming a provider the login manager does not register SHALL fail the manager's construction.

#### Scenario: Hook and provisioning on one provider
- **WHEN** provider `corp` has a sign-in hook and just-in-time provisioning
- **THEN** building the broker fails with a configuration error naming `corp`

#### Scenario: Hook and claim mirroring on one provider
- **WHEN** provider `corp` has a sign-in hook and claim mirroring
- **THEN** building the broker fails with a configuration error naming `corp`

#### Scenario: Hook and role sync on one provider
- **WHEN** provider `corp` has a sign-in hook and role sync
- **THEN** building the broker fails with a configuration error naming `corp`

#### Scenario: Hook and provisioning on different providers
- **WHEN** provider `corp` has a sign-in hook and provider `partner` has just-in-time provisioning
- **THEN** the broker is built

#### Scenario: Link store that cannot list
- **WHEN** provider `corp` has a sign-in hook and the consumer's link store cannot list a user's links
- **THEN** building the broker fails with a configuration error, and succeeds once several links per user are allowed for `corp`

#### Scenario: Hook for an unregistered provider
- **WHEN** a sign-in hook names `ghost` and the login manager registers only `corp`
- **THEN** building the login manager fails with a configuration error naming `ghost`

### Requirement: A hooked provider refuses options the hooked login never applies
Building the broker SHALL fail with a configuration error naming the provider when a hooked provider also has a name, password or role claim, a role mapping, an allowed-role list, or a just-in-time sub-option, because the hooked login never applies them. The same options on a provider without a hook SHALL be accepted.

#### Scenario: Hook and role allowlist on one provider
- **WHEN** provider `corp` has a sign-in hook and an allowed-role list
- **THEN** building the broker fails with a configuration error naming `corp`
