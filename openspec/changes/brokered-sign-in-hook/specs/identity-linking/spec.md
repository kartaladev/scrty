# Spec Delta

## MODIFIED Requirements

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

## ADDED Requirements

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
A decision error that is the unlinked-identity or refused-provisioning outcome SHALL fail the login as that authentication failure. Any other decision or apply error, and a decision naming no user, SHALL fail the login as a broker failure, and SHALL NOT be reported as any other library outcome it wraps. Before an error reaches the caller or a log, the library SHALL scrub the identity's subject and email and the upstream access token from its text.

#### Scenario: Consumer refuses an inactive account
- **WHEN** the hook returns the unlinked-identity outcome because the consumer's account is inactive
- **THEN** the login fails as an unlinked identity and is reported as an authentication failure

#### Scenario: Hook failure
- **WHEN** the hook returns an error that is neither refusal outcome
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
