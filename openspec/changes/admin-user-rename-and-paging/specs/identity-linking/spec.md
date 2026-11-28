# Spec Delta

## MODIFIED Requirements

### Requirement: Link store contract
A link store SHALL:
- find a link by provider, issuer and subject, reporting "link not found" when none matches;
- insert a link, refusing with a "link exists" outcome when a link for the same provider, issuer and subject exists, even when the new link is identical, and leaving the stored link unchanged;
- delete every link for a user reference, returning how many were removed;
- list every link that names a user reference;
- remove one link, identified by its link identifier and its provider, issuer and subject together.

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
- **THEN** every link lookup, insert, listing and removal is served by that store

### Requirement: A link store can remove one link
A link store SHALL remove one stored link, identified by its link identifier and its provider, issuer and subject together, and report whether it removed one. It SHALL NOT remove any other link.

#### Scenario: Removing one of a user's links
- **WHEN** links from `corp` subject `s-1` and `partner` subject `p-1` both name `u-7`, and the `corp` link is removed by its identifier and external identity
- **THEN** the `partner` link to `u-7` remains, and the removal reports one link removed

#### Scenario: Identifier and identity disagree
- **WHEN** a removal names the identifier of the `corp` link with the subject `s-2`
- **THEN** nothing is removed and the removal reports none

### Requirement: A link store can list a user's links
A link store SHALL list every link that names a user reference, returning the links with their stored fields byte for byte, and an empty list for a user with none.

#### Scenario: Listing a user's links
- **WHEN** links from `corp` subjects `s-1` and `s-2` and from `partner` subject `p-1` name `u-7`, and one link names `u-8`
- **THEN** listing `u-7`'s links returns the three links naming `u-7` and not the one naming `u-8`

#### Scenario: User with no links
- **WHEN** no link names `u-9`
- **THEN** listing `u-9`'s links returns an empty list and no error

### Requirement: Sign-in hook wiring mistakes fail at construction
Building the broker SHALL fail with a configuration error when a sign-in hook has no function or no provider name, or shares its provider with just-in-time provisioning, claim mirroring or role sync (two writers of one user's data). A hook naming a provider the login manager does not register SHALL fail the manager's construction.

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
- **WHEN** provider `corp` has a sign-in hook over a consumer's link store, and several links per user are not allowed
- **THEN** the broker is built, and the one-link rule lists and removes links through that store

#### Scenario: Hook for an unregistered provider
- **WHEN** a sign-in hook names `ghost` and the login manager registers only `corp`
- **THEN** building the login manager fails with a configuration error naming `ghost`
