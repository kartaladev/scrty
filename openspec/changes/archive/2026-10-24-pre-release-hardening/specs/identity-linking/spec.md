# Spec Delta

## MODIFIED Requirements

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

#### Scenario: Unicode look-alike of an allowed domain
- **WHEN** the allowlist for `corp` is `kartala.id` and a verified identity presents `bob@Kartala.id`, with the Kelvin sign in place of `k`
- **THEN** the login fails as an authentication failure and no user is created

#### Scenario: Empty allowlist
- **WHEN** an allowlist with no entries is configured for `corp`
- **THEN** every unlinked identity from `corp` is refused

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
