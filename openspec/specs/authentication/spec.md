# authentication Specification

## Purpose

Resolves the credentials a caller presents to an authenticated principal through ordered, replaceable providers. Every failure reads the same to the caller, so authentication cannot be used to learn which accounts exist or which are inactive.

## Requirements

### Requirement: Authentication is delegated to ordered providers
The authentication manager SHALL offer presented credentials to its providers in the order they were configured. A provider that does not handle the presented kind of credentials SHALL be skipped. The first provider that handles them SHALL decide the outcome, success or failure, and no later provider SHALL be consulted.

#### Scenario: First handling provider decides
- **WHEN** a manager is configured with a token provider and then a password provider, and username-and-password credentials are presented
- **THEN** the token provider is skipped
- **AND** the password provider's outcome is returned

#### Scenario: A failing provider is not retried by a later one
- **WHEN** two providers both handle password credentials and the first reports a failure
- **THEN** the manager returns that failure
- **AND** the second provider is not consulted

#### Scenario: Consumer-supplied provider
- **WHEN** a consumer configures a provider of their own that handles a custom kind of credentials, and those credentials are presented
- **THEN** that provider's outcome is returned exactly as it decided it

### Requirement: No eligible provider is reported as such
When every provider skips the presented credentials, the manager SHALL return a no-eligible-provider error.

#### Scenario: Unsupported credentials
- **WHEN** credentials of a kind no configured provider handles are presented
- **THEN** the no-eligible-provider error is returned

### Requirement: Construction refuses a meaningless provider list
Constructing an authentication manager with no providers, or with any absent provider (including an interface holding a nil value), SHALL fail with a configuration error.

#### Scenario: No providers
- **WHEN** a manager is constructed with no providers
- **THEN** construction fails with a configuration error

#### Scenario: Absent provider in the list
- **WHEN** a manager is constructed with a valid provider and an absent one
- **THEN** construction fails with a configuration error

### Requirement: Identity ports have no silent defaults
A component that needs a user loader, role loader, user provisioner or MFA requirement lookup SHALL NOT substitute an in-memory or empty implementation when none is supplied. When the component cannot work without the port, it SHALL fail at construction with a configuration error naming the port. A component SHALL load users, privileges and the MFA requirement only through the supplied port.

#### Scenario: Missing user loader
- **WHEN** a component that requires a user loader is constructed without one
- **THEN** construction returns a configuration error naming the user loader

#### Scenario: Consumer implementation
- **WHEN** a consumer supplies their own user loader backed by their user table
- **THEN** the component loads users only through it

#### Scenario: No substituted default
- **WHEN** a component that requires a user loader is constructed without one
- **THEN** it does not fall back to an in-memory or empty user store

### Requirement: A success without a principal is a failure
When a deciding provider reports no error but returns no result, or a result without a principal, the manager SHALL return the uniform authentication failure rather than a success.

#### Scenario: Provider returns nothing
- **WHEN** a deciding provider returns neither an error nor a result
- **THEN** the manager returns the uniform authentication failure

#### Scenario: Provider returns a result with no principal
- **WHEN** a deciding provider returns a result whose principal is absent, and no error
- **THEN** the manager returns the uniform authentication failure

### Requirement: Password authentication does not reveal why it failed
The username-and-password provider SHALL return the same uniform failure, with no distinguishing error, in all of these cases:
- an unknown username;
- a wrong password;
- a correct password for an inactive account;
- a failure to load the user.

The account's active state SHALL be checked only after the password has been verified. A user-load failure other than "not found" SHALL be logged at error level. Constructing the provider without a user loader SHALL fail with a configuration error.

#### Scenario: Unknown user
- **WHEN** a username that does not exist is presented
- **THEN** the uniform authentication failure is returned

#### Scenario: Wrong password
- **WHEN** an existing, active username is presented with a wrong password
- **THEN** the uniform authentication failure is returned

#### Scenario: Inactive account
- **WHEN** an inactive account's username is presented with its correct password
- **THEN** the uniform authentication failure is returned, indistinguishable from the scenarios above

#### Scenario: User store unavailable
- **WHEN** the user loader returns a connection error
- **THEN** the uniform authentication failure is returned
- **AND** an error-level record naming the connection error is logged

### Requirement: An unknown user costs the same password work as a known one
When loading the user fails, the password provider SHALL still perform a full password verification against a reference hash that the configured password encoder produced at construction. Construction SHALL fail if that reference hash cannot be produced. When no encoder is configured, the default password encoder SHALL be used.

#### Scenario: Default encoder
- **WHEN** a provider built without an encoder receives an unknown username
- **THEN** the default encoder performs one full verification before the failure is returned

#### Scenario: Consumer-supplied encoder
- **WHEN** a provider is built with a consumer's password encoder and receives an unknown username
- **THEN** that encoder performs one full verification against a hash it produced itself

#### Scenario: Reference hash cannot be produced
- **WHEN** the configured encoder fails to produce a hash at construction
- **THEN** construction fails with that error

### Requirement: Presented secrets are wiped after a successful authentication
After a provider authenticates credentials successfully, it SHALL clear the secret those credentials hold before returning the result.

#### Scenario: Wiped on success
- **WHEN** a correct password is presented
- **THEN** the credentials in the result no longer hold the password

### Requirement: A successful authentication describes itself
A successful authentication SHALL carry:
- a unique authentication identifier;
- the presented credentials, already wiped;
- the resolved principal;
- the time it occurred;
- for password authentication, the time the user's password was last changed, as reported by the user loader (the zero time when unknown).

The password hash SHALL never be part of the result.

#### Scenario: Password success
- **WHEN** a correct password is presented for an active user
- **THEN** the result carries a fresh identifier, the user's principal, the current time and the loader's password-changed time

#### Scenario: Consumer identifier generator
- **WHEN** the provider is configured with a consumer's identifier generator
- **THEN** the result's identifier is the one that generator returned

### Requirement: Bearer tokens are authenticated by a verifier
The bearer-token provider SHALL delegate token verification to the configured token verifier, and SHALL build the principal only from the verified claims. A verification error SHALL be returned as an error that matches both the uniform authentication failure and the verifier's error. The result's identifier SHALL be the token's identifier. Constructing the provider without a verifier SHALL fail with a configuration error.

#### Scenario: Valid token
- **WHEN** a token the verifier accepts, with subject `ada`, is presented
- **THEN** the result's principal is built from subject `ada`

#### Scenario: Rejected token
- **WHEN** the verifier rejects a token as expired
- **THEN** the returned error matches the uniform authentication failure and the verifier's expiry error

#### Scenario: Missing verifier
- **WHEN** a bearer-token provider is constructed without a verifier
- **THEN** construction fails with a configuration error

### Requirement: Authentication refusal logs are bounded and never carry the password
The password provider SHALL write its refusal log records through the log sampler: one record per refusal reason per window, with a reporter so every suppressed record is counted. Log records SHALL NOT contain the submitted password, and SHALL NOT contain the submitted username unless the consumer opts in by an option whose documentation states that users type email addresses, and sometimes passwords, into that field. A user loader failure SHALL be recorded as the diagnostic-redaction capability requires, without its text. The default window SHALL be one minute, configurable by an option that governs only the password provider's logs. A window of zero or less SHALL log every refusal.

#### Scenario: Default sampling
- **WHEN** 50 unknown-username attempts arrive within one minute
- **THEN** one refusal record is written for that minute
- **AND** the 49 suppressed attempts are reported when the key ages out or the provider's logs are flushed

#### Scenario: Consumer disables sampling
- **WHEN** the provider is configured with a log interval of zero and 50 unknown-username attempts arrive
- **THEN** 50 refusal records are written

#### Scenario: Username withheld by default
- **WHEN** an unknown username `alice@example.com` is refused
- **THEN** the refusal record names the reason and does not contain `alice@example.com`

#### Scenario: Consumer opts in
- **WHEN** the provider is configured to include usernames and an unknown username `alice` is refused
- **THEN** the refusal record contains `alice`

### Requirement: The authentication result can travel with a request
The library SHALL provide a way to attach a successful authentication to a request context and read it back. Reading a context with no authentication attached SHALL report that none is present.

#### Scenario: Round trip
- **WHEN** a successful authentication is attached to a context and read back
- **THEN** the same authentication is returned

#### Scenario: Nothing attached
- **WHEN** a context with no authentication is read
- **THEN** the read reports that no authentication is present
