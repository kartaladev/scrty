# Spec Delta

## MODIFIED Requirements

### Requirement: The enrolment path is off unless enabled on both the policy and the chain
The enrolment path SHALL be off by default. With it off, a required user with no usable enrolment SHALL be refused exactly as before this capability offered a path. A consumer SHALL turn it on explicitly, on the MFA requirement policy and on the chain. Chain assembly SHALL fail with a configuration error when only one side is configured:
- the policy side is on and nothing registered enforces the enrolment challenge;
- the chain side is on and no registered policy can raise the enrolment challenge.

It SHALL also fail when the chain side is on and no MFA method is enabled, or no enabled method can enrol, or a method the consumer names for the path is not enabled or cannot enrol, or the consumer names an empty list. Every enrolment store SHALL record a device proof, so every method that can enrol can enrol through the path. The methods that can be enrolled through the path SHALL be, by default, every enabled MFA method that can enrol, and a consumer SHALL be able to narrow them by naming them; no method outside the verify endpoint's methods SHALL be enrolled through the path.

#### Scenario: Default is off
- **WHEN** MFA is required for all users, the path is not enabled, and a user who has never enrolled logs in by password with a correct password
- **THEN** the login is refused with the enrolment-required reason
- **AND** no session is established

#### Scenario: Consumer enables the path
- **WHEN** the consumer enables the path on both the policy and the chain, and the same user logs in by password
- **THEN** the login is refused with an enrolment challenge carrying a session and a token

#### Scenario: Policy side only
- **WHEN** the path is enabled on the MFA requirement policy and the chain has no enrolment interceptor
- **THEN** chain assembly fails with a configuration error naming the enrolment challenge

#### Scenario: Chain side only
- **WHEN** the enrolment interceptor is enabled and no registered policy can raise the enrolment challenge
- **THEN** chain assembly fails with a configuration error

#### Scenario: Method that cannot enrol
- **WHEN** the enrolment interceptor is enabled and no enabled MFA method can enrol
- **THEN** chain assembly fails with a configuration error

#### Scenario: Consumer names a method that cannot enrol
- **WHEN** TOTP and a consumer's method that cannot enrol are enabled, and the enrolment interceptor is told to enrol the consumer's method
- **THEN** chain assembly fails with a configuration error

#### Scenario: Store that cannot record a device proof
- **WHEN** the enrolment interceptor is enabled and the TOTP method's enrolment store is a consumer's store
- **THEN** chain assembly succeeds, and that store records the device proof of each enrolment through the path

### Requirement: MFA enrolments take part in the authenticator reset of a recovery
The library SHALL provide an authenticator kind for the recovery reset port over a set of MFA methods. It SHALL list, as the authenticators a user holds, the methods the user is enrolled on, and SHALL remove an enrolment through the method that holds it. Every MFA method SHALL be able to remove a user's enrolments. After removing, the kind SHALL read the user's enrolments again, and a method that still holds an enrolment SHALL fail the reset with an error, never report it removed. A failed enrolment lookup SHALL be returned as an error, never as holding nothing. An MFA method used as a proof in a recovery SHALL count as proven, so the default reset keeps it.

#### Scenario: Listing
- **WHEN** TOTP and `email-code` are configured and `u-1` is enrolled on TOTP only
- **THEN** the kind lists TOTP as held by `u-1`

#### Scenario: Method without a remover
- **WHEN** the kind is constructed over a consumer's MFA method and `u-1`'s enrolments are reset
- **THEN** construction succeeds, and the reset removes `u-1`'s enrolment through that method

#### Scenario: Method that does not remove
- **WHEN** a consumer's MFA method reports success removing `u-1`'s enrolment but `u-1` is still enrolled on it
- **THEN** the reset returns an error

#### Scenario: Lookup failure
- **WHEN** the TOTP enrolment lookup fails while `u-1`'s authenticators are listed
- **THEN** the listing returns an error
