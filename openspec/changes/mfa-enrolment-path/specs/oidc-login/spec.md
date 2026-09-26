## MODIFIED Requirements

### Requirement: OIDC logins are exempt from local MFA by default, as a stated limit
By default, a login established through OIDC SHALL be classified as exempt from the local MFA challenge and MFA requirement, per the first-factor classification of the `identity-model` and `security-policy` capabilities. The library SHALL NOT read the provider's authentication method or assurance claims to decide this. This exemption SHALL be documented as a limit: the application trusts the provider's own authentication strength entirely. A consumer SHALL be able to remove the exemption through that classification, after which OIDC logins are evaluated by the MFA policies like any other login. Removing it SHALL require the second-factor challenge to be wired, as the chain already requires of any policy that can raise one.

With the exemption removed, a required user with no usable enrolment SHALL enter the MFA enrolment path only when the consumer has also added OIDC to that path's allowlist, as the `security-policy` capability defines; OIDC is off it by default.

#### Scenario: Default exemption
- **WHEN** a user required to use MFA logs in through OIDC with the default classification
- **THEN** the redemption creates a session without an MFA challenge

#### Scenario: Consumer removes the exemption
- **WHEN** the consumer's classification makes OIDC non-exempt and a user required to use MFA with no enrolment redeems a code
- **THEN** redemption is refused with the enrolment-required reason
- **AND** the code is not consumed

#### Scenario: Consumer removes the exemption and admits OIDC to the enrolment path
- **WHEN** the consumer's classification makes OIDC non-exempt, the enrolment path is on with OIDC on its allowlist, and a user required to use MFA with no enrolment redeems a code
- **THEN** the code is consumed and a session is created in the enrolment-pending state
- **AND** the response is the enrolment challenge outcome
