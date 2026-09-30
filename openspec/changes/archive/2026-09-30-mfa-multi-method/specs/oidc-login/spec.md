# Spec Delta

## MODIFIED Requirements

### Requirement: Handoff redemption is check-then-consume
The handoff redemption endpoint SHALL accept the code only in the body of a POST request, and SHALL ignore a code in the query string. Redemption SHALL proceed in this order:
1. validate the code: it is well formed, its record exists, its secret matches in constant time, and it has not expired;
2. resolve the account by the recorded user reference through the user loader, and refuse it unless the loaded details carry exactly that reference and the user is enabled;
3. run the refusal checks, including the post-authentication policy evaluation from the `security-policy` capability;
4. consume the code in one atomic operation, last.

An already-consumed record MAY be rejected before step 2, but that rejection SHALL NOT be what guarantees single use; only the atomic consume SHALL decide. A refusal or failure at step 2 or 3 SHALL leave the code redeemable until it expires. Refusal checks SHALL be documented as required to be side-effect free, because racing redemptions of one code can each run them. The login completion step SHALL reuse the post-authentication decision made at step 3, rather than evaluating the post-authentication policies again after the code is consumed, so a policy lookup failure never spends the code.

#### Scenario: Racing redemptions
- **WHEN** 8 requests redeem the same valid code at the same time
- **THEN** exactly one creates a session
- **AND** the other 7 receive the invalid-handoff outcome

#### Scenario: Code in the query string
- **WHEN** a POST to the redemption endpoint carries the code only in its query string
- **THEN** redemption is refused with the invalid-handoff outcome

#### Scenario: A policy lookup failure does not spend the code
- **WHEN** a consumer's classification removes the OIDC exemption, the second-factor challenge policy's enrolment lookup fails while a valid code is redeemed, and the code is redeemed again after the lookup recovers
- **THEN** the first redemption is refused and creates no session
- **AND** the second redemption completes

### Requirement: Policy decisions at redemption cannot be lost
When the post-authentication policy evaluation denies a redemption, redemption SHALL refuse without consuming the code. It SHALL return the policy's reason, or a policy-denied error when the policy gave no reason. A deny SHALL never result in a session. When the evaluation challenges, the code SHALL be consumed and a session SHALL be created pending that challenge, as the `sessions` and `security-policy` capabilities define. When the redemption operation is replaced by a consumer implementation, the endpoint SHALL refuse with the policy-denied error, and create no session, whenever the implementation reports success but:
- the policy evaluation never ran; or
- the evaluation denied; or
- the implementation returns a user other than the one the evaluation decided on: a different user reference, or a password-change time not equal to the one the evaluation saw.

#### Scenario: Deny with no reason
- **WHEN** a consumer policy denies a redemption without giving a reason
- **THEN** redemption fails with the policy-denied error
- **AND** no session is created
- **AND** the same code redeems successfully once the policy allows, before it expires

#### Scenario: Challenge redeems
- **WHEN** a consumer's first-factor classification removes the OIDC exemption and the user is enrolled in MFA
- **THEN** the code is consumed and a session is created pending the MFA challenge
- **AND** the response is the challenge outcome

#### Scenario: Implementation skips the checks
- **WHEN** a consumer redemption implementation returns success without running the refusal checks
- **THEN** the endpoint refuses with the policy-denied error and creates no session

#### Scenario: Implementation discards a deny
- **WHEN** a consumer redemption implementation runs the refusal checks, receives a deny, ignores it and returns success
- **THEN** the endpoint refuses with the policy-denied error and creates no session

#### Scenario: Implementation returns another user
- **WHEN** a consumer redemption implementation runs the refusal checks for user `u-1` and returns success for user `u-2`
- **THEN** the endpoint refuses with the policy-denied error and creates no session

#### Scenario: Implementation returns the same user reloaded
- **WHEN** a consumer redemption implementation runs the refusal checks for `u-1` and returns success for `u-1` reloaded, with the same password-change instant in another time zone
- **THEN** the redemption completes as the evaluation decided
