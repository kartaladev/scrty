# Spec Delta

## MODIFIED Requirements

### Requirement: The redemption endpoint refuses a redeemer that skipped or discarded checks
The redemption endpoint SHALL accept a replaceable redeemer. After a redeemer reports success, the endpoint SHALL refuse the request with a policy-denied reason when the policy check it supplied never ran, or ran and denied, or when the redeemer returns a user other than the one that check decided on: a different user reference, or a password-change time not equal to the one the check saw. In that case it SHALL establish no session and issue no token. The login completion step SHALL reuse the post-authentication decision that check made, before the link was spent, rather than evaluating the post-authentication policies again after the link is spent, so a policy lookup failure never spends the link.

#### Scenario: A consumer that runs the check, discards the deny and succeeds is refused
- **WHEN** the endpoint is configured with a consumer redeemer that runs the supplied policy check, receives a deny, ignores it and reports success
- **THEN** the request is refused with the policy's deny reason
- **AND** no session is established and no token is issued

#### Scenario: A consumer that never runs the checks is refused
- **WHEN** the endpoint is configured with a consumer redeemer that reports success without running the supplied checks, and no policy is registered
- **THEN** the request is refused with the generic policy-denied reason
- **AND** no session is established

#### Scenario: A consumer that returns another user is refused
- **WHEN** the endpoint is configured with a consumer redeemer that runs the supplied check for user `u-1` and reports success for user `u-2`
- **THEN** the request is refused with the generic policy-denied reason
- **AND** no session is established and no token is issued

#### Scenario: The same user reloaded is not refused
- **WHEN** a consumer redeemer runs the supplied check for `u-1` and reports success for `u-1` reloaded, with the same password-change instant in another time zone
- **THEN** the redemption completes as the check decided

#### Scenario: A policy lookup failure does not spend the link
- **WHEN** the second-factor challenge policy's enrolment lookup fails while a valid link is redeemed, and the link is redeemed again after the lookup recovers
- **THEN** the first redemption is refused and establishes no session
- **AND** the second redemption completes
