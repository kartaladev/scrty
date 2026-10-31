# Spec Delta

## MODIFIED Requirements

### Requirement: Saved-code presentations are throttled per user
The library SHALL count failed saved-code presentations per user reference, whether in a recovery or in a confirmation. It SHALL refuse further presentations for a user at the limit with a throttled error, without looking the code up. The limit SHALL hold under concurrent presentations: each presentation SHALL be charged against the user's limit atomically before its code is looked up, and the charge SHALL be refunded when the code is valid, so that no burst of concurrent presentations for one user has more codes looked up than the limit allows. The default SHALL be 5 failures per 15 minutes. A consumer SHALL be able to replace the limiter. A limiter that cannot decide SHALL cause the presentation to be refused. Recording a failure SHALL NOT be abandoned because the caller went away.

#### Scenario: Guessing codes
- **WHEN** five wrong codes are presented for `u-1` within 15 minutes and then a valid one is presented
- **THEN** the valid one is refused with the throttled error

#### Scenario: A client that hangs up is still charged
- **WHEN** a wrong code is presented and the request's context is already cancelled
- **THEN** the failure is still recorded against that user

#### Scenario: Consumer limiter
- **WHEN** saved-code presentation is configured with a consumer's shared limiter
- **THEN** every check and failure goes to that limiter, keyed by user reference

#### Scenario: A concurrent burst stays within the limit
- **WHEN** twenty wrong codes for `u-1` are presented concurrently, with the default limit of 5 per 15 minutes
- **THEN** no more than five of them are looked up, and the rest are refused with the throttled error

#### Scenario: A valid code spends no allowance
- **WHEN** a valid code is presented for `u-1` and four wrong codes follow within 15 minutes
- **THEN** a fifth wrong code is still looked up

## ADDED Requirements

### Requirement: An unavailable user store is not a failed recovery proof
When a recovery's password proof receives the authentication capability's unavailable error, the recovery SHALL be refused with that error, which the public status mapping answers as a refused proof is. It SHALL be counted against the request's source, and SHALL NOT be counted against the user's recovery limit, because no password was compared.

#### Scenario: Outage during a recovery's password proof
- **WHEN** the user store returns a connection error while a recovery for `u-1` checks its password proof
- **THEN** the recovery is refused with the unavailable error and answered 401, as a refused proof is
- **AND** one failure is counted against the source and nothing against `u-1`'s recovery limit

### Requirement: A client that leaves during the proof's user load is charged to its source only
When a recovery's password proof receives the uniform failure for a load the request's own context ended, the recovery SHALL be refused as a failed proof and counted against the request's source as any refusal after the codes passed is, so the consumer's choice not to count those refusals applies to it, but SHALL NOT be counted against the user's recovery limit, because no password was compared.

#### Scenario: A client hangs up during the password proof
- **WHEN** a recovery for `u-1` has passed its codes, the request's context is cancelled, and the user loader fails with that cancellation during the password proof
- **THEN** the recovery is refused as a failed proof
- **AND** one failure is counted against the source and none against `u-1`'s recovery limit

### Requirement: A recovery's user lookup answers an outage as an unknown user
When a recovery cannot load its user for a reason other than "not found", and the request's own context did not end the load, the recovery SHALL be refused with the authentication capability's unavailable error, answered as a recovery for an unknown user is, and counted once against the request's source.

#### Scenario: Known and unknown users answer a partial outage alike
- **WHEN** the user store fails to load `u-1` and has no user `u-2`, and a recovery is completed for each
- **THEN** both are answered 401 with the same headers, and each is counted once against the source
