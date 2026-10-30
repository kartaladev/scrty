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
