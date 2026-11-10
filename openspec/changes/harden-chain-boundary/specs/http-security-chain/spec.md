# Spec Delta

## ADDED Requirements

### Requirement: A request path with a dot segment is refused before the chain runs
After client resolution and before any interceptor, the chain SHALL refuse with the malformed-request error (400) a request whose path, read as sent and again decoded once, holds a `.` or `..` segment, and one whose path does not decode. The refusal SHALL carry the security headers when that layer is enabled. Repeated slashes SHALL NOT be refused. There SHALL be no option to turn this off.

#### Scenario: Parent segment
- **WHEN** a request for `/public/../admin/users` reaches a chain whose rules permit `/public` and deny `/admin`
- **THEN** it is refused with 400 and neither the rules nor the handler run

#### Scenario: Encoded parent segment
- **WHEN** a request is sent for `/public/%2e%2e/admin/users` or `/public/%2E%2E/admin/users`
- **THEN** it is refused with 400

#### Scenario: Segments joined by an encoded slash
- **WHEN** a request is sent for `/public%2F..%2Fadmin/users`
- **THEN** it is refused with 400, because its decoded path holds a `..` segment

#### Scenario: Current-directory segment
- **WHEN** a request is sent for `/account/./delete` or `/account/%2e/delete`
- **THEN** it is refused with 400, so a route marked for the recovery cool-down cannot be reached by such a path

#### Scenario: Undecodable path
- **WHEN** a request path holds a percent sign not followed by two hexadecimal digits, through an adapter that passes such a path on
- **THEN** it is refused with 400

#### Scenario: Dots inside a segment
- **WHEN** a request is sent for `/files/report..v2.txt`, `/.well-known/jwks.json` or `/a//b`
- **THEN** it is not refused by this check

#### Scenario: Refusal carries the security headers
- **WHEN** security headers are enabled and a request for `/a/../b` is refused
- **THEN** the 400 response carries the layer's headers, as a refusal by client resolution does

#### Scenario: Refusal behind a trusted proxy
- **WHEN** security headers are enabled, a trusted proxy forwards a request as HTTPS, and the request for `/a/../b` is refused
- **THEN** the 400 response carries the headers sent only on secure responses

### Requirement: A session cannot be published once the gates have begun
Once a request has entered the first enabled gate, the chain SHALL refuse to publish a session through the consumer's publishing operation: the operation returns an error that matches the configuration error and publishes neither the caller nor the session. The gates are the recovery, enrolment, second-factor and password-change gates. The refusal SHALL hold while the gates run, and SHALL also apply to any chain run inside them.

#### Scenario: Authenticator after logout's slot
- **WHEN** the second-factor gate is enabled and a consumer interceptor registered after the logout slot publishes a session owing a second factor
- **THEN** publishing fails, the request is refused with a 500 and the handler does not run

#### Scenario: Authenticator between two gates
- **WHEN** a consumer interceptor registered immediately after the second-factor slot publishes a session owing a second factor, with the password-change gate also enabled
- **THEN** publishing fails and the handler does not run

#### Scenario: Slot-mate of the enrolment gate
- **WHEN** a consumer interceptor is registered at the enrolment gate's slot after the option enabling enrolment, and publishes an enrolment-only session
- **THEN** publishing fails and the handler does not run

#### Scenario: Authenticator at the bearer slot
- **WHEN** a consumer interceptor at the bearer token slot publishes a session owing a second factor
- **THEN** publishing succeeds and the second-factor gate refuses the request, as before

#### Scenario: No gate enabled
- **WHEN** no gate is enabled and a consumer interceptor after the logout slot publishes a live session
- **THEN** publishing succeeds and the handler reads the session

#### Scenario: Retried pass
- **WHEN** a gate is enabled and a consumer interceptor before the bearer token slot calls the rest of the chain twice, with an authenticator at the bearer token slot
- **THEN** the authenticator publishes on both passes

#### Scenario: Second chain inside the gates
- **WHEN** a chain with the second-factor gate mounts a different chain with no gates, through any adapter, and that chain's authenticator, the consumer's or a built-in one, publishes a session owing a second factor
- **THEN** publishing fails, the request is refused with a 500 and the handler does not run

#### Scenario: Gateless chain on its own
- **WHEN** a chain with no gates, not run inside another chain's gates, publishes a session at any slot
- **THEN** publishing succeeds

### Requirement: The authorization stage refuses a session owing a built-in challenge
The authorization stage SHALL refuse a request whose published session still owes a built-in challenge (recovery, enrolment, second factor or password change) whose gate the chain enables, with the error that gate would return, before the consumer's rules and the handler, whether or not rules are configured.

#### Scenario: Owing session reaches the stage
- **WHEN** a session owing a password change is published on a request that reaches the authorization stage
- **THEN** the request is refused with the password-change challenge error and the handler does not run

#### Scenario: Several challenges owed
- **WHEN** a session owing both a second factor and a password change reaches the stage on a chain enabling both gates
- **THEN** the request is refused with the second-factor challenge error, the gate that runs first

#### Scenario: Gate not enabled
- **WHEN** a session owing a second factor is published on a chain that does not enable the second-factor gate
- **THEN** the authorization stage does not refuse it for that challenge

#### Scenario: Full session
- **WHEN** a full session is published and the rules permit the request
- **THEN** the authorization stage lets it through

### Requirement: A chain entered again on a request it already ran on lets it through
When a chain is entered on a request whose context shows that the same chain already ran on it, the chain SHALL pass the request straight to what follows it, without running any interceptor, resolving the client or recording anything. A different chain entered on that request SHALL run in full.

#### Scenario: Mounted at the application and at a group
- **WHEN** one chain is mounted both at the application and at a route group, and a request with valid Basic credentials reaches a route in that group
- **THEN** the credentials are verified once and the attempt counters are touched once

#### Scenario: Two different chains
- **WHEN** two different chains are mounted one inside the other
- **THEN** both run on the request

### Requirement: Single-value chain options given twice fail at construction
Building a chain SHALL fail with a configuration error naming the option when the logger, the time source, the policy engine, the rate-limiter factory or the error handler is given more than once, whatever the values. The authorizer of the authorization option SHALL keep its documented rule, that the last call's authorizer is used, and each call's authorizer SHALL be checked, so an absent authorizer in any call fails construction.

#### Scenario: Two policy engines
- **WHEN** a chain is given two policy engines
- **THEN** construction fails naming the policy engine option, and no policy of either engine escapes the check that every challenge has an enforcer

#### Scenario: The same logger twice
- **WHEN** a chain is given the same logger twice
- **THEN** construction fails naming the logger option

#### Scenario: Earlier absent authorizer
- **WHEN** the authorization option is given first with an absent authorizer and then with a valid one
- **THEN** construction fails naming the authorization option and the authorizer

#### Scenario: Consumer replaces the authorizer
- **WHEN** the authorization option is given twice with two valid authorizers and a rule in each call
- **THEN** construction succeeds, both rules apply in call order, and the second authorizer judges them
