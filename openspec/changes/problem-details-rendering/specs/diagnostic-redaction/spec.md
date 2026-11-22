## MODIFIED Requirements

### Requirement: Returned errors caused by a dependency carry fixed library text
Where a library interceptor, guard or manager returns an error caused by a consumer-supplied dependency, the returned error's text SHALL be fixed library text.
- The library error it stands for, and the dependency's original error, SHALL stay reachable by error identity and type, so the status it maps to and any consumer match are unchanged.
- Errors the consumer's own refusal checks, guards, authorizers and rule sets return SHALL be returned unchanged, as their own capabilities require.
- Both rules hold for an error whose chain can be walked. A dependency's error whose chain cannot be walked is replaced by the library's fixed error, as the http-error-propagation capability requires. The original error is then neither reachable nor returned, and the status is the one the dependency's failure maps to.

#### Scenario: Session store outage at login
- **WHEN** a login's session creation fails with an error quoting the user reference `u-123`
- **THEN** the error reaching the consumer's error handler does not contain `u-123` in its text
- **AND** it matches the store's original error by identity, and maps to the same status as before

#### Scenario: Consumer check unchanged
- **WHEN** a consumer's magic-link refusal check returns its own `terms-not-accepted` error
- **THEN** the error returned is that error, text included

#### Scenario: Unwalkable store error at login
- **WHEN** a login's session creation fails with an error whose chain contains itself and quotes the user reference `u-123`
- **THEN** the error reaching the consumer's error handler does not contain `u-123`, does not match the store's error, and maps to the status a plain store failure maps to
