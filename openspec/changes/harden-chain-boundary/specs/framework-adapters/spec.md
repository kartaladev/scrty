# Spec Delta

## ADDED Requirements

### Requirement: Every adapter refuses a path its router could resolve differently
The net/http, gin and fiber integrations SHALL refuse a request whose path holds a dot segment, sent as is or percent-encoded, before the chain decides anything about it, with the same 400 on all three. This SHALL hold whatever the framework's routing configuration, including fiber's escaped-path decoding. The shared conformance suite SHALL send such paths over a real connection, so no client or test transport cleans them first.

#### Scenario: fiber parent segment
- **WHEN** a fiber application's rules permit `/public` and deny `/admin`, and a client sends `GET /public/../admin/users` as written
- **THEN** the chain answers 400 and the `/admin/users` handler does not run

#### Scenario: fiber with escaped-path decoding
- **WHEN** fiber decodes escaped paths and a client sends `GET /public%2F..%2Fadmin/users`
- **THEN** the chain answers 400 and the `/admin/users` handler does not run

#### Scenario: Same answer on every framework
- **WHEN** the same request for `/x/%2e%2e/y` is sent through net/http, gin and fiber
- **THEN** all three answer 400 with no body by default

### Requirement: A chain mounted twice on one framework runs once
Each adapter SHALL hand on the request context the chain ran on, so that when one chain is mounted both at the application and at a route group of the same framework, it runs once per request.

#### Scenario: gin application and group
- **WHEN** one chain is used by a gin engine and by one of its route groups, and a request with valid Basic credentials reaches a route in that group
- **THEN** the credentials are verified once

#### Scenario: fiber application and group
- **WHEN** one chain is used by a fiber application and by one of its groups, and a request with valid Basic credentials reaches a route in that group
- **THEN** the credentials are verified once
