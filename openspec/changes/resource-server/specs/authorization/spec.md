## ADDED Requirements

### Requirement: A scope refusal names the scopes it needed
A requirement for any of, or all of, a set of scopes SHALL refuse a caller that does not meet it with an error that is identifiable as access denied and as not granted, and that reports the scopes the requirement names and whether all or any were needed, so that a caller can be told which scopes to ask for. A refusal for no caller SHALL stay the anonymous refusal.

#### Scenario: Any of
- **WHEN** a requirement for any of `orders:write` refuses a caller holding `orders:read`
- **THEN** the error is access denied and not granted, and reports `orders:write` with "any"

#### Scenario: All of
- **WHEN** a requirement for all of `orders:read orders:export` refuses a caller holding `orders:read`
- **THEN** the error reports both scopes with "all"

#### Scenario: No caller
- **WHEN** the same requirement is judged with no caller
- **THEN** the error is the anonymous refusal and reports no scopes

#### Scenario: Inside a composite requirement
- **WHEN** a requirement for all of "role `clerk`" and "any of `orders:write`" refuses a clerk holding `orders:read`
- **THEN** the refusal still reports `orders:write` with "any", found beneath the composite's error
