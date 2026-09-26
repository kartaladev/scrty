## ADDED Requirements

### Requirement: Every adapter reads a form field with the same precedence
Reading a form field through the framework-neutral request abstraction SHALL look in the posted form first and fall back to the URL query, on every adapter the library provides. A consumer interceptor that reads a field SHALL therefore get the same value on net/http, gin and fiber. The abstraction's documentation SHALL state the precedence, and that the library's own credential reads never take the query.

#### Scenario: Body and query both carry the field
- **WHEN** a consumer interceptor reads field `x` from a POST whose body carries `x=body` and whose query carries `x=query`
- **THEN** it reads `body` on net/http, gin and fiber

#### Scenario: Only the query carries the field
- **WHEN** a consumer interceptor reads field `x` from a POST whose body lacks it and whose query carries `x=query`
- **THEN** it reads `query` on every adapter
