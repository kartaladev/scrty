## ADDED Requirements

### Requirement: Every adapter reads a form field with the same precedence
Reading a form field through the framework-neutral request abstraction SHALL look in the posted form first and fall back to the URL query, on every adapter the library provides. Only POST, PUT and PATCH requests carry a posted form; for any other method the field SHALL be read from the URL query alone. Reading a field SHALL NOT consume the body: reading the body before or after a form field SHALL return the same bytes. Reading a field SHALL NOT change the size limit a later body read applies, and each body read SHALL refuse a body longer than its own limit whatever an earlier read on the same request read or refused. The form read SHALL read at most 10 MiB of a URL-encoded body and 32 MiB of a multipart body; a larger body, an unparseable content type or an unparseable body SHALL be answered from the query. A consumer interceptor that reads a field SHALL therefore get the same value on net/http, gin and fiber. The abstraction's documentation SHALL state the precedence, and that the library's own credential reads never take the query, apart from the OIDC authorization response, whose `code` and `state` the protocol delivers in the query.

#### Scenario: Body and query both carry the field
- **WHEN** a consumer interceptor reads field `x` from a POST whose body carries `x=body` and whose query carries `x=query`
- **THEN** it reads `body` on net/http, gin and fiber

#### Scenario: Only the query carries the field
- **WHEN** a consumer interceptor reads field `x` from a POST whose body lacks it and whose query carries `x=query`
- **THEN** it reads `query` on every adapter

#### Scenario: Multipart body and query both carry the field
- **WHEN** a consumer interceptor reads field `x` from a POST whose multipart body carries `x=body` and whose query carries `x=query`
- **THEN** it reads `body` on net/http, gin and fiber

#### Scenario: A GET with a body reads the query
- **WHEN** a consumer interceptor reads field `x` from a GET whose body carries `x=body` and whose query carries `x=query`
- **THEN** it reads `query` on net/http, gin and fiber

#### Scenario: Reading a field leaves the body readable
- **WHEN** a consumer interceptor reads field `x` from a POST with a URL-encoded body and then reads the body
- **THEN** the body it reads is the full posted body on net/http, gin and fiber

#### Scenario: A field read does not widen a body limit
- **WHEN** a consumer interceptor reads a form field from a POST whose URL-encoded body is 8 KiB, and a library endpoint then reads the body with a 4 KiB limit
- **THEN** the endpoint's read is refused as too large on net/http, gin and fiber

#### Scenario: An oversized upload is left intact
- **WHEN** a consumer interceptor reads field `x` from a POST whose multipart body is larger than 32 MiB, and the handler then parses the upload
- **THEN** the interceptor reads the query's `x`, and the handler parses the whole upload

#### Scenario: An earlier, larger body read does not widen a later limit
- **WHEN** a consumer interceptor reads the body of an 8 KiB POST with a 64 KiB limit, and a library endpoint then reads it with a 4 KiB limit
- **THEN** the endpoint's read is refused as too large on net/http, gin and fiber
