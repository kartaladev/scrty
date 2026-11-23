# oidc-provider-device-authorization Specification

## Purpose

Lets a client on a device without a usable browser, such as a command-line application on a headless machine, obtain a user's authorization through the OAuth 2.0 Device Authorization Grant (RFC 8628). The user enters a short code in a browser elsewhere, signs in and consents there, and the device collects its tokens at the token endpoint.

## Requirements

### Requirement: The device grant is enabled for the provider by the consumer
The device grant SHALL be off by default. A consumer SHALL enable it for the provider with an option naming the consumer's code-entry page. That page SHALL be an absolute URI on the issuer's origin. Another origin, or a URI with a fragment or user information, SHALL fail construction. So SHALL a URI that holds whitespace, a control character, invalid UTF-8 or a malformed query, or whose query already carries `user_code` or `result`. The error SHALL NOT repeat the URI.

#### Scenario: A provider built without the option serves no device grant
- **WHEN** the provider is built without enabling the device grant
- **THEN** no device authorization or code-entry endpoint is served
- **AND** the metadata names neither the endpoint nor the grant type

#### Scenario: A code-entry page on another origin fails construction
- **WHEN** the consumer enables the device grant with a code-entry page on another origin than the issuer
- **THEN** building the provider fails with a configuration error naming the option

#### Scenario: A code-entry page whose query carries the user code fails construction
- **WHEN** the consumer enables the device grant with a code-entry page whose query already has a `user_code` parameter
- **THEN** building the provider fails with a configuration error naming the option and `user_code`

### Requirement: The device authorization endpoint accepts a form POST over TLS
The device authorization endpoint SHALL accept only POST requests with a form-encoded body, over TLS as the chain reports the connection, unless the provider was built with the loopback issuer. A repeated parameter SHALL make the request invalid, a parameter without a value SHALL be treated as omitted, and an unknown parameter SHALL be ignored.

#### Scenario: A GET is refused
- **WHEN** a client sends a GET to the device authorization endpoint
- **THEN** the request is refused, and nothing is issued

#### Scenario: A repeated scope is invalid
- **WHEN** a request carries `scope` twice
- **THEN** it is answered with `invalid_request`, and nothing is issued

### Requirement: A device authorization request authenticates the client as the token endpoint does
A confidential client SHALL authenticate by its registered method, as at the token endpoint, and a public client SHALL name its `client_id`. A client credential in the query SHALL be refused with `invalid_request`. A failed authentication SHALL be answered with `invalid_client`, and nothing SHALL be issued.

#### Scenario: A confidential client with a wrong secret
- **WHEN** a confidential client sends a device authorization request with a wrong secret
- **THEN** it is answered with `invalid_client`, and no device code or user code is issued

#### Scenario: A public client names itself
- **WHEN** a public client registered for the device grant sends `client_id` and no credential
- **THEN** the request proceeds to scope validation

### Requirement: Only a client registered for the device grant may start one
A client not registered for the device-code grant SHALL be answered with `unauthorized_client`, and nothing SHALL be issued.

#### Scenario: A code-flow-only client asks for a device code
- **WHEN** a client registered only for `authorization_code` sends a device authorization request
- **THEN** it is answered with `unauthorized_client`

### Requirement: Requested scopes and resources are limited as at the authorization endpoint
A device authorization request's `scope` and `resource` values SHALL be validated by the authorization endpoint's rules: scopes the client may not ask for SHALL be answered with `invalid_scope`, and resources with `invalid_target`. A scope including `openid` SHALL make the request an OpenID Connect request. Strings SHALL be bounded as at the authorization endpoint.

#### Scenario: A scope the client may not ask for
- **WHEN** a request names a scope outside the client's allowed scopes
- **THEN** it is answered with `invalid_scope`, and nothing is issued

#### Scenario: A NUL byte in a parameter
- **WHEN** a request carries a parameter holding a NUL byte or invalid UTF-8
- **THEN** it is answered with `invalid_request` without echoing the value, and nothing is issued

### Requirement: A successful device authorization response carries the codes and how to use them
A successful response SHALL be 200 with a JSON body holding `device_code`, `user_code`, `verification_uri` (the code-entry page), `expires_in` and `interval`, with `Cache-Control: no-store`. It SHALL add `verification_uri_complete` only for a client registered for it. Error responses SHALL use the token endpoint's error body.

#### Scenario: A default response
- **WHEN** a public client registered for the device grant sends a valid request
- **THEN** the answer is 200 with `device_code`, `user_code`, `verification_uri`, `expires_in` 600 and `interval` 5
- **AND** it carries no `verification_uri_complete`

#### Scenario: A client registered for the complete URI
- **WHEN** a client registered for `verification_uri_complete` sends a valid request
- **THEN** the answer also carries `verification_uri_complete`: the code-entry page with the user code as its `user_code` parameter

### Requirement: Device codes are high-entropy and kept only as digests
A device code SHALL carry at least 128 bits from a cryptographically secure source, and SHALL be stored only as a digest. No device code or user code SHALL appear in a log line, an error's text or a security event.

#### Scenario: The store holds no clear code
- **WHEN** a device authorization is issued
- **THEN** the stored record holds the digests of its device code and user code, and neither code in clear

### Requirement: User codes follow a typeable default format
By default a user code SHALL be 8 characters drawn uniformly from `BCDFGHJKLMNPQRSTVWXZ`, shown as two groups of four joined by a dash. A consumer MAY replace the alphabet and length. A format allowing fewer than 2^29 distinct codes, or an alphabet with a repeated character or a non-printable one, SHALL fail construction.

#### Scenario: The default format
- **WHEN** a device authorization is issued with the default format
- **THEN** its user code matches `^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`

#### Scenario: A consumer's digit format
- **WHEN** the consumer sets a 9-digit format
- **THEN** user codes are 9 digits, shown in groups of three joined by dashes

#### Scenario: Too weak a format
- **WHEN** the consumer sets a 6-digit format
- **THEN** building the provider fails with a configuration error naming the option

### Requirement: User codes are stored under a keyed digest
A user code SHALL be stored only as a digest keyed with a secret the provider holds, so that a copy of the store does not let the codes be recovered by trying every possible code. By default the key SHALL come from a cryptographically secure source when the provider is built. A consumer MAY supply a stable key, and SHALL supply one with a durable device authorization store, or construction SHALL fail.

#### Scenario: A durable store without a key
- **WHEN** the consumer enables the device grant with a durable device authorization store and supplies no user-code key
- **THEN** building the provider fails with a configuration error naming the option

#### Scenario: Two replicas sharing a key
- **WHEN** two providers share a durable store and a user-code key, and a code issued by one is entered at the other
- **THEN** the code is found and claimed

#### Scenario: A key shorter than 32 bytes
- **WHEN** the consumer supplies a user-code key shorter than 32 bytes
- **THEN** building the provider fails with a configuration error naming the option

### Requirement: A user code is unique among live device authorizations
A new user code SHALL differ from every unexpired device authorization's user code. A collision SHALL be retried with a fresh code a bounded number of times, and exhausting the bound SHALL fail the request as a server error, issuing nothing.

#### Scenario: A collision is retried
- **WHEN** the first generated user code collides with a live one
- **THEN** a fresh code is generated, and the response carries the fresh one

#### Scenario: Collisions exhaust the bound
- **WHEN** every attempt within the bound collides
- **THEN** the request fails as a server error, and nothing is stored

### Requirement: The device authorization lifetime and polling interval are bounded
A device authorization SHALL expire 600 seconds after issue by default, and the polling interval SHALL be 5 seconds by default. A consumer MAY set the lifetime between 60 seconds and 30 minutes, and the interval between 1 and 60 seconds and below the lifetime. Any other value SHALL fail construction. An interval that is no whole number of seconds SHALL be answered rounded up to whole seconds, while polls are paced by the interval as set.

#### Scenario: A consumer's lifetime
- **WHEN** the consumer sets the lifetime to 15 minutes
- **THEN** responses carry `expires_in` 900, and the authorization expires 900 seconds after issue

#### Scenario: A lifetime past the bound
- **WHEN** the consumer sets the lifetime to 1 hour
- **THEN** building the provider fails with a configuration error naming the option

#### Scenario: An interval that is no whole number of seconds
- **WHEN** the consumer sets the interval to 1.5 seconds, and a device polls every `interval` seconds as answered
- **THEN** responses carry `interval` 2, and the device is never answered `slow_down`

### Requirement: An entered user code is normalised before it is compared
An entered user code SHALL be compared after removing whitespace and dashes and converting to upper case, when the format's alphabet has no lower-case letters. A code with any other character outside the alphabet, or of the wrong length after normalisation, SHALL be answered as an invalid code.

#### Scenario: Lower case with a space
- **WHEN** the user enters `bcdf ghjk` for the user code `BCDF-GHJK`
- **THEN** the code is accepted

#### Scenario: A character outside the alphabet
- **WHEN** the user enters a code containing the vowel `A`
- **THEN** it is answered as an invalid code

### Requirement: Invalid user codes all get one answer
An unknown, expired, already-claimed, denied or exchanged user code SHALL be answered with the same refusal, in the same response shape, so that the answer reveals nothing about which codes exist. The refusal SHALL be an error the consumer's page can recognise and render.

#### Scenario: An expired code and an unknown code
- **WHEN** the user enters an expired user code, and then a code never issued
- **THEN** both are answered with the same invalid-code refusal

### Requirement: Failed user-code entries are throttled per source
The provider SHALL throttle failed user-code entries per source, by default 5 failures per source in 10 minutes. A throttled source SHALL be refused before the code is looked up. The throttle SHALL apply to the chain's endpoint and to the consumer-callable entry alike. A consumer MAY replace the limiter or its rate.

#### Scenario: The sixth failure is throttled
- **WHEN** one source has entered 5 invalid user codes within 10 minutes and enters a sixth code, valid or not
- **THEN** it is refused as throttled, and the code is not looked up

#### Scenario: A concurrent burst does not exceed the limit
- **WHEN** one source sends more concurrent entries of wrong codes than its limit allows
- **THEN** no more of them are looked up than the limit allows, and the rest are refused as throttled

#### Scenario: The consumer's own entry handler is throttled too
- **WHEN** the consumer's handler passes the same source to the provider's entry call after 5 failures
- **THEN** the call is refused as throttled

#### Scenario: A consumer's limiter
- **WHEN** the consumer supplies its own limiter for user-code entry
- **THEN** the provider asks that limiter, and not the default, whether a source may enter a code

### Requirement: A user code is claimed by the first browser that enters it
A valid user code entered by a browser SHALL be claimed for that browser by one conditional write, and a pending request bound to that browser's flow cookie SHALL be parked for it. Of concurrent entries of one code, exactly one SHALL claim it. A later entry by another browser SHALL be answered as an invalid code. A re-entry by the claiming browser, even a concurrent one, SHALL be handed off again, not refused.

#### Scenario: Two browsers enter one code at once
- **WHEN** two browsers enter the same valid user code concurrently
- **THEN** exactly one claims it, and the other is answered as an invalid code

#### Scenario: The claiming browser enters it again
- **WHEN** the browser that claimed a code enters it again before it expires
- **THEN** it is handed off again, to the consent page when its browser session holds a sign-in, otherwise to the login page

#### Scenario: The store applies a claim but reports a failure
- **WHEN** the device store records a claim and then answers with an error
- **THEN** the entry fails as a dependency error that still carries the browser's flow secret, and the browser's re-entry reaches its claim

#### Scenario: The claiming browser submits twice at once
- **WHEN** one browser enters a valid user code twice concurrently, with the same flow cookie
- **THEN** neither entry is answered as an invalid code, and no failure is charged to the throttle

### Requirement: Code entry hands off to the consumer's login and consent pages
After a claim, the browser SHALL be sent with status 303 to the consumer's login page with the pending request's handle, or to the consent page when a valid browser session already holds a sign-in. The login stage SHALL follow the authorization endpoint's rules for resuming with a complete sign-in of a known, enabled user.

#### Scenario: No browser session
- **WHEN** a browser without a browser session claims a user code
- **THEN** it is redirected with 303 to the login page carrying the handle

#### Scenario: A browser session exists
- **WHEN** a browser holding a valid browser session claims a user code
- **THEN** it is redirected with 303 to the consent page carrying the handle

### Requirement: The code-entry endpoint follows the flow cookie rules
The code-entry endpoint SHALL accept GET with `user_code` and form POST. A form POST without a flow cookie SHALL NOT mint one, and SHALL be answered with 303 to the same endpoint carrying the code in the query, as the authorization endpoint answers. The endpoint SHALL require TLS as the authorization endpoint does.

#### Scenario: A cross-site POST without the cookie
- **WHEN** a form POST with a user code arrives without a flow cookie
- **THEN** it is answered with 303 to the code-entry endpoint carrying the code, and no cookie is set

### Requirement: The consumer's own handler can enter a user code
The provider SHALL offer a call that takes an entered user code, the browser's flow secret and the source, and answers where the browser goes next and the flow secret to set. It SHALL apply the same normalisation, throttle, claim and handoff as the chain's endpoint, which SHALL use it.

#### Scenario: A consumer handler enters a valid code
- **WHEN** the consumer's handler calls the entry with a valid user code, no flow secret and the request's source
- **THEN** it receives the login page location with a handle, and a flow secret to set as the cookie

### Requirement: The consumer's pages see a device request as such
The pending-request view of a device request SHALL say that it comes from a device authorization, and SHALL carry the user code as issued, the time the device asked, the client's identifier and name, and the scopes asked for. It SHALL carry no device code, handle or flow secret.

#### Scenario: The consent page reads a device request
- **WHEN** the consent page reads the pending request of a claimed user code
- **THEN** the view marks it as a device request and shows the user code, the request time, the client and the scopes

### Requirement: Approval and denial are recorded on the device authorization
When consent is given, the device authorization SHALL become approved by one conditional write, holding the user, the granted scopes and the sign-in that approved it. When consent is denied, it SHALL become denied. Neither SHALL happen after the authorization expires.

#### Scenario: The user approves part of the scopes
- **WHEN** the user approves `openid` but not `offline_access`
- **THEN** the authorization is approved with `openid` alone

#### Scenario: Approval after expiry
- **WHEN** consent is given after the device authorization has expired
- **THEN** the authorization stays unapproved, and the consent answer reports it as expired

### Requirement: The flow ends on the code-entry page with its outcome
After approval or denial, or when the authorization expired while the user was signing in, the resume SHALL answer with the code-entry page carrying `result` set to `approved`, `denied` or `expired`, and nothing else from the request.

#### Scenario: The user approves
- **WHEN** the user approves a device request at the consent page
- **THEN** the resume answers `redirect_to` as the code-entry page with `result=approved`

### Requirement: Device authorizations are swept after they expire
Expired device authorizations SHALL be removed by the provider's expiry tasks. A record SHALL be judged expired by the provider's clock, never the store's.

#### Scenario: The sweep removes an expired record
- **WHEN** the expiry task runs after a device authorization's expiry
- **THEN** the record is removed, and its user code can be issued again

### Requirement: The device authorization lifecycle is reported as security events
The provider SHALL emit security events when a device authorization is issued, claimed, approved, denied and exchanged, when a spent device code is presented again, and when user-code entry is throttled. Each event SHALL name the client and, once known, the user, and SHALL carry no code.

#### Scenario: A denial is reported
- **WHEN** the user denies a device request
- **THEN** a denial event is emitted naming the client and the user, with no device code or user code
