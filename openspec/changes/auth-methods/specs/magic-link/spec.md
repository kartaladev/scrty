## Purpose

Lets a user sign in by following a single-use link sent to their email address. Requesting a link reveals nothing about which addresses have accounts. A link authenticates only the user it was minted for, and a refused or failed redemption never costs the holder their link or gives an attacker free replays.

## ADDED Requirements

### Requirement: Requesting a link is uniform
Requesting a link for a submitted address SHALL produce the same result for the caller in every one of these cases:
- the address resolves to an active user and a link is sent;
- the address is unknown, or resolves to a disabled user;
- resolution fails;
- the user's issuance limit is reached;
- the random source or the token store fails;
- the message cannot be sent.

The request endpoint SHALL match only POST requests to its path. It SHALL always answer with the same status and the same body, and SHALL NOT pass the request to later handlers. A missing or malformed body SHALL be treated as an empty address. Each cause SHALL be logged server-side only.

#### Scenario: Known and unknown addresses look alike
- **WHEN** a link is requested for an active user's address and, separately, for an address with no account
- **THEN** both requests receive the same status, the same body and cookies with the same names and attributes

#### Scenario: Issuance limit reached
- **WHEN** a link is requested for a user who has reached the issuance limit
- **THEN** the caller receives the same result as for an unknown address
- **AND** no link is issued and no message is sent

#### Scenario: Malformed body
- **WHEN** a request with an unparsable body is posted to the request endpoint
- **THEN** it receives the same status and body as any other request

### Requirement: Addresses resolve to users through a replaceable resolver
By default, the submitted address SHALL be passed unchanged to the user loader as a username. A consumer SHALL be able to supply an address resolver, which SHALL then be the only way addresses are resolved. A link SHALL be issued only for a resolved user who is enabled.

#### Scenario: Default resolution
- **WHEN** a link is requested for ` Ada@Example.com` with default options
- **THEN** the user loader receives the username ` Ada@Example.com` unchanged

#### Scenario: Consumer resolver
- **WHEN** a consumer resolver maps `ada@example.com` to user `u-7`, and a link is requested for `ada@example.com`
- **THEN** a link is issued for `u-7`
- **AND** the user loader's load by username is not called

### Requirement: A link authenticates only the user it was minted for
A link SHALL record the user reference of the user it was issued for. Redemption SHALL load the user by that reference. It SHALL refuse the redemption when no user is found, when the user is disabled, or when the loaded user's reference differs from the recorded one. A username or address that later belongs to another user SHALL NOT let a link authenticate that other user.

#### Scenario: Username reissued
- **WHEN** a link is issued for user `u-1` with username `ada`, `u-1` is deleted, and username `ada` is given to new user `u-2`
- **THEN** redeeming the link is refused
- **AND** no session is established for `u-2`

#### Scenario: Loader returns a different user
- **WHEN** the user loader, asked for `u-1` during redemption, returns details for `u-9`
- **THEN** the redemption is refused

### Requirement: Link issuance is limited per user
The library SHALL NOT issue a link for a user who already has the issuance limit's number of links issued within the one-time-token issuance window. The default limit SHALL be 5, replaceable by an option. A limit below 1 SHALL fail construction with a configuration error.

#### Scenario: Default limit
- **WHEN** five links were issued for `u-1` in the last hour and a sixth is requested
- **THEN** no sixth link is issued

#### Scenario: Consumer limit
- **WHEN** the limit is configured as 2, two links were issued for `u-1` in the last hour, and a third is requested
- **THEN** no third link is issued

### Requirement: Links are absolute and point at the configured confirmation page
Construction SHALL fail with a configuration error when no link base URL is given, or when the base URL is not absolute `https`. The one exception is `http` on a loopback host, which SHALL be accepted. The emailed link SHALL be the base URL joined with the confirmation path, and SHALL carry the token and the sanitised redirect target, both query-escaped.

#### Scenario: Missing base URL
- **WHEN** a magic-link manager is constructed without a link base URL
- **THEN** construction fails with a configuration error

#### Scenario: Cleartext base URL
- **WHEN** a manager is constructed with base URL `http://app.example.com`
- **THEN** construction fails with a configuration error

#### Scenario: Local development
- **WHEN** a manager is constructed with base URL `http://localhost:3000`
- **THEN** construction succeeds

### Requirement: The sign-in message is neutral and replaceable
By default, the message SHALL contain the link, SHALL say that it expires shortly and can be used once, and SHALL name no product, brand or organisation. A consumer SHALL be able to supply a renderer that receives the link and the redirect target, and returns the message. Whatever the renderer returns, the recipient SHALL be the submitted address.

#### Scenario: Default content
- **WHEN** a link is sent with the default renderer
- **THEN** the message body contains the link
- **AND** contains no product or organisation name

#### Scenario: Consumer renderer
- **WHEN** a consumer renderer returns subject `Sign in to Payroll` and sets the recipient to `other@example.com`
- **THEN** the message is sent with subject `Sign in to Payroll` to the submitted address

### Requirement: Delivery time does not reveal whether an account exists
A magic-link manager SHALL require a sender that declares it does not wait for delivery. Construction with a sender that does not declare this SHALL fail with a configuration error, unless the consumer explicitly accepts synchronous delivery. The documentation of that option SHALL state that response time then reveals which addresses have accounts.

#### Scenario: Synchronous sender refused
- **WHEN** a manager is constructed with the SMTP sender directly
- **THEN** construction fails with a configuration error

#### Scenario: Queued sender accepted
- **WHEN** a manager is constructed with the queued sender wrapping the SMTP sender
- **THEN** construction succeeds

#### Scenario: Consumer accepts synchronous delivery
- **WHEN** a manager is constructed with the SMTP sender directly and the option accepting synchronous delivery
- **THEN** construction succeeds

### Requirement: Redemption checks everything before it consumes
Redeeming a link SHALL proceed in this order:
1. check the token;
2. resolve the user;
3. evaluate the post-authentication policy phase, with the `magic-link` first factor and the user's password-change time;
4. run the consumer's refusal checks in order;
5. consume the token atomically, last.

A failure or refusal at any step before the last SHALL leave the link redeemable until it expires. The link SHALL be spent only by a redemption that goes on to succeed. Of racing redemptions of one link, at most one SHALL succeed.

#### Scenario: Refused, then fixed, then redeemed
- **WHEN** a link is redeemed while a policy denies the user because they must enrol in MFA, the user then enrols, and the same link is redeemed again
- **THEN** the first redemption is refused with the enrolment-required reason
- **AND** the second redemption succeeds

#### Scenario: Transient user lookup failure
- **WHEN** the user loader fails with a connection error during redemption, and the same link is redeemed after the loader recovers
- **THEN** the first redemption fails
- **AND** the second succeeds

#### Scenario: Racing redemptions
- **WHEN** 16 requests redeem the same valid link at the same time
- **THEN** exactly one succeeds and establishes a session

### Requirement: Consumer refusal checks are returned unchanged
A consumer SHALL be able to supply refusal checks, each receiving the resolved principal and the user's password-change time. The first check that returns an error SHALL stop redemption. Its error SHALL be returned unchanged, and later checks SHALL NOT run. Checks SHALL be documented as required to have no side effects, because each of several racing redemptions of one link may run them.

#### Scenario: Consumer sentinel
- **WHEN** a consumer check returns the consumer's `terms-not-accepted` error
- **THEN** redemption returns an error matching `terms-not-accepted`
- **AND** the link stays redeemable

### Requirement: Policy decisions are honoured at redemption
A deny from the post-authentication phase SHALL refuse the redemption with the deny's reason. A deny without a reason SHALL still refuse, with a generic policy-denied reason. A challenge SHALL NOT refuse. The link SHALL be redeemed, the session SHALL be created with that challenge pending, and a challenge error SHALL propagate to the consumer.

#### Scenario: Challenge still redeems
- **WHEN** a link is redeemed for a user enrolled on an authenticator-app method, and the policy challenges for MFA
- **THEN** the link is spent
- **AND** a session is created recording the `magic-link` first factor with the MFA challenge pending
- **AND** an MFA challenge error propagates

#### Scenario: Deny without a reason
- **WHEN** a consumer policy denies without giving a reason
- **THEN** the redemption is refused with the generic policy-denied reason
- **AND** the link stays redeemable

### Requirement: The redemption endpoint refuses a redeemer that skipped or discarded checks
The redemption endpoint SHALL accept a replaceable redeemer. After a redeemer reports success, the endpoint SHALL refuse the request with a policy-denied reason when the policy check it supplied never ran, or ran and denied. In that case it SHALL establish no session and issue no token.

#### Scenario: A consumer that runs the check, discards the deny and succeeds is refused
- **WHEN** the endpoint is configured with a consumer redeemer that runs the supplied policy check, receives a deny, ignores it and reports success
- **THEN** the request is refused with the policy's deny reason
- **AND** no session is established and no token is issued

#### Scenario: A consumer that never runs the checks is refused
- **WHEN** the endpoint is configured with a consumer redeemer that reports success without running the supplied checks, and no policy is registered
- **THEN** the request is refused with the generic policy-denied reason
- **AND** no session is established

### Requirement: Redemption failures reveal nothing about the cause
Redemption SHALL fail with the same invalid-link error for:
- a malformed, unknown, expired, consumed or wrong-purpose token;
- a wrong secret or a wrong binding;
- a user who is not found, is disabled or does not match the link;
- a failure of the token store or user loader.

Policy denials and consumer check errors SHALL be the only redemption errors that are not the invalid-link error. No error or log record SHALL contain the token, the binding value or the submitted address.

#### Scenario: Disabled user and wrong secret look alike
- **WHEN** a link for a disabled user and a link with a wrong secret are redeemed
- **THEN** both fail with the same invalid-link error

#### Scenario: Consume write fails
- **WHEN** every check passes but the store fails while consuming the token
- **THEN** redemption fails with the invalid-link error
- **AND** no session is established

### Requirement: Refused redemptions of a valid link count against the source by default
The redemption endpoint SHALL check the request's source with a source guard before redeeming. A throttled or unattributable source SHALL be refused with the invalid-link error without redeeming. The default limit SHALL be 10 failures per source per 15 minutes, from a limiter used by no other flow.

By default, the endpoint SHALL record a failure for the source whenever redemption fails, including a policy denial or consumer check refusal of a valid link.

A consumer SHALL be able to choose not to record policy denials and consumer check refusals. Every other redemption failure SHALL still be recorded.

A consumer SHALL be able to replace the limiter. A nil limiter SHALL fail construction with a configuration error.

#### Scenario: Refused replays are throttled by default
- **WHEN** one source redeems a valid link 10 times within 15 minutes and a policy denies each redemption
- **THEN** the eleventh attempt from that source is refused with the invalid-link error without redeeming

#### Scenario: Consumer opts out
- **WHEN** the endpoint is configured not to record policy and check refusals, a source's redemption of a valid link is denied by policy 10 times, the policy then allows, and the source redeems again
- **THEN** the redemption succeeds

#### Scenario: Invalid tokens still count after opting out
- **WHEN** the endpoint is configured not to record policy and check refusals, and a source presents 10 wrong tokens within 15 minutes
- **THEN** the source's next attempt is refused as throttled

#### Scenario: Consumer limiter
- **WHEN** the endpoint is configured with a consumer's shared limiter
- **THEN** every check and failure for redemptions goes to that limiter

### Requirement: Links are bound to the requesting device by default
By default, requesting a link SHALL issue it with a binding value. The request endpoint SHALL set a binding cookie on every response, whatever the outcome. The cookie SHALL carry the genuine value when a link was issued, and otherwise a random decoy of the same shape. The cookie SHALL:
- be HttpOnly and Secure, with SameSite Lax;
- be scoped to the redemption path;
- have a lifetime equal to the configured link lifetime.

Redemption SHALL require the cookie's value to match the link's binding.

A consumer SHALL be able to disable binding. The request endpoint SHALL then never set the cookie, and redemption SHALL ignore any presented binding.

#### Scenario: Cookie presence is constant
- **WHEN** a link is requested for a known address and for an unknown address
- **THEN** both responses set a binding cookie with the same attributes and a value of the same length

#### Scenario: Another device
- **WHEN** a link is redeemed from a browser that does not hold the binding cookie set when it was requested
- **THEN** redemption fails with the invalid-link error

#### Scenario: Consumer disables binding
- **WHEN** binding is disabled, a link is requested, and it is redeemed from another device
- **THEN** no binding cookie was set
- **AND** redemption succeeds

### Requirement: Only a POST redeems a link
The redemption endpoint SHALL match only POST requests to its path, and SHALL read the token from the `token` form field. Any other method, including GET and HEAD, SHALL pass through without reading or spending the token. A successful redemption response SHALL carry `Referrer-Policy: no-referrer`.

#### Scenario: Mail scanner prefetch
- **WHEN** a GET request is made to the redemption path with a valid token in the query string
- **THEN** the token is not spent
- **AND** a later POST with that token succeeds

#### Scenario: Referrer suppressed
- **WHEN** a link is redeemed successfully
- **THEN** the response carries `Referrer-Policy: no-referrer`

### Requirement: Redirect targets are allowlisted exactly
A submitted redirect target SHALL be used only when it exactly equals an entry of the redirect allowlist, and that entry is either a host-relative path or an absolute URL without userinfo on an origin the consumer declared. Every other target SHALL be replaced by `/`. By default the allowlist and the declared origins SHALL be empty.

Construction SHALL fail with a configuration error that names the entry when an allowlist entry:
- is empty;
- is neither host-relative nor absolute;
- is absolute on an undeclared origin;
- carries userinfo.

Construction SHALL also fail when a declared origin has more than a scheme, host and optional port (a single trailing slash is accepted), or uses `http` on a host that is not loopback.

#### Scenario: Default allowlist
- **WHEN** a link is requested with redirect target `/dashboard` and default options
- **THEN** the link and the redemption response use redirect target `/`

#### Scenario: Consumer allowlist
- **WHEN** the allowlist contains `/dashboard` and redirect target `/dashboard` is submitted
- **THEN** redirect target `/dashboard` is used

#### Scenario: Prefix is not a match
- **WHEN** the allowlist contains `/dashboard` and redirect target `/dashboard.evil.example` or `//evil.example/dashboard` is submitted
- **THEN** redirect target `/` is used

#### Scenario: Undeclared absolute entry
- **WHEN** the endpoints are constructed with allowlist entry `https://partner.example.com/landing` and no declared origins
- **THEN** construction fails with a configuration error naming that entry

#### Scenario: Consumer declares an origin
- **WHEN** origin `https://partner.example.com` is declared and the allowlist contains `https://partner.example.com/landing`
- **THEN** construction succeeds, and that target is used when submitted exactly

### Requirement: Magic-link throttle refusal logs are sampled
Throttle refusal records written by the redemption endpoint SHALL be written through the source guard's log sampler with a reporter. They SHALL contain no token, binding value or submitted address.

#### Scenario: Throttled link guessing
- **WHEN** one throttled source makes 500 redemption attempts within one minute
- **THEN** one throttle record is written for that source in that minute
- **AND** no written record contains any presented token
