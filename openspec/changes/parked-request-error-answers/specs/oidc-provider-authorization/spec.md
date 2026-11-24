## ADDED Requirements

### Requirement: A login-stage parked request can be ended with an error
The provider SHALL offer a call that ends a parked request at its login stage with an error code from a closed set: `access_denied`, `temporarily_unavailable` or `server_error`. It SHALL apply the resume's checks of the handle, the flow cookie and the client as it is now. It SHALL spend the request and answer the client's redirect URI with `error`, the request's `state` unchanged when one was sent, and `iss`.

#### Scenario: Request ended with access denied
- **WHEN** the call ends a login-stage request parked with `state=s-1` with `access_denied`
- **THEN** it answers the client's redirect URI carrying `error=access_denied`, `state=s-1` and `iss`, with no `error_description`
- **AND** a later resume or end of the same handle is refused as an unknown handle

#### Scenario: Code outside the set
- **WHEN** the call is asked to end a request with `invalid_grant`
- **THEN** it fails with a configuration error and the request stays parked

#### Scenario: Handle of another browser
- **WHEN** the call presents a live handle without the flow cookie that binds it
- **THEN** it is refused as an unknown handle and the request stays parked

#### Scenario: Request past its login stage
- **WHEN** the call presents the handle of a request waiting at its consent stage
- **THEN** it is refused as an unknown handle and the request stays parked

#### Scenario: Device request
- **WHEN** the call presents the handle of a request parked by user-code entry
- **THEN** it is refused as an unknown handle, and no redirect is answered

#### Scenario: Redirect URI no longer registered
- **WHEN** the client stopped registering the parked redirect URI, and the call ends the request
- **THEN** it is refused as an unknown handle, and the browser is not sent to that URI

#### Scenario: Ending races a resume
- **WHEN** a resume and an end of the same login-stage handle run at the same time
- **THEN** exactly one of them succeeds, and the other is refused as an unknown handle

### Requirement: The login page can cancel a parked request
The chain SHALL serve a cancel endpoint, at `/authorize/cancel` under the provider prefix by default, taking a POST with the handle and the flow cookie and no sign-in. It SHALL end the login-stage request with `access_denied` and answer 200 with `redirect_to` as a resume does, with `Cache-Control: no-store`. It SHALL follow the resume endpoint's TLS, origin, body and throttle rules.

#### Scenario: User gives up on the login page
- **WHEN** the login page POSTs the cancel endpoint with a live handle and its flow cookie
- **THEN** the response is 200 with `redirect_to` set to the client's redirect URI carrying `error=access_denied`, `state` and `iss`

#### Scenario: Unknown handle charged
- **WHEN** the cancel endpoint receives an unknown handle
- **THEN** it is refused as an unknown handle and the handle is charged to the source, as at the resume endpoint

#### Scenario: Consumer moves the endpoint
- **WHEN** the consumer sets the cancel endpoint's path to `/login/give-up`
- **THEN** the cancel is served there and not at the default path

### Requirement: A dependency failure after the request is read is answered at the redirect URI
When a resume or an end has read a parked request and validated its client and redirect URI, and a store or other dependency then fails, the provider SHALL try to spend the request and answer the client's redirect URI with `server_error`, `state` and `iss`. If that also fails, the failure SHALL be answered as it is today.

#### Scenario: Store fails while writing the code
- **WHEN** a resume's code cannot be stored, and the request can still be spent
- **THEN** the resume answers 200 with `redirect_to` carrying `error=server_error`, `state` and `iss`

#### Scenario: Store cannot spend the request either
- **WHEN** a resume's code cannot be stored and spending the request also fails
- **THEN** the resume fails as a dependency failure with no `redirect_to`, and the request stays parked

### Requirement: An expired request is answered within a grace window
A request that has expired, is still bound to the browser's flow cookie, and has been expired for less than the grace window SHALL be answered, at a resume, an end or a completion, at the client's redirect URI with `access_denied`, `state` and `iss`, and spent. The grace window SHALL be 10 minutes by default; a consumer MAY set it between 0 and 30 minutes, where 0 turns the answer off. Past it, the request SHALL be refused as an unknown handle.

#### Scenario: Slow user
- **WHEN** a request expired 2 minutes ago and its login page resumes it with the flow cookie
- **THEN** the resume answers 200 with `redirect_to` carrying `error=access_denied`, `state` and `iss`

#### Scenario: Past the grace window
- **WHEN** a request expired 11 minutes ago and its login page resumes it
- **THEN** the resume is refused as an unknown handle

#### Scenario: Consumer turns the grace off
- **WHEN** the consumer sets the grace window to 0, and a request expired 1 minute ago is resumed
- **THEN** the resume is refused as an unknown handle

#### Scenario: Grace too long
- **WHEN** the consumer sets the grace window to 2 hours
- **THEN** construction fails with a configuration error

### Requirement: Expired requests are swept after the grace window
The pending-request expiry task SHALL delete only requests whose expiry is older than the grace window, judged by the provider's clock.

#### Scenario: Sweep keeps a request within the window
- **WHEN** the sweep runs 5 minutes after a request expired, with the default grace window
- **THEN** the request is kept

#### Scenario: Sweep removes a request past the window
- **WHEN** the sweep runs 11 minutes after a request expired, with the default grace window
- **THEN** the request is removed

### Requirement: A consumer can cap the live parked requests
A consumer MAY set a ceiling on the number of live parked requests. It is off by default. Once the ceiling is reached, a valid request that would be parked SHALL be answered at its redirect URI with `temporarily_unavailable`, `state` and `iss`, and SHALL NOT be stored. A ceiling over a store that cannot count its live requests SHALL fail construction.

#### Scenario: Default has no ceiling
- **WHEN** no ceiling is set and requests are parked
- **THEN** every valid request is parked

#### Scenario: Ceiling reached
- **WHEN** the consumer sets a ceiling of 1000, 1000 requests are live, and another valid request arrives
- **THEN** the browser is redirected with `error=temporarily_unavailable`, `state` and `iss`, and nothing is stored

#### Scenario: Store cannot count
- **WHEN** the consumer sets a ceiling and supplies a pending-request store that cannot count its live requests
- **THEN** construction fails with a configuration error naming the store

## MODIFIED Requirements

### Requirement: A pending request expires
A pending request SHALL expire 10 minutes after it was created. An expired request SHALL NOT be resumed, consented to or ended as a live request. Within the grace window it SHALL be answered at the client's redirect URI, as the requirement on the grace window states.

#### Scenario: Handle expired
- **WHEN** a resume presents a handle 11 minutes after its request was parked, with the grace window turned off
- **THEN** the resume is refused as an unknown handle

#### Scenario: Consumer shortens the lifetime
- **WHEN** the consumer sets the pending-request lifetime to 5 minutes and turns the grace window off, and a resume presents a handle after 6 minutes
- **THEN** the resume is refused as an unknown handle

#### Scenario: Expired request answered within the grace window
- **WHEN** a resume presents a handle 11 minutes after its request was parked, with the default grace window
- **THEN** the resume answers `redirect_to` at the client's redirect URI carrying `error=access_denied`, and no code

### Requirement: A pending request is resumed with the sign-in that completes it
The resume endpoint SHALL accept a handle together with a sign-in credential in the `Authorization` header and the flow cookie. It SHALL refuse the resume as an unknown handle when the handle is unknown, expired past the grace window, already spent for its stage, or not bound to the flow cookie sent. It SHALL refuse the sign-in as unauthenticated when the credential does not authenticate.

#### Scenario: Resume from another browser
- **WHEN** a resume presents a valid handle and a valid sign-in, but not the flow cookie set for that handle
- **THEN** the resume is refused as an unknown handle, and no code is issued

#### Scenario: Handle resumed twice
- **WHEN** a handle's login stage is resumed successfully, and the same stage is resumed again
- **THEN** the second resume is refused as an unknown handle

#### Scenario: Login finished in another browser
- **WHEN** a user starts a request in one browser, opens a magic link in another, and that browser's page resumes the handle
- **THEN** the resume is refused as an unknown handle, and the user must start again from the relying party

#### Scenario: No sign-in credential
- **WHEN** a resume presents a valid handle and flow cookie but no `Authorization` header
- **THEN** it is refused as unauthenticated

### Requirement: A resume judges the client as it is now
Every resume, end and completion SHALL judge the parked request against the client as read at that moment. If the client is gone or the parked redirect URI is no longer registered, it SHALL be refused as an unknown handle, with no redirect. If the client lost the code grant, it SHALL answer the redirect URI with `unauthorized_client`; if `openid` was parked and may no longer be asked for, or no scope is left, with `invalid_scope`; each with `state` and `iss`, spending the request. A scope or resource the client may no longer use, and `offline_access` for a client that lost the refresh grant, SHALL be left out, and the request SHALL carry on.

#### Scenario: Redirect URI removed after parking
- **WHEN** a client stops registering a redirect URI, and a request parked with it resumes
- **THEN** the resume is refused as an unknown handle, and the browser is not sent to that URI

#### Scenario: Scope withdrawn after parking
- **WHEN** a client may no longer ask for `profile`, and a request parked with `openid profile` resumes
- **THEN** the code is issued for `openid` alone

#### Scenario: Code grant withdrawn after parking
- **WHEN** a client loses the code grant, and a request parked for it resumes
- **THEN** the resume answers `redirect_to` carrying `error=unauthorized_client`, `state` and `iss`, and the handle is spent

#### Scenario: openid withdrawn after parking
- **WHEN** a client may no longer ask for `openid`, and a request parked with `openid profile` resumes
- **THEN** the resume answers `redirect_to` carrying `error=invalid_scope`, `state` and `iss`, and the handle is spent

### Requirement: The authorization endpoint is throttled per source
Requests to the authorization, resume and cancel endpoints SHALL pass through the chain's per-source throttling. An unknown handle at the resume or cancel endpoint SHALL be charged to the source.

#### Scenario: Guessing handles
- **WHEN** one source presents unknown handles past the throttle's limit
- **THEN** its further resumes are refused by the throttle before the handle is looked up

#### Scenario: Guessing handles at the cancel endpoint
- **WHEN** one source presents unknown handles to the cancel endpoint past the throttle's limit
- **THEN** its further cancels are refused by the throttle before the handle is looked up
