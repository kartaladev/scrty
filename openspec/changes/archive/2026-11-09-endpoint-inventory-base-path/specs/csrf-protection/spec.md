# Spec Delta

## MODIFIED Requirements

### Requirement: Cross-site unsafe requests are refused by Fetch Metadata and Origin
With CSRF protection enabled, a request whose method is not exactly `GET`, `HEAD` or `OPTIONS`, compared case-sensitively, SHALL be judged before any authentication interceptor runs:
1. `Sec-Fetch-Site` of `same-origin` or `none` SHALL pass.
2. `Sec-Fetch-Site` of `same-site` or `cross-site`, or any other value, SHALL be refused unless its `Origin` is a trusted origin.
3. With no `Sec-Fetch-Site`, an `Origin` whose scheme, host and port differ from the request's own scheme and host SHALL be refused unless it is a trusted origin. `Origin: null` SHALL never match and SHALL never be trusted.
4. With neither header, the request SHALL pass this check.

The request's own scheme and host SHALL be those the chain resolves, including through trusted proxies. The refusal SHALL be the cross-site-request error, and the check SHALL read no session and no body.

#### Scenario: Cross-site form post
- **WHEN** a page on `https://evil.example` submits a form to `POST https://app.example.com/settings` and the browser sends `Sec-Fetch-Site: cross-site`
- **THEN** the request is refused with the cross-site-request error and the handler does not run

#### Scenario: Login CSRF
- **WHEN** a page on `https://evil.example` posts the attacker's credentials to `POST https://app.example.com/sign-in/password` with `Sec-Fetch-Site: cross-site`
- **THEN** the request is refused with the cross-site-request error, no credential is checked and no session is created

#### Scenario: Older browser without Fetch Metadata
- **WHEN** a request arrives with `Origin: https://evil.example`, no `Sec-Fetch-Site`, and the request's own origin is `https://app.example.com`
- **THEN** it is refused with the cross-site-request error

#### Scenario: Sandboxed or privacy-redirected origin
- **WHEN** a `POST` arrives with `Origin: null` and no `Sec-Fetch-Site`
- **THEN** it is refused with the cross-site-request error

#### Scenario: Port differs
- **WHEN** a `POST` to `https://app.example.com` arrives with `Origin: https://app.example.com:8443` and no `Sec-Fetch-Site`
- **THEN** it is refused with the cross-site-request error

#### Scenario: Unusual method
- **WHEN** a request with method `get` (lower case) or `PROPFIND` arrives with `Sec-Fetch-Site: cross-site`
- **THEN** it is judged as unsafe and refused

#### Scenario: Behind a trusted proxy
- **WHEN** a trusted proxy forwards scheme `https` and host `app.example.com`, the app receives the request over plain HTTP for host `10.20.1.5:8080`, and the browser sends `Origin: https://app.example.com` with no `Sec-Fetch-Site`
- **THEN** the request passes the check

#### Scenario: Non-browser client
- **WHEN** a server-to-server `POST` arrives with neither `Sec-Fetch-Site` nor `Origin`
- **THEN** it passes the Fetch Metadata check

#### Scenario: Safe method
- **WHEN** a cross-site `GET` arrives with `Sec-Fetch-Site: cross-site`
- **THEN** it is not refused by CSRF protection

