## MODIFIED Requirements

### Requirement: Logout expires the cookie
A successful logout on a cookie chain, of a request that carried the session cookie, SHALL expire the session cookie with the same name, path, domain and security attributes it was set with. A logout authenticated by another credential, such as Basic or an API key, without the session cookie SHALL set no cookie.

#### Scenario: Logout
- **WHEN** a signed-in user logs out on a cookie chain with the session cookie
- **THEN** the response sets `__Host-scrty-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`

#### Scenario: Logout by another credential
- **WHEN** a request authenticated by Basic, without the session cookie, logs out on a cookie chain
- **THEN** the logout succeeds and the response sets no cookie

#### Scenario: Logout fails on a provider store outage
- **WHEN** the provider's store fails while a logout on a cookie chain ends the sign-in's grants
- **THEN** the logout fails as a dependency failure, the session stays, and the cookie is not expired
