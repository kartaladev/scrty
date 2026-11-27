## ADDED Requirements

### Requirement: A cookie chain's sessions are never sender-bound
On a chain with the cookie session, the requirements that an issuing endpoint binds the session to a request's proof or client certificate, verifies that proof before anything is spent, and refuses a request without a proof when DPoP is required SHALL NOT apply to the session. Every sign-in, re-proof and renewal there SHALL create or rotate an unbound session without reading the proof or the certificate. The OpenID Provider's token endpoint on that chain SHALL still bind the tokens it issues.

#### Scenario: Sign-in with a DPoP proof on a cookie chain
- **WHEN** a cookie chain with DPoP enabled signs a user in with a valid proof
- **THEN** the session is unbound, and the next request's cookie authenticates

#### Scenario: Invalid proof ignored
- **WHEN** a cookie-chain login, second-factor verification or renewal carries a proof that does not verify
- **THEN** the request proceeds as if it carried none, and nothing is recorded for the proof

#### Scenario: Required DPoP on a cookie chain
- **WHEN** DPoP is required on a cookie chain and a browser signs in without a proof
- **THEN** the sign-in succeeds with an unbound session

#### Scenario: Provider tokens still bound
- **WHEN** the OpenID Provider runs on a cookie chain with DPoP and a client requests a token with a valid proof
- **THEN** the issued token carries `cnf.jkt` for the proof's key
