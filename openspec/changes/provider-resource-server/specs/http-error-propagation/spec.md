# Spec Delta

## ADDED Requirements

### Requirement: An invalid provider access token is a public refusal mapped to 401
The library SHALL expose a public invalid-token refusal for a provider access token the bearer refuses: one that does not verify, whose grant has ended, whose audience is not the configured one, or that is unbound where binding is required. It SHALL also be identifiable as the uniform authentication failure, and the status mapping SHALL answer it 401. Only a provider-routed token's refusal SHALL be it.

#### Scenario: Status and identity
- **WHEN** the invalid-token refusal is mapped to a status
- **THEN** the status is 401, and the error is identifiable both as the invalid-token refusal and as the authentication failure

#### Scenario: First-party bearer unchanged
- **WHEN** signed bearer tokens refuse a first-party token their verifier rejects
- **THEN** the refusal is the authentication failure, not identifiable as the invalid-token refusal, and carries no `invalid_token` challenge

### Requirement: An invalid-token refusal carries an invalid_token challenge
The chain SHALL answer the invalid-token refusal with a `WWW-Authenticate` challenge naming `error="invalid_token"`: under the `DPoP` scheme with the accepted algorithms when the refusal was made under DPoP, and under `Bearer` otherwise. The challenge SHALL be set whether or not the chain enables DPoP, SHALL name no check, and a consumer's error handler SHALL be able to replace or remove it.

#### Scenario: Under DPoP
- **WHEN** the bearer refuses a provider token presented under `DPoP` on a chain accepting ES256
- **THEN** the response carries `WWW-Authenticate: DPoP error="invalid_token", algs="ES256"`

#### Scenario: Under Bearer without DPoP
- **WHEN** the chain does not enable DPoP, the bearer allows unbound grant-backed tokens, and an expired provider token is presented under `Bearer`
- **THEN** the response carries `WWW-Authenticate: Bearer error="invalid_token"`

#### Scenario: Consumer handler edits it
- **WHEN** a consumer's error handler removes the `WWW-Authenticate` header for an invalid-token refusal
- **THEN** the response carries no challenge

### Requirement: An inactive-account refusal is a public error, disclosed only by choice
The library SHALL expose a public inactive-account refusal. By default it SHALL reach the chain only beneath the uniform authentication failure, answered 401 with nothing in the status, headers or timing to tell it from a wrong password. With inactive-account disclosure enabled, a password login for an inactive account SHALL be refused with the inactive-account refusal alone, which the status mapping SHALL answer 403.

#### Scenario: Default is concealed
- **WHEN** an inactive account signs in by form login with its correct password on a chain with default options
- **THEN** the response is 401, as for a wrong password
- **AND** a consumer's error handler finds the inactive-account refusal beneath the error

#### Scenario: Disclosed
- **WHEN** inactive-account disclosure is enabled and an inactive account signs in with its correct password
- **THEN** the response is 403, and the error is the inactive-account refusal, not identifiable as the uniform authentication failure

#### Scenario: Disclosure needs the password
- **WHEN** inactive-account disclosure is enabled and an inactive account is presented with a wrong password
- **THEN** the response is 401, the uniform authentication failure, and nothing identifies the account as inactive
