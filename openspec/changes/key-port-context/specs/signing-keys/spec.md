# Spec Delta

## MODIFIED Requirements

### Requirement: Signing and verification keys can be supplied without the key manager
Token issuance and verification SHALL obtain the signing key and the verification keys through a key source contract that the key manager implements. The contract SHALL describe a verification key as its key identifier, its algorithm and its public key, using only standard-library types and this capability's own algorithm names, so that implementing it requires no JOSE library. A consumer SHALL be able to supply their own key source, such as one backed by an external key service, in place of the key manager. Verification keys handed to a caller SHALL be copies of what the source holds: writing to a returned key SHALL NOT change the keys the key manager publishes or the key it signs with.

Every request to the key source SHALL carry the caller's context. Issuance SHALL pass the context of the issuing call, and verification the context of the verifying call, without substituting a context of their own or imposing a deadline of their own. The key manager performs no input or output when asked for a key, and SHALL answer whatever state the context is in.

Asked for a signing key, a key source SHALL report a missing key apart from an outage. A source that holds no key for the algorithm SHALL return the no-key error, and the key manager SHALL do so for an algorithm it was not configured with. Any other error SHALL mean the source could not answer.

Issuance SHALL ask for a signing key once for each token, and SHALL use the signer it is given only for that token, never keeping or reusing it. A key source backed by an external service MAY therefore return a signer bound to the context it was asked with.

#### Scenario: External key source
- **WHEN** a consumer supplies a key source backed by an external signing service
- **THEN** tokens are issued and verified with its keys and no key manager is constructed

#### Scenario: A key source implemented without a JOSE library
- **WHEN** a consumer implements the key source contract using only the standard library, returning for each key its identifier, its algorithm and its public key
- **THEN** tokens are issued and verified with those keys, and the implementation imports no JOSE library

#### Scenario: A returned verification key cannot be mutated
- **WHEN** a caller obtains the key manager's verification keys and overwrites the public key material in the key it was given
- **THEN** the key manager still publishes that key unchanged and still verifies tokens signed by it

#### Scenario: The key source receives the caller's context
- **WHEN** a consumer key source records the context it is given, and a token is issued and then verified, each under a context carrying a distinct value
- **THEN** the request for a signing key carries the issuing context's value
- **AND** the request for verification keys carries the verifying context's value

#### Scenario: A signer is asked for once per token and never reused
- **WHEN** a consumer key source returns a fresh signer for each request, and three tokens are issued
- **THEN** the source is asked for a signing key three times, and each signer signs exactly one token

#### Scenario: The key manager answers under a cancelled context
- **WHEN** a key manager configured for RS256 is asked for its RS256 signer and its verification keys under a context that is already cancelled
- **THEN** it returns them with no error

#### Scenario: The key manager reports a missing key
- **WHEN** a key manager configured only for RS256 is asked for an EdDSA signer
- **THEN** it returns an error matching the no-key error
