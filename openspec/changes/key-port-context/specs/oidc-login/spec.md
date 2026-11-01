# Spec Delta

## MODIFIED Requirements

### Requirement: Handoff redemption is check-then-consume
The handoff redemption endpoint SHALL accept the code only in the body of a POST request, and SHALL ignore a code in the query string. Redemption SHALL proceed in this order:
1. validate the code: it is well formed, its record exists, its secret matches in constant time, and it has not expired;
2. resolve the account by the recorded user reference through the user loader, and refuse it unless the loaded details carry exactly that reference and the user is enabled;
3. run the refusal checks, including the post-authentication policy evaluation from the `security-policy` capability, with the assurance the record carries;
4. build the session and issue its credential, through the login completion step of the `http-security-chain` capability;
5. consume the code in one atomic operation, last, and only then store the session and hand out its credential.

An already-consumed record MAY be rejected before step 2, but that rejection SHALL NOT be what guarantees single use; only the atomic consume SHALL decide. A refusal or failure at step 2, 3 or 4 SHALL leave the code redeemable until it expires. A losing redemption of a race SHALL discard its credential, and its session SHALL never be stored. Issuing the credential writes no state, so the refusal checks' documentation SHALL state that the library may issue a credential, which it discards on a lost race, between the checks and the consume. Refusal checks SHALL be documented as required to be side-effect free, because racing redemptions of one code can each run them. The login completion step SHALL reuse the post-authentication decision made at step 3, rather than evaluating the post-authentication policies again after the code is consumed, so a policy lookup failure never spends the code.

#### Scenario: Racing redemptions
- **WHEN** 8 requests redeem the same valid code at the same time
- **THEN** exactly one creates a session
- **AND** the other 7 receive the invalid-handoff outcome

#### Scenario: Code in the query string
- **WHEN** a POST to the redemption endpoint carries the code only in its query string
- **THEN** redemption is refused with the invalid-handoff outcome

#### Scenario: A policy lookup failure does not spend the code
- **WHEN** a required user's code carries no accepted assurance, the MFA requirement policy's enrolment lookup fails while the code is redeemed, and the code is redeemed again after the lookup recovers
- **THEN** the first redemption is refused and creates no session
- **AND** the second redemption completes

#### Scenario: Credential cannot be issued
- **WHEN** a valid code passes every check, the key source fails when the credential is issued, and the code is redeemed again after the key source recovers and before it expires
- **THEN** the first redemption fails as a dependency failure, not with the invalid-handoff outcome, and creates no session
- **AND** the second redemption succeeds

### Requirement: Handoff redemption failures reveal nothing about the cause
Redemption SHALL fail with the same invalid-handoff outcome for:
- an unknown, malformed, wrong-secret, expired or already-consumed code;
- an account that is missing, disabled, or whose loaded reference differs from the recorded one;
- a failure of the handoff store or the user loader, including a failure of the consume.

Policy denials, consumer check errors and a failure to issue the credential SHALL be the only redemption errors that are not the invalid-handoff outcome. A failure to issue the credential is a dependency failure: it SHALL be returned with fixed library text that keeps its cause reachable, and SHALL leave the code redeemable. The cause SHALL be available only to logs, at error level for a store or loader failure. No error or log record SHALL contain the code.

#### Scenario: Disabled user and wrong secret look alike
- **WHEN** a code for a disabled user and a code with a wrong secret are redeemed
- **THEN** both fail with the same invalid-handoff outcome

#### Scenario: Transient loader failure keeps the code
- **WHEN** a valid code is redeemed while the user loader is failing, and the same code is redeemed again after the loader recovers and before the code expires
- **THEN** the first redemption fails with the invalid-handoff outcome, creates no session and logs the failure at error level
- **AND** the second redemption succeeds

#### Scenario: Reference mismatch
- **WHEN** a code recorded for user reference `u-1` is redeemed and the loader returns details for `u-2`
- **THEN** redemption fails with the invalid-handoff outcome
- **AND** the code is not consumed

#### Scenario: Consume fails
- **WHEN** a valid code passes every check but the store fails while consuming it
- **THEN** redemption fails with the invalid-handoff outcome
- **AND** no session is created and no access token is handed out

### Requirement: A successful redemption establishes a federated session
A redemption that consumes the code SHALL complete the login through the login completion step of the `http-security-chain` capability, as every other first factor does. The session SHALL record the OIDC first-factor kind, together with the provider name, verified issuer, provider session id, ID token, and asserted `amr` and `acr` carried by the code, all in the write that creates the session. The session SHALL be created for the principal built from the resolved account's stored details, so that it holds only the user's stored roles. An access token SHALL be issued for it through the `token-issuance` capability before the code is consumed, and the session SHALL be stored only after the code is consumed. The response SHALL be the JSON body form login answers with, plus the destination re-validated against the redirect allowlist as `next`, with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. A consumer who needs a different response replaces the conveyance with a callback success handler.

#### Scenario: Session carries the federation fields
- **WHEN** a code issued for user `u-1`, issuer `https://idp.example` and provider session `sid-9` is redeemed
- **THEN** the created session records the OIDC first factor, issuer `https://idp.example` and provider session `sid-9`

#### Scenario: Session carries the asserted assurance
- **WHEN** a code carrying `amr` `["mfa"]` and `acr` `urn:corp:loa:2` is redeemed
- **THEN** the created session records `amr` `["mfa"]` and `acr` `urn:corp:loa:2`
- **AND** its second-factor state is not satisfied

#### Scenario: Response body
- **WHEN** a code is redeemed with destination `/welcome`, which is allowlisted
- **THEN** the response body carries `access_token`, `valid_until` and `next` equal to `/welcome`, in the same form a form login's body carries its token
- **AND** the response carries `Cache-Control: no-store`
