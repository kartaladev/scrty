## ADDED Requirements

### Requirement: A password change at the resolve endpoint clears the user's lockout failures
When the consumer's function at the password-change resolve endpoint succeeds, the chain SHALL clear the lockout failures recorded against the identifier the user signs in with, so the new password is not refused for guesses made at the old one. A failure of the function SHALL clear nothing. A failure to clear SHALL be logged and SHALL NOT change the outcome. The documentation SHALL state that a password changed outside the chain must be cleared through the lockout policy's reset.

#### Scenario: New password is not held to old failures
- **WHEN** `ada` has seven failures in the window, so pre-authentication owes a wait of 120 seconds, and a session of `ada` resolves a password change successfully
- **THEN** a form login by `ada` with the new password, posted at once, succeeds

#### Scenario: Recovered account at the ceiling
- **WHEN** `ada` has one hundred failures in the window, recovers, and the recovery-pending session resolves a password change successfully
- **THEN** a form login by `ada` with the new password succeeds

#### Scenario: Refused change clears nothing
- **WHEN** `ada` has seven failures in the window, and the consumer's function at the resolve endpoint refuses the new password as reused
- **THEN** `ada` still has seven failures in the window

#### Scenario: Clearing fails
- **WHEN** a session of `ada` resolves a password change successfully, and the attempt store fails to clear
- **THEN** the consumer's function still owns the response, and one error record names the failed clearing

### Requirement: An unknown username is locked exactly like a known one
Form login and Basic authentication SHALL record a failure for a submitted username with no account exactly as for one with an account, and SHALL refuse it under lock with the same error, the same status and the same password work, so the lockout cannot tell an attacker whether an account exists.

#### Scenario: Unknown and known look alike under lock
- **WHEN** five form logins with wrong passwords are refused for `ada`, which has an account, and five for `nobody`, which does not, and each then posts once more within the first wait
- **THEN** both sixth requests are refused with the same error and status, and each spends one decoy verification

#### Scenario: Disclosure chosen
- **WHEN** the chain is configured to disclose locks, and the same sequence is posted for `ada` and `nobody`
- **THEN** both sixth requests are answered 429 with the account-locked refusal
