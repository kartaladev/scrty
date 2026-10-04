## ADDED Requirements

### Requirement: A refusal made before checking a password can cost the same password work
The username-and-password provider SHALL offer a decoy verification. It SHALL verify the presented password against the provider's reference hash, without loading the user, and SHALL report nothing about the outcome. The authentication manager SHALL offer it too, delegating to the first provider that supports the credentials and offers it. With no such provider it SHALL do nothing. The manager SHALL report whether any of its providers offers a decoy, so a caller can warn when none will ever be spent.

#### Scenario: Decoy through the password provider
- **WHEN** a decoy verification is asked of a password provider for username `ada`
- **THEN** its encoder performs one full verification against the reference hash
- **AND** the user loader is not called

#### Scenario: Manager delegates
- **WHEN** a manager over a bearer-token provider and a password provider is asked for a decoy verification of username-and-password credentials
- **THEN** the password provider performs it

#### Scenario: No provider offers it
- **WHEN** a manager whose only provider does not offer a decoy verification is asked for one
- **THEN** no verification runs and nothing is reported
- **AND** the manager reports that it offers no decoy
