## ADDED Requirements

### Requirement: A client may be registered for the device grant
A client of either type MAY list the device-code grant among its grant types. Only a provider that has enabled the device grant SHALL accept such a client. Otherwise a configured client SHALL fail construction, and one read from a registry SHALL be treated as unknown and logged with the setting it fails on. A client registered for the device grant alone SHALL need no redirect URI.

#### Scenario: A CLI client with only the device grant
- **WHEN** a public native client lists only the device-code grant, with no redirect URI, on a provider that has enabled the device grant
- **THEN** construction succeeds

#### Scenario: A device client on a provider without the grant
- **WHEN** a configured client lists the device-code grant on a provider that has not enabled it
- **THEN** building the provider fails with a configuration error naming the client and the grant

#### Scenario: A registry returns a device client to a provider without the grant
- **WHEN** a consumer's registry returns a client listing the device-code grant, and the provider has not enabled it
- **THEN** the client is treated as unknown, and the log names the setting

### Requirement: A client opts in to the complete verification URI
A client registered for the device grant MAY opt in to receiving `verification_uri_complete`. It SHALL be off by default. Opting in without the device grant SHALL fail construction, or make a registry's client unknown.

#### Scenario: Opt-in without the grant
- **WHEN** a client opts in to the complete verification URI without listing the device-code grant
- **THEN** building the provider fails with a configuration error naming the client and the setting

### Requirement: A client can let its device grants outlive the approving sign-in
A client registered for the device grant MAY be set so that its device grants without `offline_access` survive the end of the sign-in that approved them. It SHALL be off by default. Setting it on a client that ends its grants with their sign-in, by its own setting or as a public web client's default, or on a client without the device grant, SHALL fail construction, or make a registry's client unknown.

#### Scenario: The setting on a native CLI client
- **WHEN** a public native client with the device grant sets its device grants to outlive their sign-in
- **THEN** construction succeeds

#### Scenario: Contradicting the end-with-sign-in setting
- **WHEN** a client sets both that its grants end with their sign-in and that its device grants outlive it
- **THEN** building the provider fails with a configuration error naming both settings

#### Scenario: A public web client under its default
- **WHEN** a public web client with the device grant sets its device grants to outlive their sign-in, without turning off its default of ending grants with the sign-in
- **THEN** building the provider fails with a configuration error naming both settings
