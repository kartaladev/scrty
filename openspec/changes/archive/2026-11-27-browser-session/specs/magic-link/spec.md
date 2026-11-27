# Spec Delta

## MODIFIED Requirements

### Requirement: Only a POST redeems a link
The redemption endpoint SHALL match only POST requests to its path, and SHALL read the token from the `token` form field by default, or from the field the consumer names. Any other method, including GET and HEAD, SHALL pass through without reading or spending the token. A successful redemption response SHALL carry `Referrer-Policy: no-referrer`.

#### Scenario: Mail scanner prefetch
- **WHEN** a GET request is made to the redemption path with a valid token in the query string
- **THEN** the token is not spent
- **AND** a later POST with that token succeeds

#### Scenario: Referrer suppressed
- **WHEN** a link is redeemed successfully
- **THEN** the response carries `Referrer-Policy: no-referrer`

#### Scenario: Consumer token field
- **WHEN** the consumer names the token field `code` and a valid link is redeemed by a POST carrying it in `code`
- **THEN** the redemption succeeds
- **AND** a POST carrying a valid token only in `token` is refused as a failed redemption, and that token is not spent

## ADDED Requirements

### Requirement: Magic-link form field names are replaceable
The endpoints SHALL read the address from `email`, the destination from `next` and the token from `token` by default, in a form body and, at the request endpoint, in a JSON body. The consumer SHALL be able to name each of the three fields. An empty name, or two fields given one name, SHALL fail construction with a configuration error.

#### Scenario: Default fields
- **WHEN** a link is requested by a form POST carrying `email` and `next` with default options
- **THEN** the request endpoint reads the address from `email` and the destination from `next`

#### Scenario: Consumer fields
- **WHEN** the consumer names the address field `login` and a link is requested by a POST carrying `login`
- **THEN** the link is requested for that address

#### Scenario: Two fields with one name
- **WHEN** the consumer names both the address and the token field `value`
- **THEN** construction fails with a configuration error

### Requirement: Magic-link request bodies are bounded by a replaceable limit
Both endpoints SHALL read at most a bounded number of body bytes, 64 KiB by default, the same default as form login. A body over the limit SHALL be read as carrying no values, so the request endpoint still gives its uniform answer and the redemption endpoint refuses without spending anything. The consumer SHALL be able to change the limit. A limit of zero or less SHALL fail construction.

#### Scenario: Oversized link request
- **WHEN** a POST with a 65 KiB body reaches the request endpoint with default options
- **THEN** it receives the same status and body as any other request, and no link is issued

#### Scenario: Oversized redemption
- **WHEN** a POST with a 65 KiB body carrying a valid token reaches the redemption endpoint with default options
- **THEN** it is refused as a failed redemption, and the token is not spent

#### Scenario: Consumer limit
- **WHEN** the consumer sets the limit to 4 KiB and a 5 KiB redemption body carrying a valid token arrives
- **THEN** it is refused as a failed redemption, and the token is not spent

#### Scenario: Zero limit
- **WHEN** the consumer sets the limit to zero
- **THEN** construction fails with a configuration error
