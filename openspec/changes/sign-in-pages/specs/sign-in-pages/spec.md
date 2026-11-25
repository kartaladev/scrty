# Spec Delta

## Purpose

Defines what each scrty-served sign-in, second-factor, recovery, session and error page shows and
does, so that a consumer gets complete, safe sign-in screens without writing them.

## ADDED Requirements

### Requirement: Pages answer at documented default paths
With default options, the pages SHALL answer `GET` at: `/sign-in` (sign-in), `/sign-in/magic-link/confirm` (magic-link confirmation), `/sign-in/challenge` (second factor), `/account/second-factors` (enrolment and saved codes), `/account/reauthenticate`, `/account/password`, `/account/sessions`, `/recovery` and `/sign-out/confirm`.

#### Scenario: Default paths
- **WHEN** the default page set is enabled on a chain with every sign-in feature on
- **THEN** each listed path answers `200` with its page, and no listed path collides with a built-in endpoint

#### Scenario: Consumer path
- **WHEN** the consumer moves the sign-in page to `/login`
- **THEN** `GET /login` answers with the sign-in page, and `GET /sign-in` passes through

### Requirement: The sign-in page offers only the methods the chain answers
The sign-in page SHALL show a password form when form login is on, a magic-link request form when magic link is on, a passkey button when passwordless passkey login is on, and one button per configured federated provider. A method that is off SHALL NOT appear.

#### Scenario: Password and one provider
- **WHEN** form login and OIDC login with provider `corp` are on, and magic link and passkeys are off
- **THEN** the page shows a password form and a `corp` button, and no magic-link form or passkey button

### Requirement: The sign-in page carries its destination
The sign-in page SHALL pass the `next` it was opened with to the sign-in it submits, and SHALL NOT validate it itself: the chain's destination rules decide where the browser lands.

#### Scenario: Destination kept
- **WHEN** a browser opens `/sign-in?next=/orders` and signs in with a password
- **THEN** the form posts `next=/orders`, and the browser lands on `/orders`

#### Scenario: Off-site destination
- **WHEN** a browser opens `/sign-in?next=https://evil.example/` and signs in
- **THEN** the browser lands on `/`

### Requirement: Every sign-in failure shows one message
A failed sign-in on any page SHALL show the same message whether the account is unknown, the password is wrong, the account is locked or disabled, or the request was throttled, unless the consumer has enabled a disclosure the chain already supports, in which case that refusal's own message SHALL be shown.

#### Scenario: Unknown user and wrong password
- **WHEN** one browser signs in as an unknown user and another with a wrong password for a known user
- **THEN** both pages show the same message with the same status

#### Scenario: Inactive disclosure enabled
- **WHEN** the consumer enabled inactive-account disclosure and an inactive user signs in with the right password
- **THEN** the page shows the inactive-account message

### Requirement: Magic-link confirmation spends the link only on a click
The magic-link confirmation page SHALL show the product name and one button that posts the link's token to the redemption endpoint. Opening the page SHALL NOT spend the token.

#### Scenario: Link scanner
- **WHEN** a mail scanner opens the confirmation link
- **THEN** the page is shown and the token is not spent

#### Scenario: User clicks
- **WHEN** the user clicks the button
- **THEN** the link is redeemed, the session cookie is set, and the browser lands on the link's destination

### Requirement: The second-factor page follows a pending challenge
After a sign-in is challenged, the browser SHALL land on the second-factor page. It SHALL list the methods the sign-in can use, begin the chosen one, and verify the code or assertion the user gives. A verified factor SHALL send the browser to the sign-in's destination.

#### Scenario: TOTP challenge
- **WHEN** a password sign-in is challenged and the user enters a valid TOTP code
- **THEN** the session is rotated, the cookie re-set, and the browser lands on the destination

#### Scenario: Wrong code
- **WHEN** the user enters a wrong code
- **THEN** the page shows the failure message, and the remaining attempts follow the chain's rules

### Requirement: Enrolment shows secrets once
The enrolment page SHALL let a signed-in user enrol the second-factor methods the chain offers. A TOTP secret and its QR code, and a new set of saved recovery codes, SHALL be shown only in the response that created them, and never again.

#### Scenario: TOTP enrolment
- **WHEN** a user begins TOTP enrolment
- **THEN** the page shows the secret and its QR code, and reloading the page does not show them again

#### Scenario: New saved codes
- **WHEN** a user regenerates saved codes after a recent authentication
- **THEN** the page shows the ten new codes once

### Requirement: Re-authentication returns to where it was asked
When a request is refused for lack of a recent authentication, the re-authentication page SHALL ask for the factor the chain requires and, once verified, send the browser back to the page that asked.

#### Scenario: Sensitive page
- **WHEN** a user opens a page that requires a recent authentication and re-proves their password
- **THEN** the browser lands back on that page

### Requirement: The password page resolves an owed change
When a sign-in owes a password change, every page SHALL send the browser to the password page, which SHALL submit the change to the password-change gate's resolve endpoint and, on success, send the browser to the sign-in's destination.

#### Scenario: Expired password
- **WHEN** a user whose password expired signs in
- **THEN** the browser lands on the password page, and after a valid change on the destination

#### Scenario: Policy refusal
- **WHEN** the new password breaks the password policy
- **THEN** the page shows the policy's reasons, and the change stays owed

### Requirement: Recovery pages reveal nothing about the account
The recovery pages SHALL start a recovery and collect the proofs the chain requires. Starting a recovery SHALL show the same page whether or not the account exists.

#### Scenario: Unknown account
- **WHEN** a recovery is started for an unknown address and for a known one
- **THEN** both browsers see the same page with the same status

### Requirement: The sessions page lets a user end their other sign-ins
The sessions page SHALL list the user's live sign-ins with the metadata the chain records, mark the current one, and let the user end any other one, or all others.

#### Scenario: End another sign-in
- **WHEN** a user ends a sign-in listed on the page
- **THEN** that sign-in's cookie no longer authenticates, and the page lists one fewer

### Requirement: Signing out asks first
The sign-out confirmation page SHALL post to the logout endpoint when the user confirms, and the browser SHALL land on the sign-in page.

#### Scenario: Confirm
- **WHEN** the user confirms sign-out
- **THEN** the cookie is expired, and the browser lands on `/sign-in`

### Requirement: The error page shows nothing the library knows
The error page SHALL show the product name, a message chosen by the refusal's kind from the message bundle, and a link back to the sign-in page. It SHALL NOT show error text, identifiers or stack details.

#### Scenario: Dependency failure
- **WHEN** a page request fails because the session store is down
- **THEN** the error page shows the generic failure message with status `500`, and no store error text
