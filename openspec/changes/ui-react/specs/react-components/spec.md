# Spec Delta

## Purpose

Defines how the `@kartaladev/scrty-react` package's hooks and components behave inside a
consumer's own React app, against a scrty chain whose sign-ins are cookie sessions.

## ADDED Requirements

### Requirement: The package never stores a credential in JavaScript
Hooks and components SHALL rely on the session cookie for authentication, SHALL NOT read, store or send a session identifier or access token, and SHALL NOT write to `localStorage`, `sessionStorage` or `IndexedDB`.

#### Scenario: After sign-in
- **WHEN** a user signs in through `useSignIn`
- **THEN** no session identifier or token is present in any JavaScript-accessible storage or in the hook's state

### Requirement: Unsafe requests carry the CSRF token
Every unsafe request the package sends SHALL carry the sign-in's CSRF token in the header the chain names, read from the chain's CSRF token endpoint, and SHALL be sent with `credentials: "same-origin"`.

#### Scenario: Revoke a session
- **WHEN** `useSessions` revokes one of the user's sign-ins
- **THEN** the request carries `X-CSRF-Token` with the sign-in's token

### Requirement: An unsupported contract or flow is refused up front
On first use, the package SHALL read the chain's discovery. When the contract version is one it does not support, or a component's flow is not enabled, the component SHALL render an explanatory message and send no request for that flow.

#### Scenario: Newer contract
- **WHEN** the chain's discovery reports contract `2` and the package supports only `1`
- **THEN** every component renders the unsupported-contract message and sends no sign-in request

#### Scenario: Flow off
- **WHEN** the chain does not offer magic link and the app renders `<MagicLinkForm/>`
- **THEN** the component renders the flow-unavailable message

### Requirement: A pending challenge is surfaced, not hidden
When a sign-in is answered with a challenge problem, the sign-in hook SHALL report the challenge kind and the methods the chain lists, and the second-factor hook SHALL be able to complete it.

#### Scenario: TOTP required
- **WHEN** a password sign-in is answered with a second-factor challenge
- **THEN** `useSignIn` reports the challenge with its methods, and `useSecondFactor` verifying a valid code completes the sign-in

### Requirement: Components are styled by the shared design tokens
The styled components SHALL take their look from the same `--scrty-*` CSS variables as scrty's server-rendered pages, and SHALL accept a class name for the consumer's own styling.

#### Scenario: Shared theme
- **WHEN** the app sets `--scrty-primary: #4f46e5`
- **THEN** `<SignInForm/>`'s primary button uses that colour

### Requirement: Hooks work without the styled components
Every flow SHALL be usable through its hook alone, with the consumer rendering every element, so a team with its own design system gets the logic without the markup.

#### Scenario: Own components
- **WHEN** an app calls `useSignIn().signIn({username, password})` from its own form
- **THEN** the sign-in proceeds exactly as through `<SignInForm/>`
