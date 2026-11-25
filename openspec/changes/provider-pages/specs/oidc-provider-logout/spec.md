# Spec Delta

## MODIFIED Requirements

### Requirement: A confirmation ends only the browser's sign-in
A confirmation SHALL end the sign-in of the browser's session. A browser with no session SHALL end nothing, except that when the consumer turned browser sessions off, a confirmation SHALL end the sign-in a valid hint names. The answer SHALL be 200 with a JSON object holding `redirect_to`, and `Cache-Control: no-store`, or, on a chain whose sign-ins are cookie sessions, `303` to that location for a form post or a request preferring HTML. A refusal by the user SHALL end nothing.

It SHALL NOT be an error for a relying party to ask for a logout when no sign-in is live.

#### Scenario: User confirms
- **WHEN** the logout page confirms that handle, and the browser holds a session
- **THEN** that sign-in ends, and `redirect_to` is the consumer's logged-out page

#### Scenario: Hint for another sign-in
- **WHEN** a valid hint names a sign-in other than the browser session's, and the user confirms
- **THEN** the browser session's sign-in ends, and the sign-in the hint names does not

#### Scenario: Holder of a hint in another browser
- **WHEN** someone holding a user's ID token sends it from a browser with no session, and confirms
- **THEN** no sign-in ends

#### Scenario: Nothing to end
- **WHEN** a valid hint names a sign-in that has already ended, and the browser holds no session
- **THEN** the response is not an error, and the browser goes to the logout page

#### Scenario: Form confirmation on a cookie chain
- **WHEN** on a cookie chain, the logout page posts the form `req=<handle>&confirmed=true` with the flow cookie, and the browser holds a session
- **THEN** that sign-in ends, and the response is `303` to the consumer's logged-out page

## ADDED Requirements

### Requirement: The logout confirmation endpoint accepts a form body on a cookie chain
On a chain whose sign-ins are cookie sessions, the logout confirmation endpoint SHALL accept an `application/x-www-form-urlencoded` body as well as JSON, with the fields `req` and `confirmed`. A form whose fields cannot be read SHALL be refused as malformed. Other chains SHALL keep accepting JSON only.

#### Scenario: Stay signed in
- **WHEN** on a cookie chain, the logout page posts `req=<handle>&confirmed=false`
- **THEN** nothing ends, and the response is `303` to where the provider sends a declined logout
