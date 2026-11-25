# Spec Delta

## Purpose

Lets a chain serve polished sign-in pages of its own, switched on deliberately, safe by default,
and replaceable in whole or in any part without forking.

## ADDED Requirements

### Requirement: Pages are served only when the consumer enables them
A chain SHALL serve no page unless the consumer builds a page set and enables it on the chain. With a page set enabled, every page whose endpoint the chain answers SHALL be served at its documented default path.

#### Scenario: Not enabled
- **WHEN** a chain with form login and the cookie session is built without a page set
- **THEN** `GET /sign-in` passes through to the consumer's handler

#### Scenario: Enabled
- **WHEN** the same chain is built with the default page set
- **THEN** `GET /sign-in` answers `200` with the sign-in page

### Requirement: A page set requires the protections its pages rest on
Building a chain with a page set SHALL fail with a configuration error when the chain lacks the cookie session, CSRF protection or security headers, or when the page set names no product.

#### Scenario: No cookie session
- **WHEN** a page set is enabled on a chain that issues signed tokens
- **THEN** construction fails with a configuration error naming the pages and the cookie session

#### Scenario: No product name
- **WHEN** a page set is built without a product name
- **THEN** construction fails with a configuration error

### Requirement: A page needs the endpoint it talks to
A page whose endpoint the chain does not answer SHALL NOT be served. When the consumer explicitly asks for such a page, construction SHALL fail with a configuration error naming the page and the endpoint.

#### Scenario: Second-factor page without MFA
- **WHEN** the default page set is enabled on a chain without second factors
- **THEN** the challenge page is not served, and the sign-in page builds

#### Scenario: Page asked for explicitly
- **WHEN** the consumer replaces the challenge page with its own handler on a chain without second factors
- **THEN** construction fails with a configuration error naming the page and the second-factor endpoints

### Requirement: Each page can be switched off or replaced
The consumer SHALL be able to switch any page off, so its path passes through to the consumer's handler, or to serve it with the consumer's own handler. The endpoints behind a switched-off page SHALL stay as they are.

#### Scenario: Page off
- **WHEN** the consumer switches the recovery pages off
- **THEN** `GET /recovery` passes through, and `POST /recovery/start` still answers

#### Scenario: Page replaced
- **WHEN** the consumer serves the sign-in page with its own handler
- **THEN** `GET /sign-in` is answered by the consumer's handler, and every other page by the page set

### Requirement: Page paths follow the base path and are checked for collisions
Page paths SHALL move with the chain's base path, as the endpoints they talk to do, and SHALL be part of the chain's endpoint inventory, so a collision with a built-in endpoint or a consumer route fails construction.

#### Scenario: Base path
- **WHEN** the chain's base path is `/auth`
- **THEN** the sign-in page answers at `/auth/sign-in`, and its form posts to `/auth/sign-in/password`

#### Scenario: Collision
- **WHEN** the consumer registers a route at `/sign-in` and enables the default page set
- **THEN** construction fails with a configuration error naming the path

### Requirement: Pages are never cached or framed
Every page SHALL be answered with `Cache-Control: no-store`, a Content-Security-Policy that uses a per-response nonce for its scripts and `frame-ancestors 'none'` unless the chain's security headers allow named origins, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.

#### Scenario: Headers
- **WHEN** the sign-in page is requested
- **THEN** the response carries `Cache-Control: no-store`, a CSP with a nonce and `frame-ancestors 'none'`, `nosniff` and `no-referrer`

### Requirement: Pages carry the sign-in's CSRF token in every form
Every form a page renders that posts to an unsafe endpoint SHALL carry the CSRF token of the request's sign-in, or, before a sign-in exists, pass the chain's cross-site check by being same-origin.

#### Scenario: Signed-in form
- **WHEN** the sessions page is rendered for a signed-in user
- **THEN** each revoke form carries that sign-in's CSRF token in the configured field

### Requirement: Pages are themed through CSS variables
Pages SHALL take their colours, radius, font and logo from documented `--scrty-*` CSS custom properties, with defaults that need no configuration. The consumer SHALL be able to set them, and to add a stylesheet loaded after scrty's.

#### Scenario: Default look
- **WHEN** no theme is configured
- **THEN** every page renders with scrty's default variables

#### Scenario: Consumer theme
- **WHEN** the consumer sets the primary colour to `#4f46e5` and adds `/static/acme.css`
- **THEN** every page's stylesheet sets `--scrty-primary: #4f46e5`, and `/static/acme.css` is linked after scrty's stylesheet

### Requirement: Markup is overridden by named blocks, checked at construction
Each page SHALL be built from documented named blocks. The consumer SHALL be able to override any block from their own templates. Each override SHALL be rendered once at construction; one that fails to render, or that removes a field the page needs (the CSRF token, a handle, a credential field), SHALL fail construction.

#### Scenario: Footer override
- **WHEN** the consumer overrides `signin.footer` with a support link
- **THEN** the sign-in page shows the link, and everything else is scrty's

#### Scenario: Override drops a required field
- **WHEN** the consumer overrides `signin.form` with a form that has no CSRF token field
- **THEN** construction fails with a configuration error naming the block and the field

### Requirement: Consumer text is escaped
Every value a page shows, the consumer's messages and product name included, SHALL be escaped for the context it appears in, so no consumer or user value can add markup or script to a page.

#### Scenario: Markup in a message
- **WHEN** the consumer's message for the sign-in title is `<script>alert(1)</script>`
- **THEN** the page shows the text literally, and no script element is added

### Requirement: Wording and language come from replaceable message bundles
Pages SHALL take every word they show from a message bundle, English by default. The consumer SHALL be able to replace messages and add languages. The language SHALL be chosen from the consumer's choice, then the request's `Accept-Language`, then English.

#### Scenario: Consumer language
- **WHEN** the consumer adds an Indonesian bundle and a browser sends `Accept-Language: id`
- **THEN** the sign-in page is shown in Indonesian

#### Scenario: Missing message
- **WHEN** a consumer bundle lacks a message the page needs
- **THEN** the English message is shown

### Requirement: Browser refusals are rendered as a page
When a page set is enabled, a refusal of a request that prefers HTML SHALL be answered with an error page carrying the refusal's status, on every supported framework. A refusal of any other request SHALL be answered exactly as without pages.

#### Scenario: HTML request refused
- **WHEN** a browser's request to a page is refused as cross-site
- **THEN** the response has the refusal's status and an error page

#### Scenario: API request refused
- **WHEN** a JSON request is refused on a chain with pages
- **THEN** the response is what the chain answers without pages

### Requirement: Static assets are served from the page set
The page set SHALL serve its stylesheet, scripts and default logo itself, under the chain's base path, with content-hashed names and long-lived caching, so pages need no external host.

#### Scenario: Stylesheet
- **WHEN** the sign-in page is rendered
- **THEN** it links a stylesheet whose path is under the base path and whose name carries a content hash, and that path answers with the stylesheet
