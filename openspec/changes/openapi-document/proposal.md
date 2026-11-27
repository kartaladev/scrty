# Proposal

## Why

A consumer who embeds scrty has to describe its endpoints to whoever calls them. Today that means writing OpenAPI by hand for login, MFA, re-authentication, passkeys, recovery and the rest. That description drifts as soon as an option changes a path, a form field name or a responder. What a chain answers depends on which `Enable*` options it was given, so only the chain can describe it accurately.

The endpoint inventory (`endpoint-inventory-base-path`) now lists every enabled endpoint with its resolved path. This change turns that list into an OpenAPI document, opt-in, without adding a dependency to the core module.

## What Changes

- **A new nested module, `github.com/kartaladev/scrty/httpsec/openapisec`,** that builds an OpenAPI 3.1.2 document of the enabled built-in endpoints:
  - `openapisec.Enable(...)` serves it publicly at `{base}/openapi.json`, relocatable within the base path;
  - `openapisec.Build(chain, ...)` returns the same bytes without serving them, for a consumer who wants to merge them into their own description or keep them private.
- **Generated dynamically and cached.** The document is built once, eagerly, while `httpsec.New` assembles the chain:
  - a failure (an unreflectable type, a hook error) fails construction;
  - the bytes never change afterwards, so the endpoint answers with an `ETag` and `304`.
- **Accurate by construction.** Each operation is derived from what the chain actually does:
  - paths, under the base path;
  - request fields, with the names the consumer configured;
  - security schemes, from the enabled authenticators;
  - the refusal statuses each endpoint can return;
  - default response schemas, reflected from the structs the default responders encode, never written by hand.
- **A replaced response is never misdescribed.** When a consumer replaces a responder, its schema comes from one of three tiers, or is dropped:
  1. **Inferred:** a new typed JSON form of each responder. The consumer returns a Go value, the library writes it, and its type is the schema.
  2. **Declared by type:** the consumer names a Go type for an operation's response. No schema is written by hand.
  3. **The hook:** a final document hook edits anything else.

  With none of them, the operation keeps its status and says the application defines the body.
- **Error bodies are declared, never guessed.** By default each refusal status is listed with no content, which is what the library's default rendering sends. A consumer whose error rendering writes a body declares its type once. On gin and fiber the framework renders errors, so the chain cannot infer this.
- **Begin steps with a method-owned shape** (an MFA method's begin data, passkey options) are described by the method, through an optional interface. The WebAuthn module implements it.
- **Schemas are reflected with `github.com/invopop/jsonschema`,** inside the nested module only.

## Capabilities

### New Capabilities

- `openapi-document`: the generated document and what it contains:
  - building, caching and serving it, and building it without serving;
  - the response tiers, error bodies and the document hook;
  - the version and schema dialect.

### Modified Capabilities

- `http-security-chain`:
  - the typed JSON form of each replaceable responder;
  - the inventory's request, response and refusal descriptors;
  - a named slot for the document endpoint;
  - a hook that lets a registered interceptor finish building once the chain is assembled.
- `multi-factor-auth`: a challenge method may describe the shape of its begin data.
- `passkey-authentication`: the passkey verifier may describe the shape of its begin options.
- `module-layout`:
  - `httpsec/openapisec` joins the listed integration modules;
  - the core module must not require `github.com/invopop/jsonschema`.

## Impact

- **New module:** `httpsec/openapisec`, requiring the root module and `github.com/invopop/jsonschema`. Its write-only document model is the module's own. No third-party type appears in its exported API.
- **Code:**
  - `httpsec`:
    - typed JSON responder options;
    - inventory descriptors;
    - `OrderOpenAPI`;
    - the post-assembly hook.
  - `authenticate/mfa` and `authenticate/passkey`: the optional describing interfaces.
  - `authenticate/passkey/webauthn`: their implementation.
- **Tests:**
  - in `test`:
    - generated documents validated with `github.com/pb33f/libopenapi`;
    - each default responder's real output validated against its reflected schema;
    - each endpoint's observed refusal statuses checked against those it declares;
  - conformance on net/http, gin and fiber.
- **Docs:** a README section on the document, its tiers, and the `jsonschema` struct-tag convention for consumer types.
- **Builds on** `endpoint-inventory-base-path`. Can run beside `observability`.
- **No schema change.**
