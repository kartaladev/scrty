# Design

## Context

See proposal.md for the motivation.

- **The inventory** (`endpoint-inventory-base-path`) lists each enabled endpoint's methods, resolved path, segment parameters, operation identifier, enabling option and required session state. It does not yet carry request, response or refusal shapes.
- **Responders are plain functions.** The 17 replaceable responders are `func(*Exchange, R) error` and write to `ex.Writer`. A Go function value is opaque: it cannot be inspected and closures cannot be compared. Fourteen of them write a JSON result. Two pass through raw JSON whose shape belongs to the method (`MFABeginResponder`, `PasskeyBeginResponder`). One redirects (`CallbackSuccess`).
- **Errors are not rendered by the chain on every adapter.** With nothing wired, a refusal is a bare status with no body. On net/http, `WithErrorHandler` renders refusals. On gin and fiber, refusals go to the framework's error handling and `WithErrorHandler` does not run.
- **Some shapes come from configuration.** `WithLoginParams` renames form fields. The API key header is configurable. The bearer mode is either a JWT or a session reference.
- **The core module stays lean.** `module-layout` keeps protocol libraries in nested modules.
- **Method names are not secret.** The set of methods is configuration (the `ErrUnknownMFAMethod` godoc).

## Goals / Non-Goals

**Goals:**
- A document that is exact for the enabled endpoints, and never states a shape the library cannot vouch for.
- Inference wherever a Go type is available, and no hand-written schema anywhere the library owns.
- Opt-in, with no new dependency in the core module.

**Non-Goals:**
- Describing the consumer's own routes or interceptors. The consumer merges `Build`'s output into their own description.
- Validating requests against the document at runtime.
- A UI (Swagger UI, Redoc) or CORS for cross-origin viewers. Both are the consumer's.

## Decisions

### D1. A nested module, joined to the chain at assembly

```go
// core, httpsec
const OrderOpenAPI Order = 150

// BuildHook is implemented by a registered interceptor that needs the
// assembled chain. New calls each one, in slot order, after assembly; an
// error fails New.
type BuildHook interface{ ChainBuilt(c *Chain) error }

// nested module, httpsec/openapisec
func Enable(opts ...Option) httpsec.Option // registers the endpoint at OrderOpenAPI
func Build(c *httpsec.Chain, opts ...Option) ([]byte, error)
```

- **Placement.** The generator, its document model and the schema reflector live in `httpsec/openapisec`. The core only describes endpoints and records Go types (D5, D6).
- **The core cannot call into the nested module, so it offers a seam.**
  - `BuildHook` is implemented by the endpoint `Enable` registers.
  - `New` calls it with the assembled chain, which is where the document is built.
  - A build failure is a construction error.
  - The hook is general: a consumer interceptor that needs the assembled chain can implement it.
- **Build without serving.** `Build` produces the same bytes from a chain that was built without `Enable`.
- **Consequence of the nested module:** the `(*Chain).OpenAPI()` accessor discussed during exploration becomes `openapisec.Build`. The core cannot return a document it does not know how to build.
- **Alternative rejected: the generator in the core.** invopop's dependencies would land in every consumer's module graph, including consumers who never enable the document. They include a pre-release YAML module.

### D2. Served publicly, built once

- **Slot.** `OrderOpenAPI` (150) is just inside the key set (100) and outside every authenticator and the authorization stage. A stale credential cannot refuse it, and no rule set covers it.
- **Path.** `/openapi.json`, joined to the base path. It is relocatable with `WithPath`, within the base. It answers GET and HEAD.
- **Cache.** The bytes are built once in `New` and are immutable afterwards, because the chain's endpoints never change after assembly. Responses carry a strong `ETag` and answer `If-None-Match` with `304`. The content type is `application/json`.
- **Default:** public, because the document lists configuration, not secrets. **Override:** a consumer who wants it private does not call `Enable`, calls `Build`, and serves the bytes behind their own route.
- **Alternatives rejected:**
  - *Behind the authorization stage.* That would protect it under a default-deny rule set, but you chose a public endpoint.
  - *Lazy building.* It defers a hook or reflection failure to the first request, against `library-design` rule 6.

### D3. OpenAPI 3.1.2

- **What we emit.** The document states `openapi: 3.1.2`, the latest 3.1 patch, with JSON Schema 2020-12 as the schema dialect.
- **Why not 3.2.** 3.2 breaks nothing in a 3.1 document. Its additions (`QUERY`, `additionalOperations`, `querystring` parameters, streaming media types, tag hierarchies, device flow) cover nothing scrty needs. Tooling has supported 3.1 for longer.
- **Override:** the document hook may restamp the version. Moving to 3.2 later is a one-line change.

### D4. Our own write-only document model

- **The model belongs to the module.** It covers only what the generator writes: info, servers, paths, operations, parameters, request bodies, responses, components (schemas, security schemes), security requirements and tags. Schemas inside it are 2020-12 JSON values.
- **The hook sees this model.** It is the module's own type, so no third-party type enters the exported API. This follows the `module-layout` rule for the WebAuthn library.
- **Defaults:**
  - `info.title` is "Security endpoints" and `info.version` is "1", both neutral and replaceable with `WithInfo`;
  - no `servers` entry, so clients resolve against the origin that served the document;
  - `WithServer(url)` declares a public URL, for a proxy that strips a prefix (see `endpoint-inventory-base-path` D6);
  - one tag per feature.
- **Alternative rejected: a full OpenAPI library** (`getkin/kin-openapi`, `pb33f/libopenapi`). Its v0 types would enter the hook API, or the module would convert at its boundary. kin-openapi also carries 19 OSV entries, not triaged.

### D5. Schemas are reflected with invopop/jsonschema

- **Why invopop over google/jsonschema-go.** Compared from both libraries' source, 2026-11-01:
  - invopop emits `$defs` and `$ref`, so named Go types become `components/schemas`, recursive types work, and generated clients get named types;
  - it reads 36 constraint keywords from struct tags (`enum`, `format`, `pattern`, length and range bounds, `default`, `example`, `readOnly`, ...);
  - a type can describe itself through `JSONSchema()` or `JSONSchemaExtend()`;
  - google's library inlines every type, refuses recursive types, and reads only a description from its tag. It is the cleaner dependency (standard library only) and returns errors, but for a document consumers generate clients from, completeness wins.

  Performance does not decide it: each type is reflected once, in `New`.
- **invopop returns no error, so the module validates what it gets.** Each reflected schema is checked (for example, no empty schema where a struct was given). A failure fails `New`, naming the operation and the type.
- **The tag convention is a documented contract.** A consumer's response type uses invopop's `jsonschema` struct tags for constraints. The README documents this as optional.
- **A type with its own `MarshalJSON`** is described by its `JSONSchema()` method or by a declaration (D6). Otherwise it is documented as a type the reflector cannot see through.
- **Library defaults are reflected too.** The unexported document structs the default responders encode (`loginDocument`, `methodListingDocument`, `reauthMethodsDocument`, ...) are recorded as their endpoints' response types. Their schemas cannot drift from the code.

### D6. Responses: three tiers, or no schema

| Tier | How | Schema |
|---|---|---|
| Default responder | nothing | reflected from the library's own document struct |
| Typed JSON form | `httpsec.With<Feature>JSONResponse(status, func(*Exchange, R) (T, error))` | reflected from `T`, recorded in the core |
| Declared by type | `openapisec.WithResponse[T](operationID, status)` | reflected from `T` |
| Document hook | `openapisec.WithCustomizer(func(*Document) error)` | whatever the hook writes |
| Plain responder, nothing declared | `With<Feature>Responder(fn)` | none: status kept, described as "defined by the application" |

- **The typed form.** Fourteen generic siblings, one for each responder that writes a JSON result (`WithLoginJSONResponse`, `WithReauthenticationJSONResponse`, ...):
  - the consumer's function returns a value, and the library writes it as JSON with the status given;
  - Go infers `T` at the call site;
  - the core records `reflect.TypeFor[T]()` in the endpoint's response descriptor, with no dependency;
  - the MFA listing's responder is a setting of `WithMFAMethodListing`, so its typed form is the setting `ListingJSONResponse`;
  - a status outside 200–299 is refused at construction: a typed form describes a success, and a refusal belongs to an error.
- **Precedence.** Hook, then declaration, then typed form, then default. A declaration overrides an inferred schema for the same operation and status.
- **Runtime inference is rejected.** It would read live responses, which carry access tokens and recovery codes. The document would change after it was published, breaking its `ETag` and any client generated from it. And one sample cannot show optional fields or other branches.
- **Alternative rejected: change the 17 responder options to accept an interface.** It is breaking and free before the first tag, but every existing call site would need an adapter. The typed siblings are additive.
- **Alternative rejected: keep advertising the default schema after a replacement.** That is silently wrong, against `library-design` rule 4.

### D7. Refusals and error bodies

- **Statuses.** Each endpoint's inventory entry lists the refusals it can return. Their statuses come from `StatusForError`'s table, so the document and the mapping cannot disagree. Each becomes a response with a description and, by default, no content.
- **Error bodies.** `openapisec.WithErrorBody[T](mediaType)` declares the type of the consumer's error body, for example RFC 9457 `application/problem+json`. It then becomes the content of every refusal response.
- **Stated limit.** The chain cannot see how refusals are rendered: on gin and fiber the framework renders them. The default document describes the library's default rendering, and the godoc says that a consumer whose rendering writes a body must declare it.

### D8. Requests, parameters and security

- **Request bodies** use the configured field names and the media types each endpoint accepts. For example, login accepts a form and JSON, with the names set by `WithLoginParams`.
- **Path segments** become path parameters. A segment naming a configured method or provider carries an `enum` of the configured names, consistent with "the set of methods is configuration, not a secret".
- **Security schemes** come from the enabled authenticators: `http`/`basic` for Basic; `http`/`bearer` for bearer, with `bearerFormat: JWT` in token mode; `apiKey` in the configured header. Each operation's `security` follows its inventory entry's required session state. Login and recovery start have none.

### D9. Begin data the method owns

- **An optional describing interface** on `mfa.ChallengeMethod` and on the passkey verifier returns the Go type, or a 2020-12 schema value, of the begin data.
- **Who implements it.** The `authenticate/passkey/webauthn` module implements it for WebAuthn's credential options, without exposing its library's types.
- **Fallback.** A method that does not implement it leaves the operation without a schema, as in D6's last row.

### D10. Verification

- **The test module validates each generated document** with `github.com/pb33f/libopenapi`, which supports 3.1 and 3.2 and had no OSV entries on 2026-11-01. That covers a minimal chain, a full chain, and a chain with a base path.
- **Each default responder's real output** is validated against the schema reflected for it.
- **Each endpoint's refusal tests** assert that every status observed is one the endpoint declares.
- `libopenapi` lives only in the test module, as `module-layout` allows.

## Risks / Trade-offs

- **invopop silently produces a wrong schema for an exotic type.** → D5's check of what it returns, D10's validation of default outputs, and the declaration tier as the consumer's fix.
- **invopop's v0 API, or its dependency on a pre-release YAML module, changes.** → It is pinned and confined to the nested module's internals. The core never sees it.
- **Fourteen typed siblings enlarge the API.** → They are additive, uniform, and documented once. The alternative breaks every responder call site.
- **The public document discloses enabled methods and paths.** → This is consistent with scrty's stance that configuration is not secret. `Build` is the private alternative.
- **A consumer's error rendering differs from what they declared.** → This is a stated limit. The document describes what is declared.

## Migration Plan

Nothing to migrate: the document is opt-in. A consumer:

1. Adds `httpsec/openapisec`.
2. Calls `openapisec.Enable(...)` or `openapisec.Build(chain, ...)`.
3. Declares error bodies and replaced responses as they need.

## References

### Researched (accessed 2026-11-01)

**D3: the version**
- [OpenAPI Specification versions](https://spec.openapis.org/oas/): 3.1.2 is the latest 3.1 patch and 3.2.1 the latest 3.2 patch.
- [Upgrading from OpenAPI 3.1 to 3.2](https://learn.openapis.org/upgrading/v3.1-to-v3.2.html): 3.2 introduces no breaking changes, and lists its additions.
- [Swagger launches support for OpenAPI 3.2.0](https://swagger.io/blog/swagger-launches-support-for-openapi-3-2-0/): Swagger's tooling added 3.2 in April 2026.

**D4, D5: the model and the reflector.** Figures were read live and drift.
- [invopop/jsonschema](https://github.com/invopop/jsonschema) (`reflect.go`, `go.mod`): `$defs`/`$ref`, 36 tag keywords, self-describing types, `Reflect` without an error. Depends on `pb33f/ordered-map`, `generic-list-go`, `jsonparser`, `yaml.v3` and `yaml/v4` v4.0.0-rc.2. 965 stars, v0.14.0 (April 2026), no OSV entries.
- [google/jsonschema-go](https://github.com/google/jsonschema-go) (`jsonschema/infer.go`, `jsonschema/doc.go`, `go.mod`): inlined inference that refuses recursive types, a description-only tag, `TypeSchemas` overrides, 2020-12 and draft-07 validation, and nothing outside the standard library. 484 stars, v0.4.3 (April 2026), no OSV entries.
- [getkin/kin-openapi](https://github.com/getkin/kin-openapi): 3.1 support, 3.2 partial, v0.152.0, 19 OSV entries (not triaged).
- [pb33f/libopenapi](https://github.com/pb33f/libopenapi): 3.0, 3.1 and 3.2, v0.41.8, no OSV entries. Chosen as the test validator (D10).
- [swaggest/openapi-go](https://github.com/swaggest/openapi-go): reflection to 3.0 and 3.1, v0.2.61.
- [OSV query API](https://api.osv.dev/v1/query): the vulnerability counts above.

**D2, D6, D7, D8: placement, tiers, errors, security**
- Reasoned from scrty's own settled specs (`http-security-chain`, `http-error-propagation`, `framework-adapters`, `module-layout`, `multi-factor-auth`) and the decisions taken while exploring this change.

### Primary documentation

- [OpenAPI Specification 3.1.2](https://spec.openapis.org/oas/v3.1.2.html): the document format emitted.
- [JSON Schema 2020-12](https://json-schema.org/draft/2020-12): the schema dialect of OpenAPI 3.1.
- [RFC 9457: Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457.html): the example error body in D7.
- [RFC 9110 §8.8.3 and §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html): `ETag` and `If-None-Match`, for D2.
