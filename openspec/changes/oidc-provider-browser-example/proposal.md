# Proposal

## Why

Nothing in scrty has run in a real browser. The session stream's Fetch Metadata and `Origin` checks, its `EventSource` behaviour and the provider's cookies are proved only by Go tests, which send whatever headers the test writes. The OpenID conformance suite drives the provider with HtmlUnit, which is not a real browser. So it is unverified what a browser really sends, and what a cross-site page can learn from a stream's answers. A consumer also has no runnable example of a provider built on `oidcprovider`.

## What Changes

- **`examples/oidc-provider`**, a runnable, generic, unbranded OpenID Provider built on `oidcprovider` and `httpsec`, with session signals on, in a nested module that is never published.
- **Real-browser tests** beside it, driving Chromium, Firefox and WebKit through the example, behind a gate so `make test` needs no browser.
- **A `browser` CI job**, required by `ci-ok`.
- **A new promise, pending proof:** a cross-site page learns nothing about a sign-in from the stream's answers.

**"Generic" is taken to mean** a plain OpenID Provider a consumer can read and copy: no brand, no product domain, standard endpoints, and clients and users set by flags or a small file, usable by any standards-following relying party. It is not an example tied to one provider such as Keycloak, and not a client of one. The user may correct this reading.

## Capabilities

### New Capabilities
- `oidc-provider-example`: what the example provides, and what is checked in real browsers.

### Modified Capabilities
- `session-signals`: a cross-site page learns nothing from the stream's answers.
- `module-layout`: an example module, unlisted as an integration and never published.

## Impact

- **New module:** `examples/oidc-provider`, in `go.work`, holding `playwright-go` and its driver. No other module depends on it, and the core gains nothing.
- **Layout guards:** `layout_guard_test.go` gains an example list beside `integrationTable`.
- **`Makefile`:** a `browser-test` target outside `make check`, with `sbom` and the release gate skipping the example.
- **CI:** one more job, with pinned actions.
- **Library code:** none planned. If a browser check fails, that is a defect for its own fix.
- **The Node harness** in the scratch tools directory is replaced by a check that runs the README's snippets against a real server.

## References

See `design.md`.
