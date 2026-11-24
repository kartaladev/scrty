# Design

## Context

See proposal.md - Why. "First-party" appears in two senses across the tree:

- **The token sense**, to be renamed:
  - `token.TypeFirstParty` and its godoc;
  - `validateFirstPartyType` in `token`;
  - the godoc of `token`, `oidcprovider` and `httpsec` where they speak of first-party tokens, the
    first-party type, a first-party verifier or `Generator`, or first-party sessions;
  - the test helper `firstPartyRefused` in `httpsec`;
  - test case names such as "the first-party type";
  - four places in `README.md`;
  - four specs: `token-issuance`, `oidc-provider-tokens`, `oidc-provider-userinfo` and
    `oidc-provider-logout`.
- **The OAuth client sense**, to be kept:
  - `oidcprovider.Client.FirstParty`;
  - the `oidc-provider-consent` and `oidc-provider-clients` specs;
  - `oidcprovider/consent.go`, and the client-related comments in `doc.go`, `endsignin.go` and
    `client.go`;
  - the test fixtures `firstParty`, `firstPartyClient`, `firstPartyRedirect`, `flowFirstParty` and
    `opFirstParty`.

**Terms** this change uses, and the resource-server change uses after it:

| Term | Means |
|---|---|
| **session token** | the signed JWT a `token.Generator` issues at sign-in (`scrty+jwt`), read by `EnableBearerToken` |
| **session reference** | the opaque session identifier issued under `EnableSessionBearer` |
| **sign-in credential** | either of the two: what the chain hands a user who signed in |
| **the sign-in's sessions** | the `session.Session` records a sign-in holds, as opposed to the provider's browser session (`__Host-scrty-op-session`) |

The project is at v0.5.0. While the major version is 0, CHANGELOG.md promises no compatibility, and
each break is stated under *Changed*.

## Goals / Non-Goals

**Goals:**
- One meaning of "first-party" in the tree, the OAuth client meaning.
- The token the chain issues at sign-in is called the session token in code, godoc, specs and the
  README.
- No change on the wire, in storage, or in any behaviour.

**Non-Goals:**
- Renaming `Generator`, `EnableBearerToken`, `EnableSessionBearer` or any other identifier. Only the
  type constant and the helpers named after it change.
- Changing the wire value `scrty+jwt`.
- Touching the OAuth client sense, which follows the standard term.
- Rewording archived changes under `openspec/changes/archive/`, which are a record.

## Decisions

### 1. The name is `TypeSessionToken`

`token.TypeFirstParty` becomes `token.TypeSessionToken`, with the value `scrty+jwt`.

- **Why:**
  - It matches its siblings `TypeAccessToken`, `TypeIDToken` and `TypeLogoutToken`, which all end
    in `Token`.
  - It matches OWASP's term, session token.
  - It names what backs the token: its `jti` is a session's identifier.
- **Alternatives considered:**
  - `TypeSignInToken`: says when the token is issued, but is no established term.
  - `TypeSignIn`: breaks the `...Token` pattern and reads as an event.
  - The user chose `TypeSessionToken`.
- **Default and override:** unchanged. The default type stays `scrty+jwt`. A consumer still
  replaces it with `token.WithTokenType`, and the verifier's with `token.WithVerifyTokenType`.

### 2. The old name is removed, with no deprecated alias

- **Why:**
  - The user asked for removal, so that the old term cannot keep the confusion alive.
  - A deprecated alias would keep "first-party" in the public API and in pkg.go.dev for at least
    one more release.
  - The major version is 0, so a minor release may break the API, as the CHANGELOG states.
- **Alternative considered:** a `// Deprecated:` alias for one release. It was rejected at the
  user's request.
- **What a consumer sees:** a compile error naming `token.TypeFirstParty`. The CHANGELOG entry gives
  the one-line migration. Nothing else changes, so a consumer who compiles runs exactly as before.

### 3. Wording rules for godoc, specs and the README

A mention of "first-party" is renamed only when it refers to the token, the sessions behind it, or
the store that holds them. The test is whether it can be read as "the client the provider trusts":
if it can, it stays. The rewording is applied **per construction**, reading each sentence, never by
substituting a phrase blindly:

| Construction | Becomes |
|---|---|
| first-party token(s) | session token(s) |
| the first-party type | the session token type |
| a first-party verifier / a verifier for first-party tokens | a session token verifier |
| the first-party `Generator` / token generator | the session token `Generator` / generator |
| a first-party, ID or logout token | a session, ID or logout token |
| its first-party sessions | its sessions |
| the sign-in's first-party sessions | the sign-in's sessions |
| the first-party sessions (the sign-in named in the sentence) | its sessions |
| a first-party session | a session of the sign-in |
| the i-th first-party session (`test/storetest`) | the i-th session |
| the first-party store (`httpsec` logout tests) | the chain's session store |
| first-party credential (README, the browser-session section) | sign-in credential |
| first-party client, flag, `Client.FirstParty` | unchanged |

The README's browser-session section (around line 898) describes the provider's browser-session
cookie: "It issues no first-party credential" becomes "It issues no sign-in credential", which is
what that cookie does not do. It does not become "session token", which would make the sentence
false.

The `oidc-provider-userinfo` refusal list is reworded to name the terms without nesting one in
another: "A sign-in credential (a session token or a session reference), an ID token or a refresh
token SHALL be refused."

The inventory below is the complete list, found by a case-insensitive search for `first-party`,
including phrases wrapped across lines, and reviewed line by line on 2026-11-25:

| File | Lines (token sense) |
|---|---|
| `token/config.go` | 29-31 |
| `token/claims.go` | 70-76 |
| `token/generator.go` | 186, 194, 217 |
| `token/verifier.go` | 120, 122, 147 |
| `token/issuer.go` | 20-22, 209 (error text) |
| `token/generator_tokentype_test.go` | 40, 43 |
| `token/issuer_test.go` | 533, 534, 613 |
| `token/verifier_tokentype_test.go` | 91, 103, 144 |
| `token/helpers_test.go` | the comment beside line 145 |
| `oidcprovider/accesstoken.go` | 232 |
| `oidcprovider/doc.go` | 113 (not 208) |
| `oidcprovider/endsession.go` | 51, 69, 110-120 |
| `oidcprovider/endsignin.go` | 39, 87 (not 287) |
| `oidcprovider/accesstoken_test.go` | 933 |
| `oidcprovider/authorize_test.go` | 840 |
| `httpsec/oidc_provider.go` | 479, 491 |
| `httpsec/oidc_endsession.go` | 186-187 |
| `httpsec/oidc_logout_retry_test.go` | 42-47, 117, 135, 145, 188, 226 |
| `httpsec/oidc_logout_read_test.go` | the call to `firstPartyRefused` (renamed by gopls) |
| `httpsec/bearer_tokentype_test.go` | 18, 63 |
| `test/storetest/session_settle.go` | 157 |
| `test/cmd/conformanceop/pages.go` | 300 |
| `README.md` | 898, 944, 949, 954 |

Client sense only, **not touched**: `httpsec/oidc_completion_test.go`, `httpsec/oidc_authorize_test.go`
(`flowFirstParty`), `oidcprovider/endsignin_test.go`, `oidcprovider/consent*.go` and their tests,
`oidcprovider/client.go`, `oidcprovider/doc.go:208`, `oidcprovider/endsignin.go:287`,
`test/httpsecconformance/*` (`opFirstParty`), and `test/migrate_securitystate_test.go`'s
`FirstParty` column map.

### 4. Unexported and test names follow the constant

- `validateFirstPartyType` becomes `validateSessionTokenType`.
- `firstPartyRefused` becomes `sessionTokenRefused`.
- Test case names that say "first-party type" or "first-party token" are reworded by decision 3.
  Renaming a subtest changes its `-run` path. No CI filter names these subtests.

### 5. Renames go through gopls

The identifier renames use `gopls rename` (`gopls-navigation.md`), so every reference, the test
packages included, moves at once. The wording is edited by hand, under decision 3's rules.

## Failure modes

| # | Failure | State | What a caller sees |
|---|---|---|---|
| F1 | A consumer still references `token.TypeFirstParty` | **Accepted**: the break the user asked for. Stated in the CHANGELOG with its migration, and reported by `make release-check` (gorelease), which is accepted for this release | A compile error naming the identifier; nothing at run time |
| F2 | The wire value changes by mistake during the rename | **Tested**: the table cases assert the literal `scrty+jwt` at the generator (`generator_tokentype_test.go:40,43`) and the verifier (`verifier_tokentype_test.go:91`). They stay literal | Without the guard, every token issued before the upgrade would be refused |
| F3 | The issuer stops refusing an `Issue.Type` of the session token type | **Tested**: `TestIssuer_RefusalAsksNoKey/the first-party type` and `…/spelled with the prefix and other case` (`issuer_test.go:533-534`). They are renamed, not removed. (The case at `issuer_test.go:613` guards a different rule, that `NewIssuer` refuses every option, and is not part of this guard) | Without the guard, an `Issuer` could mint tokens a session verifier accepts |
| F4 | A client-sense mention is renamed by mistake | **Handled**: decision 3's test and its "not touched" list; the reviewer checks every changed and every remaining mention | Without the guard, the consent docs would misdescribe the client flag |
| F5 | A token-sense mention is missed, including one wrapped across lines | **Handled**: a case-insensitive search for `first-party` and for `firstparty` (ignoring separators) over the whole tree outside `openspec/` and `.claude/`, plus a multi-line search, whose every hit must be on decision 3's "not touched" list | Without the guard, the leftover term keeps the confusion alive |
| F6 | The issuer's error text changes ("does not issue session tokens") | **Accepted**: no test or settled spec asserts the text; the error's identity (`ErrConfig`) is the contract and is unchanged. Stated in the CHANGELOG | A different message for the same error |
| F7 | The reworded prose reads wrongly ("the the sign-in's sessions") | **Handled**: decision 3 is applied per construction, and the review reads every changed sentence | Without the guard, garbled godoc |

There is no failure at run time to consider: no behaviour, data or dependency changes.

## Risks / Trade-offs

- [Three scenario titles in `token-issuance` keep "first-party": "First-party token", "Access
  token at a first-party verifier" and "ID token at a first-party verifier"] → OpenSpec cannot
  rename a scenario inside a MODIFIED requirement: its validation refuses a block that drops a
  scenario name, and a renamed title counts as dropped (confirmed with `openspec validate --strict`
  1.17.0). Their requirement text and steps say "session token", so the titles are the only
  leftover. **Accepted**, and stated in the CHANGELOG entry so that a reader of the spec is not
  misled; retitling them needs a REMOVED-and-ADDED requirement, which loses its history.
- [The rename touches many files for a wording fix] → Every edit is mechanical or listed in
  decision 3's inventory, and the existing suites cover each renamed identifier.
- [Other v0.6.0 changes touch the same files] → `resource-server` (PR #151) and
  `fold-migrations-callback-server-error` (PR #149) both add entries under `CHANGELOG.md`'s
  *Unreleased*, so a conflict there is certain; #149 also touches README.md, test files and store
  godoc. This change merges first, and each later change merges its CHANGELOG entries by hand into
  one `### Changed` and one `### Added`. `resource-server` uses this change's terms from the start;
  its implementation rebases onto this change and uses `token.TypeSessionToken`.

## Migration Plan

For consumers, stated in the CHANGELOG:

```go
// before
token.WithVerifyTokenType(token.TypeFirstParty)
// after
token.WithVerifyTokenType(token.TypeSessionToken)
```

There is no data or wire migration. Rolling back means restoring the old constant name.

## References

**Researched** (consulted 2026-11-25):
- Reasoned from scrty's own settled specs and code: `token/config.go:29-41` (the type constants),
  `oidcprovider/client.go:197-198` (`Client.FirstParty`, the OAuth sense), the `token-issuance`,
  `oidc-provider-consent` and `oidc-provider-clients` specs, and `CHANGELOG.md`'s compatibility
  statement. Supports decisions 1–3.
- The user's choice of `TypeSessionToken` and of removal without an alias, 2026-11-25. Supports
  decisions 1 and 2.

**Primary documentation** (relied on and cited as such, not re-checked on this date):
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html):
  "session ID or token" as the term for the credential an application issues to its signed-in
  users. Supports decision 1.
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068): the `at+jwt` type, the sibling the naming
  pattern follows. Supports decision 1.
