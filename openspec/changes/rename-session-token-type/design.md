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

A mention of "first-party" is renamed only when it refers to the token or the sessions behind it.
The test is whether it can be read as "the client the provider trusts": if it can, it stays.

| Was | Becomes |
|---|---|
| first-party token(s) | session token(s) |
| the first-party type | the session token type |
| first-party verifier | session token verifier |
| first-party `Generator` / token generator | session token `Generator` / generator |
| first-party credential | session token |
| first-party session(s) | the sign-in's session(s), or session(s) where the sign-in is already named |
| first-party client, flag, `Client.FirstParty` | unchanged |

"The sign-in's sessions" is the wording the `oidc-provider-logout` spec already uses in its
scenarios, so the requirement text now agrees with them.

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
| F1 | A consumer still references `token.TypeFirstParty` | **Accepted**: the break the user asked for. Stated in the CHANGELOG with its migration | A compile error naming the identifier; nothing at run time |
| F2 | The wire value changes by mistake during the rename | **Tested**: the existing table cases assert the literal `scrty+jwt` at the generator (`generator_tokentype_test.go`) and the verifier (`verifier_tokentype_test.go`). They must stay literal, not be rewritten to the constant | Without the guard, every token issued before the upgrade would be refused |
| F3 | The issuer's reserved-type check stops refusing the session token type | **Tested**: the issuer tests that refuse `Issue.Type` and `WithTokenType` set to the session token type already exist (`issuer_test.go`). They are renamed, not removed | Without the guard, an `Issuer` could mint tokens a session verifier accepts |
| F4 | A client-sense mention is renamed by mistake (e.g. `Client.FirstParty`, consent text) | **Handled**: decision 3's test, and the review step checks every remaining and every changed mention | Without the guard, the consent docs would misdescribe the client flag |
| F5 | A token-sense mention is missed | **Handled**: a final search for `TypeFirstParty`, `first-party token`, `first-party type`, `first-party session` and `first-party credential` (case-insensitive, outside `openspec/` and `.claude/`) must come back empty. The specs are covered by this change's deltas instead | Without the guard, the leftover term keeps the confusion alive |
| F6 | `README.md` or the CHANGELOG still uses the old name | **Handled** by F5's search, which covers Markdown | Consumers follow stale docs |

There is no failure at run time to consider: no behaviour, data or dependency changes.

## Risks / Trade-offs

- [Three scenario titles in `token-issuance` keep "first-party": "First-party token", "Access
  token at a first-party verifier" and "ID token at a first-party verifier"] → OpenSpec cannot
  rename a scenario inside a MODIFIED requirement: its validation refuses a block that drops a
  scenario name, and a renamed title counts as dropped. Their requirement text and steps say
  "session token", so the titles are the only leftover. **Accepted**: retitling them needs either a
  REMOVED-and-ADDED requirement, which loses the requirement's history, or a later OpenSpec that
  supports scenario renames.

- [The rename touches many files for a wording fix] → Every edit is mechanical, and the existing
  suites cover each renamed identifier. The scoped test run covers `token` and every package that
  depends on it.
- [The open `provider-resource-server` proposal (PR #117) and its branch still say "first-party"] →
  That change is on hold and will be revised anyway. Its revision uses "session token".
- [Another session's branch, `fix/fold-migrations-callback-server-error`, may touch the same
  files] → That branch is limited to `store/migrate/`, the migration tests and the callback mapping
  in `httpsec/oidc_login.go`. None holds a mention in scope. Whichever merges second rebases.

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
