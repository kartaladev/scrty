# Proposal

## Why

scrty's layout and names make it hard to read:

- **Too many root directories.** About 36 directories sit at the root of the repository, and 25 of them are public packages. They mix three levels of abstraction in one flat list: domain concepts (`session`, `policy`), login methods (`passkey`, `magiclink`), and plumbing (`storeerr`, `expiry`, `migrate`). Some are tiny: `storeerr` holds one sentinel.
- **Scattered files inside packages.**
  - `httpsec` has 60 production files and 153 test files.
  - Its `options.go` is 2,659 lines and holds the options of ten features, while four other features keep theirs beside them.
  - Feature families are spelled three ways: glued (`mfaenrolconfirm`), underscored (`oidc_callback`) and mixed (`mfabegin_race`).
  - One unit's tests are spread over up to eleven scenario files.
  - Satellite files under 100 lines sit apart from the code they serve.
- **Names that do not say what a type is.**
  - Nine packages name their main type `Manager` (`oidc.Manager`, `oidc.HandoffManager`, `signingkey.KeyManager` and others).
  - A few outliers break rules the rest of the API follows: `JwtOption`, `GetSigner`, `token.VerifyWith…`, and `ErrMFAEnrollmentRequired` beside "Enrolment" everywhere else.
- **Names that do not say what they bound.** `lockout.WithCap(100)` does not say what is capped, in a package that also has a threshold, a ceiling, a window, waits and a store capacity. A sweep of the public API on 2026-10-31 found about thirty such names, and the same idea spelled several ways across packages: TTL, Lifetime and Timeout; Limit, Max, Cap, Ceiling and Capacity.
- **What a security review of PR #27 proved.** A review on 2026-10-31 made nine claims. Each was then tested in a disposable copy of the tree, and four are defects or unsafe defaults that a failing test shows:
  - an API key keeps authenticating after the user it was issued for is deactivated, and the chain offers no way to check;
  - `token.NewVerifier` checks neither issuer nor audience unless told to, so a token minted for one service verifies at another that shares its keys;
  - a user-store outage during a password login is counted as a failed login, so under a consecutive-failure limit an outage places holds on real accounts that never expire;
  - twenty concurrent wrong recovery codes all reach the store against a limit of five, because the limit is checked and recorded in two steps.

  A fifth, the shared `storekit.Column`, lets any caller put text into a SQL statement. No caller does today; the type this change introduced made it possible.

Nothing is tagged yet and there are no consumers, so moving and renaming public packages, and changing these defaults, is free now. It becomes a breaking change at `v0.1.0`. This change therefore lands before `release-readiness` tags the first release. Its moves and renames change no behaviour; the security fixes change only what the review proved.

## What Changes

**BREAKING** for import paths and exported identifiers, and for the four behaviours the security review proved. The moves and renames change no behaviour.

- **Directories regrouped by concept.** The root drops from about 36 directories to 18. A parent directory is a real package wherever one exists.
  - Under `authenticate/`: `factor`, `password`, `apikey`, `magiclink`, `oidc`, `passkey` (with the nested module `passkey/webauthn`), and `mfa`.
  - Under `token/`: `signingkey` and `onetime`.
  - `policy` is split: the account-lockout group becomes `policy/lockout`.
  - `storeerr` becomes the parent package `store`. Under it: `sqlstore`, `migrate`, `seal`, and the nested modules `pgxstore` (was `pgx`) and `gormstore` (was `gorm`).
  - The Redis limiter module moves to `ratelimit/redisstore` (package `redisstore`, was `scrtyredis`).
  - The scheduler module moves to `expiry/sweep`.
  - The framework adapters move to `httpsec/ginsec` and `httpsec/fibersec`.
  - Unchanged: `identity`, `authorize`, `session`, `recovery`, `ratelimit`, `outbound`, `notify`, `pkg/`, `internal/`, `test/` and `tools/`.
- **Files consolidated into feature families inside every package.**
  - Files are named `<concept>_<aspect>.go`.
  - Each feature's options sit beside that feature. `httpsec/options.go` keeps only the chain-level options.
  - A production file under about 100 lines folds into its family's main file.
  - One test file per production file. Scenarios become table cases or subtests, and harnesses fold into the test file they serve.
  - Generated mocks, example tests and `export_test.go` keep their own files.
  - Shared code is filed by what it is, for example the login tail every feature uses.
- **Identical helpers in the three SQL backends move into `internal/storekit`.** This covers `bestEffort`, `checkUser`, `parseUserID`, `survivingRoles`, the detached-error family with its SQLSTATE filter, and `sqlStater`, and the partial user UPDATE that `sqlstore` and `pgxstore` both build. Each backend keeps its own transaction context key, because a shared key would let one backend see another's transaction.
- **`Manager` removed from every type name.**
  - `oidc.Manager` → `RelyingParty`
  - `oidc.HandoffManager` → `Handoff`
  - `authenticate.Manager` and `authorize.Manager` → `FirstOf`
  - `session.Manager` → `Sessions`
  - `passkey.Manager` → `Passkeys`
  - `signingkey.KeyManager` → `Keys`
  - `apikey.Manager` → `Keys`
  - `onetime.Manager` → `Tokens`
  - `magiclink.Manager` → `Links`

  Their constructors and option types follow the new names. Where a package has one main type, its constructor is `New`.
- **Outlier names corrected:**
  - initialisms (`JWT…`);
  - getter prefix (`Signer`);
  - spelling (`ErrMFAEnrolmentRequired`, `UnavailableFallbackToLocal`, `NormalizeName`);
  - the shared sentinel name (`seal.ErrConfig`);
  - option form (`token.WithVerify…`);
  - structs that read as constructors (`identity.UserChange`, `passkey.CredentialInput`);
  - sibling consistency (`LimiterFactory`, `NewMemoryKeyStore`, `UserVerificationRequired`).
- **Naming rules applied across the API:**
  - Sentinel errors drop the package noun (`session.ErrNotFound`, `password.ErrTooLong`, `token.ErrInvalid`, `policy.ErrDenied`).
  - Policy types drop the `Policy` suffix (`policy.IdleTimeout`, `policy.ConcurrentSessions`, `policy.PasswordAge`, `lockout.Policy`).
  - Options are `Option`/`With<Thing>` in a package with one configurable type, and `<Type>Option`/`With<Stem><Thing>` where several types share a package.
  - Typed enum constants carry their type's prefix.
- **Names say what they bound.**
  - The lockout family names the consecutive-failure limit after the record it already keeps: `WithFailureStreakLimit`, `NISTFailureStreakLimit`, `WithFailureStreakRetention`. Its threshold, ceiling, window and store capacity follow (`WithWaitThreshold`, `WithWindowFailureLimit`, `WithFailureWindow`, `WithAttemptStoreMaxIdentifiers`).
  - About twenty more names in `passkey`, `recovery`, `token`, `signingkey`, `onetime`, `policy`, `mfa`, `oidc`, `notify` and `httpsec` gain the noun they lacked.
  - One vocabulary across the API: Limit for a count per subject, `Max<Entity>` for a container's size, never Cap, Ceiling or Capacity; Timeout for how long to wait for something, and for the session deadlines OWASP calls idle and absolute timeouts; Lifetime for how long one issued key, token or session lives; TTL for how long a one-time artifact stays redeemable; `…LogInterval` for every log sampler.
- **Security review fixes:**
  - `storekit.Column` can no longer carry an arbitrary column name: the SQL backends build columns only through `storekit`'s own constructors.
  - The `identity.WithUserRoles` godoc says what an empty list does on `Update`, which the spec already requires: nothing.
  - API key authentication can be given a user loader (`httpsec.WithAPIKeyOwners`), and then refuses a key whose user is inactive or gone. Without one it looks nothing up, as now, because a key's principal is the consumer's reference and need not be a user.
  - `token.NewVerifier` requires an issuer and an audience, or an explicit waiver of each (`WithoutVerifyIssuer`, `WithoutVerifyAudience`).
  - A user-store outage during a password login is its own outcome, `authenticate.ErrUnavailable`, answered as a wrong password is. Form login, Basic authentication and a recovery's password proof charge it to the source, never to the username, so an outage never holds an account and reveals nothing about one.
  - The limiter port gains an atomic charge and refund, which every shipped limiter implements. Saved recovery codes charge before the lookup and refund on success, so the limit holds under concurrency.
- **Repository wiring updated to the new paths:**
  - every `go.mod` `replace` directive, `go.work`, and the module directories the layout tests name;
  - the `config.yaml` context;
  - the path references in active changes' artifacts.
- **The test module's HTTP clients stop sharing Go's default transport.** The OIDC login harness's client, the Keycloak browser client and the SMTP helper's message-API reads each get a transport of their own, closed when the test ends. Every `httptest.Server.Close` clears the idle connections of `http.DefaultTransport`, so one parallel test's server shutdown could cut another test's request. CI saw it once on PR #27 (2026-10-29). Test code only; folded into this change on 2026-10-30.

### Not in this change

- **Changes to API shape or behaviour other than the security review fixes.** These go to separate later changes, before `v0.1.0`:
  - `idiomatic-api-shape`: constructors returning concrete types, consistent construction errors for in-memory stores, one lifecycle convention, and the exported mutable `oidc.DefaultScopes`;
  - `key-port-context`: `context.Context` on the key and cipher ports.
- **Any new feature** beyond the options and the limiter methods the security fixes need.
- **Any change to what a test asserts, outside the security fixes.** Assertions move unchanged when tests become table cases. The only text that may change is an error-message prefix, which follows its new package name. The security fixes change the assertions their decisions name, and nothing else.
- **The security review's other claims** (`design.md`, "Review claims not acted on"):
  - an empty role list on `Update` is meant to leave the grants alone, as the identity store spec requires; only the godoc was wrong;
  - the net/http adapter's missing trusted-proxy option is `trusted-proxy-client-ip`'s whole purpose;
  - a full in-memory limiter refusing new sources is its documented fail-closed bound, with an option to raise it;
  - the API key timing claim did not hold: the unknown-key path is the slower one, and every refusal is the same 401.

### Order

1. `fix/stabilize-intermittent-tests` merges (done, and archived). A reliable gate is this change's proof that nothing broke.
2. This change.
3. `idiomatic-api-shape`.
4. `key-port-context`.
5. `trusted-proxy-client-ip`.
6. `release-readiness`.

`minimize-test-containers` changes test code only and may land at any point before `release-readiness`. It is not implemented at the same time as this change, whose moves rewrite the test module's imports.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `module-layout`:
  - the WebAuthn adapter's module path becomes `github.com/kartaladev/scrty/authenticate/passkey/webauthn`;
  - the nested integration modules are named at their new paths, and the workspace may hold no other nested module besides the test and tools modules;
  - the list of modules the core must never require gains the four that the layout guard already refuses (`github.com/redis/go-redis`, `github.com/pressly/goose`, and the testcontainers `postgres` and `redis` modules), at any major version;
  - the supported Go releases become 1.27 and above, matching every `go.mod` and the CI matrix. The text is the one `release-readiness` states for the same requirement, word for word, so whichever change is archived first leaves the main spec as the other expects.

  The last two only bring the spec in line with what the code and CI already enforce.
- `test-provisioning`: an HTTP client a test-module helper builds keeps its connections when another test's server closes, and releases them when its own test ends.
- The security review fixes:
  - `token-issuance`: a verifier enforces an issuer and an audience unless each check is explicitly waived, and construction refuses a verifier with neither;
  - `authentication`: a user-store failure other than "not found" is a distinct unavailable error, not the uniform failure, and costs the same password work;
  - `http-error-propagation`: the unavailable error maps to 401, as a wrong password does;
  - `http-security-chain`: form login and Basic authentication answer an unavailable user store as a wrong password, charge it to the source and never to the username, and charge a client that leaves during the load to the source only;
  - `identity-model`: input a user store cannot represent is "not found", not a load failure;
  - `api-keys`: a consumer can require a key's owner to be an active user;
  - `rate-limiting`: every limiter charges and refunds atomically, and a flow that must hold its limit under concurrency charges first;
  - `account-recovery`: the saved-code limit holds under concurrent presentations.

No other requirement changes. Renames change no spec text, because the specs name behaviour, not identifiers. Behaviour specs that use "manager" as plain English, not as an identifier, keep their wording.

## Impact

- **Code:** every package in the core module, and every nested module (`fibersec`, `ginsec`, `gorm`, `pgx`, `redis`, `sweep`, `passkey/webauthn`, `test`, `tools`). Import paths and exported names change, and files are reorganised. In the test module, the HTTP client helpers in `test/oidc/idp_test.go`, `test/oidc_keycloak_test.go` and `test/testutils.go` take a transport of their own.
- **Module paths:**
  - `passkey/webauthn` → `authenticate/passkey/webauthn`
  - `pgx` → `store/pgxstore`
  - `gorm` → `store/gormstore`
  - `redis` → `ratelimit/redisstore`
  - `sweep` → `expiry/sweep`
  - `ginsec` → `httpsec/ginsec`
  - `fibersec` → `httpsec/fibersec`

  `release-readiness`'s tag prefixes change to match.
- **Security fixes:** `authenticate` (password authenticator), `httpsec` (form login, Basic, API key, the status table), `token` (verifier), `ratelimit` and every shipped limiter (`ratelimit/redisstore`, `store/sqlstore`, `store/pgxstore`, `store/gormstore`) with the limiter conformance suite, `recovery`, `internal/storekit` and its two SQL callers, and `identity`'s godoc. Tests that build a verifier with no issuer or audience gain them; the password authenticator's load-failure case and the chain's outage cases change as `design.md` D18 and D19 state.
- **Proof of no regression** (for the moves and renames; the security fixes prove themselves with red tests, `design.md` D13):
  - the set of test names is the same before and after, mapped through the renames;
  - every former test survives, as itself or as a named table case;
  - no package's coverage drops;
  - test diffs touch only import paths, identifiers, file placement, error-message prefixes, and assertions moved unchanged into table cases;
  - an old-to-new map of every exported identifier is checked against an API diff, so nothing disappears without a successor;
  - an inventory of every top-level declaration, exported or not, survives each phase, apart from the duplicate backend helpers replaced by their shared copy, so no feature is dropped in a file merge;
  - `make check`, including the Docker-backed suites, is green in CI.
- **Dependencies and stored data:** unchanged. **Migrations:** unchanged unless a SQL limiter's atomic charge needs one, which `design.md` D20 avoids.
- **Consumers:** none yet. Nothing is tagged.

## References

### Directory grouping

**Researched (accessed 2026-10-25):**
- [Organizing a Go module](https://go.dev/doc/modules/layout): a module's packages may be structured hierarchically and nested, and supporting packages belong in `internal/`.
- [Go blog: Package names](https://go.dev/blog/package-names): a directory only arranges files and implies no relationship between packages; avoid stutter and catch-all packages.
- [volatiletech/authboss](https://github.com/volatiletech/authboss): a flat layout with one package per feature, considered and not chosen.
- [ory/fosite](https://github.com/ory/fosite): a concept-grouped layout (`handler/oauth2`, `handler/openid`, `token`, `storage`).

### Type names

**Researched (accessed 2026-10-25):**
- [OpenID Connect Core 1.0, Terminology](https://openid.net/specs/openid-connect-core-1_0.html): the component that requests authentication from an OpenID Provider is the Relying Party; OAuth 2.0 clients using OpenID Connect are also called Relying Parties.
- [zitadel/oidc, package rp](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/client/rp): a Go relying party exported as `RelyingParty`.
- [coreos/go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc): a Go OIDC library with no `Manager` type, naming its parts `Provider` and `IDTokenVerifier`.

**Primary documentation:**
- [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments): initialisms, getters, error strings and receiver names.
- [Effective Go: Names](https://go.dev/doc/effective_go#names): getters without `Get`, `-er` interface names, MixedCaps.

### Adapter package names

**Researched (accessed 2026-10-25):**
- [alexedwards/scs](https://github.com/alexedwards/scs): every storage adapter is named `<driver>store` (`pgxstore`, `gormstore`, `redisstore`), which avoids clashing with the driver's own package name.
