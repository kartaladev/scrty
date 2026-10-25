# Design

## Context

See `proposal.md` (Why) for the motivation. The facts below shaped the approach. Counts are as of 2026-10-25.

- **The import graph.**
  - `httpsec` imports 24 core packages.
  - `passkey` and `recovery` import `mfa`, `session`, `policy` and `onetime`.
  - `factor` imports nothing, by design: its doc makes it the import-free owner of the first-factor vocabulary.
  - In Go a parent directory is only a namespace. Nesting a package changes its import path and never its import edges.
- **The lockout group in `policy` is self-contained.** It is made up of `lockout.go`, `lockout_error.go`, `lockout_observer.go`, `attempts.go`, `streak.go` and `LockoutExpiryTask` in `expiry.go`. The rest of `policy` reaches it through one edge only: `Engine.RequiredAttemptViews`, which uses `AttemptViewRequirer` and `RequiredAttemptView` from `attempt_views.go`.
- **`httpsec` is one package of 60 production files and 153 test files.** About 30 of the test files are generated mocks. Its `options.go` (2,659 lines) holds the chain core (configuration, `New`, the build and the chain-level options) and the `Enable…` function and option set of ten features. oidc, recovery, passkey and MFA enrolment keep theirs in their own files.
- **No `httpsec` feature group can become a sub-package** without first moving its shared machinery (`config`, the login tail, the source throttle, the request readers) into an internal package. `Option` is `func(*config) error` over an unexported `config`.
- **The three SQL backends repeat helpers with identical bodies:** `bestEffort` (also in `storekit`), `checkUser`, `parseUserID`, `survivingRoles`, `dbFailed`, `detachedError`/`detachedText`, `errPasskeyHandleHeld`, `errStreakContended`, `txKey`, `optionKind` and `sqlStater` (also in `internal/pglimiter`).
- **Error strings are prefixed with their package name** (`"pgx: …"`, `"policy: …"`, `"scrtyredis: …"`). The tests assert on some of these texts.
- **Docker is not available in the planning session.** The testcontainers suites under `test/` run in CI.

## Goals / Non-Goals

**Goals:**
- **Every move and rename is mechanical, and checkable after the fact.** Each one comes with a before-and-after inventory that a script compares.
- **Each dispatch fits one lane's file ownership.** Phases that touch callers across packages run in one lane; phases confined to one package run in parallel.

**Non-Goals:**
- **No default changes and no behaviour changes.** Every option and port keeps its default. A renamed option's godoc still names the default it replaces. `library-design`'s requirement to state the default and the override does not arise, because no decision here introduces or changes behaviour.
- **No change to the test module's own layout.** `test/` keeps its sub-packages (`test/pgxstore`, `test/sqlstore`, …) and file layout. Only its imports and the names it references change.
- **No consolidation of generated mocks.** Each one stays `<source>_mock_test.go`, produced by its `//go:generate` directive, as `use-mockgen` requires.
- **None of `idiomatic-api-shape`'s items** (see `proposal.md`, Not in this change).

## Decisions

### D1. Concept directories, with a real package as the parent where one exists

The parents are `authenticate`, `token`, `policy`, `store`, `expiry`, `httpsec` and `ratelimit`, each of which already exists as a package or becomes one (`store`). This follows the standard-library pattern (`crypto` → `crypto/ecdsa`, `net/http` → `net/http/httptest`).

| Today | Target import path (under `github.com/kartaladev/scrty/`) | Package |
|---|---|---|
| `factor` | `authenticate/factor` | `factor` |
| `password`, `apikey`, `magiclink`, `oidc`, `mfa` | `authenticate/<name>` | unchanged |
| `passkey` | `authenticate/passkey` | `passkey` |
| `passkey/webauthn` (module) | `authenticate/passkey/webauthn` (module) | `webauthn` |
| `signingkey`, `onetime` | `token/<name>` | unchanged |
| lockout group of `policy` | `policy/lockout` | `lockout` (D3) |
| `storeerr` | `store` | `store` (D4) |
| `sqlstore`, `migrate` (+ `migrate/identity`, `migrate/securitystate`), `seal` | `store/<name>` | unchanged |
| `pgx` (module) | `store/pgxstore` (module) | `pgxstore` |
| `gorm` (module) | `store/gormstore` (module) | `gormstore` |
| `redis` (module) | `ratelimit/redisstore` (module) | `redisstore` (was `scrtyredis`) |
| `sweep` (module) | `expiry/sweep` (module) | `sweep` |
| `ginsec`, `fibersec` (modules) | `httpsec/ginsec`, `httpsec/fibersec` (modules) | unchanged |

**Unchanged:** `identity`, `authenticate`, `authorize`, `session`, `recovery`, `policy`, `ratelimit`, `token`, `expiry`, `httpsec`, `outbound`, `notify`, `pkg/*`, `internal/*`, `test` and `tools`.

**Why these placements:**
- **`recovery` stays at the root.** It restores access after losing any authenticator, with two independent proofs, so it is account-level rather than MFA-level.
- **`ratelimit` stays at the root.** `mfa`, `recovery`, `passkey` and `httpsec` use it, and `policy` does not import it.
- **`seal` goes under `store`.** Its capability, secrets-at-rest, belongs with persistence.
- **`onetime` goes under `token`.** It is a primitive that several flows issue and redeem, not a login method of its own.

**Alternatives considered:**
- **A flat layout with merges only.** It leaves 20 root directories, and the root still mixes concept levels.
- **A few large merged packages.** These make catch-all namespaces, force many identifier collisions, and risk import cycles.
- **Merging `factor` into `identity` or `authenticate`.** Merging into `identity` collides with `identity.Kind`. Merging into `authenticate` loses the import-free property `factor` documents.

### D2. Module paths, and wiring that follows the modules

The seven nested integration modules take the paths in D1, as the `module-layout` delta requires. Every other module requires them at the new paths. Both of the following are rewritten for the new paths:
- the `replace` directives and `go.work`;
- the CI workflow matrix, the `Makefile` targets, and the `testdata/layout` and `testdata/graph` fixtures that the layout checks read.

The test module's path stays `github.com/kartaladev/scrty/test`.

`release-readiness` names tag prefixes after module directories. It is updated to `authenticate/passkey/webauthn/`, `store/pgxstore/`, `store/gormstore/`, `ratelimit/redisstore/`, `expiry/sweep/`, `httpsec/ginsec/`, `httpsec/fibersec/` and `test/`. Nothing is tagged, so no published version is affected.

### D3. `policy/lockout` takes the lockout group; attempt views stay with the engine

**What moves to `lockout`:**
- the lockout policy and its options;
- the error, observer and report types;
- the attempt store and its in-memory implementation;
- the failure streak;
- the lockout expiry task.

**What stays in `policy`:** `attempt_views.go`, because `Engine` reads `AttemptViewRequirer`.

**Import direction:** `lockout` imports `policy` for `Phase`, `Decision`, `Input` and the attempt-view types. `policy` never imports `lockout`, so no cycle can form.

| `policy` today | `lockout` |
|---|---|
| `AccountLockoutPolicy`, `NewAccountLockoutPolicy`, `LockoutOption` | `Policy`, `New`, `Option` |
| `WithLockoutCap`, `…CapRetention`, `…Ceiling`, `…Clock`, `…Threshold`, `…Wait`, `…Window`, `…Logger`, `…Observer` | `WithCap`, `WithCapRetention`, `WithCeiling`, `WithClock`, `WithThreshold`, `WithWait`, `WithWindow`, `WithLogger`, `WithObserver` |
| `WithSlidingLockout`, `WithAttemptStore` | `WithSliding`, `WithAttemptStore` |
| `LockoutError`, `LockoutObserver`, `LockoutReport`, `LockoutReportKind` | `Error`, `Observer`, `Report`, `ReportKind` |
| `LockoutAtCeiling`, `LockoutCleared`, `LockoutHeld`, `LockoutReleased` | `ReportAtCeiling`, `ReportCleared`, `ReportHeld`, `ReportReleased` |
| `NISTLockoutCap`, `LockoutExpiryTask` | `NISTCap`, `ExpiryTask` |
| `AttemptStore`, `AttemptReaper`, `FailureStreak`, `FailureStreakStore`, `MemoryAttemptStore`, `NewMemoryAttemptStore`, `MemoryAttemptOption`, `WithAttemptStoreCapacity`, `ErrAccountLocked`, `ErrAccountHeld`, `ErrAttemptStoreFull`, `ErrReapUnsupported`, `ErrRetainSinceRequired` | same names in `lockout` |

**Alternative considered:** leave the group in `policy`. That keeps 21 files and the `Lockout…` prefix stutter on every name.

### D4. `storeerr` becomes the parent package `store`

`storeerr.ErrIsolationTooStrong` becomes `store.ErrIsolationTooStrong`. The backends keep their aliases (`sqlstore.ErrIsolationTooStrong`, and the same in `pgxstore` and `gormstore`), so a consumer can match the sentinel from either package.

`session.ErrDeleteDidNotSettle` stays where it is. Where it should live is part of API shape, so it belongs to `idiomatic-api-shape`.

**Alternative considered:** `internal/storekit`. That would force a consumer to import a backend in order to match the sentinel.

### D5. Identical backend helpers move into `internal/storekit`

The helpers listed in Context, together with their `storekit` and `pglimiter` copies, become single `storekit` declarations. Each backend calls those declarations.

Only helpers with identical bodies move. Near-duplicates that differ by driver API stay in their backend. The store-conformance suites under `test/` prove that nothing changed.

**Alternative considered:** a driver-neutral executor port that would remove more of the duplication. It is a redesign, not a move, so it is out of scope.

### D6. Files consolidate into feature families

These rules apply to every package in the core module and the nested modules, except the test module:

1. **File names.** A production file is `<concept>.go` or `<concept>_<aspect>.go`, with the concept first and an underscore, so that `ls` groups each family. Multi-word concepts use the package's own word for them (`magiclink`, `passkey`, `session_bearer`).
2. **Options sit beside their feature.** A feature's `Enable…` function, option type and options live in its family. They go in the feature file, or in `<concept>_options.go` when the feature file would otherwise pass about 800 lines. In `httpsec`, `options.go` keeps only the chain core.
3. **Small files fold into their family.** A production file under about 100 lines merges into its family's main file. `doc.go`, and seams kept deliberately apart, stay as they are.
4. **One test file per production file.**
   - Each production file has at most one `_test.go`, named after it.
   - A test of several features working together goes into the package's `integration_test.go`.
   - Helpers shared by several test files go into `helpers_test.go`.
   - Generated mocks, `example_*_test.go`, `export_test.go` and `main_test.go` keep their own files.
5. **Shared code is filed by what it is,** not under the first feature that used it.

The `httpsec` production map follows. In this map, "§X" means the `Enable…` function, option type and options of feature X, taken out of today's `options.go`.

| Target | From |
|---|---|
| `chain.go` | `chain.go`, `order.go`, `expiry.go`, `refusallog.go`, `now` from `clock.go` |
| `options.go` | chain core of `options.go`, `WithClock` from `clock.go`, `lockout_wiring.go` |
| `exchange.go`, `resolve.go`, `throttle.go`, `guards.go`, `redemption.go`, `doc.go` | unchanged |
| `session.go` | `context.go`, `sessiontouch.go` |
| `errors.go` | `errors.go`, `status.go` |
| `posted.go` | `postedfield.go`, `postedjson.go` |
| `nethttp.go` | `nethttp.go`, `middleware.go` |
| `complete.go` | `logincomplete.go` (the login tail every feature uses), plus `declaresJSON` from `login.go` |
| `login.go`, `login_options.go` | `login.go`; §login, including `WithLoginLifetime` |
| `basic.go`, `bearer.go`, `apikey.go`, `logout.go`, `jwks.go`, `authorization.go` | each file plus its § |
| `password_change.go` | `passwordchange.go` + §password change |
| `magiclink.go`, `magiclink_options.go` | `magiclink.go`; §magic link |
| `mfa_begin.go` | `mfabegin.go`, `mfapath.go` |
| `mfa_verify.go` | `mfaverify.go`, `mfachallengeerr.go`, `mfalisting.go` |
| `mfa_options.go` | §MFA |
| `mfa_enrol.go`, `mfa_enrol_options.go` | `mfaenrol.go`; `mfaenroloptions.go` |
| `passkey.go` | `passkey.go`, `passkeyoptions.go` |
| `passkey_login.go`, `passkey_manage.go` | `passkeylogin.go`; `passkeymanage.go` |
| `passkey_register.go` | `passkeyregister.go`, `passkeyconfirm.go` |
| `oidc.go`, `oidc_options.go`, `oidc_backchannel.go` | unchanged names |
| `oidc_login.go` | `oidc_authorize.go`, `oidc_callback.go` |
| `oidc_redeem.go` | `oidc_redeem.go`, `federated.go` |
| `recovery.go` | `recoverycomplete.go`, `recoverystart.go`, `recoveryhold.go` |
| `recovery_codes.go`, `recovery_gate.go`, `recovery_cooldown.go`, `recovery_options.go` | the matching files today |
| `session_bearer.go`, `session_renewal.go` | `sessionbearer.go`; `renewal.go` |

This brings `httpsec` from 60 production files to 45.

The `oidc` production map follows (31 files to 16):

| Target | From |
|---|---|
| `relying_party.go` | `manager.go`, `options_manager.go` |
| `broker.go` | `broker.go`, `options_broker.go` |
| `broker_provision.go`, `broker_roles.go`, `broker_password.go` | `provision.go` with `mirror.go`; `roles.go`; `passwordclaim.go` |
| `handoff.go` | `handoff.go`, `options_handoff.go`, `handoffstore_memory.go`, `HandoffExpiryTask` |
| `flow.go` | `flow.go`, `flowstore_memory.go`, `FlowExpiryTask` |
| `link.go` | `link.go`, `linkstore_memory.go` |
| `login.go` | `authorize.go`, `callback.go`, `exchange.go` |
| `assurance.go` | `assurance.go`, `assurance_source.go` |
| `verify.go` | `verify.go`, `claims.go` |
| `logout.go` | `logouttoken.go`, `endsession.go` |
| `remote.go` | `keycache.go`, `discovery.go` (documents fetched from a provider) |
| `registry.go`, `ports.go`, `errors.go`, `doc.go` | unchanged (`expiry.go` is dissolved into `flow.go` and `handoff.go`) |

**Every other package** applies the five rules. The dispatch that consolidates a package reports its file map in the same form as the tables above, and the reviewer checks the map against the rules.

**Alternatives considered:**
- **One file per concept.** Files of up to about 3k lines, which also reduces how much work can run in parallel under the file-ownership rule.
- **Renames only.** The naming becomes consistent, but the file count stays the same.

### D7. Tests merge, and same-shaped scenarios become table cases

When the test files of one unit merge, the test functions that call the same SUT become cases of a table. They follow the project's `table-test` rule: an `assert` closure, a `ctx` modifier where the component reads its context, and `t.Context()`.

Five constraints keep the conversion from weakening any test:
- **A case's name keeps its old function's suffix.** `TestMFAVerify_Attempts` becomes `TestMFAVerify/attempts`. Its assertions move into the case's closure unchanged.
- **A function with a structurally different setup stays standalone,** as `table-test` allows, with its one-line comment explaining why.
- **Parallelism is preserved, not added.** A case runs `t.Parallel()` only if its original did. Adding concurrency to a test that never ran concurrently is a change in what the test exercises.
- **New cases are limited.** The only new case allowed is the cancelled-context case that `table-test` requires of a context-sensitive table.
- **A new case that fails stops that table's conversion.** The case is not committed, and the defect is reported as `REPRODUCED`, as `defect-claims.md` requires. Fixing it is a behaviour change, which belongs in its own change, decided by the user.

**Alternative considered:** move test functions unchanged, without converting them to tables. That keeps the strictest proof, but it was declined so that `table-test` is applied while each file is being touched anyway.

### D8. Every `Manager` is renamed to what its type is

| Today | New type, constructor, option type |
|---|---|
| `oidc.Manager`, `NewManager`, `ManagerOption` | `RelyingParty`, `NewRelyingParty`, `Option` (main type; see D10) |
| `oidc.HandoffManager`, `NewHandoffManager` | `Handoff`, `NewHandoff` |
| `authenticate.Manager`, `NewManager` | `FirstOf`, `NewFirstOf` |
| `authorize.Manager`, `NewManager` | `FirstOf`, `NewFirstOf` |
| `session.Manager`, `NewManager`, `ManagerOption` | `Sessions`, `New`, `Option` |
| `passkey.Manager` (built by `New`) | `Passkeys` (still built by `New`) |
| `signingkey.KeyManager`, `NewKeyManager` | `Keys`, `New` |
| `apikey.Manager`, `NewManager` | `Keys`, `New` |
| `onetime.Manager`, `NewManager` | `Tokens`, `New` |
| `magiclink.Manager`, `NewManager` | `Links`, `New` |
| `httpsec.WithSessionManager` | `WithSessions` |

`FirstOf` is a type, so its constructor cannot also be called `FirstOf`: Go allows only one package-level identifier of a given name. It is therefore `NewFirstOf(delegates...)`.

**Alternatives considered:**
- **`Chain`.** It clashes in meaning with `httpsec.Chain`.
- **`Composite`.** It names how the type is built rather than what it does.
- **`oidc.Client`.** In Go, "Client" usually names a client for a remote API.

### D9. Outlier names follow the rule the rest of the API keeps

| Today | New |
|---|---|
| `authenticate.JwtOption`, `NewJwtAuthenticator`, `WithJwtVerifier`, `WithJwtIDGenerator` | `JWTOption`, `NewJWTAuthenticator`, `WithJWTVerifier`, `WithJWTIDGenerator` |
| `signingkey.KeySource.GetSigner` and its implementation | `Signer` |
| `signingkey.NewInMemoryKeyStore` | `NewMemoryKeyStore` |
| `policy.ErrMFAEnrollmentRequired` | `ErrMFAEnrolmentRequired` |
| `seal.ErrInvalidConfiguration` | `ErrConfig` |
| `token.VerifyWithAudience`, `…Clock`, `…Issuer`, `…KeySource`, `…MaxTokenSize` | `WithVerifyAudience`, `WithVerifyClock`, `WithVerifyIssuer`, `WithVerifyKeySource`, `WithVerifyMaxTokenSize` |
| `identity.NewUser` (struct) | `UserChange` |
| `passkey.NewCredential` (struct) | `CredentialInput` |
| `scrtyredis.Factory` | `redisstore.LimiterFactory` |
| `policy.UnknownPasswordAge`, `AllowUnknown`, `ChallengeUnknown` | `UnknownAgeMode`, `UnknownAgeAllow`, `UnknownAgeChallenge` |
| `passkey.UVRequired`, `UVPreferred` | `UserVerificationRequired`, `UserVerificationPreferred` |
| `passkey.AwaitingSavedCodes`, `AwaitingEmailCode` | `PendingSavedCodes`, `PendingEmailCode` |
| `httpsec.IssuerSessions`, `AllSessions` | `BackchannelLogoutScopeIssuer`, `BackchannelLogoutScopeAll` |
| `oidc.MatchAny`, `MatchAll` | `AssuranceMatchAny`, `AssuranceMatchAll` |
| `ratelimit.UnavailableFallBackToLocal` | `UnavailableFallbackToLocal` |
| `passkey.NormaliseName` | `NormalizeName` |
| `mfa.MaxEmailCodeFailures` | `MaxEmailCodeAttempts` (it counts attempts charged, as `passkey`'s constant does) |

**Kept on purpose:**
- `sweep.Sweeper`, `clock.Timed`, `notify.NonBlocking`, `recovery.AuthenticatorKind`, `ratelimit.PolicyReporter`, `policy.FederatedAssuranceUser`;
- `passkey.EndOtherSessions` and `KeepOtherSessions` (per-call options that read as English);
- `session.Session`, `id.ID`, `clock.Clock`, `policy.Policy` (the `time.Time` precedent).

### D10. Naming rules applied across the API

**Sentinels drop the package noun:**

| Package | Today | New |
|---|---|---|
| `session` | `ErrSessionExpired`, `ErrSessionNotFound`, `ErrSessionRenewalConflict`, `ErrSessionRenewalRequired`, `ErrSessionReused`, `ErrSessionSuperseded`, `ErrSessionUnreadable` | `ErrExpired`, `ErrNotFound`, `ErrRenewalConflict`, `ErrRenewalRequired`, `ErrReused`, `ErrSuperseded`, `ErrUnreadable` |
| `password` | `ErrPasswordReused`, `ErrPasswordContainsNUL`, `ErrPasswordTooLong` | `ErrReused`, `ErrContainsNUL`, `ErrTooLong` |
| `token` | `ErrTokenInvalid` | `ErrInvalid` |
| `policy` | `ErrPolicyDenied` | `ErrDenied` |

A sentinel that names something other than its package keeps its noun (`identity.ErrUserNotFound`).

**`policy` types drop the `Policy` suffix:**
- `IdleTimeoutPolicy` → `IdleTimeout`, `ConcurrentSessionPolicy` → `ConcurrentSessions`, `PasswordAgePolicy` → `PasswordAge`, each with a matching `New…`.
- `NewMFAPolicy` → `NewMFA`, `NewMFARequirementPolicy` → `NewMFARequirement`.

**Options.**
- **Main type.** A package's main type has the option type `Option` and options named `With<Thing>`.
- **Other types.** Every other configurable type `T` has `<Stem>Option` and `With<Stem><Thing>`. The stem is `T`'s name, or the distinctive part of it that the package already uses (`Throttle` for `VerifyThrottle`, `Guard` for `SourceGuard`).
- **Packages with no main type** prefix every option.
- **Per-call option types** (`CreateOption`, `RotateOption`, `IssueOption`, `RemoveOption`) are named after the call and stay as they are.
- **A name that already carries the stem and reads as English** keeps its word order (`WithMaxPasswordAge`, `WithIPv6SourcePrefix`).

The main types:

| Package | Main type |
|---|---|
| `apikey` | `Keys` |
| `expiry` | the runner |
| `magiclink` | `Links` |
| `mfa` | `TOTP` |
| `oidc` | `RelyingParty` |
| `onetime` | `Tokens` |
| `outbound` | the client |
| `passkey` | `Passkeys` |
| `recovery` | `Recoverer` |
| `seal` | the sealing stores |
| `session` | `Sessions` |
| `signingkey` | `Keys` |
| `token` | `Generator` |
| `httpsec` | `Chain` |
| `lockout` | `Policy` |
| `pgxstore`, `gormstore`, `sqlstore` | the stores |
| `redisstore` | `LimiterFactory` |
| none | `authenticate`, `identity`, `notify`, `password`, `policy`, `ratelimit` |

The option renames:

| Package | Today | New |
|---|---|---|
| `session` | `WithSessionLogger`; `WithHousekeepingInterval` (MemoryStore) | `WithLogger`; `WithMemoryStoreHousekeepingInterval` |
| `oidc` | `WithAllowedRoles`, `WithClaimMirror`, `WithDefaultRole`, `WithJIT`, `WithJITAllowUnverifiedEmail`, `WithJITEmailDomains`, `WithNameClaim`, `WithPasswordClaim`, `WithPasswordClaimCostRange`, `WithPasswordEncoder`, `WithProvisioner`, `WithRoleClaim`, `WithRoleMapping`, `WithRoleSync` | `WithBroker…` with the same `<Thing>` |
| `oidc` | `WithMaxFlows` | `WithMemoryFlowStoreMaxFlows` |
| `mfa` | `TOTPOption`, `WithTOTPIDGenerator`, `WithTOTPLogger` | `Option`, `WithIDGenerator`, `WithLogger` |
| `mfa` | `ThrottleOption`, `WithVerifyClock`, `WithVerifyLimiter`, `WithVerifyLimiterFactory`, `WithVerifyLogInterval`, `WithVerifyLogger` | `ThrottleOption`, `WithThrottleClock`, `WithThrottleLimiter`, `WithThrottleLimiterFactory`, `WithThrottleLogInterval`, `WithThrottleLogger` |
| `mfa` | `WithoutSessionRevocation` (reset) | `WithoutResetSessionRevocation` |
| `authenticate` | `WithPasswordAuthenticatorLogInterval`, `WithPasswordAuthenticatorLogger`, `WithUsernameInRefusalLogs` | `WithPasswordLogInterval`, `WithPasswordLogger`, `WithPasswordUsernameInRefusalLogs` |
| `policy` | `WithIdlePolicyTimeout`, `WithIdlePolicyAbsoluteTimeout` | `WithIdleTimeout`, `WithIdleAbsoluteTimeout` |
| `policy` | `WithMFAPolicyClock`, `WithMFAPolicyLogInterval`, `WithMFAPolicyLogger`, `WithFederatedChallengeWhenUnmet`, `WithSameChannelEnrolment` | `WithMFAClock`, `WithMFALogInterval`, `WithMFALogger`, `WithMFAFederatedChallengeWhenUnmet`, `WithMFASameChannelEnrolment` |
| `policy` | `WithFederatedAssurance` (MFA requirement) | `WithMFARequirementFederatedAssurance` |
| `recovery` | `WithCodeLimiter`, `WithCodeLimiterFactory`, `WithCodeStore`, `WithLowThreshold`, `WithSetSize` | `WithCodesLimiter`, `WithCodesLimiterFactory`, `WithCodesStore`, `WithCodesLowThreshold`, `WithCodesSetSize` |
| `seal` | `WithEncryptionKey`, `WithRetiredEncryptionKey` | `WithKeyringEncryptionKey`, `WithKeyringRetiredEncryptionKey` |
| `token` | `GenerateOption`; `VerifyOption` | `Option`; `VerifyOption` (the functions as in D9) |
| `passkey` | `WithPasskeyLimit` | `WithLimit` (matches `ErrLimitReached`) |
| `redisstore` | `WithLimiterClock`, `WithUnavailableProbeInterval` | `WithClock`, `WithProbeInterval` (the same `<Thing>` as the SQL limiters) |
| `httpsec` | `WithAllowedOrigins`, `WithAllowedRedirects`, `WithBindingCookieName` (magic link) | `WithMagicLinkAllowedOrigins`, `WithMagicLinkAllowedRedirects`, `WithMagicLinkBindingCookieName` |
| `httpsec` | `WithBackchannelLogoutPath`, `WithBackchannelLogoutScope`, `WithCallbackSuccess`, `WithHandoffCountRefusals`, `WithHandoffLimiter`, `WithHandoffRateLimit`, `WithHandoffRedeemer` | `WithOIDC…` with the same `<Thing>` |
| `httpsec` | `WithContactResolver`, `WithLabelResolver`, `WithoutEmailConfirmation` (enrolment) | `WithEnrolmentContactResolver`, `WithEnrolmentLabelResolver`, `WithoutEnrolmentEmailConfirmation` |
| `httpsec` | `WithPasswordlessLogin`, `WithPasswordlessPrefix` | `WithPasskeyPasswordlessLogin`, `WithPasskeyPasswordlessPrefix` |
| `httpsec` | `WithRegenerationFreshness` | `WithRecoveryRegenerationFreshness` |
| `httpsec` | `WithChangePasswordEndpoint` | `WithPasswordChangeEndpoint` |

**Typed enum constants carry their type's name, or its distinctive part, as a prefix** (D9 lists the renames).

### D11. Error-message prefixes follow the package name

An error string keeps the `"<package>: "` form under the new package name:
- `"pgx: …"` → `"pgxstore: …"`, `"gorm: …"` → `"gormstore: …"`, `"scrtyredis: …"` → `"redisstore: …"`, `"storeerr: …"` → `"store: …"`;
- the lockout messages → `"lockout: …"`.

Sentinel identity does not change, so `errors.Is` behaves as before.

This is the one place where a test assertion may change: only the prefix of an asserted string. D13 checks this.

**Alternative considered:** keep the old prefixes. Packages would then report errors under names that no longer exist.

### D12. How the work is carried out

- **Renames go through gopls, not text replacement.** Every identifier rename and package move uses `gopls rename`, or the equivalent refactor, across the whole `go.work` workspace, so every caller in every module is updated.
  - A text sweep afterwards catches what gopls cannot see: doc comments, README, OpenSpec prose, strings, `%T` output and `reflect` uses.
  - That sweep excludes `.claude/.legacy`.
- **File moves use `git mv`,** so history follows each file.
- **Four phases, in order:**
  1. **Moves.** Directory and module moves (D1, D2, D4, then D3), in a single lane, because a package move rewrites the imports of every caller.
  2. **Renames.** The identifier renames (D8–D10) and the error-prefix change (D11), in a single lane, leaf packages first. A workspace-wide rename touches callers in many packages, so two parallel renamers would edit the same files.
  3. **Families.** File families and table conversion (D6, D7). One lane per package, running in parallel, because these edits stay inside one package.
  4. **Helpers.** The `storekit` de-duplication (D5), in one lane over the three backends.

  Each phase ends with the D13 checks before the next one starts.

### D13. Proof that nothing broke

These checks run before phase 1 starts, and again after each phase:
1. **Test inventory.**
   - A run of the core module and the nested modules with `go test -json` records every test and subtest name together with its result.
   - For the Docker-backed suites in the test module, `go test -list` gives the top-level names, and CI supplies their results.
   - The new inventory, mapped through D1–D10, must contain every old name: an old function name maps to its D7 case name. Every test must pass.
2. **API inventory.** An old-to-new map of every exported identifier is checked against `golang.org/x/exp/cmd/apidiff` output for each package:
   - every reported removal is a key of the map;
   - every reported addition is a value of the map;
   - nothing else is reported.
3. **Coverage.** No package's statement coverage drops. The conversion in D7 must exercise the same code as before.
4. **Assertion review.** Outside D7, a test diff touches only import paths, identifiers, file placement and D11 prefixes. A reviewer compares every D7 case's assertions with its original function's.
5. **Gates.** `make check` (gofmt, vet, lint, race tests, `go generate` drift and the layout checks) passes locally where it can, and in CI with the Docker suites.

## Risks / Trade-offs

- **gopls misses a mention it cannot resolve** (prose, strings, `%T`, `reflect`). → The text sweep in D12, and a reviewer search for every old name in the D8–D10 tables.
- **A converted table asserts less than the functions it replaced.** → The case-name mapping, the per-case assertion review and the coverage check in D13. Cases keep their original parallelism.
- **A new cancelled-context case fails** (a real defect). → D7 stops that table, records the defect as `REPRODUCED`, and hands it to the user. It is not fixed in this change.
- **The diff is very large and hard to review.** → One commit per phase and per lane. Each phase is reviewed against its own decisions, and the whole branch is reviewed once at the end.
- **The layout checks and fixtures hard-code module names.** → They are updated in phase 1, and the layout tests prove the new paths before any rename runs.
- **Other branches in flight conflict with the moves.** → The order in `proposal.md`. The moves start from a `main` that has `fix/stabilize-intermittent-tests` merged, and no other change is implemented until this one is merged.
- **Longer import paths** (`authenticate/passkey/webauthn`). → Accepted, in exchange for the concept grouping. Package names stay short.

## Migration Plan

1. Merge `fix/stabilize-intermittent-tests`, then branch from `main`.
2. Capture the D13 baseline: test inventory, API inventory and coverage.
3. Run phases 1–4 (D12), with D13 after each.
4. In the same branch, update the repository's own references:
   - the `openspec/config.yaml` context (the module list and the `pkg/` and adapter names);
   - the README;
   - the path and identifier references in the artifacts of the active changes (`trusted-proxy-client-ip`, `release-readiness` and its tag prefixes, `di-wiring`, `bff-resource-server`, `stabilize-intermittent-tests` if it is not yet archived).
5. Run the whole-branch review, then merge.

**Rollback:** revert the merge. Nothing is tagged and there are no consumers, so a revert is complete.

## References

### Directory grouping (D1, D3, D4)

**Researched (accessed 2026-10-25):**
- [Organizing a Go module](https://go.dev/doc/modules/layout): a module's packages may be structured hierarchically and nested; supporting packages go in `internal/`.
- [Go blog: Package names](https://go.dev/blog/package-names): a directory only arranges files and implies no relationship between packages; avoid stutter and catch-all packages.
- [volatiletech/authboss](https://github.com/volatiletech/authboss): a flat layout with one package per feature, considered and not chosen.
- [ory/fosite](https://github.com/ory/fosite): a concept-grouped layout (`handler/oauth2`, `handler/openid`, `token`, `storage`).

### Type names (D8, D9, D10)

**Researched (accessed 2026-10-25):**
- [OpenID Connect Core 1.0, Terminology](https://openid.net/specs/openid-connect-core-1_0.html): the Relying Party, also called the Client.
- [zitadel/oidc, package rp](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/client/rp): a Go relying party exported as `RelyingParty`.
- [coreos/go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc): no `Manager` type; its parts are named `Provider` and `IDTokenVerifier`.

**Primary documentation:**
- [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments): initialisms, getters, error strings with a lowercase package prefix.
- [Effective Go: Names](https://go.dev/doc/effective_go#names): getters without `Get`, MixedCaps.

### Adapter package names (D1, D2)

**Researched (accessed 2026-10-25):**
- [alexedwards/scs](https://github.com/alexedwards/scs): storage adapters named `<driver>store` (`pgxstore`, `gormstore`, `redisstore`).

### Proof of no regression (D13)

**Researched (accessed 2026-10-25):**
- [golang.org/x/exp/cmd/apidiff](https://pkg.go.dev/golang.org/x/exp/cmd/apidiff): "determines whether two versions of a package are compatible". The page does not document its flags; the invocation is to be confirmed when the change is implemented.
