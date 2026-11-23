# Tasks

Every task is test-first. For each one:

1. Write the failing test.
2. Run it focused: `go test -run '<Name>' -count=1 ./<pkg>/`.
3. Confirm it fails for the intended reason, not a compile error or a missing fixture.
4. Implement until it is green, then refactor.

Each task's verification names the test or command that shows it is done.

## 1. Upstream access and UserInfo (`authenticate/oidc`)

- [x] 1.1 Keep the token response's `access_token` in a callback-local value, and discard the refresh token. **Verify:** a test shows `CallbackResult`, `Flow` and `HandoffRecord` hold neither token.
- [x] 1.2 Add `Upstream`: a pointer to unexported state, with redacted `Format`, `String` and `LogValue`, plus `AccessToken()` and `HasAccessToken()`. **Verify:** a table test over `%v`, `%+v`, `%#v`, `%s`, a slog attribute, and an exported and an unexported field of a consumer struct; no output contains the token (F2).
- [x] 1.3 Add the optional `UpstreamBroker` interface and the dispatch in `Callback`. **Verify:** tests show a plain broker unchanged, an upstream broker receiving the token, and a response with no `access_token` still logging in (F1).
- [x] 1.4 Add discovered `userinfo_endpoint` and an optional pinned `Provider.UserInfoEndpoint` (D4). **Verify:** tests for the discovered endpoint, the pin winning, a refused scheme failing construction, and an absent endpoint not failing discovery.
- [x] 1.5 Implement `Upstream.UserInfo(ctx)` and `ErrUserInfoFailed` (D3). **Verify:** a table test against `httptest` with these rows:
  - ok;
  - `sub` mismatch;
  - `sub` missing;
  - same e-mail but another `sub`;
  - 401 and 500;
  - oversized body;
  - JWT response;
  - non-object JSON;
  - no endpoint;
  - no token;
  - cancelled context;
  - a large integer member returned with every digit (`json.Number`);
  - a repeated member name, `sub` included;
  - a redirect to another origin (no request reaches it, no token in the error);
  - a non-string `access_token` in the token response (a plain broker still logs in, and `HasAccessToken()` is false).

  Every row also asserts, by log capture, that neither the token nor the body appears in a log record or an error (F3–F6).
- [x] 1.6 Write godoc for every symbol added in 1.1–1.5, each naming its default and override. **Verify:** `go doc`, and an `ExampleUpstream_UserInfo` that runs.

## 2. Listing a user's links (link stores)

- [x] 2.1 Add the optional `LinkLister` interface and implement it on `NewMemoryLinkStore`. **Verify:** a test lists a user with three links across two providers, and a user with none (empty list, no error).
- [x] 2.6 Add the optional `LinkRemover` interface (`DeleteLink(ctx, Link) (bool, error)`) and implement it on `NewMemoryLinkStore`; require it beside `LinkLister` under a hook without allow-many (D11). **Verify:** a test removes one of a user's two links and keeps the other, a mismatched identity removes nothing, and a hook over a store with a lister but no remover is refused at construction.
- [x] 2.2 Add `ListByUser` and `DeleteLink` cases to the link-store conformance suite in `test/oidc`, skipped for a store without the capability. **Verify:** the suite runs green against the memory store.
- [x] 2.3 Implement `ListByUser` and `DeleteLink` in `store/sqlstore`, with the query in `internal/pgschema`. **Verify:** the conformance suite runs green against it in a PostgreSQL container (`use-testcontainers`).
- [x] 2.4 Implement `ListByUser` and `DeleteLink` in `store/pgxstore`. **Verify:** the conformance suite is green.
- [x] 2.5 Implement `ListByUser` and `DeleteLink` in `store/gormstore`. **Verify:** the conformance suite is green.

## 3. Sign-in hook on the library broker (`authenticate/oidc`)

- [x] 3.1 Add `SignInDecision`, `SignInHook`, `WithBrokerSignInHook` and `WithBrokerSignInHookAllowManyLinks`, with the construction errors (D6, D11). **Verify:** a table test over:
  - a nil hook;
  - an empty provider;
  - a hook plus JIT, mirroring or role sync on one provider;
  - a hook and JIT on different providers (accepted);
  - a hook over a store with no lister (refused, then accepted with allow-many);
  - an unregistered hook provider refused by `NewRelyingParty`.
- [x] 3.2 Implement `Broker.BrokerUpstream` and `ErrUpstreamRequired`. **Verify:** tests show an unhooked provider takes today's path, and a hooked provider through `Broker()` fails with the hook not called (F15).
- [x] 3.3 Classify and scrub decision errors (D10). **Verify:** a table test over:
  - refusal sentinels passed through;
  - another error becoming a broker failure;
  - an error wrapping `ErrExchangeFailed` or `ErrFlowUnspent`, not reported as either;
  - an empty user;
  - an error text holding the e-mail, the subject and the token, absent from the error (in every `fmt` verb, `%#v` included) and from the logs;
  - a wrapped library concrete type (such as `*httpsec.ChallengeError`) and an interface target implementing `error`, neither reachable through `errors.As`;
  - a stored link with an empty user reference, a broker failure with the hook not called (F43).

  No row writes anything (F7, F8).
- [x] 3.4 Implement the checks made before any write (D5, step 3). **Verify:** tests show that an existing link to another user, a missing user, a disabled user and a mismatched user are each refused, with `Apply` never called and no link inserted. The link conflict logs one WARN, with no user references (F9, F10).
- [x] 3.5 Implement the link insert, the `ErrLinkExists` re-read, and the one-link rule with its post-insert re-check (D5, step 4; D11). **Verify:**
  - a test refuses a second subject for an already linked user, without running `Apply` (F16);
  - with allow-many, the same case links;
  - a barrier test under `-race` races two first sign-ins of one identity (one link, both resolve) (F11);
  - a barrier test races two new subjects for one user (at most one link; refused logins never `Apply`) (F17);
  - a barrier test where a sign-in of the same identity finds the link mid-undo: it is refused by the existing-link check, never signed in through a link that is then removed;
  - a user holding two links from one issuer is refused through either (unless allow-many);
  - a request cancelled after the insert still removes its duplicate (the undo is detached), leaving at most one link;
  - an insert that hits `ErrLinkExists` whose link a concurrent undo then removes is refused as `ErrNoLinkedAccount`, not a store fault (F49);
  - store faults on find, insert, list and delete are broker failures (F12).
- [x] 3.6 Implement `Apply` after the link, then the reload and the active check (D5, steps 5–6). **Verify:** tests show `Apply` runs once on first and later sign-ins; a failing `Apply` keeps the link and is a broker failure (F13); `Apply` deactivating the user is refused, with the link kept (F19).
- [x] 3.8 Implement the provisioning decision (D13). **Verify:** tests show:
  - a first sign-in that provisions `u-new` stores the link before `Apply` runs, with an empty username, and resolves to `u-new`;
  - provisioning a user that exists and is not linked to the identity is refused, with `Apply` never called and no link (F32);
  - provisioning with no `Apply` is a broker failure, with no link (F33);
  - an `Apply` that fails, or returns without creating the user, is a broker failure, and the link stays; a later provisioning decision resumes and resolves (F34);
  - a barrier test under `-race` races two first sign-ins provisioning `u-a` and `u-b`: one link, the loser refused, and the loser's `Apply` never called (F35);
  - provisioning a reference that another identity's link already names (another provider included) is refused, with nothing written (F52);
  - a barrier test where two identities of different providers provision the same reference at once ends with at most one link, and no refused sign-in runs `Apply` (F52).
- [x] 3.7 Write godoc and an example for the hook. The godoc covers:
  - decide-then-apply and its ordering;
  - the meaning of the `linked` argument;
  - the library never matching by e-mail, with the `email_verified` advice;
  - the one-link default and its override;
  - running inside the request (F31);
  - provisioning a new user, and why the link comes first.

  **Verify:** `go doc`, and an `ExampleWithBrokerSignInHook` that compiles.

## 4. Server-side completion of a federated provider sign-in (`oidcprovider`, `httpsec`)

- [x] 4.1 Add the read-only `Provider.LoginURL()` accessor. **Verify:** a test shows it returns the configured login URL unchanged.
- [x] 4.2 Add `OIDCDeps.Users`, `WithOIDCProviderCompletion` and the assembly checks (F28). **Verify:** a table test refuses each of these:
  - no provider;
  - a callback success handler;
  - a custom redeemer;
  - no handoff;
  - no loader;
  - a foreign session manager;
  - a callback off the issuer's origin;
  - a login URL with a query;
  - a user loader without completion.

  A valid wiring is accepted.
- [x] 4.3 Recognise the parked-request destination, and apply the allowlist carve-out. **Verify:**
  - a table test over the exact URL, plus look-alikes in host, port, path case, trailing slash, encoding, an extra parameter, a repeated `req`, an empty `req`, and a relative URL (F27);
  - a login URL configured with an empty path recognised as `/`, and a URL carrying userinfo refused;
  - a chain test showing that with completion off, a `<LoginURL>?req=<handle>` destination keeps the handoff to `/`;
  - a chain test showing non-qualifying destinations take the allowlisted handoff;
  - a chain test showing a qualifying destination is never replaced by `/`, at the callback and in the answer to the fallback handoff's redemption.
- [x] 4.4 Pre-check the handle before any side effect (D7, step 2). **Verify:** tests for an unknown handle, an expired handle and a foreign flow cookie. Each answers the unknown-handle refusal, charges the source, and leaves no session, no login event and held recoveries untouched (F20). Also: a handle past its login stage answers the unknown-handle refusal uncharged; a throttled source answers `ErrOIDCThrottled` with no lookup; a pending-request store failure is an uncharged dependency failure (F38).
- [x] 4.5 Load the user and run the post-authentication policy, with the owed-step fallback (D7, steps 3–4; D8). **Verify:** tests show:
  - a missing or disabled user is refused (F21);
  - a policy deny returns its reason with no session;
  - an owed second factor redirects to `<LoginURL>?req=<handle>&handoff=…` with no session;
  - a stored password time requiring a change falls back;
  - a meeting `amr` proceeds (F22).
- [ ] 4.6 Implement the success path: session, recoveries, per-request policy, resume with the chain's assurance mapping, confirm after resume, and the answer (D7, steps 5–9). **Verify:** a chain test asserts:
  - stored roles only;
  - the federated session fields and assurance;
  - a held recovery cancelled;
  - the consumer's assurance mapping used;
  - a 303 to the client with `code`, `state` and `iss`;
  - the browser-session cookie set and the login flow cookie cleared;
  - `no-store`, `no-referrer`, and no handoff or credential;
  - a consent redirect when consent is needed;
  - the code exchanging at `/oauth2/token`.
- [ ] 4.7 Implement the completion failure paths. **Verify:** tests for each of:
  - a per-request policy refusal, and a per-request challenge falling back to the handoff (F23);
  - an error handler that finds no session after one was ended (F46);
  - a resume error;
  - a resume answering `login_required` with no error;
  - a confirmation failure (F24), including a sign-in that ends during `Resume`'s own write, which must reach no client (confirm runs after resume);
  - a client whose registered redirect URI carries its own `error` parameter completes, because completion reads `ResumeResult.Outcome`, not the query;
  - a cancelled request still ends the session (the end is detached), and a failed confirmation with a failing family delete still ends the provider sign-in;
  - a session-end failure logging ERROR (F25);
  - a session-store failure (F26).

  In each, the session is ended where one was stored, and no code reaches the client.
- [ ] 4.8 Check events and refusal reporting (D10). **Verify:** a test shows a completed sign-in emits the same events in the same order as a redemption, and a hook refusal at a completion-enabled callback emits `AuthnLoginFail`.
- [ ] 4.9 Write godoc for `LoginURL`, `OIDCDeps.Users` and `WithOIDCProviderCompletion`, covering the default, the trusted login URL, the fallback, the exclusions and the one-SSO-login-per-browser limit (F29). **Verify:** `go doc`.

## 5. Documentation (`README.md`)

- [ ] 5.1 In the "OIDC" section, document the sign-in hook (decide, then apply), the upstream access with a `UserInfo` example, the one-link default, the e-mail responsibility, and that assurance stays ID-token-only. **Verify:** read it against the `identity-linking` and `oidc-login` deltas, and check the example matches `ExampleWithBrokerSignInHook`.
- [ ] 5.2 In the "OpenID Provider" section, document the standards-only frontend shape, server-side completion with its fallback, and the one-SSO-login-per-browser limit, without stating that a frontend never talks to the upstream provider. **Verify:** read it against the completion requirements.

## 6. Integration and gate

- [ ] 6.1 Add an end-to-end test in the `test` module covering the consumer's acceptance list. **Verify:** `go test -run '<Name>' -count=1 ./oidc/` in `test/`. The list:
  - an imported user matched by e-mail with no link is updated through admin, with one link and no second user;
  - the second sign-in goes through the link and refreshes the user;
  - an inactive account is refused;
  - a conflicting e-mail on a linked identity writes nothing;
  - with the hook off, behaviour is unchanged;
  - no access token, UserInfo body or password hash appears in any log.
- [ ] 6.2 Run the scoped verification after each dispatch (`test-scope.md`): `go test -race`, `go vet` and `gofmt -l`. **Verify:** read the output; it is green with no files listed.
- [ ] 6.3 Run the final gate, `make check` and `make spec-check`, after the last code edit. **Verify:** read the output; it is green.

## Workflow follow-up

- Whole-branch review against every requirement of the `oidc-login` and `identity-linking` deltas, before archive.
- Archive after review; confirm that the main specs carry the deltas.
