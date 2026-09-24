# Tasks

Every task follows the project's test-first rule: write the failing test, run it, confirm it fails
for the intended reason (a compile error is not a red step), then implement. "Verify" in a task
names the focused run that must first fail and then pass.

`design.md`'s Go snippets predate the code that now exists. Throughout, read `identity.Channel` as
`factor.Channel` and `identity.Kind`/first-factor kinds as `factor.Kind`: `factor` is the sole owner
of that vocabulary and already names `AuthenticatorApp`, `MagicLink` and `APIKey`. The enrolment
lookup the policies consult is not a new `mfa.EnrolmentLookup` but the existing
`policy.MFAMethodLookup` (`Enrolled` + `Channel`), whose godoc already pins the "an outage is an
error, never a false" contract decision 4 describes, and the redirect allowlist is not a new
unexported `httpsec` helper but the existing `internal/origin.Allowlist`, which already validates
entries and declared origins and resolves a requested target. Task 16.2 records all of this in
`design.md`.

Group 1 builds three APIs this change's specs require that the archived `sessions` and
`identity-model` capabilities did not ship. Nothing is tagged, so they are additive. Task 16.3
reports the resulting drift in those archived specs rather than editing them.

The API-key rotation scenario that demands atomicity inside an attached transaction cannot be
closed here: no transactional store exists until `durable-persistence` lands. Task 8.8 builds and
documents the two-write behaviour, and task 16.4 flags the atomic case to that change.

## 1. Prerequisites in archived capabilities

- [x] 1.1 Add `Session.MFASatisfiedAt time.Time`, set when the second factor is accepted and
  carried through `clone`, save and load. It is library-owned, so it sits beside `MFA` rather than
  in `Data`. Verify a table test asserting the field round-trips through the store and that a
  consumer `Data` entry cannot forge it: `go test -run TestSessionMFASatisfiedAt -count=1
  ./session/`.
- [x] 1.2 Add `func (m *Manager) Rotate(ctx context.Context, s *Session) (*Session, error)`, which
  mints a new identifier from `newIdentifier`, writes the session under it and deletes the old
  entry, returning the session carrying the new ID and leaving every other field untouched. Verify
  the old handle no longer loads, the new one loads with the same user, first factor, timestamps
  and consumer data, and a store failure on the write leaves the old handle loadable: `go test -run
  TestManagerRotate -count=1 ./session/`.
- [x] 1.3 Verify `Rotate` is safe under concurrency: 16 goroutines rotating one session yield
  exactly one live handle and no orphaned entry. `go test -run TestManagerRotateConcurrent -race
  -count=1 ./session/`.
- [x] 1.4 Add `LoadByUserID(ctx context.Context, id identity.UserID) (*Details, error)` to
  `identity.UserLoader`, with the same miss-versus-outage contract `LoadByUsername` documents
  (`ErrUserNotFound` for a miss, any other error for a failure) and the same byte-for-byte
  treatment of the reference. Verify the port guard test still passes and a table test pins both
  outcomes against a stub loader: `go test -run 'TestUserLoader|TestPortsGuard' -count=1
  ./identity/`.
- [x] 1.5 Regenerate every `UserLoader` mock the new method breaks and confirm the tree builds:
  `go generate ./...` then `go build ./...` in each workspace module, and `make generate-check`.

## 2. notify: the message, the port and construction

- [x] 2.1 Create the `notify` package with `Message{To, From, Subject, TextBody}`, `Sender` and the
  `NonBlocking` marker interface, plus `ErrUnsafeHeaderValue`, `ErrQueueFull` and the closed-sender
  sentinel. Verify the package builds and the sentinels are distinct: `go test -run
  TestNotifySentinels -count=1 ./notify/`.
- [x] 2.2 Implement header-injection refusal: `To`, `From` or `Subject` containing CR or LF is
  refused with `ErrUnsafeHeaderValue` before any network activity, never stripped or escaped
  (spec: "Header values that could inject headers are refused"). Verify a table covering a subject
  with `\r\n`, a recipient with `\n`, a sender with `\r`, and clean values, asserting no dial
  happened: `go test -run TestSMTPSenderRefusesUnsafeHeaders -count=1 ./notify/`.
- [x] 2.3 Implement `NewSMTPSender(host, opts...)` with `WithSMTPPort` (587), `WithSMTPAuth`,
  `WithSMTPFrom`, `WithSMTPTimeout` (30 s) and `WithSMTPOpportunisticTLS`, failing construction on
  an empty host, a port outside 1–65535 and a timeout of zero or less (D13). Verify a construction
  table: `go test -run TestNewSMTPSender -count=1 ./notify/`.
- [x] 2.4 Implement the sender-address rule: a message naming no sender uses the configured default,
  and a message with neither fails before any network activity. Verify both, plus a message whose
  own sender overrides the default: `go test -run TestSMTPSenderFrom -count=1 ./notify/`.

## 3. notify: the SMTP sender

- [x] 3.1 Build a scripted in-process SMTP server test helper in `notify`'s test package that can
  stall the greeting, offer or withhold STARTTLS, fail a handshake and reject at any command, and
  that records every line it received. Verify it by driving one successful send through it:
  `go test -run TestScriptedServerDelivers -count=1 ./notify/`.
- [x] 3.2 Implement the single absolute deadline: fixed before dialling as the earlier of
  `now + timeout` and the context deadline, passed to the dialler and set on the connection, with
  `context.AfterFunc` forcing the connection deadline to now when the context ends. Verify a server
  that never greets fails within about the bound, and a context already ended fails before any
  network activity: `go test -run TestSMTPSenderDeadline -count=1 ./notify/`.
- [x] 3.3 Verify the dial does not extend the bound: against an address whose connection completes
  after 1.5 s and whose server then never replies, a 2-second sender fails about 2 s after starting,
  not 2 s after connecting. `go test -run TestSMTPSenderDeadlineSpansDial -count=1 ./notify/`.
- [x] 3.4 Verify an earlier caller deadline wins and that cancelling mid-exchange returns promptly:
  `go test -run 'TestSMTPSenderContextDeadline|TestSMTPSenderCancelMidTransfer' -count=1
  ./notify/`.
- [x] 3.5 Implement required STARTTLS by default, upgrading before AUTH or any message data and
  verifying the certificate against the configured host; a server that does not offer it, or whose
  handshake fails, fails the send with no message data written (D12). Verify all three against the
  scripted server, asserting the recorded lines carry no `DATA`: `go test -run
  TestSMTPSenderRequiresSTARTTLS -count=1 ./notify/`.
- [x] 3.6 Implement `WithSMTPOpportunisticTLS`, which upgrades when offered and otherwise continues
  in plaintext. Verify delivery to a scripted server without STARTTLS, and that `smtp.PlainAuth`
  still refuses to send credentials over an unencrypted non-loopback connection: `go test -run
  TestSMTPSenderOpportunisticTLS -count=1 ./notify/`.
- [x] 3.7 Implement encoding: body normalised to CRLF, sent as `text/plain; charset=UTF-8`, a
  non-ASCII subject encoded with `mime.QEncoding`, and no header naming scrty or any product.
  Verify against the scripted server's recorded bytes: `go test -run TestSMTPSenderEncoding
  -count=1 ./notify/`.
- [x] 3.8 Add a testcontainers SMTP server helper to the `test` module's `testutils.go`, exposed as
  a single `RunTestSMTP(t *testing.T, opts ...TestOption)` per the `use-testcontainers` skill, and
  add the testcontainers requirement to `test/go.mod` only. Verify the core module's guard still
  refuses it in a production build: `go test -run TestLayoutGuard -count=1 ./...` at the root.
- [x] 3.9 Verify real delivery, AUTH and encoding end to end against that container: the decoded
  subject of `Masuk ke akun Anda — tautan` arrives exactly, the body's lines are CRLF-separated and
  no received header value contains `scrty`. `go test -run TestSMTPSenderIntegration -count=1 ./...`
  in `test`.
- [x] 3.10 Verify no log record written by the SMTP sender contains the message body, using a
  failed delivery of a message whose body holds a sign-in link: `go test -run
  TestSMTPSenderLogsCarryNoBody -count=1 ./notify/`.

## 4. notify: the queued sender

- [x] 4.1 Implement `NewQueuedSender(inner, opts...)` with `WithQueueWorkers` (2), `WithQueueSize`
  (256), `WithQueueSendTimeout` (30 s) and `WithQueueLogger`, failing construction on an absent
  inner sender or a non-positive worker count, queue size or timeout, and reporting
  `NonBlocking() bool` as true. Verify a construction table: `go test -run TestNewQueuedSender
  -count=1 ./notify/`.
- [x] 4.2 Implement queuing: `Send` returns as soon as the message is queued, detaching the caller's
  context with `context.WithoutCancel` so values survive and cancellation does not, and bounding
  each delivery by the send timeout. Verify a send through an inner sender that takes 5 s returns
  within 50 ms, and that a message queued just before the caller's context is cancelled is still
  delivered, under `testing/synctest`: `go test -run TestQueuedSenderReturnsBeforeDelivery -count=1
  ./notify/`.
- [x] 4.3 Implement full-queue behaviour: drop the message, log at error, return `ErrQueueFull`,
  never block. Verify with a queue of 1 and one busy worker: `go test -run TestQueuedSenderFull
  -count=1 ./notify/`.
- [x] 4.4 Implement `Close(ctx)`: stop intake, drain what is queued within the closing context, and
  refuse later sends with the closed error. Verify three queued messages are all delivered before
  `Close` returns and a later send is refused: `go test -run TestQueuedSenderClose -count=1
  ./notify/`.
- [x] 4.5 Implement panic recovery in a worker, logged, without stopping the worker. Verify a
  second message is still delivered after the inner sender panics on the first: `go test -run
  TestQueuedSenderRecoversPanic -count=1 ./notify/`.
- [x] 4.6 Verify consumer sizing and goroutine hygiene: 8 workers run up to 8 deliveries at once,
  and `Close` joins every worker with no leak. `go test -run
  'TestQueuedSenderWorkers|TestQueuedSenderNoLeak' -race -count=1 ./notify/` with `goleak`.

## 5. mfa: the method port, channels and the enrolment store

- [x] 5.1 Create the `mfa` package with `Method` (`Name`, `Channel() factor.Channel`, `Enrolled`,
  `Verify`) and the sentinels `ErrInvalidCode`, `ErrAlreadyEnrolled`, `ErrSameChannel` and
  `ErrVerifyThrottled`. Verify the sentinels are distinct and `Method` satisfies
  `policy.MFAMethodLookup` with a compile-time assertion: `go test -run TestMethodSatisfiesLookup
  -count=1 ./mfa/`.
- [x] 5.2 Implement `LookupFor(m Method) policy.MFAMethodLookup`, refusing a method whose channel is
  empty (D1) and one that is nil or a typed nil, using `internal/nilcheck.IsNil`. Verify a table
  covering a good method, an empty channel and both nil shapes: `go test -run TestLookupFor -count=1
  ./mfa/`.
- [x] 5.3 Pin the lookup contract with a table: `enrolled` is true only for a confirmed enrolment, a
  store outage and an unreadable secret each return an error rather than false, and `channel` is the
  method's constant channel (spec: "Enrolment answers are definitive or errors"). `go test -run
  TestLookupContract -count=1 ./mfa/`.
- [x] 5.4 Define `Enrolment` and the `EnrolmentStore` port (`Get`, `PutPending`, `Confirm`,
  `AcceptStep`, `Delete`) with the godoc that pins `PutPending`'s already-enrolled decision to the
  write and `AcceptStep`'s conditional update. Verify `go doc ./mfa` shows the contract.
- [x] 5.5 Implement the in-memory `EnrolmentStore` as the non-durable default, holding its own
  copies so a caller cannot reach stored state through a returned record, and documented as losing
  enrolments on restart. Verify a table over every port method including the unknown-user cases, and
  a copy-isolation case: `go test -run TestMemoryEnrolmentStore -count=1 ./mfa/`.
- [x] 5.6 Verify `AcceptStep` is atomic under concurrency: 16 goroutines accepting the same step for
  one user yield exactly one true. `go test -run TestMemoryEnrolmentStoreAcceptStepRace -race
  -count=1 ./mfa/`.

## 6. mfa: TOTP

- [x] 6.1 Add `github.com/pquerna/otp` to the core `go.mod` and confirm the module-layout guard
  still passes, with `boombuler/barcode` arriving only as an indirect requirement: `go test -run
  TestLayoutGuard -count=1 ./...` at the root, plus `make vuln`.
- [x] 6.2 Implement `NewTOTP(store, issuer, opts...)` with `WithDigits` (6), `WithPeriod` (30 s),
  `WithClock` and `WithRandom`, failing construction on an empty issuer, an issuer containing a
  colon, a digit count other than 6 or 8, and a period of zero or less (D3). Verify a construction
  table asserting the error names the issuer where the issuer is at fault: `go test -run TestNewTOTP
  -count=1 ./mfa/`.
- [x] 6.3 Verify `(*TOTP).Channel()` reports `factor.AuthenticatorApp` and that it equals the
  channel of no first-factor kind the library names, by iterating `factor`'s `AllKinds`: `go test
  -run TestTOTPChannel -count=1 ./mfa/`.
- [x] 6.4 Implement code computation and matching: reject anything that is not exactly the
  configured number of ASCII digits, compute the expected code for steps `s-1`, `s` and `s+1`, and
  compare each in constant time. Verify with the RFC 6238 Appendix B SHA-1 vectors, including
  `94287082` at Unix time 59 with 8 digits: `go test -run TestTOTPRFC6238Vectors -count=1 ./mfa/`.
- [x] 6.5 Verify the step window under an injected clock: the previous step is accepted, the next
  step is accepted, two steps back is refused with `ErrInvalidCode`, and a non-digit or wrong-length
  code is refused without consulting the store. `go test -run TestTOTPStepWindow -count=1 ./mfa/`.
- [x] 6.6 Implement replay refusal (D2): `Verify` takes the matched step and only then calls
  `AcceptStep`, returning `ErrInvalidCode` when it reports false. Verify a valid code accepted once
  is refused when presented again within its step: `go test -run TestTOTPReplay -count=1 ./mfa/`.
- [x] 6.7 Verify racing verifications: 16 goroutines verifying the same valid code for one user
  yield exactly one success. `go test -run TestTOTPVerifyRace -race -count=1 ./mfa/`.
- [x] 6.8 Implement `BeginEnrolment`: 20 random bytes, a pending record, and a return of the base32
  secret plus `otpauth://totp/<issuer>:<label>?secret=…&issuer=…&digits=…&period=…`. Reject an empty
  label or one containing a colon, never derive the label, and on a random-source failure return an
  error and store nothing. Verify a table over the URI's fields, both label refusals and the random
  failure asserting no write: `go test -run TestTOTPBeginEnrolment -count=1 ./mfa/`.
- [x] 6.9 Implement `ConfirmEnrolment`: a valid code for the pending secret makes the enrolment
  confirmed and records the code's step; a wrong code fails with `ErrInvalidCode` and leaves the
  user unenrolled. Verify pending is not enrolled, confirmation makes it enrolled, and a wrong code
  changes nothing: `go test -run TestTOTPConfirmEnrolment -count=1 ./mfa/`.
- [x] 6.10 Implement the replace-and-refuse rules: beginning again while pending replaces the
  pending secret, and beginning for a user with a confirmed enrolment fails with
  `ErrAlreadyEnrolled` and leaves the confirmed enrolment working. Verify both, asserting the
  existing authenticator's codes still verify after the refusal: `go test -run
  TestTOTPBeginEnrolmentTwice -count=1 ./mfa/`.
- [x] 6.11 Implement `RemoveEnrolment`, which deletes only the enrolment record and touches no
  requirement. Verify removal makes the user unenrolled and that an `MFARequirementLookup` reporting
  required still reports required afterwards: `go test -run TestTOTPRemoveEnrolment -count=1
  ./mfa/`.

## 7. mfa: the verification throttle and failing closed

- [x] 7.1 Implement the per-user verification throttle: a limiter keyed by user reference,
  defaulting to an in-memory 5 failures per 15 minutes, checked before the code is read, refusing
  with `ErrVerifyThrottled` when exceeded and also when the limiter errors (D4). A successful
  verification spends nothing. Verify with a mockgen limiter: five wrong codes then a valid one is
  refused, a second user is unaffected, and a limiter error refuses. `go test -run TestVerifyThrottle
  -count=1 ./mfa/`.
- [x] 7.2 Verify the consumer override: a shared limiter supplied by the consumer receives every
  check and failure for code verification, keyed by user reference. `go test -run
  TestVerifyThrottleConsumerLimiter -count=1 ./mfa/`.
- [x] 7.3 Implement sampled throttle-refusal logging through `pkg/logsample` with a reporter, keyed
  by refusal reason, with a window defaulting to one minute and an option governing MFA verification
  logs alone. Verify 200 refusals for one throttled user in one minute write one record: `go test
  -run TestVerifyThrottleLogSampling -count=1 ./mfa/`.
- [x] 7.4 Verify no log record written for verification or enrolment contains a presented code, an
  enrolment secret or a provisioning URI, using wrong code `123456` and a begun enrolment: `go test
  -run TestMFALogsCarryNoSecrets -count=1 ./mfa/`.
- [x] 7.5 Verify the whole fail-closed path end to end (decision 7): a user whose
  `MFARequirementLookup` reports required, with their enrolment deleted, is refused at password
  login with the enrolment-required reason and no session; and the same holds when the enrolment
  store fails instead of missing. Run it through `policy`'s requirement policy with `LookupFor`, not
  a stub. `go test -run TestRequiredUserFailsClosed -count=1 ./mfa/`.
- [x] 7.6 Verify the require-for-all limit is real and documented: a user who never enrolled is
  refused at every non-exempt login with the enrolment-required reason, and the option's godoc says
  to enrol users before enabling it and names `mfa-enrolment-path` as the path that will close it.
  `go test -run TestRequireForAllLocksOutUnenrolled -count=1 ./mfa/` and `go doc ./policy`.

## 8. apikey: the manager and the in-memory store

- [x] 8.1 Create the `apikey` package with `Key{ID, Principal, Name, Scopes, SecretDigest,
  ExpiresAt, RevokedAt, LastUsedAt, CreatedAt}`, the `Store` port, and the sentinels
  `ErrVerificationFailed` and the key-not-found error. Verify the record carries no secret field by
  a reflection guard over its fields: `go test -run TestKeyCarriesNoSecret -count=1 ./apikey/`.
- [x] 8.2 Implement `NewManager(opts...)` with `WithStore`, `WithPrefix` (`sk`), `WithDigest`
  (SHA-256), `WithIDGenerator`, `WithClock` and `WithRandom`, failing construction on a prefix that
  is not 1–16 of `[a-z0-9]` and on a nil digest, generator, clock or random source. Verify a
  construction table including `Bad-Prefix`: `go test -run TestNewAPIKeyManager -count=1 ./apikey/`.
- [x] 8.3 Implement the in-memory store as the default, holding its own copies so mutating scopes
  passed in or returned cannot change stored state, and returning the key-not-found error for an
  unknown lookup, revocation or last-use update. Verify a copy-isolation case and the unknown-key
  cases: `go test -run TestMemoryKeyStore -count=1 ./apikey/`.
- [x] 8.4 Implement `Issue`: refuse an empty principal reference, read 32 random bytes, store only
  the digest, and return the presented key `<prefix>_<id>.<secret>` once alongside the record (D9,
  D10). On a random-source failure return an error and write nothing. Verify the presented form, the
  absence of the secret from the record and from `List`, the empty-principal refusal and the random
  failure asserting no write: `go test -run TestManagerIssue -count=1 ./apikey/`.
- [x] 8.5 Implement presented-key parsing: strip `<prefix>_`, cut at the first `.`, strictly parse
  the `id` as a `pkg/id.ID`, and refuse a wrong prefix or wrong shape with `ErrVerificationFailed`
  before any store call. Verify a table of malformed forms asserting the store was never consulted:
  `go test -run TestManagerParsePresented -count=1 ./apikey/`.
- [x] 8.6 Implement `Verify`: constant-time digest comparison, expiry and revocation checks, and the
  uniform `ErrVerificationFailed` for every failure including a store outage, with no error or log
  containing the presented key. Build `identity.Principal{Kind: KindService}` carrying the
  reference, name and exactly the stored scopes on success. Verify a table over unknown, wrong
  secret, expired, revoked and store-error rows asserting one identical error, and a success row
  asserting the principal: `go test -run TestManagerVerify -count=1 ./apikey/`.
- [x] 8.7 Implement expiry and revocation: a positive lifetime expires at issue time plus it, a
  lifetime of zero or less never expires, and revoking makes every later verification fail while
  revoking an unknown key returns the key-not-found error. Verify with an injected clock at 8 days
  and at 5 years: `go test -run 'TestManagerExpiry|TestManagerRevoke' -count=1 ./apikey/`.
- [x] 8.8 Implement `Rotate`: issue a new key for the same reference, name and scopes with the
  caller's lifetime, then revoke the old one, returning the new key only when both steps succeed and
  issuing nothing for an unknown key. Document on the method that the two steps are separate writes
  outside an attached transaction. Verify the new key verifies with the same principal and scopes,
  the old key fails, an unknown key issues nothing, and a revoke failure surfaces as an error:
  `go test -run TestManagerRotate -count=1 ./apikey/`.
- [x] 8.9 Implement best-effort `LastUsedAt`: a successful verification records it, and a failure to
  record does not fail verification. Verify both against an injected clock: `go test -run
  TestManagerLastUsed -count=1 ./apikey/`.
- [x] 8.10 Verify the consumer overrides: a consumer prefix appears on issued keys and a key issued
  under another prefix fails verification without a store call; a consumer digest function is used
  for both issuance and verification; and a consumer store serves every operation. `go test -run
  TestAPIKeyConsumerOverrides -count=1 ./apikey/`.

## 9. magiclink: requesting a link

- [x] 9.1 Create the `magiclink` package with `RequestResult{BindingNonce}`, `Redemption{Principal,
  PasswordChangedAt}`, the `Check` type and `ErrInvalidLink`. Verify the package builds and
  `Request`'s signature returns no error: `go test -run TestMagicLinkSurface -count=1 ./magiclink/`.
- [x] 9.2 Implement `NewManager(tokens, users, sender, linkBaseURL, opts...)` failing construction
  on an empty or relative base URL, and on `http` for a host that is not loopback (D11). Verify a
  table covering a missing base URL, `http://app.example.com`, `http://localhost:3000` and a good
  `https` URL: `go test -run TestNewMagicLinkManager -count=1 ./magiclink/`.
- [x] 9.3 Implement the synchronous-delivery refusal (D6): construction fails unless the sender
  reports `NonBlocking() bool` true or `WithSynchronousDelivery()` is given, and that option's
  godoc states that response time then reveals which addresses have accounts. Verify the SMTP
  sender is refused, the queued sender is accepted and the explicit option accepts the SMTP sender:
  `go test -run TestManagerRefusesSynchronousSender -count=1 ./magiclink/`.
- [x] 9.4 Implement the remaining options — `WithConfirmPath` (`/login/magic/confirm`, refusing a
  target that is not host-relative), `WithIssuanceLimit` (5, refusing below 1), `WithAddressResolver`,
  `WithRenderer`, `WithSameDeviceBinding` (true) — and the `BindingEnabled` and `TTL` readers.
  Verify a construction table plus the two readers: `go test -run TestMagicLinkOptions -count=1
  ./magiclink/`.
- [x] 9.5 Implement `Request`'s uniformity: every branch — unknown address, disabled user, resolver
  error, issuance limit reached, random or token-store failure, send failure, and success — returns
  the same empty result, with the cause logged server-side only. Verify one table walking every
  branch and asserting an identical result, and that no message is sent on any refusing branch:
  `go test -run TestRequestIsUniform -count=1 ./magiclink/`.
- [x] 9.6 Implement address resolution: by default the submitted address is passed unchanged to
  `LoadByUsername`, and a consumer resolver, when supplied, is the only path. Verify
  ` Ada@Example.com` reaches the loader untrimmed and unfolded, and that a consumer resolver
  mapping to `u-7` issues for `u-7` without `LoadByUsername` being called: `go test -run
  TestRequestResolvesAddress -count=1 ./magiclink/`.
- [x] 9.7 Implement per-user issuance counting against `onetime`'s issuance window, refusing at the
  limit. Verify five links in the last hour refuse a sixth with the default, and a configured limit
  of 2 refuses a third: `go test -run TestRequestIssuanceLimit -count=1 ./magiclink/`.
- [x] 9.8 Implement link construction and delivery: the token is issued with subject = user
  reference (D7) and, when binding is on, a binding value; the link is
  `base + confirmPath + "?token=" + token + "&next=" + QueryEscape(next)`; the message is rendered
  and its recipient forced to the submitted address. Verify the link's shape and that a consumer
  renderer's subject is used while its attempt to change the recipient is overridden: `go test -run
  TestRequestBuildsLink -count=1 ./magiclink/`.
- [x] 9.9 Verify the default message is neutral: it contains the link, says the link expires shortly
  and can be used once, and names no product, brand or organisation. `go test -run
  TestDefaultRenderer -count=1 ./magiclink/`.

## 10. magiclink: redemption

- [x] 10.1 Implement `Redeem` on top of `onetime.Manager.Redeem`, passing as the first refusal check
  a resolver that loads by user reference with `LoadByUserID`, refuses a miss, a disabled user or an
  ID mismatch, and records the principal; the caller's checks follow. Verify the ordering with a
  counting store asserting no consume on each refusing step: `go test -run TestRedeemOrdering
  -count=1 ./magiclink/`.
- [x] 10.2 Verify a link authenticates only the user it was minted for (D7): a link issued for `u-1`
  with username `ada`, after `u-1` is deleted and `ada` is reissued to `u-2`, is refused and
  establishes nothing for `u-2`; and a loader returning `u-9` when asked for `u-1` is refused.
  `go test -run TestRedeemBindsToUserReference -count=1 ./magiclink/`.
- [x] 10.3 Verify a refusal never spends the link: a policy deny followed by the user enrolling and
  redeeming the same link succeeds, and a loader connection error followed by recovery succeeds.
  `go test -run TestRefusalDoesNotSpendLink -count=1 ./magiclink/`.
- [x] 10.4 Verify racing redemptions: 16 requests redeeming one valid link yield exactly one
  success. `go test -run TestRedeemRace -race -count=1 ./magiclink/`.
- [x] 10.5 Implement the uniform `ErrInvalidLink` for a malformed, unknown, expired, consumed or
  wrong-purpose token, a wrong secret or binding, a user not found, disabled or mismatched, and a
  token-store or loader failure, with the cause logged at debug for expected traffic and at error
  for outages. Verify one table asserting an identical error across every row, and that a consume
  write failure establishes no session: `go test -run TestRedeemFailuresAreUniform -count=1
  ./magiclink/`.
- [x] 10.6 Verify consumer checks are returned unchanged: the first check that errors stops
  redemption, later checks do not run, the error matches the consumer's own sentinel, and the link
  stays redeemable. Document on `Check` that checks must have no side effects because racing
  redemptions each run them. `go test -run TestConsumerChecksReturnedUnchanged -count=1
  ./magiclink/`.
- [x] 10.7 Verify no error or log record contains the token, the binding value or the submitted
  address, across a failed and a successful redemption: `go test -run TestRedeemLogsCarryNoSecrets
  -count=1 ./magiclink/`.

## 11. httpsec: the MFA verify endpoint and the pending gate

- [x] 11.1 Implement `EnableMFA(method, opts...)` registering at `OrderMFAChallenge`, with
  `WithMFAVerifyPath` (`/mfa/totp`), `WithMFAVerifyLimiter` and `WithMFALogInterval` (1 min),
  failing construction on a method whose channel is empty, a nil or typed-nil method and a nil
  limiter (D1). Verify a construction table: `go test -run TestEnableMFA -count=1 ./httpsec/`.
- [x] 11.2 Implement the verify endpoint's ordering, written as one table that asserts what each
  step did and did not do: no session returns `ErrAuthenticationRequired`; a same-channel method
  returns `mfa.ErrSameChannel` before `code` is read, records no failure and leaves the challenge
  pending; the throttle is checked next; then the code is verified. Verify: `go test -run
  TestMFAVerifyOrdering -count=1 ./httpsec/`.
- [x] 11.3 Verify the same-channel cases from the spec: an email one-time-code method refuses on a
  magic-link session without being asked to verify, while a TOTP method on the same session proceeds
  and succeeds. `go test -run TestMFAVerifySameChannel -count=1 ./httpsec/`.
- [x] 11.4 Implement success: resolve the challenge (setting `MFASatisfiedAt`), rotate the handle
  (D5), place the new handle on the exchange, write 200 and end the chain. Verify the session
  reports no pending challenge and a satisfied time, the previous handle no longer loads, and the
  request never reaches a later handler: `go test -run TestMFAVerifySuccess -count=1 ./httpsec/`.
- [x] 11.5 Verify failure leaves everything as it was: a wrong code propagates `ErrInvalidCode`, the
  challenge stays pending and the handle is unchanged; and a GET to the verify path passes through
  verifying nothing. `go test -run TestMFAVerifyFailure -count=1 ./httpsec/`.
- [x] 11.6 Verify the consumer path override: configured at `/auth/second-factor`, a pending session
  posting a valid code there resolves the challenge. `go test -run TestMFAVerifyConsumerPath
  -count=1 ./httpsec/`.
- [x] 11.7 Implement the gate: any other request whose session has the MFA challenge pending is
  refused with `&ChallengeError{Kind: ChallengeMFA, Session: s}` and reaches no later handler.
  Verify a pending session requesting `/invoices` is refused and the handler is not called:
  `go test -run TestMFAGate -count=1 ./httpsec/`.
- [x] 11.8 Implement the logout exemption (D15): chain assembly gives the gate the configured logout
  path, so a POST there passes through and deletes the session whatever the slot order. Verify a
  pending session logs out and its handle no longer loads, with the default path and with a
  consumer's `/auth/sign-out`: `go test -run TestMFAGateLogoutExempt -count=1 ./httpsec/`.

- [x] 11.9 Implement `MFAResponder` and `WithMFAResponder`, called on success instead of a bare 200
  and given the rotated session, with a default that issues an access token for the rotated session
  and writes it with its expiry as JSON — the shape `LoginResponder`'s default already writes. An
  error the responder returns becomes the request's refusal. Verify the default response carries a
  token that names the rotated session and not the previous one, and that a responder returning an
  error refuses the request: `go test -run TestMFAVerifyResponder -count=1 ./httpsec/`.
- [x] 11.10 Verify rotation does not strand the caller, which is the defect that made 11.9
  necessary: a bearer caller completes its second factor, then uses the credential the verify
  response returned to reach a protected route successfully. Write it first against the bare-200
  endpoint and watch it fail with the caller unauthenticated, so the regression is pinned. Then
  verify a consumer responder that sets a cookie and writes no body replaces the default entirely
  and still receives the rotated session: `go test -run
  'TestMFAVerifyDoesNotStrandCaller|TestMFAVerifyConsumerResponder' -count=1 ./httpsec/`.

## 12. httpsec: the magic-link endpoints

- [x] 12.1 Implement `EnableMagicLink(manager, opts...)` registering at `OrderMagicLink`, with
  `WithMagicLinkRequestPath`, `WithMagicLinkConsumePath`, `WithBindingCookieName`,
  `WithAllowedRedirects`, `WithAllowedOrigins`, `WithMagicLinkCountRefusals` (true) and
  `WithMagicLinkLimiter`, failing construction on a nil or typed-nil manager or limiter. Verify a
  construction table: `go test -run TestEnableMagicLink -count=1 ./httpsec/`.
- [x] 12.2 Wire redirect validation to `internal/origin.NewAllowlist`, passing the option names so a
  bad entry's error names the entry and the option. Verify the spec's cases: an empty allowlist
  turns `/dashboard` into `/`, an allowlisted `/dashboard` is used exactly, `/dashboard.evil.example`
  and `//evil.example/dashboard` become `/`, an absolute entry on an undeclared origin fails
  construction naming it, and a declared origin makes that entry usable. `go test -run
  TestMagicLinkRedirects -count=1 ./httpsec/`.
- [x] 12.3 Implement the request endpoint: POST only, reading `email` and `next` from the form and
  falling back to a JSON body with parse failures degrading to empty values, sanitising `next`,
  calling `Request`, and writing 202 with a fixed body without passing the request on. Verify a
  known address, an unknown address and an unparsable body all receive the same status and body:
  `go test -run TestMagicLinkRequestEndpoint -count=1 ./httpsec/`.
- [x] 12.4 Implement the binding cookie: when `BindingEnabled()` is true the endpoint always sets it,
  with the genuine nonce or a same-shaped decoy of 16 random bytes in base64url, as `HttpOnly;
  Secure; SameSite=Lax; Path=<consumePath>; Max-Age=<TTL>`, its lifetime from configuration and
  never from the result. Verify the known and unknown responses carry cookies with identical
  attributes and equal-length values: `go test -run TestBindingCookieIsConstant -count=1
  ./httpsec/`.
- [x] 12.5 Verify binding is read from the manager, not configured on the interceptor: with binding
  disabled no cookie is ever set and a redemption from another device succeeds, and with it enabled
  a redemption without the cookie fails with `ErrInvalidLink`. `go test -run
  TestBindingFollowsManager -count=1 ./httpsec/`.
- [x] 12.6 Implement the consume endpoint: POST only, reading `token` and `next` from the form and
  the nonce from the cookie, with GET and HEAD passing through unread and unspent. Verify a GET with
  a valid token in the query leaves it spendable by a later POST, and that a successful redemption
  carries `Referrer-Policy: no-referrer`: `go test -run TestMagicLinkConsumeEndpoint -count=1
  ./httpsec/`.
- [x] 12.7 Implement the interceptor's policy `Check`, evaluating `PostAuthentication` with
  `FirstFactor: factor.MagicLink` and the password-change time, capturing `decision` and `evaluated`
  in the closure, returning `decision.Reason` or `policy.ErrPolicyDenied` on a deny and nil on
  challenge or allow. Verify a deny refuses and leaves the link redeemable, a deny without a reason
  refuses with the generic reason, and a challenge still spends the link, creates the session with
  the challenge pending and propagates the challenge error: `go test -run TestMagicLinkPolicyCheck
  -count=1 ./httpsec/`.
- [x] 12.8 Implement the post-success guard: when `!evaluated || decision.Outcome == Deny` the
  interceptor returns the deny reason (or the generic one) and creates no session and no token.
  Write both non-conforming redeemers first and see each fail with the guard removed: one that runs
  the check, receives a deny and reports success anyway, and one that never runs the checks. Verify:
  `go test -run TestRedeemerGuard -count=1 ./httpsec/`.
- [x] 12.9 Implement success: create the session with `WithFirstFactor(factor.MagicLink)` through
  the shared login tail, mark any challenge pending, issue the access token and return the challenge
  error or the success result. Verify the session records the magic-link first factor and the token
  is issued: `go test -run TestMagicLinkSuccess -count=1 ./httpsec/`.
- [x] 12.10 Implement rate-limit accounting (D8): check the source guard before `Redeem`, refusing a
  throttled or unattributable source with `ErrInvalidLink` without redeeming, and record a failure
  for the source on any `Redeem` error. Default to 10 failures per source per 15 minutes from a
  limiter owned by this flow alone. Verify ten policy-denied redemptions from one source refuse the
  eleventh without redeeming: `go test -run TestMagicLinkSourceAccounting -count=1 ./httpsec/`.
- [x] 12.11 Implement `WithMagicLinkCountRefusals(false)`, exempting exactly the refusal the
  interceptor's own check produced — matched with `errors.Is` against the captured `denyErr` — and
  the consumer check errors, while every other error, including one from a redeemer that discarded
  the deny and failed for another reason, is still recorded. Verify the opt-out lets a
  ten-times-denied source succeed once the policy allows, that ten wrong tokens still throttle it,
  and that the discarded-deny case is still recorded: `go test -run TestMagicLinkCountRefusalsOptOut
  -count=1 ./httpsec/`.
- [x] 12.12 Verify the throttle refusals are sampled through the guard's sampler with a reporter and
  carry no token, binding value or address: 500 attempts from one throttled source in a minute write
  one record. `go test -run TestMagicLinkThrottleLogSampling -count=1 ./httpsec/`.

- [x] 12.13 Implement `MagicLinkResult{Session, Token, Next}`, `MagicLinkResponder` and
  `WithMagicLinkResponder`, called on a successful redemption instead of writing the document
  directly, with the current document as the default it replaces: the access token, an empty refresh
  token field, the session's validity and the **resolved** redirect target. A nil responder is a
  configuration error, and an error the responder returns becomes the request's refusal. Verify the
  default document is unchanged from what shipped, and that a responder returning an error refuses:
  `go test -run TestMagicLinkResponder -count=1 ./httpsec/`.
- [x] 12.14 Verify the consumer override and the redirect-target guarantee together: a responder that
  sets a cookie and writes no body replaces the default entirely and receives the established
  session; and a responder handed a submitted target of `/dashboard` with an empty allowlist receives
  `/`, never the submitted value, so a consumer cannot reintroduce the redirect the allowlist
  refused. `go test -run 'TestMagicLinkConsumerResponder|TestMagicLinkResponderSeesResolvedTarget'
  -count=1 ./httpsec/`.

## 13. httpsec: the API key interceptor

- [x] 13.1 Implement `EnableAPIKey(manager, opts...)` registering at `OrderAPIKey`, with
  `WithAPIKeyScheme` (`ApiKey `) and `WithAPIKeyLimiter` (in-memory, 20 failures per source per
  minute), failing construction on a nil or typed-nil manager or limiter. Verify a construction
  table: `go test -run TestEnableAPIKey -count=1 ./httpsec/`.
- [x] 13.2 Implement header matching: a key is read only from `Authorization` after the literal
  scheme prefix, and a request without it passes through unauthenticated without consulting the
  limiter. Verify a table covering no header, a key in the `api_key` query parameter, a wrong
  scheme, and a consumer scheme `Service `: `go test -run TestAPIKeyHeaderMatching -count=1
  ./httpsec/`.
- [x] 13.3 Implement the ordering: check the source guard, refusing a throttled or unattributable
  source with `ErrAuthenticationFailed` joined with `apikey.ErrVerificationFailed` without
  verifying; then verify, recording a failure for the source and returning the same joined error on
  failure. Verify 20 invalid keys from one source then a valid key is refused without verification:
  `go test -run TestAPIKeyThrottle -count=1 ./httpsec/`.
- [x] 13.4 Implement the stateless phase: evaluate `StatelessAuthentication` with
  `FirstFactor: factor.APIKey`, refuse a deny with the policy's reason without recording a source
  failure, and populate the exchange without creating a session. Verify no session is created for a
  valid key, a consumer policy's reason refuses the request, and 25 policy-denied valid keys do not
  throttle a later allowed one: `go test -run TestAPIKeyStateless -count=1 ./httpsec/`.
- [x] 13.5 Verify the consumer limiter override and the sampled logging: a consumer's shared limiter
  receives every check and failure, and 300 keys from one throttled source in a minute write one
  record containing no presented key. `go test -run
  'TestAPIKeyConsumerLimiter|TestAPIKeyThrottleLogSampling' -count=1 ./httpsec/`.

## 14. The flagged construction refusal from http-security

- [x] 14.1 Implement the refusal `http-security` flagged: chain assembly fails with a configuration
  error when a registered policy can raise `policy.ChallengeMFA` and no interceptor is registered at
  `OrderMFAChallenge`. Verify a chain with an MFA policy and no `EnableMFA` fails to assemble, and
  that adding `EnableMFA` makes it succeed: `go test -run TestChainRefusesUnenforcedMFAChallenge
  -count=1 ./httpsec/`.
- [x] 14.2 Verify the refusal does not fire where it should not: a policy that can only challenge
  for a password change assembles without `EnableMFA`, and a chain with neither assembles. `go test
  -run TestChainMFAChallengeRefusalScope -count=1 ./httpsec/`.
- [x] 14.3 Verify the same wiring mistake fails the same way on every adapter, extending the
  existing construction conformance table: `go test -run TestConformanceConstruction -count=1 ./...`
  in `test`.

## 15. Integration across the methods

- [x] 15.1 Verify a magic-link login that the policy challenges for MFA runs end to end through one
  chain: the link is spent, a session is created with the magic-link first factor and the challenge
  pending, the challenge error propagates, the gate refuses `/invoices`, the verify endpoint accepts
  a TOTP code, the handle rotates and `/invoices` then succeeds. `go test -run
  TestMagicLinkThenMFA -count=1 ./httpsec/`.
- [x] 15.2 Verify an API key request is unaffected by an MFA policy: a valid key authenticates with
  no session and reaches the handler even while the chain enforces an MFA challenge for sessions,
  because `factor.APIKey` is MFA-exempt. `go test -run TestAPIKeyBypassesMFAGate -count=1
  ./httpsec/`.
- [x] 15.3 Verify the three flows' limiters are independent by default: exhausting the magic-link
  source limit leaves API key verification and MFA code verification unaffected. `go test -run
  TestFlowLimitersAreIndependent -count=1 ./httpsec/`.

## 16. Documentation, simplification and reconciling the artifacts

- [x] 16.1 Run `/simplify` over each of `notify`, `mfa`, `apikey`, `magiclink` and the new `httpsec`
  interceptors, and re-run each package's suite afterwards: `go test -count=1 ./notify/ ./mfa/
  ./apikey/ ./magiclink/ ./httpsec/`.
- [x] 16.2 Record in `design.md` the corrections this implementation made: `factor.Channel` and
  `factor.Kind` in place of `identity.Channel`; the existing `policy.MFAMethodLookup` in place of a
  new `mfa.EnrolmentLookup`, so `LookupFor` adapts rather than declares; and `internal/origin.Allowlist`
  in place of a new unexported `httpsec` redirect helper, which `oidc-login` will therefore also
  reuse. Verify `openspec validate auth-methods` passes.
- [x] 16.3 Record in `design.md` the three prerequisite APIs group 1 added — `Session.MFASatisfiedAt`,
  `session.Manager.Rotate` and `identity.UserLoader.LoadByUserID` — as decisions naming why each
  belongs to the capability that owns its package, and report that the archived `sessions` and
  `identity-model` specs now understate those packages. Report it; do not edit the archived specs.
- [x] 16.4 Report to `durable-persistence` what this change needs from it: `confirmed_at` and
  `last_step` columns on the MFA enrolment table, an API key table matching `apikey.Key`, and the
  `store-conformance` scenarios these ports need — `AcceptStep`'s conditional write, `PutPending`'s
  already-enrolled decision made by the write, and API key rotation's atomicity inside an attached
  transaction, which task 8.8 could not close here. Record the flag in `design.md`'s Risks.
- [x] 16.5 Write the `notify`, `mfa`, `magiclink` and `apikey` package godoc, naming for every option
  the default it replaces and for every port what the library uses when the consumer supplies none.
  State the limits the design commits to documenting: the queued sender's send timeout bounds only
  an inner sender that honours cancellation, and messages queued at a crash or a missed `Close` are
  lost; an attacker holding a password can lock a user out of MFA verification for 15 minutes; a
  magic-link request still does store work only for real accounts, so a small timing difference
  remains; an API key issued with a lifetime of zero or less never expires; and rotation is two
  writes outside a transaction. Verify `go doc` shows each: `go doc ./notify ./mfa ./magiclink
  ./apikey`.
- [x] 16.6 Run the full gate across every module and confirm it is green: `make check`.

## 17. Findings closed before archive

Both were raised by the simplification pass and recorded in `design.md` as labelled claims. They are
inside this change's own packages, and each contradicts something the change itself states.

- [x] 17.1 Make `notify`'s built-in senders report to `slog.Default()` when the consumer supplies no
  logger, replacing the discarding default on `WithSMTPLogger` and `WithQueueLogger`, and update both
  options' godoc to name the new default and to say that a consumer wanting silence supplies a
  discarding handler explicitly. A dropped queued message is a sign-in link that never arrives, and
  `Send` has already returned nil, so the failure is otherwise invisible at both ends. Verify a
  queued sender with no logger configured writes a record when it drops a message, and that a
  supplied discarding logger writes none: `go test -run TestQueuedSenderReportsDropsByDefault
  -count=1 ./notify/`.
- [x] 17.2 Strip cancellation from the context `mfa.VerifyThrottle.RecordFailure` hands its limiter,
  with `context.WithoutCancel`, matching `ratelimit.Limiter`'s documented contract that a client
  which hangs up mid-attempt is still charged for the guess it made — the contract
  `ratelimit.SourceGuard.RecordFailure` and `httpsec`'s source recorder already honour. Write the
  reproducing test first against a mockgen limiter that reports whether the context it received was
  already cancelled, and see it fail: `go test -run TestVerifyThrottleChargesAHangUp -count=1
  ./mfa/`.
