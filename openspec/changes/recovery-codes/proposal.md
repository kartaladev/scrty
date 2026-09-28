## Why

scrty has no account recovery. A user who loses every authenticator the account depends on has no way back in: their only TOTP device, or, once `passkey-authentication` lands, every passkey. The only exit is the operator's MFA reset, and it covers MFA enrolments alone. The obvious shortcut, an emailed link, would let whoever controls the inbox take an account protected by two factors, downgrading it to one. NIST SP 800-63B-4 names three kinds of recovery proof: saved recovery codes, issued recovery codes and recovery contacts. Recovering an account at AAL2 requires two independent proofs. scrty supports none of the three today, and the passkey change needs a recovery path that is not weaker than the passkey itself.

## What Changes

- **Saved recovery codes.** A user can generate a set of codes to store offline:
  - each code carries at least 128 bits from `crypto/rand`, written as 26 Crockford base32 characters in groups of four;
  - only the SHA-256 hash of each code is stored, and a presented code is found by its hash;
  - entry tolerates case and dashes, and the alphabet leaves out I, L, O and U, so codes survive being read aloud or retyped;
  - a test or construction check pins the generated length, so no later change can silently shorten the codes;
  - a set holds 10 codes by default. This is the user's decision, the count Google and Dropbox issue. An option replaces the count, and a count of zero or less is refused at construction;
  - proving the set was kept, by entering one code back at passkey registration, spends nothing: it is a check, not a recovery;
  - when one or two codes remain, the recovery result and the code listing report it, so the consumer's interface can prompt a regeneration. The library reports the count and renders nothing;
  - a code is spent on its first use;
  - the user can see how many remain, and regenerating replaces the whole set;
  - presentation is throttled per user.

  No code is ever written to a log or an error.

  Storing the codes as plain SHA-256 is the user's decision, taken on security grounds:
  - **Meets NIST:** SP 800-63B-4 §3.1.2.2 requires a salted password hashing scheme only for look-up secrets below 112 bits, and an approved hash at or above that.
  - **Secure without configuration:** at 128 bits a code is secure by its entropy alone, so it does not depend on hash parameters staying high.
  - **No cost per attempt:** the unauthenticated recovery path spends no key derivation on a guess, so it cannot be used to exhaust CPU or memory.
  - **Consistent with scrty:** API keys and one-time tokens already use the same reasoning.
  - **Rejected:** short codes with Argon2id, which are easier to type but depend on configuration and cost a derivation per attempt; and short codes with a keyed fast hash, which does not meet NIST below 112 bits and adds key management.
- **Issued recovery codes.** When recovery starts, a code is sent by email through the existing sending port, to the address the existing contact resolver gives. By default that is the username, as for the MFA enrolment path. The library keeps no email address of its own, and the default identity store discards one, so a consumer whose usernames are not addresses supplies a resolver. It uses a one-time token manager under its own recovery purpose, so it is checked and then consumed, and valid for at most 24 hours. Issuance is throttled per user and per source. Starting recovery answers the same way whether or not the user exists, so it cannot be used to find accounts.
- **A two-proof recovery flow.** Recovery completes only with two proofs of different kinds:
  - a saved code and an issued code; or
  - one recovery code and an authenticator the user still holds: the password, or a method enrolled on the MFA slot `mfa-multi-method` introduces, such as TOTP.

  One proof alone never recovers an account, and an emailed code alone is never enough. Every proof is checked before any is spent, so a refused attempt consumes nothing.
- **A confined recovery session.** A completed recovery does not produce a full session. It produces a recovery-pending session, confined to the endpoints that bind a new authenticator, with a short lifetime. It becomes a full session only once a new authenticator is bound and proven. This follows the enrolment-pending pattern the MFA enrolment path already uses.
- **After recovery:**
  - the user is notified at every address the contact resolver gives, as NIST requires of a recovery. The notice gives clear instructions and contact details for repudiating a recovery the user did not make, as SP 800-63B-4 §4.6 requires;
  - every other session of the user ends by default, following the operator reset. Keeping them takes an explicit option, documented as weakening recovery;
  - existing authenticators are removed as described next.
- **Recovery completes without a waiting period by default.** This is the user's decision.
  - **Default:** a recovery that presents its two proofs completes at once. The session records when it was recovered (`RecoveredAt`), so a consumer can always act on a recent recovery.
  - **Why:** NIST SP 800-63B-4 requires no waiting period. The two proofs, the reset and the notification already keep recovery no weaker than login. A delay costs every legitimate user who lost everything, and Apple's multi-day waits are the common complaint. Whether that cost is worth paying depends on what the consumer's product protects, so it is the consumer's decision.
  - **Opt-in hardening, which can be combined:**
    - **A fixed, cancellable delay** (Apple's pattern). The proofs are checked when recovery starts, since an emailed code lives at most 24 hours, and the recovery becomes pending until a stated time. The user is notified at once with a cancel link. The recovery completes afterwards through a completion token issued at the start.
    - **A delay only when a recovery looks risky** (Google's security-hold pattern). The consumer supplies the risk function, because scrty keeps no device or location history. The library provides the hook.
    - **A cool-down after recovery** (the pattern exchanges use to hold withdrawals). A guard refuses the routes the consumer marks as sensitive, such as changing the email address, for a stated time after `RecoveredAt`.
  - **Guarantees under every choice:**
    - the notification with repudiation instructions;
    - while a recovery waits, the user's existing authenticators stay valid, and any normal login by the user, or the notice's cancel link, cancels it. That is how a delay protects the real user;
    - the authenticator reset runs when recovery completes, never when it starts, so a delay never locks out the real user it exists to protect.
- **A recovery resets the account's authenticators by default.** This is the user's decision.
  - **What it removes:** every passkey and MFA enrolment of the user, except an authenticator the user proved possession of in this recovery, such as an MFA method used as the second proof, which is evidently not lost.
  - **How it reaches each kind:** the reset goes through an authenticator-reset port this change defines. MFA enrolments implement it here. `passkey-authentication` implements it for passkeys when it lands, so recovery never depends on a kind of authenticator that does not exist yet.
  - **Why:** NIST requires compromised authenticators to be invalidated promptly, but the library cannot know which one is compromised: a lost phone can hold synced passkeys and TOTP at once. Current guidance treats recovery as an account-wide change in security state. A clean reset leaves no possibly-stolen authenticator behind and asks the user for no judgement at recovery time.
  - **Opt-in alternatives:**
    - **Remove only what was reported:** the user names what they lost, and only that is removed. It is less disruptive, and it is documented as trusting the user's report at the moment they are least sure.
    - **A custom policy:** a consumer's own function decides what to remove. It is given what the user holds, what they reported and what they proved in this recovery.
  - **Guarantees no option removes:**
    - the notification;
    - the confined session, so recovery never ends in a full session on its own;
    - a new authenticator must be bound before the session becomes full.
  - **A stated limit:** keeping every authenticator is not a built-in choice. A custom policy that removes nothing is possible, and the documentation states that it leaves possibly-compromised authenticators valid, against NIST's invalidation requirement.
- **Saved codes are required for a user who would otherwise have no way back in.** This is the user's decision. A user with no other way back into the account holds saved codes before their first passwordless authenticator counts. That covers a user with no password, no TOTP and no qualifying linked identity.
  - **Rule:** such a user's first passkey stays pending until a set of saved codes has been generated and the user proves they kept it by entering one code back. Only then does the passkey become usable. `passkey-authentication` enforces this at registration through a check this change provides.
  - **The check's contract:** this change defines and exports the check, which reports whether a user has another way back in given the enabled proof kinds and the user's authenticators. Kinds of authenticator added later, such as passkeys, feed it through the same authenticator port. The pending state and the confirm step are `passkey-authentication`'s.
  - **What counts as another way back in:**
    - a password or an enrolled MFA method, since it can pair with an issued code. This holds only while issued codes are enabled, because a password alone pairs with nothing else. The check therefore depends on the proof kinds the consumer enabled;
    - saved codes already held;
    - a linked OIDC identity, but only when that provider's login would admit the user without the second factor they might lose. The check reuses the MFA policy decision that the login itself would make, so the two cannot disagree. Today OIDC logins are exempt, so any linked provider qualifies. Under `oidc-mfa-assurance`, only a provider whose asserted assurance meets its configuration qualifies.
  - **Why:** NIST SP 800-63B-4 asks that a recovery code be issued at enrolment, and that subscribers be encouraged to keep two means of authentication. Both are SHOULDs. Services that are their users' only recovery path make codes mandatory at setup: GitHub requires downloading them to finish 2FA setup, and Microsoft requires a recovery code. scrty's consumers are in that position. Without saved codes, a passwordless-only user who loses every passkey can come back only through the operator reset.
  - **Opt-in alternative:** optional codes. Registration succeeds at once and reports that recovery is not set up, so the consumer's interface can prompt. The documentation states that this allows accounts only the operator can recover. Leaving everything to the consumer is not a separate mode: it is the optional mode with the prompt left unrendered.
  - **A wiring mistake:** passwordless login enabled while recovery codes are disabled, without the optional mode chosen, is a construction error, because the default could not be met. `passkey-authentication` applies this rule, since passwordless login arrives with it.
- **A linked OIDC identity is not a recovery proof.** This is the user's decision.
  - **Not a NIST route:** NIST's AAL2 recovery routes are recovery codes of different kinds, or one recovery code with an authenticator bound to the account. SP 800-63C-4 treats a federated login as an assertion, not an authenticator bound at the relying party, and names no federated recovery method.
  - **No assurance to rely on:** a federated login that declares no assurance carries none, and scrty does not read provider assurance today.
  - **Not independent:** a provider account is typically recoverable by the same email inbox that would receive the issued code, so the two proofs would not be independent, the cascading dependency recovery research describes.
  - **Nothing lost:** a linked identity that already admits the user is a way back in on its own. Making it a proof would add nothing but that dependency.
- **Off by default.** No recovery endpoint exists until the consumer enables it. Each proof kind is enabled separately. Wiring mistakes, such as recovery enabled with no second proof kind available, fail at construction.
- **Not in this change:** recovery contacts (the third NIST kind), and repeated identity proofing, which stays the consumer's process behind the operator reset.

## Capabilities

### New Capabilities

- `account-recovery`:
  - saved recovery codes, from generation, storage and spending through throttling and regeneration;
  - issued recovery codes;
  - the two-proof recovery flow;
  - the confined recovery session and its completion;
  - the authenticator reset on recovery, its opt-in alternatives and the guarantees no option removes;
  - post-recovery notification and session revocation;
  - the rule that recovery is never weaker than the authentication it replaces.

### Modified Capabilities

- `http-error-propagation`: status rows for the new refusals: recovery refused, a request from a recovery-pending session outside its confined endpoints, a route refused during a cool-down, and a cancelled or not-yet-completable delayed recovery.
- `one-time-tokens` and `rate-limiting`: no requirement changes. Issued codes use a one-time token manager under a recovery purpose, and the per-user and per-source throttles use the existing limiters and source guard, as both settled capabilities already allow.
- `sessions`: a recovery-pending state with its own shortened deadlines, and the time a session was recovered (`RecoveredAt`), both written only by the library.
- `http-security-chain`: the recovery endpoints, the gate that confines a recovery-pending session, the cancel endpoint for a delayed recovery, and the opt-in guard that refuses sensitive routes during a cool-down.
- `multi-factor-auth`: a recovery-pending session may bind a new second factor through the enrolment path, which by then serves several methods (`mfa-multi-method`), and a completed recovery removes MFA enrolments through the authenticator-reset port.
- `security-state-stores`: the saved-recovery-code store contract, with one-time spending decided by a conditional write and ambient-transaction participation.
- `schema-migrations`: the saved-recovery-code table in the security-state migration set.
- `store-conformance`: conformance cases for the saved-recovery-code store.

## Impact

- **Code:**
  - core: a recovery package, with its ports, saved-code generation and verification, and the flow;
  - `httpsec` gains the recovery endpoints and the gate;
  - `session` gains the recovery-pending state;
  - `onetime` is reused under a recovery purpose;
  - `notify` is reused for the emailed code and the notice.
- **Stores:** `sqlstore`, `pgx` and `gorm` gain the saved-code store. `migrate` gains its security-state table.
- **Dependencies:** none. Hashing and randomness come from the standard library.
- **Ordering:** the queue is `default-identity-store`, then `mfa-multi-method`, then this change, then `passkey-authentication`, by the user's decision.
  - This change builds on `mfa-multi-method`'s slot, because both change the enrolment path and the chain.
  - It does not depend on `default-identity-store`: it works with any identity store, and reaches addresses through the contact resolver.
  - `passkey-authentication` depends on this change, for recovery, the reset port and the check.

## Open Questions

None open. Every question raised during exploration was decided by the user:
- saved codes of 128 bits, stored as SHA-256;
- the authenticator reset on recovery, with its opt-ins;
- saved codes required for a user with no other way back in;
- a linked OIDC identity is not a recovery proof;
- no waiting period by default, with the opt-in delays and cool-down;
- 10 codes per set.

## References

All sources below are **Researched**: they were consulted while exploring this change, on 2026-09-28, and are grouped by the decision they informed. The one exception is marked: scrty's own `apikey` godoc, cited as project precedent.

### Recovery proofs and what a recovery requires
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/):
  - the three recovery proofs (saved codes, issued codes, recovery contacts) and the combinations AAL2 requires;
  - issued-code lifetimes, at most 24 hours by email;
  - the mandatory notification on recovery and on binding an authenticator;
  - the prompt invalidation of compromised authenticators.
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NIST SP 800-63B-4, second public draft (PDF)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.2pd.pdf)

### Saved codes are 128-bit and stored as SHA-256
- [NIST SP 800-63B-4: Authenticators, section 3.1.2.2](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/): look-up secrets below 112 bits need a salted password hashing scheme, and at or above it an approved hash is enough
- scrty's own `apikey` package godoc: the settled reasoning that a high-entropy secret leaves nothing for a slow hash to defend

### A recovery resets the account's authenticators by default
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) ([source](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)): recovery no weaker than authentication, notification when a recovery code is used, and re-authentication after recovery
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP WSTG: Testing Multi-Factor Authentication](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication.md)
- [Revoking sessions and trusted devices after MFA recovery (OneUptime)](https://oneuptime.com/blog/post/2026-08-29-how-to-revoke-sessions-and-trusted-devices-after-mfa-recovery-or-factor-replacement/view): treat recovery as an account-wide change in security state
- [Lost-device MFA recovery without a support authentication bypass (OneUptime)](https://oneuptime.com/blog/post/2026-08-29-how-to-design-lost-device-mfa-recovery-without-turning-support-into-an-authentication-bypass/view)
- [MFA's weakest link: account recovery is the new attack path (BleepingComputer)](https://www.bleepingcomputer.com/news/security/mfas-weakest-link-account-recovery-is-the-new-attack-path/)
- [Account takeover prevention in 2026 (ID Dataweb)](https://www.iddataweb.com/account-takeover-prevention-in-2026-closing-the-recovery-path-attackers-actually-use/)
- [MFA stops account takeover, until the recovery channel is compromised (iVerify)](https://iverify.io/blog/mfa-account-takeover-sim-swap-recovery-risk)
- [How to reset MFA safely: Entra ID, Okta, Duo (Trusona)](https://www.trusona.com/blog/how-to-reset-mfa-safely)

### Saved codes are required for a user with no other way back in
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/): "At enrollment, a CSP that supports this recovery option SHOULD issue a recovery code" (§4.2.1), and "SHOULD encourage subscribers to maintain at least two separate means of authentication" (§4.1.2.1)
- [Configuring two-factor authentication recovery methods (GitHub Docs)](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication-recovery-methods), [About two-factor authentication (GitHub Docs)](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/about-two-factor-authentication) and [community discussion #66864](https://github.com/orgs/community/discussions/66864): recovery codes must be downloaded to finish 2FA setup
- [How to go passwordless with your Microsoft account](https://support.microsoft.com/en-us/accounts-billing/security/how-to-go-passwordless-with-your-microsoft-account) and [How to get a Microsoft account recovery code](https://support.microsoft.com/en-us/accounts-billing/manage/how-to-get-a-microsoft-account-recovery-code) (Microsoft Support): a recovery code at 2FA and passwordless setup
- [Set up a recovery key for your Apple Account](https://support.apple.com/en-us/109345) and [About the security of passkeys](https://support.apple.com/en-us/102195) (Apple Support): optional there, because Apple is the passkey provider and recovers passkeys itself
- [Passkeys user journeys (Google for Developers)](https://developers.google.com/identity/passkeys/ux/user-journeys) and [Create a passkey for passwordless logins (web.dev)](https://web.dev/articles/passkey-registration): set up recovery at passkey creation. The single-proof methods Google suggests, email, phone or social login alone, were not adopted, because they would make recovery weaker than the passkey

### A linked OIDC identity is not a recovery proof
- [NIST SP 800-63C-4: Federation and Assertions](https://pages.nist.gov/800-63-4/sp800-63c.html) ([CSRC](https://csrc.nist.gov/pubs/sp/800/63/c/4/final)): an RP MAY offer recovery, linking requires an authenticated session, and a transaction that makes no assurance claim gets no assumed level. No federated recovery method is named.
- [How do users chain email accounts together? (ResearchGate)](https://www.researchgate.net/publication/352486300_How_Do_Users_Chain_Email_Accounts_Together): email recovery topologies and their exploitable loops
- [Understanding account recovery in the wild and its security implications (ResearchGate)](https://www.researchgate.net/publication/339634999_Understanding_Account_Recovery_in_the_Wild_and_Its_Security_Implications): email as a single point of failure for recovery
- [Is it really you who forgot the password? (arXiv)](https://arxiv.org/pdf/2403.11798)
- [A social approach to last-resort authentication (Microsoft Research)](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/paper1459-schechter.pdf)
- [Why your secondary email account could be your biggest privacy risk (Mailbird)](https://www.getmailbird.com/secondary-email-account-privacy-security-risk/): the cascading dependency on one inbox
- Reasoned also from scrty's own settled specs: `oidc-login` (OIDC logins are MFA-exempt and provider assurance is not read), `identity-linking`, and the active `oidc-mfa-assurance` change

### Recovery completes without a waiting period by default
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/): no waiting period required; issued-code lifetimes (§4.2.1.2, at most 24 hours by email); a notice "SHALL provide clear instructions, including contact information, in case the recipient repudiates the event" (§4.6)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) ([source](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Forgot_Password_Cheat_Sheet.md)) and [issue #2436](https://github.com/OWASP/CheatSheetSeries/issues/2436): recovery after a suspected compromise is not yet covered
- [How to use account recovery when you can't reset your Apple Account password (Apple Support)](https://support.apple.com/en-us/118574): a waiting period of several days or longer that support cannot shorten. User reaction: [Apple Community thread 253709721](https://discussions.apple.com/thread/253709721) and [thread 255064765](https://discussions.apple.com/thread/255064765)
- [Why your account recovery request is delayed (Google Account Help)](https://support.google.com/accounts/answer/9412469?hl=en): a risk-based security hold. See also [pcxio's timeline summary](https://pcxio.com/how-long-does-a-google-account-stay-locked-recovery-timelines-explained/)
- Cool-downs after a security reset:
  - [Binance.US](https://support.binance.us/en/articles/10128496-how-to-reset-two-factor-authentication) (48 hours);
  - [KuCoin](https://www.kucoin.com/support/900006118646);
  - [Bitvavo](https://support.bitvavo.com/hc/en-us/articles/4405081304593-Resetting-two-factor-authentication-2FA);
  - [Crypto.com](https://help.crypto.com/en/articles/3511454-how-do-i-reset-my-2fa);
  - [Bitget](https://www.bitget.com/support/articles/12560603807361);
  - [Bitso](https://support.bitso.com/hc/en-us/articles/14396463073428-Why-are-my-withdrawals-disabled).

### Ten codes per set by default
- [Sign in with backup codes (Google Account Help)](https://support.google.com/accounts/answer/1187538?hl=en&co=GENIE.Platform%3DDesktop) and [Google Authenticator backup codes explained (Guard.io)](https://guard.io/blog/google-authenticator-backup-codes): a set of 10 single-use codes, regenerated as a set
- [How to turn 2-factor authentication on and off (Dropbox Help)](https://help.dropbox.com/account-access/enable-2-factor-authentication): 10 single-use codes
- [Configuring two-factor authentication recovery methods (GitHub Docs)](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication-recovery-methods): 16 codes, and regenerating invalidates the old set
- [Need help signing in using 25 character recovery code (Microsoft Q&A)](https://learn.microsoft.com/en-us/answers/questions/3864786/need-help-signing-in-using-25-character-recovery-c): a single 25-character code
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/): no count specified

### How major services recover accounts
- [Recovering your account if you lose your 2FA credentials (GitHub Docs)](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/recovering-your-account-if-you-lose-your-2fa-credentials): saved recovery codes, and no support bypass
- [Configuring two-factor authentication recovery methods (GitHub Docs)](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication-recovery-methods)
- [FIDO Passkeys (FIDO Alliance)](https://fidoalliance.org/passkeys/): register at least two credentials, and keep another recovery method
- [Customer support (Passkey Central, FIDO Alliance)](https://www.passkeycentral.org/resources-and-tools/customer-support)
- [Passkeys user journeys (Google for Developers)](https://developers.google.com/identity/passkeys/ux/user-journeys)
