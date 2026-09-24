// Package apikey issues and verifies the credentials machine clients present
// on every request, without a session.
//
// A Manager mints a key for a service principal, hands it back once, and
// afterwards knows it only by a digest. Verification turns a presented key into
// an identity.Principal of the service kind carrying the reference, name and
// scopes the key was issued with. Nothing here creates a session: a key
// authenticates one request and the next request presents it again.
//
// # Shown once
//
// Issue returns the presented key and its record. The presented key is the only
// place the secret ever exists outside the caller's hands — 32 bytes read from
// the operating system's random source — and what the store receives is a
// digest of it. No record, no read of a record and no listing of a principal's
// keys can produce the secret again, so a store that leaks yields nothing that
// authenticates and a caller who loses the string issues a new key.
//
// The digest is deliberately a fast hash, SHA-256 by default, and not a
// password hash. A secret of 256 bits from a cryptographically secure source
// leaves no search space for a slow key-derivation function to defend; all a
// slow hash would buy is latency on every machine request. A consumer whose
// policy names another digest supplies it, and both issuance and verification
// then use it.
//
// # Prefixed
//
// A presented key reads "<prefix>_<record identifier>.<secret>", with "sk" as
// the prefix unless a consumer sets their own. The prefix is there so that
// secret scanners, log redactors and the person reading a paste can recognise
// the string as a key before anything parses it. The record identifier is not a
// secret; it is what Revoke and Rotate are addressed by.
//
// Parsing is strict and runs before any store call, so a key of the wrong shape
// or the wrong prefix is refused without a lookup: a scanner firing malformed
// strings at an endpoint costs a string comparison, not a query.
//
// # One refusal
//
// Every verification failure is ErrVerificationFailed — a wrong shape, an
// unknown identifier, a wrong secret, an expired key, a revoked key and a store
// that could not answer alike. A caller able to tell them apart could enumerate
// which identifiers were ever issued, and an outage that looked different from
// a refusal would announce when the store was down. Digests are compared in
// constant time, and no error returned and no log written by this package
// carries the presented key or its secret.
//
// # Revocable
//
// A key issued with a positive lifetime stops being accepted after it. A key
// issued with a lifetime of zero or less never expires: nothing ages it out,
// and revocation is the only thing that ever ends it. That is deliberate — a
// machine credential on no rotation schedule is the ordinary case — but it
// means a deployment that issues such keys has to find the forgotten ones
// itself, which is what the record's LastUsedAt is for. Revoke takes effect on
// the next verification.
//
// Rotation is not atomic. Rotate issues a replacement with the same principal,
// name and scopes, and then revokes the old key, and outside a transaction the
// caller has attached to the store those are two separate writes: a failure
// between them leaves the new key issued and the old one still live. The error
// says so and names both identifiers, neither of which is a secret, so an
// operator can revoke the old one by hand. A store that carries a transaction
// can make the pair atomic; this package neither opens one nor requires one.
//
// # Defaults and ports
//
// Every default is replaceable without forking, and every option names the
// default it replaces: the store (NewMemoryStore, which does not survive a
// restart), the prefix ("sk"), the digest (SHA-256), the identifier generator
// (id.NewV7Generator), the clock (time.Now), the random source
// (crypto/rand.Reader) and the logger (slog.Default). A nil value is a
// configuration error for every one of them except the logger, where nil is
// read as "do not log from this component".
//
// A wiring mistake — an impossible prefix, a nil port — is a configuration
// error from NewManager, before any key is issued.
package apikey
