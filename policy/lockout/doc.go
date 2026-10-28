// Package lockout holds the account lockout policy. It counts failed logins
// per submitted identifier and refuses an identifier that has failed too
// often, before its password is checked.
//
// Policy implements policy.Policy and runs in the pre-authentication phase.
// The store it counts failures in is the port policy.AttemptStore. The default
// is NewMemoryAttemptStore, which counts within one replica, and
// WithAttemptStore replaces it. A wiring mistake is refused by New with an
// error wrapping policy.ErrConfig.
//
// The policy makes an identifier wait, longer each time, by default.
// Equal first and longest waits (WithWait) make a lock of fixed
// duration instead. Unlike the CIS benchmark's lockout, the count is not
// cleared when that lock ends, so each further failure locks again. The
// ceiling still applies: a guesser who keeps to one failure per duration
// reaches it within about a day, and is then refused until failures age out of
// the window.
//
// A consumer who wants NIST SP 800-63B-4 §3.2.2's limit on consecutive
// failures adds a cap with WithCap(NISTCap); there is none by
// default. Under a cap, the identifier that reaches it is held: refused before
// its password is checked, whatever its waits, until its failures are cleared
// by a password change through the chain or by the policy's Reset, the unlock
// for an administrator. A hold never expires, and anyone who knows a username
// can cause one, which is why the cap is opt-in; WithCap documents the
// mitigations. A count below the cap expires after 30 days of inactivity
// (WithCapRetention).
package lockout
