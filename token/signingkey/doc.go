// Package signingkey manages the asymmetric keys scrty signs tokens with.
//
// A key manager generates a key per configured algorithm, writes it to a key
// store before using it, reloads the store so a restart invalidates no token,
// rotates keys on a schedule, and stops publishing keys past their retire time. It
// supplies the signer to sign with and the public keys to verify against to
// token issuance and verification through KeySource.
//
// KeySource names no type from a JOSE library, and neither does anything else
// this package exports. A consumer implementing the port describes its keys
// with the standard library's own crypto types, so the JOSE library scrty
// happens to use, and the major version it is pinned to, stay scrty's business
// rather than that consumer's.
//
// # Wiring
//
// New returns a manager that already has a current key and starts no
// goroutine. Start launches the rotation, reload and housekeeping loops, once:
// they keep the start context's values but not its cancellation, so only
// Shutdown ends them. Shutdown waits for them to end, an in-flight store write
// included, for as long as its own context allows. It is terminal: the loops
// never run again, but the manager keeps serving the keys it holds.
//
//	km, err := signingkey.New(ctx)
//	if err != nil {
//		return err
//	}
//	if err := km.Start(ctx); err != nil {
//		return err
//	}
//	defer func() {
//		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
//		defer cancel()
//		_ = km.Shutdown(shutdownCtx)
//	}()
//
// # Storage
//
// The default store is in-memory and lasts only as long as the process, so
// every token the previous process signed stops verifying. A consumer supplies
// any KeyStore instead through WithKeyStore — a durable one, or one that wraps
// another and seals Record.Private, which is opaque to every store and is
// where the secrets-at-rest capability hooks in.
//
// # When a key retires, and when it leaves the store
//
// A key retires one reload interval after the later of its creation plus the key
// lifetime, and its successor's creation plus the key lifetime minus the rotation
// interval. Its successor is the next newer stored key of its algorithm, not counting
// one dated later than the present plus the reload interval, so a far-future date
// cannot hold every older key back; a key with no successor counts only its creation
// plus the lifetime. A key is published at exactly its retire time, and retires
// strictly after it. So a key replaced on time retires one lifetime and one reload
// interval after its creation, and a key that stayed current through a rotation
// outage stays published for as long as the tokens it signed can be valid, since
// package token caps a token's lifetime at the lifetime minus the rotation interval.
// Construction, reload, housekeeping and deletion all apply this one rule, and the
// current key of a configured algorithm is published whatever its age.
//
// The reload interval is there because a replica sharing the store goes on signing
// with a replaced key until its next successful reload, and a token at the cap that
// it signs in that time verifies until it expires. The margin holds however short the
// cap is, including a lifetime less than a reload interval longer than the rotation
// interval, where with a grace of zero it is also what leaves a replaced key in the
// store until the replicas signing with it have reloaded. What it does not cover: a
// replica whose reloads keep failing signs for longer than the margin, each failure
// being reported, and the time a store write takes to make a successor visible is not
// counted.
//
// Housekeeping deletes a key from the store once its retire time has passed by
// longer than the grace, which is one key lifetime unless WithRetiredKeyGrace says
// otherwise, so the store stays the size the lifetime, the grace and the rotation
// interval imply. A key dated in the future is only unpublished, since that date may
// come from another replica's clock, and a failed delete is reported and attempted
// again at the next run. It never deletes a current key of this manager, or the
// newest stored key of an algorithm, whether or not this manager signs with it,
// since another replica may. The newest is judged from the store's listing alone, so
// a key this manager holds that the store no longer lists never stands in for it.
// Unless WithRetiredKeysKept is set, housekeeping lists the store at each run, and a
// listing that fails is reported and attempted again at the next run.
// WithRetiredKeysKept keeps retired keys for a consumer who audits them, and with it
// housekeeping only unpublishes and never lists the store.
//
// # Replicas sharing a store
//
// Replicas sharing a store must be configured alike, in WithKeyLifetime,
// WithRotateInterval, WithReloadInterval, WithRetiredKeyGrace and WithRetiredKeysKept,
// and must keep synchronised clocks. Each of those enters the rule above, so a replica
// rotating every 12 hours refuses a token that one rotating hourly verifies. A replica
// judges a key's age by its own clock and configuration, and a delete costs every
// replica. The grace reduces the harm of a skewed clock and does not remove it:
// with the defaults, a clock fast by more than about 47 hours deletes a key another
// replica is still signing with, and one fast by more than about a day can delete a
// key while a token at the lifetime cap is still live, which then fails to verify on
// any replica restarted before it expires. Nothing here detects a skewed clock.
//
// A key housekeeping deleted never brings back the keys before it: their retire times
// stay passed. Two other things do bring a retired key back. Removing a key by hand
// before it has retired makes the next newer key its predecessor's successor, and a
// predecessor already retired is published again until the later retire time that
// gives it. No rule read from the listing alone can tell, so leave deletion to
// housekeeping. And the newest stored key of an algorithm this manager does not sign
// with, which stays in the store past its retire time because another replica may be
// signing with it, comes back for one window when a successor later appears, including
// when a far-future key's date arrives, since its tokens may be live. A configured
// algorithm's key is current in that position, so this reaches no key this manager
// signs with.
//
// # Publishing
//
// Whatever verifies scrty's tokens elsewhere needs the keys they were signed
// with, so Keys.JWKS renders the ones it holds as the RFC 7517 document
// a /.well-known/jwks.json endpoint serves — bytes, so writing that response
// needs no JOSE library either. A consumer whose endpoint must say something
// else builds its own document from the keys VerificationKeys reports.
//
// # Two lags a consumer should expect
//
// A rotated key signs immediately, so an external verifier that caches the
// published keys — a JWKS endpoint's response, typically — will reject tokens
// signed with the new key until its cache expires. Keep that cache well inside
// the key lifetime, which is what keeps the replaced key published.
//
// Replicas sharing a store see each other's keys one reload interval later, a
// minute by default, so for up to that long one replica rejects a token
// another has just minted. WithReloadInterval narrows the window.
package signingkey
