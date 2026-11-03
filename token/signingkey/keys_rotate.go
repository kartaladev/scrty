package signingkey

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/eventsink"
)

// rotateAll mints and stores a new key for every configured algorithm. Each
// becomes current as soon as it is stored, and the key it replaces stays
// published until housekeeping removes it, so tokens already issued keep
// verifying.
//
// A failure leaves the previous key current, is reported, and is retried one
// rotation interval later. One algorithm failing does not stop the others.
func (km *Keys) rotateAll(ctx context.Context) {
	for _, alg := range km.algs {
		if _, f := km.mintAndStore(ctx, alg); f != nil {
			km.report(ctx, "rotate", alg, f)

			continue
		}

		eventsink.Deliver(ctx, km.events.Sink(), event.Event{
			Name: event.SigningKeyRotated, At: km.clock.Now(), Outcome: event.OutcomeSuccess,
		}, km.logger)
	}
}

// report tells the consumer about a rotation, reload or housekeeping failure: it calls the
// error hook, and writes a record to the logger unless the sampling window
// WithLogInterval describes has already had one for this operation and
// algorithm. The hook is never sampled.
//
// The record carries the failure's fixed reason and its cause's Go type
// through diag.Failure, never the cause's text: a consumer who wants that
// detail logs it inside their own implementation of KeyStore. The hook
// receives the failure's full error.
//
// Both reach consumer code, so no caller may hold the keyring lock across it:
// WithErrorHook promises a hook that Signer and VerificationKeys answer,
// and either one
// under the lock a caller already held would deadlock on the loop goroutine.
// The hook also runs on that goroutine, so a Shutdown it calls cannot wait
// for the work to end — documented in WithErrorHook and Shutdown, because
// nothing here can enforce it.
func (km *Keys) report(ctx context.Context, op string, alg Alg, f *failure) {
	if km.errorHook != nil {
		km.errorHook(f.err)
	}

	write, suppressed := km.sampler.Allow(sampleKey(op, alg), km.clock.Now())
	if !write {
		return
	}
	km.logger.LogAttrs(ctx, slog.LevelError, "signingkey: "+op+" failed",
		slices.Concat(failureAttrs(op, alg, suppressed), f.attrs, diag.Failure(f.reason, f.cause))...)
}

// opHousekeep is the operation a housekeeping failure is sampled and recorded by.
const opHousekeep = "housekeep"

// The fixed reasons a failure record names what failed by.
const (
	// reasonStore is the consumer's KeyStore failing a read or a write.
	reasonStore = "signing-key-store"
	// reasonDecode is a stored record this package cannot turn into a key.
	reasonDecode = "key-decode"
	// reasonGenerate is this package's own key generation failing, never a
	// consumer dependency.
	reasonGenerate = "key-generate"
)

// failure is one rotation, reload or housekeeping failure, as report needs it.
type failure struct {
	// err is the library's own error: what the hook receives and what
	// construction returns.
	err error
	// reason is the fixed word the record names the failure by.
	reason string
	// cause is the failing dependency's own error, or the decoding error,
	// whose Go type the record carries in place of err's wrapping.
	cause error
	// attrs are public identifiers of what failed, such as a key id.
	attrs []slog.Attr
}

// reportSuppressed writes the counts the sampler would otherwise discard: a
// failure that stops recurring before its next window still gets a record
// saying how many times it happened. The loops flush the sampler as they end,
// so a shutdown accounts for whatever was still pending.
//
// The sampler's reporter contract carries no context, so there is none to
// propagate here.
func (km *Keys) reportSuppressed(key string, suppressed int) {
	op, alg, _ := strings.Cut(key, sampleKeySeparator)
	km.logger.LogAttrs(context.Background(), slog.LevelError,
		"signingkey: repeated failures suppressed",
		failureAttrs(op, alg, suppressed)...)
}

// sampleKeySeparator joins the two halves of a sampler key. The key is a string
// because that is what the sampler counts by; reportSuppressed splits it back
// so a flushed record names the operation and algorithm the same way a live one
// does.
const sampleKeySeparator = ":"

func sampleKey(op string, alg Alg) string { return op + sampleKeySeparator + alg }

// failureAttrs renders a failure the same way whether it is written as it
// happens or accounted for at shutdown, so a consumer's handler sees one record
// shape. A whole-store reload failure belongs to no algorithm, and publishes no
// alg attribute rather than an empty one.
func failureAttrs(op string, alg Alg, suppressed int) []slog.Attr {
	attrs := make([]slog.Attr, 0, 4)
	attrs = append(attrs, slog.String("op", op))
	if alg != "" {
		attrs = append(attrs, slog.String("alg", alg))
	}
	return append(attrs, slog.Int("suppressed", suppressed))
}

// reload publishes every stored key the manager does not already hold and the
// publishing rule admits, re-picks the current key per algorithm, and stops
// publishing a held key past the rule that the store no longer lists.
//
// That last step is what keeps a key another replica's housekeeping deleted from
// being published here for up to a housekeeping interval longer. It asks both
// questions, because a key the store does not list may simply have been minted
// here after the listing was read, and such a key is well within the rule.
//
// This is what lets replicas sharing a store verify each other's tokens:
// without it, a key one replica rotated in would be rejected by every other
// replica until it restarted.
//
// A failure keeps the keys already held, so the manager goes on signing and
// verifying with them. A single record that cannot be decoded is reported and
// skipped rather than failing the whole reload, because the keys already held
// are still good and the next reload will try again — construction is the
// stricter case, where skipping a record would mint a replacement for it.
func (km *Keys) reload(ctx context.Context) {
	recs, err := km.store.LoadAll(ctx)
	if err != nil {
		km.report(ctx, "reload", "", &failure{
			err:    diag.Wrap(err, "signingkey: reload keys"),
			reason: reasonStore,
			cause:  err,
		})
		return
	}

	now := km.clock.Now()

	km.mu.RLock()
	held := make(map[string]struct{}, len(km.keys))
	for _, kid := range km.order {
		held[kid] = struct{}{}
	}
	keys := km.knownKeysLocked(storedKeys(recs))
	km.mu.RUnlock()

	// The publishing rule asks whether a record is the newest key of its
	// algorithm, and when it retires, and both are decided over everything known:
	// the keys held and the records not yet held alike.
	newest := km.pickCurrent(keys, now)
	retire := km.retireTimes(keys, now)

	// Decoding a record parses a private key and hashes a thumbprint, which
	// for RSA is not cheap. It happens outside the keyring lock so that a
	// reload never blocks signing or a JWK Set read, and failures are
	// collected rather than reported on the spot because a consumer's error
	// hook may call back into the manager.
	var fresh []*keyEntry
	var failed []struct {
		alg Alg
		f   *failure
	}
	for _, rec := range recs {
		if _, have := held[rec.Kid]; have {
			continue
		}
		// Asked before decoding, so a record that will not be published costs
		// no key parse.
		k := storedKey{kid: rec.Kid, alg: rec.Alg, createdAt: rec.CreatedAt}
		if !km.publishable(k, retire[rec.Kid], newest[rec.Alg] == rec.Kid, now) {
			continue
		}
		entry, err := entryFromRecord(rec)
		if err != nil {
			// The record names the decoding error's own type, not the
			// "decode key" wrapping every such error shares, and the public
			// kid it belongs to; never the record's key material.
			cause := errors.Unwrap(err)
			if cause == nil {
				cause = err
			}
			failed = append(failed, struct {
				alg Alg
				f   *failure
			}{alg: rec.Alg, f: &failure{
				err:    err,
				reason: reasonDecode,
				cause:  cause,
				attrs:  []slog.Attr{slog.String("kid", rec.Kid)},
			}})
			continue
		}
		fresh = append(fresh, entry)
	}

	km.mu.Lock()
	for _, entry := range fresh {
		km.holdLocked(entry)
	}
	km.listed = storedKeys(recs)
	km.repickCurrentLocked(now)
	km.dropUnlistedLocked(now)
	km.mu.Unlock()

	for _, failed := range failed {
		km.report(ctx, "reload", failed.alg, failed.f)
	}
}

// dropUnlistedLocked stops publishing every held key the publishing rule no
// longer admits and the listing a reload has just recorded does not name. Callers
// hold km.mu, and have re-picked the current keys.
func (km *Keys) dropUnlistedLocked(now time.Time) {
	listed := make(map[string]struct{}, len(km.listed))
	for _, k := range km.listed {
		listed[k.kid] = struct{}{}
	}

	km.dropLocked(now, func(kid string) bool {
		_, ok := listed[kid]
		return !ok
	})
}

// dropLocked stops publishing every held key the publishing rule no longer admits
// and candidate accepts. DeleteFunc calls the predicate exactly once per kid, in
// order, so dropping the key there keeps the two collections in step without a
// second pass or a fresh slice. It reads only what the manager already knows, so
// it needs no store. Callers hold km.mu.
func (km *Keys) dropLocked(now time.Time, candidate func(kid string) bool) {
	retire := km.retireTimes(km.knownKeysLocked(km.listed), now)
	km.order = slices.DeleteFunc(km.order, func(kid string) bool {
		entry := km.keys[kid]
		if km.publishable(entry.stored(), retire[kid], km.current[entry.alg] == kid, now) || !candidate(kid) {
			return false
		}
		delete(km.keys, kid)
		return true
	})
}

// storedKeys is recs as the keys newestByAlg judges, in the store's own order.
func storedKeys(recs []Record) []storedKey {
	keys := make([]storedKey, 0, len(recs))
	for _, rec := range recs {
		keys = append(keys, storedKey{kid: rec.Kid, alg: rec.Alg, createdAt: rec.CreatedAt})
	}
	return keys
}

// knownKeysLocked returns every key known to the manager given a listing, in the
// order a tie in creation time is broken by: first the held keys the listing does
// not name, in the order they were held, then every key it names, in its order. A
// held key takes its place from the listing like any other, so it wins a tie only
// where the store lists it later — as it did at construction — and never merely
// because it is held. Callers hold km.mu.
func (km *Keys) knownKeysLocked(listing []storedKey) []storedKey {
	listed := make(map[string]struct{}, len(listing))
	for _, k := range listing {
		listed[k.kid] = struct{}{}
	}

	keys := make([]storedKey, 0, len(km.order)+len(listing))
	for _, kid := range km.order {
		if _, ok := listed[kid]; !ok {
			keys = append(keys, km.keys[kid].stored())
		}
	}
	for _, k := range listing {
		if entry, ok := km.keys[k.kid]; ok {
			keys = append(keys, entry.stored())
			continue
		}
		keys = append(keys, k)
	}
	return keys
}

// housekeep stops publishing every held key the publishing rule no longer
// admits: every key past its retire time, as retireTimes computes it, or dated more
// than one lifetime ahead, except the current key of each algorithm, which is kept
// however old it is, since dropping it would leave the algorithm with nothing to
// sign with. Then, unless WithRetiredKeysKept is set, it deletes from the store the
// keys one grace past their retire time.
//
// Unpublishing comes first and needs no store, so a failing store never leaves
// a retired key published.
//
// It takes the keyring lock itself and is only ever called from its own loop,
// never from rotation while rotation holds that lock. The lock is released
// before the store is called: signing and verifying must not queue behind store
// I/O, and a failure's report reaches consumer code that may read the manager.
func (km *Keys) housekeep(ctx context.Context) {
	now := km.clock.Now()

	km.mu.Lock()
	km.dropLocked(now, func(string) bool { return true })
	km.mu.Unlock()

	if !km.keepRetired {
		km.deleteRetired(ctx, now)
	}
}

// deleteRetired deletes from the store every key whose retire time has passed by
// longer than the grace, and reports a failure rather than returning it. The retire
// time is the one publishing uses, judged from the listing alone, since that is what
// says which keys are stored. A key dated ahead of now has not reached its retire
// time, however far ahead: that date may come from another replica's clock, so the
// key is only unpublished, and stays in the store for that replica.
//
// The keys to delete come from the store's own listing at every run, not from what
// this run stopped publishing. That listing is what makes a failed delete a retry:
// the key was dropped from the keys held, so nothing held would find it again, and
// nothing in memory would outlive a restart, after which construction never holds
// it at all. It also covers a key this replica never held, such as one that was
// already past its retire time when the process started. A listing that fails is
// reported the same way, and the next run lists again.
//
// A key is never deleted while it is a current key of this manager, or the newest
// stored key of its algorithm, whether or not this manager signs with that
// algorithm: another replica may be signing with it, and a replica restarted later
// has to find it. That second guard is wider than the publishing rule, which
// exempts only configured algorithms, because unpublishing a key costs this replica
// alone, while deleting one costs every replica. Newest means what pickCurrent means
// by it, so a key dated later than the present plus the reload interval does not
// take the guard from the key a replica would really sign with. It is judged from
// the store's listing alone: a held key the listing lacks, as after a backup restore
// or a manual removal, is not a stored key, and must not take the newest place from
// one that is. A listing that has not caught up with a rotation delays a delete by
// one run at worst, which is the safe direction.
//
// One delete covers the run's keys. It deletes nothing it was not sure of when it
// listed: a rotation in the meantime only adds a key newer than every key listed,
// which is the successor of the listing's newest, and that one is never in the
// delete. Every other key keeps the successor it was judged by.
func (km *Keys) deleteRetired(ctx context.Context, now time.Time) {
	recs, err := km.store.LoadAll(ctx)
	if err != nil {
		km.report(ctx, opHousekeep, "", &failure{
			err:    diag.Wrap(err, "signingkey: list retired keys"),
			reason: reasonStore,
			cause:  err,
		})
		return
	}

	keys := storedKeys(recs)
	newest := km.newestByAlg(keys, now)
	retire := km.retireTimes(keys, now)

	km.mu.RLock()
	current := maps.Clone(km.current)
	km.mu.RUnlock()

	var retired []string
	for _, rec := range recs {
		if now.Sub(retire[rec.Kid]) > km.retiredGrace && newest[rec.Alg] != rec.Kid && current[rec.Alg] != rec.Kid {
			retired = append(retired, rec.Kid)
		}
	}
	if len(retired) == 0 {
		return
	}

	if err := km.store.Delete(ctx, retired...); err != nil {
		km.report(ctx, opHousekeep, "", &failure{
			err:    diag.Wrap(err, "signingkey: delete retired keys"),
			reason: reasonStore,
			cause:  err,
			attrs:  []slog.Attr{slog.String("kids", strings.Join(retired, ","))},
		})
	}
}
