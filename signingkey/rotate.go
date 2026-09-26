package signingkey

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"

	"github.com/kartaladev/scrty/internal/diag"
)

// rotateAll mints and stores a new key for every configured algorithm. Each
// becomes current as soon as it is stored, and the key it replaces stays
// published until housekeeping removes it, so tokens already issued keep
// verifying.
//
// A failure leaves the previous key current, is reported, and is retried at the
// next tick. One algorithm failing does not stop the others.
func (km *KeyManager) rotateAll(ctx context.Context) {
	for _, alg := range km.algs {
		if _, f := km.mintAndStore(ctx, alg); f != nil {
			km.report(ctx, "rotate", alg, f)
		}
	}
}

// report tells the consumer about a rotation or reload failure: it calls the
// error hook, and writes a record to the logger unless the sampling window
// WithLogSampleWindow describes has already had one for this operation and
// algorithm. The hook is never sampled.
//
// The record carries the failure's fixed reason and its cause's Go type
// through diag.Failure, never the cause's text: a consumer who wants that
// detail logs it inside their own implementation of KeyStore. The hook
// receives the failure's full error.
//
// Both reach consumer code, so no caller may hold the keyring lock across it:
// WithErrorHook promises a hook that GetSigner and VerificationKeys answer,
// and either one
// under the lock a caller already held would deadlock on the loop goroutine.
// The hook also runs on that goroutine, so it may not call Start or Stop —
// documented in WithErrorHook, because nothing here can enforce it.
func (km *KeyManager) report(ctx context.Context, op string, alg Alg, f *failure) {
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

// failure is one rotation or reload failure, as report needs it.
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
func (km *KeyManager) reportSuppressed(key string, suppressed int) {
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

// reload publishes every stored key the manager does not already hold, skipping
// those past their lifetime, and then re-picks the current key per algorithm.
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
func (km *KeyManager) reload(ctx context.Context) {
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
	for kid := range km.keys {
		held[kid] = struct{}{}
	}
	km.mu.RUnlock()

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
		// pastLifetime, not expired: the current-key exemption cannot apply
		// here. A record that got this far is one the manager does not hold,
		// and every current key is a key it holds, so no record reaching this
		// line is current. Asking about an exemption that can never be granted
		// would read as a rule this path has and does not.
		if km.pastLifetime(rec.CreatedAt, now) {
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
	km.repickCurrentLocked()
	km.mu.Unlock()

	for _, failed := range failed {
		km.report(ctx, "reload", failed.alg, failed.f)
	}
}

// housekeep stops publishing every key created longer ago than the lifetime,
// except the current key of each algorithm, which is kept however old it is —
// dropping it would leave the algorithm with nothing to sign with.
//
// The store is not pruned: removal is from the keys held and the published JWK
// Set only. That is deliberate as well as structural — a KeyStore has no delete
// verb — because a durable store is where a restart finds the keys, and the
// records it keeps are what a consumer's own retention policy applies to.
//
// It takes the keyring lock itself and is only ever called from its own loop,
// never from rotation while rotation holds that lock.
func (km *KeyManager) housekeep(context.Context) {
	now := km.clock.Now()

	km.mu.Lock()
	defer km.mu.Unlock()

	// DeleteFunc calls the predicate exactly once per kid, in order, so
	// dropping the key there keeps the two collections in step without a
	// second pass or a fresh slice.
	km.order = slices.DeleteFunc(km.order, func(kid string) bool {
		entry := km.keys[kid]
		if !km.expired(km.current, entry.alg, kid, entry.createdAt, now) {
			return false
		}
		delete(km.keys, kid)
		return true
	})
}
