package httpsec

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
)

//go:generate mockgen -destination=replaystore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/httpsec ReplayStore

// ReplayStore remembers the DPoP proofs the chain has accepted, so each proof
// is accepted once (RFC 9449 section 11.1).
//
// The default, when DPoP.Replay is nil, is an in-memory store per process with
// no size cap: it holds one entry per valid proof for about three minutes with
// the default proof age, so its size follows the request rate the deployment
// admits. A deployment with more than one replica supplies a store its
// replicas share, for the same reason it shares its rate limiters: otherwise a
// proof can be replayed once on each replica within its lifetime. A deployment
// that needs the store bounded supplies a shared or capped one the same way.
type ReplayStore interface {
	// Record records key until the instant until, and reports whether it was
	// absent: fresh is true for the first Record of a key, and false for
	// every later one before until has passed. It must be one atomic
	// insert-if-absent, so two requests presenting the same proof at the
	// same instant cannot both be told fresh.
	//
	// key is a digest of the proof's jti and its key's thumbprint, never
	// either one as it was sent. An error fails the request as a dependency
	// failure, never as a refused proof; an error matching ctx's own end is
	// a client that left.
	Record(ctx context.Context, key string, until time.Time) (fresh bool, err error)
}

// maxProofIDLength is the longest jti, in bytes, the chain records.
const maxProofIDLength = 256

// What a replay store that failed is recorded and returned with. The text is
// fixed: a consumer's store may word its failure with the key it could not
// reach.
const (
	reasonReplayStore     = "dpop-replay-store"
	msgDPoPReplayFailed   = "httpsec: a DPoP proof could not be checked for replay; the replay store failed"
	textDPoPReplayFailed  = "httpsec: DPoP replay store unavailable"
	msgDPoPReplayEnded    = "httpsec: the request ended while its DPoP proof was checked for replay"
	textDPoPReplayEnded   = "httpsec: the request ended while its DPoP proof was checked for replay"
	dpopFlow              = "dpop"
	replaySampleKeySuffix = sampleKeySeparator + reasonReplayStore
)

// record records an accepted proof's jti, keyed with its key's thumbprint,
// until replayRetention after its iat. It runs after every other check the
// request faces, so a refused proof consumes nothing.
//
// A jti longer than maxProofIDLength, and one already recorded, refuse the
// request with ErrInvalidDPoPProof. A store that fails is a dependency
// failure: fixed text, the store's error reachable, recorded at ERROR by type,
// sampled. A store that failed because the request's own context ended is a
// hang-up: the context's error, recorded at debug.
func (v *dpopVerifier) record(ctx context.Context, p dpopProof) error {
	if len(p.jti) > maxProofIDLength {
		return v.refuse(ctx, reasonProofID)
	}

	fresh, err := v.cfg.Replay.Record(ctx, replayKey(p.jti, p.jkt), p.iat.Add(replayRetention*v.cfg.ProofMaxAge))
	if err != nil {
		if hangup.ByCaller(ctx, err) {
			v.log.LogAttrs(ctx, slog.LevelDebug, msgDPoPReplayEnded)

			return diag.Wrap(err, textDPoPReplayEnded, ctx.Err())
		}

		logSampled(ctx, v.sampler, v.log, slog.LevelError, v.now(),
			dpopFlow+replaySampleKeySuffix, msgDPoPReplayFailed,
			diag.Failure(reasonReplayStore, err)...)

		return diag.Wrap(err, textDPoPReplayFailed)
	}

	if !fresh {
		return v.refuse(ctx, reasonProofReplayed)
	}

	// The proof is accepted: only now is it owed a fresh nonce, so a refused
	// proof is handed none and costs no seal.
	if p.staleNonce {
		v.refreshNonce(ctx)
	}

	return nil
}

// replayRetention is how many proof lifetimes, counted from a proof's iat,
// its record is kept. The iat check and the store's expiry read the clock at
// different moments, so a record kept for exactly one lifetime could have
// expired by the time a proof accepted at the lifetime's last instant is
// replayed. A second lifetime covers any delay between the two reads up to a
// whole lifetime.
const replayRetention = 2

// replayKey is the key a proof is recorded under: the base64url SHA-256 of
// its jti, length-prefixed so no two pairs share an encoding, and its key's
// thumbprint. The same jti from two keys is two proofs.
func replayKey(jti, jkt string) string {
	h := sha256.New()

	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(jti))) //nolint:gosec // G115: bounded by maxProofIDLength
	h.Write(n[:])
	h.Write([]byte(jti))
	h.Write([]byte(jkt))

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// memoryReplayStore is the in-memory ReplayStore EnableDPoP uses by default:
// replayShardCount shards chosen by the key, each one map under its own lock,
// so Record is an atomic insert-if-absent and requests on different shards do
// not wait for each other.
//
// Expired keys are swept per shard, on a Record that lands on the shard, at
// most once per sweep interval. A shard holds only the records still current
// and those that expired since its last sweep, a sweep walks only its own
// shard, and no goroutine is needed to drop them. It has no size cap: the
// records still current are one per valid proof, kept for about three
// minutes, so a deployment that must bound them supplies its own store.
type memoryReplayStore struct {
	now    func() time.Time
	shards [replayShardCount]replayShard
}

// replayShard is one shard of the memory store.
type replayShard struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	nextSweep time.Time
}

// replaySweepInterval is how often the memory store sweeps expired keys.
const replaySweepInterval = time.Minute

// replayShardCount is how many shards the memory store splits its records into.
const replayShardCount = 64

// replayShardIndex returns the index of the shard key is recorded in:
// FNV-1a over its bytes, modulo replayShardCount.
func replayShardIndex(key string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key)) // a hash.Hash never fails

	return int(h.Sum32() % replayShardCount)
}

func newMemoryReplayStore(now func() time.Time) *memoryReplayStore {
	m := &memoryReplayStore{now: now}
	for i := range m.shards {
		m.shards[i].seen = make(map[string]time.Time)
	}

	return m
}

// Record records key until until, unless it is already recorded and has not
// expired. It never fails.
func (m *memoryReplayStore) Record(_ context.Context, key string, until time.Time) (bool, error) {
	now := m.now()
	s := &m.shards[replayShardIndex(key)]

	s.mu.Lock()
	defer s.mu.Unlock()

	if !now.Before(s.nextSweep) {
		for k, exp := range s.seen {
			if !now.Before(exp) {
				delete(s.seen, k)
			}
		}
		s.nextSweep = now.Add(replaySweepInterval)
	}

	if exp, ok := s.seen[key]; ok && now.Before(exp) {
		return false, nil
	}

	s.seen[key] = until

	return true, nil
}
