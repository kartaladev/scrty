package pgschema

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// The shared rate limiter's table, bounds and statements, over
// rate_limit_buckets: one row per namespace and key holding the failure
// stamps still inside the longest window recorded for it. Every statement
// reads the time once. Where a statement takes a now parameter, NULL means
// the database clock (clock_timestamp()); otherwise it is the caller's
// application-clock time.
const (
	// LimiterTable is the bucket table's name.
	LimiterTable = "rate_limit_buckets"

	// LimiterMaxLimit is the largest limit a limiter may be built with. A
	// bucket keeps at most that many stamps, which bounds the row's size.
	LimiterMaxLimit = 128

	// LimiterMaxNamespace is the longest namespace, in bytes.
	LimiterMaxNamespace = 64

	// LimiterMinServerVersion is the oldest server_version_num the limiter
	// runs against (PostgreSQL 15).
	LimiterMinServerVersion = 150000

	// LimiterMaxLockTimeoutMS is the largest value, in milliseconds, that
	// PostgreSQL accepts for lock_timeout (an int32). A record sets
	// lock_timeout from the limiter's operation timeout, so a timeout above it
	// would make every record fail.
	LimiterMaxLockTimeoutMS = 2147483647

	limiterMaxRawKey    = 512
	limiterDigestPrefix = "sha256:"
)

const (
	// LimiterCheck counts the stamps of a key still inside the window: $1
	// namespace, $2 key, $3 window in microseconds (int64), $4 now or NULL.
	// It returns one count, zero for a key with no row.
	LimiterCheck = `WITH t AS (SELECT coalesce($4::timestamptz, clock_timestamp()) AS now)
SELECT count(*) FROM rate_limit_buckets b CROSS JOIN t
CROSS JOIN LATERAL unnest(b.stamps) AS u(stamp)
WHERE b.namespace = $1 AND b.key = $2
  AND u.stamp > t.now - $3::bigint * interval '1 microsecond'`

	// LimiterRecord adds one failure stamp to a key in a single statement:
	// $1 namespace, $2 key, $3 limit (int), $4 window in microseconds
	// (int64), $5 now or NULL, $6 lock timeout as text, such as "250ms".
	//
	// A new key gets one row holding the stamp. An existing key keeps the
	// newest $3 of its stamps and the new one, ascending, so a clock behind
	// the stored newest stamp still leaves them ordered; newest_at and
	// longest_window_us only grow (GREATEST).
	//
	// lock_timeout is set, transaction-local, by a set_config in the SELECT
	// the INSERT reads from. That SELECT is evaluated before ON CONFLICT
	// waits on a row another transaction holds, so the setting is already in
	// force when the wait begins, with no separate round trip.
	LimiterRecord = `WITH t AS (SELECT coalesce($5::timestamptz, clock_timestamp()) AS now)
INSERT INTO rate_limit_buckets AS b (namespace, key, stamps, newest_at, longest_window_us)
SELECT $1, $2, ARRAY[t.now], t.now, $4::bigint
FROM t CROSS JOIN (SELECT set_config('lock_timeout', $6::text, true)) AS lt
ON CONFLICT (namespace, key) DO UPDATE SET
  stamps = (SELECT array_agg(n.s ORDER BY n.s) FROM
            (SELECT s FROM unnest(b.stamps || EXCLUDED.stamps) AS u(s) ORDER BY s DESC LIMIT $3::int) AS n),
  newest_at = GREATEST(b.newest_at, EXCLUDED.newest_at),
  longest_window_us = GREATEST(b.longest_window_us, EXCLUDED.longest_window_us)`

	// LimiterPrune deletes every key whose newest stamp is older than the
	// longest window ever recorded for it: $1 now or NULL. Rows another
	// transaction holds are skipped (FOR UPDATE SKIP LOCKED), so a sweep never
	// waits on, or deletes under, a live record. Rows affected is the count
	// removed.
	LimiterPrune = `WITH t AS (SELECT coalesce($1::timestamptz, clock_timestamp()) AS now),
victims AS (
  SELECT b.namespace, b.key FROM rate_limit_buckets b CROSS JOIN t
  WHERE b.newest_at + b.longest_window_us * interval '1 microsecond' <= t.now
  FOR UPDATE OF b SKIP LOCKED)
DELETE FROM rate_limit_buckets d USING victims v
WHERE d.namespace = v.namespace AND d.key = v.key`

	// LimiterDeleteKey forgets one key: $1 namespace, $2 key.
	LimiterDeleteKey = `DELETE FROM rate_limit_buckets WHERE namespace = $1 AND key = $2`

	// LimiterServerFacts reports, in one row, whether the server is a standby
	// (in_recovery), its server_version_num, whether the bucket table
	// resolves through search_path (table_exists) and whether that table is
	// logged (logged).
	LimiterServerFacts = `SELECT pg_is_in_recovery(),
  current_setting('server_version_num')::int,
  to_regclass('rate_limit_buckets') IS NOT NULL,
  coalesce((SELECT c.relpersistence = 'p' FROM pg_class c
            WHERE c.oid = to_regclass('rate_limit_buckets')), false)`
)

// LimiterKey maps a caller's key to its stored form: as given, unless it is
// longer than 512 bytes or itself begins "sha256:", when it is "sha256:" and
// the hex SHA-256 digest of the key, the same on every replica. Hashing a
// key that looks like a digest keeps a caller's key from colliding with the
// stored form of another.
func LimiterKey(key string) string {
	if len(key) <= limiterMaxRawKey && !strings.HasPrefix(key, limiterDigestPrefix) {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return limiterDigestPrefix + hex.EncodeToString(sum[:])
}
