package scrtyredis

import "github.com/redis/go-redis/v9"

// The scripts keep, per key, one sorted set of failure stamps. Each score is a
// stamp in microseconds. Each member is "<stamp>:<carried window>:<suffix>":
// the stamp, the longest window in microseconds any instance had recorded the
// key with when this member was added, and a random suffix, so two failures in
// the same microsecond are two members. Only recordScript reads a member; a
// member that does not have that shape is ignored. Each script touches only
// the one key it declares, so it runs on Redis Cluster without hash tags.
//
// Both read "now" from ARGV[1], or from the server's TIME when ARGV[1] is
// empty, and the window in microseconds from ARGV[2].
//
// A stamp is about 1.7e15 microseconds, exact in Lua's double but not in its
// default number-to-string conversion, which keeps 14 significant digits. A
// number concatenated into a string is therefore formatted with %.0f; one
// passed to redis.call as a number is converted by the server at full
// precision.

// recordScript records one failure. ARGV[3] is the limit and ARGV[4] the
// member's random suffix. It adds now, keeps the newest limit stamps, and
// makes the key live at least the carried window from now.
//
// It does not drop stamps older than its own window. They are already outside
// what exceededScript counts with that window, and the newest-limit cap
// bounds the set, so the count is the same either way; but another replica
// configured with a longer window, as during a rollout, still counts them, and
// a shorter-window replica trimming by its own window would disarm that
// replica's limit.
//
// For the same reason the lifetime covers the longest window the key has been
// recorded with, not only the recording instance's own. The carried window is
// the largest of this instance's window and the one every remaining member
// carries, so a shorter-window record made late in a longer window cannot
// expire the key while the longer-window replica still counts it. Every member
// is read, not only the newest, so a member stamped below the newest, under
// application-clock skew, cannot drop the carried window; the newest-limit cap
// bounds that scan. Only durations are compared, so it holds in both clock
// modes.
//
// The invariant is that the newest member always carries the longest window
// seen. The trim can remove the member that carried it, when application-clock
// skew stamps a longer-window record below a shorter-window one, so after the
// trim the newest survivor is rewritten, same score, stamp and suffix, to carry
// the carried window if it carries less.
//
// The lifetime, rounded up to whole milliseconds, is only ever extended: it is
// set only when the key's remaining lifetime is shorter. PTTL answers -1 for a
// key with no lifetime at all, which is shorter, so such a key gains one;
// PEXPIRE ... GT alone would leave it without, because GT reads no lifetime as
// an infinite one.
var recordScript = redis.NewScript(`
local now
if ARGV[1] == '' then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
else
  now = tonumber(ARGV[1])
end
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local carried = window
for _, m in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
  local w = tonumber(string.match(m, '^[^:]+:([^:]+):'))
  if w and w > carried then carried = w end
end
redis.call('ZADD', KEYS[1], now,
  string.format('%.0f', now) .. ':' .. string.format('%.0f', carried) .. ':' .. ARGV[4])
redis.call('ZREMRANGEBYRANK', KEYS[1], 0, -(limit + 1))
local newest = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
if newest[1] then
  local stamp, w, suffix = string.match(newest[1], '^([^:]+):([^:]+):(.*)$')
  w = tonumber(w)
  if w and w < carried then
    redis.call('ZREM', KEYS[1], newest[1])
    redis.call('ZADD', KEYS[1], newest[2],
      stamp .. ':' .. string.format('%.0f', carried) .. ':' .. suffix)
  end
end
local ttl_ms = math.ceil(carried / 1000)
if redis.call('PTTL', KEYS[1]) < ttl_ms then
  redis.call('PEXPIRE', KEYS[1], ttl_ms)
end
return 1
`)

// exceededScript counts the stamps strictly after now - window. It writes
// nothing, the key's lifetime included, and runs with EVALSHA_RO.
var exceededScript = redis.NewScript(`
local now
if ARGV[1] == '' then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
else
  now = tonumber(ARGV[1])
end
return redis.call('ZCOUNT', KEYS[1], string.format('(%.0f', now - tonumber(ARGV[2])), '+inf')
`)
