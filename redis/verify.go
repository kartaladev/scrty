package scrtyredis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

var (
	_ ratelimit.Verifier = (*Factory)(nil)
	_ ratelimit.Verifier = (*Limiter)(nil)
)

// Verify checks, before traffic, that the server behind the factory's client
// can hold its limits; no constructor calls it, because constructors perform
// no I/O. Call it at startup and refuse to serve on error.
//
// It checks, in order:
//   - the server version: Redis 7.0 or later, or Valkey 7.2 or later, read
//     from INFO server (valkey_version where the server reports one);
//   - the eviction policy, read with CONFIG GET: anything but
//     maxmemory-policy noeviction can evict a live key and disarm its limit.
//     A policy that cannot be read writes one WARN and passes.
//     WithEvictionPolicyCheck(false) skips this check;
//   - that both of the limiter's scripts load, with SCRIPT LOAD;
//   - that they run: the record script, then the check script, once on a
//     probe key of their own, the prefix, an empty namespace, "verify" and a
//     random suffix, which no limiter key can be. Its window is one
//     millisecond, so the key expires at once. The server checks the commands
//     a script runs against the caller's ACL only when it runs, so this is
//     what catches a user that may load the scripts but not run them.
//
// A server that fails a check, an ACL that refuses the probe included, is an
// error wrapping ratelimit.ErrConfig; an ACL refusal names what is missing
// rather than repeating the server's text. A server that cannot be reached,
// or a ctx that ends, is an error that does not wrap it. ctx bounds every call
// only because the client sets ContextTimeoutEnabled, which the constructors
// require.
//
// On a cluster, go-redis sends INFO and CONFIG GET to one node, so the version
// and the eviction policy are those of that node alone; every node must be
// configured alike, which Verify cannot check.
func (f *Factory) Verify(ctx context.Context) error { return f.check.verify(ctx) }

// Verify checks the server behind the limiter's client, as Factory.Verify
// does.
func (l *Limiter) Verify(ctx context.Context) error { return l.check.verify(ctx) }

// Server floors: the first releases with PEXPIRE's GT option and EVALSHA_RO.
var (
	redisFloor  = serverVersion{major: 7, minor: 0}
	valkeyFloor = serverVersion{major: 7, minor: 2}
)

// msgPolicyUnread is the WARN Verify writes when the eviction policy cannot
// be read. It is fixed, so that an operator's alert can match it.
const msgPolicyUnread = "scrtyredis: maxmemory-policy could not be read; the limiter needs noeviction, " +
	"because an evicted key disarms its limit"

// serverCheck is what Verify checks with.
type serverCheck struct {
	client        redis.UniversalClient
	evictionCheck bool
	logger        *slog.Logger
	// prefix is the key prefix the probe key goes under.
	prefix string
	// clock is the application clock, nil for the server's TIME, so the probe
	// runs the scripts as the limiter does.
	clock clock.Clock
}

func newServerCheck(client redis.UniversalClient, cfg config) serverCheck {
	return serverCheck{
		client:        client,
		evictionCheck: cfg.evictionCheck,
		logger:        cfg.unavailable.Logger,
		prefix:        cfg.prefix,
		clock:         cfg.clock,
	}
}

func (c serverCheck) verify(ctx context.Context) error {
	info, err := c.client.Info(ctx, "server").Result()
	if err != nil {
		return diag.Wrap(err, "scrtyredis: verify: the server version could not be read")
	}
	if err := checkVersion(info); err != nil {
		return err
	}

	if c.evictionCheck {
		if err := c.checkEvictionPolicy(ctx); err != nil {
			return err
		}
	}

	for _, s := range []*redis.Script{recordScript, exceededScript} {
		if err := s.Load(ctx, c.client).Err(); err != nil {
			if isServerError(err) {
				return diag.Wrap(err, "ratelimit: invalid configuration: the server refused to load the limiter's scripts with SCRIPT LOAD",
					ratelimit.ErrConfig)
			}
			return diag.Wrap(err, "scrtyredis: verify: the limiter's scripts could not be loaded")
		}
	}

	return c.probe(ctx)
}

// probeWindowUS is the probe's window in microseconds: one millisecond, the
// shortest lifetime a key can be given, so the probe key expires at once.
const probeWindowUS = "1000"

// probe runs the record script, then the check script, once on a probe key of
// its own. Redis checks the commands a script runs against the caller's ACL
// only when it runs, so a user that may load the scripts but not run what
// they call passes the load and would fail every record.
//
// The probe key is the prefix, an empty namespace, "verify" and a random
// suffix. No limiter has an empty namespace, so no limiter key can be it.
func (c serverCheck) probe(ctx context.Context) error {
	key := c.prefix + ":verify:" + memberSuffix()
	now := ""
	if c.clock != nil {
		now = strconv.FormatInt(c.clock.Now().UnixMicro(), 10)
	}

	if err := recordScript.Run(ctx, c.client, []string{key}, now, probeWindowUS, "1", memberSuffix()).Err(); err != nil {
		return probeError(err)
	}
	if err := exceededScript.RunRO(ctx, c.client, []string{key}, now, probeWindowUS).Err(); err != nil {
		return probeError(err)
	}
	return nil
}

// checkEvictionPolicy refuses any maxmemory-policy but noeviction. A policy
// the server will not tell, because CONFIG is blocked or renamed, is warned
// about once and passes; a connection failure is returned.
func (c serverCheck) checkEvictionPolicy(ctx context.Context) error {
	got, err := c.client.ConfigGet(ctx, "maxmemory-policy").Result()
	if err != nil && !isServerError(err) {
		return diag.Wrap(err, "scrtyredis: verify: maxmemory-policy could not be read")
	}
	policy, ok := got["maxmemory-policy"]
	if err != nil || !ok {
		var attrs []slog.Attr
		if err != nil {
			attrs = diag.Failure("config get", err)
		}
		c.logger.LogAttrs(ctx, slog.LevelWarn, msgPolicyUnread, attrs...)
		return nil
	}
	if policy != "noeviction" {
		return fmt.Errorf("%w: the server's maxmemory-policy is %q, which can evict a key whose failures still count and so disarm its limit; "+
			"the limiter needs noeviction (WithEvictionPolicyCheck(false) skips this check where the policy is verified out of band)",
			ratelimit.ErrConfig, policy)
	}
	return nil
}

// scriptCommands are the commands the scripts run, which the caller's ACL
// must allow besides the script commands themselves.
var scriptCommands = []string{"TIME", "ZRANGE", "ZADD", "ZREMRANGEBYRANK", "ZREM", "PTTL", "PEXPIRE", "ZCOUNT"}

// namedCommands are the commands an ACL refusal of the probe may name: those
// the scripts run, and those that run the scripts.
var namedCommands = append([]string{"EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO"}, scriptCommands...)

// noPermCommand finds the command an ACL refusal names.
var noPermCommand = regexp.MustCompile(`'([A-Za-z_]+)' command`)

// probeError classifies an error from the probe. An ACL refusal is a
// configuration error naming what is missing, in the library's own words:
// a command is named only when it is one the limiter sends or its scripts
// run, so no server text reaches the error. Anything else, a full server or
// an unreachable one, is not a configuration error.
func probeError(err error) error {
	text, ok := aclRefusalText(err)
	if !ok {
		return diag.Wrap(err, "scrtyredis: verify: the limiter's scripts could not run on a probe key")
	}

	// Redis 7.0 does not name the command a script was refused, so the
	// fallback names every one the scripts run.
	missing := "one of the commands they run (" + strings.Join(scriptCommands, ", ") + ")"
	if m := noPermCommand.FindStringSubmatch(text); m != nil && slices.Contains(namedCommands, strings.ToUpper(m[1])) {
		missing = "the " + strings.ToUpper(m[1]) + " command"
	} else if strings.Contains(strings.ToLower(text), "key") {
		missing = "access to keys under its prefix"
	}
	return diag.Wrap(err, "ratelimit: invalid configuration: the server's ACL refuses the limiter's scripts "+missing+
		"; grant the commands the package documentation lists", ratelimit.ErrConfig)
}

// aclRefusalText returns the server's text of err, when err is the server
// refusing a command under the caller's ACL: NOPERM for a command sent
// directly or a key refused, and for a command a script runs, "ACL failure in
// script", or on Redis 7.0 "can't run this command". The text is only
// classified, never returned.
func aclRefusalText(err error) (string, bool) {
	if !isServerError(err) {
		return "", false
	}
	text := err.Error() //nolint:forbidigo // classified only: probeError names a command from its own list, never the server's text
	refused := strings.HasPrefix(text, "NOPERM") ||
		strings.Contains(text, "ACL failure") || // Redis 7.2 and later, Valkey
		strings.Contains(text, "can't run this command") // Redis 7.0
	return text, refused
}

// isServerError reports whether err is an error reply from the server, as
// opposed to a failure to reach it.
func isServerError(err error) bool {
	var rerr redis.Error
	return errors.As(err, &rerr)
}

// serverVersion is a server's major and minor version.
type serverVersion struct{ major, minor int }

func (v serverVersion) less(o serverVersion) bool {
	return v.major < o.major || v.major == o.major && v.minor < o.minor
}

// checkVersion refuses a server older than the floor, given the text of
// INFO server. A Valkey server reports a redis_version it is compatible with
// besides its own valkey_version, and is judged by the latter.
func checkVersion(info string) error {
	fields := map[string]string{}
	for line := range strings.SplitSeq(info, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
			fields[k] = v
		}
	}

	name, raw, floor := "Valkey", fields["valkey_version"], valkeyFloor
	if raw == "" {
		name, raw, floor = "Redis", fields["redis_version"], redisFloor
	}
	if raw == "" {
		return fmt.Errorf("%w: the server reports no version in INFO server, so it cannot be checked against Redis %d.%d or Valkey %d.%d",
			ratelimit.ErrConfig, redisFloor.major, redisFloor.minor, valkeyFloor.major, valkeyFloor.minor)
	}
	v, err := parseVersion(raw)
	if err != nil {
		return fmt.Errorf("%w: the server reports %s version %q, which cannot be read, so it cannot be checked against %s %d.%d, the oldest the limiter supports",
			ratelimit.ErrConfig, name, raw, name, floor.major, floor.minor)
	}
	if v.less(floor) {
		return fmt.Errorf("%w: the server is %s %s, older than %s %d.%d, the oldest the limiter supports",
			ratelimit.ErrConfig, name, raw, name, floor.major, floor.minor)
	}
	return nil
}

// parseVersion reads the major and minor parts of a dotted version.
func parseVersion(raw string) (serverVersion, error) {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) < 2 {
		return serverVersion{}, errors.New("no minor version")
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return serverVersion{}, err
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return serverVersion{}, err
	}
	return serverVersion{major: major, minor: minor}, nil
}
