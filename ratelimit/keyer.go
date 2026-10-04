package ratelimit

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrSourceUnattributable is wrapped by every refusal of a client address that
// cannot be attributed to one source. A caller matches on it to tell "this
// request cannot be rate limited at all" from "this source is over its limit",
// which are different answers: the first is a wiring or protocol problem, the
// second is the limiter doing its job.
//
// Such an address is never keyed under a shared bucket. A shared bucket lets one
// source spend an allowance that every other unattributable caller then depends
// on, which turns one attacker into an outage for everyone behind the same gap
// in the address chain.
var ErrSourceUnattributable = errors.New("ratelimit: client address cannot be attributed to one source")

var (
	// ErrSourceEmpty is the refusal of a missing client address. It usually
	// means nothing upstream filled one in, rather than anything about the
	// caller, which is why it is worth telling apart from the other two.
	ErrSourceEmpty = fmt.Errorf("%w: no client address", ErrSourceUnattributable)

	// ErrSourceNotAnIP is the refusal of a value that is not one IP address:
	// a host and port, a forwarding list, a hostname, or anything else the
	// consumer passed through verbatim.
	ErrSourceNotAnIP = fmt.Errorf("%w: not a single IP address", ErrSourceUnattributable)

	// ErrSourceUnspecified is the refusal of the unspecified address, which
	// names no host at all and would otherwise become a bucket every caller
	// whose address was lost is counted under.
	ErrSourceUnspecified = fmt.Errorf("%w: the unspecified address", ErrSourceUnattributable)
)

// The reasons a refusal is logged and sampled under. They are stable strings, so
// an operator can alert on one without matching message text, and they are
// distinct so that one attacker flooding with a forwarding list cannot suppress
// the records that would show a misconfigured proxy sending none.
const (
	reasonEmpty       = "empty"
	reasonNotAnIP     = "not-an-ip"
	reasonUnspecified = "unspecified"
	reasonUnknown     = "unattributable"
)

// defaultIPv6Prefix is the prefix length IPv6 sources are keyed by.
//
// A /64 is the smallest allocation an IPv6 host is normally given, so it is the
// narrowest prefix that still costs an attacker something to move within.
const defaultIPv6Prefix = 64

// maxIPv6Prefix is the width of an IPv6 address, and so the widest prefix that
// can mask one.
const maxIPv6Prefix = 128

// Source is one client address that a guard has canonicalised and checked. It
// carries the key the guard counts under, and the key of its IPv6 aggregate when
// the guard has one, so the keys a check read and the keys a recording writes
// cannot drift apart.
//
// Its zero value names no source. A guard asked to record against it counts
// nothing and says so, because the alternative — inventing a key — would charge
// the failure to a source that never made the attempt.
type Source struct {
	key  string
	addr string

	aggregateKey  string
	aggregateAddr string
}

// Key returns the limiter key this source is counted under, including the flow
// the guard that produced it was constructed for. It is exported for logging and
// for a consumer's own metrics; nothing in this package accepts it back as a
// string, because a key that could be supplied by hand would let a caller charge
// one source's failure to another.
func (s Source) Key() string { return s.key }

// Addr returns the canonical form of the client address: the address itself for
// IPv4, or the prefix for IPv6. It is what a log or metric should name, rather
// than the raw value, so that two records about one source agree.
func (s Source) Addr() string { return s.addr }

// SourceKeyer turns a client address into the key failures are counted under.
//
// Canonicalising first is what makes the count mean "this source" rather than
// "this spelling of this source": an IPv4-mapped address and its plain form are
// one key, and an IPv6 address is keyed by its allocation rather than by one of
// the addresses inside it.
//
// A SourceKeyer holds no state and is safe for concurrent use.
type SourceKeyer struct {
	ipv6Prefix int
}

// NewSourceKeyer returns a keyer that keys IPv4 per address and IPv6 by prefix.
//
// Default: a /64 prefix for IPv6, replaceable with WithIPv6SourcePrefix. A
// prefix outside 1 to 128 is a configuration error wrapping ErrConfig: 0 would
// key every IPv6 source in the world under one bucket, and anything above 128 is
// wider than an address.
func NewSourceKeyer(opts ...KeyerOption) (*SourceKeyer, error) {
	k := &SourceKeyer{ipv6Prefix: defaultIPv6Prefix}
	for _, opt := range opts {
		if opt != nil {
			opt(k)
		}
	}

	if k.ipv6Prefix < 1 || k.ipv6Prefix > maxIPv6Prefix {
		return nil, fmt.Errorf(
			"%w: an IPv6 source prefix of %d is outside 1..%d, so it would either pool every "+
				"IPv6 source under one key or mask nothing at all",
			ErrConfig, k.ipv6Prefix, maxIPv6Prefix)
	}

	return k, nil
}

// Key returns the limiter key for clientAddr, or an error wrapping
// ErrSourceUnattributable when the address names no single source.
//
// The address is read exactly as the consumer supplied it. Trimming, splitting
// or picking an entry out of a list would be this package deciding which hop in
// a forwarding chain to trust, and that decision belongs to whatever terminates
// the connection: a guess here becomes a limit an attacker can aim at someone
// else by adding a header.
func (k *SourceKeyer) Key(clientAddr string) (string, error) {
	source, _, err := k.keys(clientAddr, 0)

	return source, err
}

// IPv6Prefix returns the prefix length IPv6 sources are keyed by. A guard reads
// it to refuse an aggregate that is no wider than the source, which would count
// nothing the source key does not already count.
func (k *SourceKeyer) IPv6Prefix() int { return k.ipv6Prefix }

// keys returns the source key for clientAddr and, for an IPv6 source when
// aggregateBits is positive, the enclosing /aggregateBits prefix it is also
// counted under. The aggregate is empty for IPv4 and when no aggregate is asked
// for.
//
// Both keys come from one parse so that they cannot disagree about which source
// they name: the aggregate is always the prefix that encloses the source key.
func (k *SourceKeyer) keys(clientAddr string, aggregateBits int) (source, aggregate string, err error) {
	if clientAddr == "" {
		return "", "", ErrSourceEmpty
	}

	addr, err := netip.ParseAddr(clientAddr)
	if err != nil {
		// The address itself is not repeated in the error. It is attacker-
		// controlled text on a path that logs its own refusals, and the reason
		// is what a caller acts on.
		return "", "", ErrSourceNotAnIP
	}

	// Unmapping first is what stops one IPv4 client holding two allowances,
	// one per spelling, depending on whether it reached a dual-stack listener
	// as ::ffff:a.b.c.d or as a.b.c.d. It is also what keeps a mapped IPv4
	// client out of an IPv6 aggregate it does not belong to.
	addr = addr.Unmap()

	if addr.IsUnspecified() {
		return "", "", ErrSourceUnspecified
	}

	if addr.Is4() {
		return addr.String(), "", nil
	}

	// The zone is a local interface name, not part of the source's identity:
	// the same host arriving over two interfaces is one source, and keeping the
	// zone would sell it a second allowance.
	addr = addr.WithZone("")

	prefix, err := addr.Prefix(k.ipv6Prefix)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrSourceNotAnIP, err)
	}

	if aggregateBits <= 0 {
		return prefix.String(), "", nil
	}

	wider, err := addr.Prefix(aggregateBits)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrSourceNotAnIP, err)
	}

	return prefix.String(), wider.String(), nil
}

// refusalReason names why an address was refused, for the log field and the
// sampler key. An error that is unattributable for some reason this function
// does not know is reported under its own reason rather than folded into one of
// the three, so a future refusal cannot silently inherit another's sampling.
func refusalReason(err error) string {
	switch {
	case errors.Is(err, ErrSourceEmpty):
		return reasonEmpty
	case errors.Is(err, ErrSourceNotAnIP):
		return reasonNotAnIP
	case errors.Is(err, ErrSourceUnspecified):
		return reasonUnspecified
	default:
		return reasonUnknown
	}
}
