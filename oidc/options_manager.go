package oidc

import (
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/outbound"
)

// ManagerOption customises a Manager at construction.
//
// Every option replaces a default that already works. An option given nil
// fails construction with ErrConfig rather than silently keeping the default:
// a consumer who passed one meant to replace it. A nil option is ignored.
type ManagerOption func(*Manager) error

// WithOutboundClient replaces the client every request to a provider is sent
// through: discovery, key sets and the code exchange.
//
// The default is outbound.New() with its own defaults: https only, bounded
// time, size and redirects. A consumer supplies one to trust a test
// certificate authority, to allow http for a development provider, or to
// change those bounds. Confinement is then whatever the supplied client
// configures; no option here can weaken it past what package outbound allows.
func WithOutboundClient(c *outbound.Client) ManagerOption {
	return func(m *Manager) error {
		if c == nil {
			return fmt.Errorf("%w: WithOutboundClient was given nil", ErrConfig)
		}
		m.out = c
		return nil
	}
}

// WithRandom replaces the source that state, nonce, PKCE verifier and flow
// handles are drawn from. The default is crypto/rand.Reader. A nil reader,
// including a nil pointer inside a non-nil interface, is refused. The reader
// must be safe for concurrent use, as crypto/rand.Reader is.
//
// It exists so a test can fix or fail the source; production code has no
// reason to replace it.
func WithRandom(r io.Reader) ManagerOption {
	return func(m *Manager) error {
		if nilcheck.IsNil(r) {
			return fmt.Errorf("%w: WithRandom was given nil", ErrConfig)
		}
		m.random = r
		return nil
	}
}

// WithClock replaces the clock every expiry, TTL, cooldown and backoff
// decision reads. The default is time.Now.
func WithClock(now func() time.Time) ManagerOption {
	return func(m *Manager) error {
		if now == nil {
			return fmt.Errorf("%w: WithClock was given nil", ErrConfig)
		}
		m.now = now
		return nil
	}
}

// WithFlowStore sets where login flows are held between Authorize and
// Callback. A deployment of several instances supplies a shared store, since
// a flow begun on one instance may complete on another.
//
// The default is NewMemoryFlowStore with the manager's clock and random
// source: it holds at most DefaultMaxFlows unexpired flows for one process
// only, so behind several instances without sticky routing a callback that
// lands on another instance fails. A consumer who needs another maximum
// builds their own store, for example:
//
//	s, err := oidc.NewMemoryFlowStore(oidc.WithMaxFlows(n))
//
// and passes it here. A store the consumer builds this way does not share
// the manager's WithClock or WithRandom: it draws its own defaults (time.Now
// and crypto/rand.Reader) unless the consumer also passes
// WithMemoryFlowStoreClock and WithMemoryFlowStoreRandom to it, matching
// whatever WithClock or WithRandom the manager itself was given. A nil store,
// including a nil pointer inside a non-nil interface, is refused.
func WithFlowStore(s FlowStore) ManagerOption {
	return func(m *Manager) error {
		if nilcheck.IsNil(s) {
			return fmt.Errorf("%w: WithFlowStore was given nil", ErrConfig)
		}
		m.flows = s
		return nil
	}
}

// WithFlowTTL sets how long a login flow stays completable after Authorize,
// and so the longest a user may take at the provider. The default is
// DefaultFlowTTL (10 minutes). A TTL of zero or less is refused: no login
// could complete.
func WithFlowTTL(d time.Duration) ManagerOption {
	return func(m *Manager) error {
		if d <= 0 {
			return fmt.Errorf("%w: WithFlowTTL must be positive, got %s", ErrConfig, d)
		}
		m.flowTTL = d
		return nil
	}
}

// WithLogger replaces the logger refusals and provider failures are reported
// to. The default is slog.Default().
//
// No record this package writes carries a token, a client secret, a PKCE
// verifier, a state, a nonce, a handoff code or a claim value.
func WithLogger(l *slog.Logger) ManagerOption {
	return func(m *Manager) error {
		if l == nil {
			return fmt.Errorf("%w: WithLogger was given nil", ErrConfig)
		}
		m.log = l
		return nil
	}
}

// WithDiscoveryTTL sets how long a provider's discovery document and key set
// are served from the cache, with no request, before the next use refetches
// them. The default is DefaultDiscoveryTTL (15 minutes). A TTL of zero or
// less is refused: it would send a request on every login.
func WithDiscoveryTTL(d time.Duration) ManagerOption {
	return func(m *Manager) error {
		if d <= 0 {
			return fmt.Errorf("%w: WithDiscoveryTTL must be positive, got %s", ErrConfig, d)
		}
		m.cache.ttl = d
		return nil
	}
}

// WithDiscoveryFailureBackoff sets the window during which a provider's
// discovery document or key set is not refetched after a failed fetch: later
// callers receive the recorded failure with no request. The window starts at
// base, doubles with each consecutive failure up to maxWindow, and resets on
// a success. The defaults are DefaultDiscoveryBackoffBase (1 second) and
// DefaultDiscoveryBackoffMax (30 seconds). A base of zero or less, or a
// maxWindow below the base, is refused.
func WithDiscoveryFailureBackoff(base, maxWindow time.Duration) ManagerOption {
	return func(m *Manager) error {
		if base <= 0 || maxWindow < base {
			return fmt.Errorf("%w: WithDiscoveryFailureBackoff needs 0 < base <= max, got %s and %s",
				ErrConfig, base, maxWindow)
		}
		m.cache.backoffBase, m.cache.backoffMax = base, maxWindow
		return nil
	}
}

// WithJWKSRefetchCooldown sets how long after a refetch for an unknown key id
// further unknown key ids for the same provider are refused from the cache,
// with no request. The default is DefaultJWKSRefetchCooldown (30 seconds). The
// cooldown is tracked per provider. A cooldown of zero or less is refused: it
// would let every forged key id reach the provider.
func WithJWKSRefetchCooldown(d time.Duration) ManagerOption {
	return func(m *Manager) error {
		if d <= 0 {
			return fmt.Errorf("%w: WithJWKSRefetchCooldown must be positive, got %s", ErrConfig, d)
		}
		m.cache.cooldown = d
		return nil
	}
}

// WithDiscoveryStaleWhileError lets a provider's discovery document or key
// set be served for up to window past its TTL when its refetch fails, with a
// warning logged for every such use naming the provider and the entry's age.
//
// The default is zero: an expired entry whose refetch fails is refused, so a
// provider outage fails logins rather than trusting keys the provider may have
// revoked. Even with a window, a stale key set is never served to a token
// whose key id it lacks, and a fresh set is never served in place of a failed
// refetch for an unknown key id. A negative window is refused.
func WithDiscoveryStaleWhileError(window time.Duration) ManagerOption {
	return func(m *Manager) error {
		if window < 0 {
			return fmt.Errorf("%w: WithDiscoveryStaleWhileError must not be negative, got %s", ErrConfig, window)
		}
		m.cache.stale = window
		return nil
	}
}

// DefaultClockSkew is the leeway allowed on a provider token's exp, iat and
// nbf when WithClockSkew is not given.
const DefaultClockSkew = 60 * time.Second

// WithClockSkew sets the leeway allowed between the manager's clock and a
// provider's when judging a token's expiry (exp), issued-at (iat) and
// not-before (nbf) times. The default is DefaultClockSkew (60 seconds). Zero
// tolerates no difference at all; a negative leeway is refused, since it would
// refuse tokens that are valid now.
func WithClockSkew(d time.Duration) ManagerOption {
	return func(m *Manager) error {
		if d < 0 {
			return fmt.Errorf("%w: WithClockSkew must not be negative, got %s", ErrConfig, d)
		}
		m.skew, m.skewSet = d, true
		return nil
	}
}

// WithLogoutTokenMaxAge sets how old a back-channel logout token's issued-at
// time may be, beyond the clock leeway (WithClockSkew), before the token is
// refused. The default is DefaultLogoutTokenMaxAge (2 minutes).
//
// The maximum age is also the replay window: no jti is recorded, so a captured
// token is accepted again until its issued-at is older than the maximum age
// plus the leeway, and widening one widens the other. A maximum age of zero or
// less is refused: no token could be accepted.
func WithLogoutTokenMaxAge(d time.Duration) ManagerOption {
	return func(m *Manager) error {
		if d <= 0 {
			return fmt.Errorf("%w: WithLogoutTokenMaxAge must be positive, got %s", ErrConfig, d)
		}
		m.logoutMaxAge = d
		return nil
	}
}

// WithPostLogoutRedirect sets the URL a provider is asked to send the browser
// back to after RP-initiated logout, as post_logout_redirect_uri in
// EndSessionURL. The default is none: the parameter is omitted and the
// provider shows its own page.
//
// It must be an absolute URL with a host and no user information, whose scheme
// the outbound client allows, as every provider URL must: with the default
// client that means https, and a consumer who needs http for development
// supplies a client built with outbound.WithAllowedSchemes("http") through
// WithOutboundClient. Anything else, the empty string included, fails
// construction with ErrConfig. The URL is sent exactly as given, since
// providers compare it byte for byte with the one registered.
func WithPostLogoutRedirect(u string) ManagerOption {
	return func(m *Manager) error {
		parsed, err := url.Parse(u)
		if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil {
			return fmt.Errorf("%w: WithPostLogoutRedirect needs an absolute URL with a host and no user information",
				ErrConfig)
		}
		m.postLogoutRedirect = u
		return nil
	}
}
