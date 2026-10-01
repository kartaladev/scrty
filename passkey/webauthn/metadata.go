package webauthn

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/clock"
)

// DefaultMDSURL is where MetadataFromMDS fetches the FIDO Metadata Service
// BLOB unless WithMDSURL names another.
const DefaultMDSURL = "https://mds3.fidoalliance.org/"

// MaxMetadataAge is the longest a fetched BLOB is used before it is fetched
// again, however late its nextUpdate.
const MaxMetadataAge = 24 * time.Hour

// MetadataSource supplies the FIDO Metadata Service (MDS3) BLOB that trusted
// attestation is checked against. Build one with MetadataBlob or
// MetadataFromMDS.
//
// A source decodes the BLOB itself and checks its signature chains to the
// metadata root (WithMDSRoot). It keeps a decoded BLOB until its nextUpdate
// and at most MaxMetadataAge, and then fetches it again on the next
// registration that needs it. A fetch or check that fails refuses every
// trusted registration until one succeeds: stale metadata is never used in its
// place, so the source fails closed.
//
// One source may be shared by several Verifiers; it is safe for concurrent
// use. Registrations that need the BLOB while it is being fetched wait for
// that one fetch and share its result, success or failure. Each waits only as
// long as its own context allows, and a registration whose context ends
// returns the context's error rather than a refusal. The fetch runs detached
// from the cancellation of the registration that started it, so that one
// registration giving up does not fail the others.
type MetadataSource interface {
	// provider returns the metadata trusted attestation is judged against
	// now, fetching it first when the cached BLOB has expired.
	provider(ctx context.Context) (metadata.Provider, error)
	// configErr reports the wiring mistake the source was built with, for New
	// to return wrapped in passkey.ErrConfig.
	configErr() error
}

// MDSOption configures a MetadataSource. Every option names the default it
// replaces.
type MDSOption func(*mdsConfig)

type mdsConfig struct {
	url    string
	urlSet bool
	root   *x509.Certificate
	clock  clock.Clock
	err    error
}

// WithMDSURL sets where MetadataFromMDS fetches the BLOB. Default:
// DefaultMDSURL. The URL must be absolute and one the confined client would
// send to, or New fails with passkey.ErrConfig. It has no meaning for
// MetadataBlob, whose BLOB the consumer fetches, and given there it is a
// configuration error.
func WithMDSURL(u string) MDSOption {
	return func(c *mdsConfig) { c.url, c.urlSet = u, true }
}

// WithMDSRoot sets the certificate the BLOB's signing chain must end at.
// Default: the FIDO Alliance's production MDS3 root, GlobalSign Root R46.
// A nil root is a configuration error.
func WithMDSRoot(root *x509.Certificate) MDSOption {
	return func(c *mdsConfig) {
		if root == nil {
			c.fail("the metadata root is nil")
			return
		}

		c.root = root
	}
}

// WithMDSClock sets the clock the BLOB's signing chain and its expiry are
// judged by. Default: clock.System(). A nil clock is a configuration error.
func WithMDSClock(clk clock.Clock) MDSOption {
	return func(c *mdsConfig) {
		if nilcheck.IsNil(clk) {
			c.fail("the metadata clock is nil")
			return
		}

		c.clock = clk
	}
}

func (c *mdsConfig) fail(reason string) {
	if c.err == nil {
		c.err = errors.New(reason)
	}
}

// MetadataBlob returns a source whose BLOB fetch returns: the MDS3 JWT,
// as the Metadata Service serves it. fetch is called when the cached BLOB has
// expired, and must not be nil.
//
// Concurrent registrations share one call of fetch, so its context carries
// the values of the registration that started it but not its cancellation or
// deadline. fetch must bound its own duration: while it runs, every
// registration that needs metadata waits for it.
//
// The consumer decides where the bytes come from, and so takes on what
// fetching them means: scrty only decodes and checks them.
func MetadataBlob(fetch func(ctx context.Context) ([]byte, error), opts ...MDSOption) MetadataSource {
	cfg := buildMDSConfig(opts)

	if cfg.urlSet {
		cfg.fail("WithMDSURL has no meaning for a consumer-fetched metadata BLOB")
	}

	if fetch == nil {
		cfg.fail("the metadata fetch function is nil")
	}

	return newMetadataCache(cfg, fetch)
}

// MetadataFromMDS returns a source that fetches the BLOB from the FIDO
// Metadata Service through client, scrty's confined outbound client, and
// never through the verification library's own HTTP client. client must not
// be nil, and must be configured to reach the service: the production BLOB is
// several megabytes, above outbound.DefaultMaxResponseBytes, so the client
// needs outbound.WithMaxResponseBytes raised to fit it.
func MetadataFromMDS(client *outbound.Client, opts ...MDSOption) MetadataSource {
	cfg := buildMDSConfig(opts)

	if !cfg.urlSet {
		cfg.url = DefaultMDSURL
	}

	if client == nil {
		cfg.fail("the metadata client is nil")
	} else if u, err := url.Parse(cfg.url); err != nil || !u.IsAbs() || u.Host == "" {
		cfg.fail("the metadata URL is not an absolute URL")
	} else if !client.AllowsScheme(u.Scheme) {
		cfg.fail("the metadata client does not send to the metadata URL's scheme")
	}

	target := cfg.url

	return newMetadataCache(cfg, func(ctx context.Context) ([]byte, error) {
		res, err := client.Get(ctx, target, nil)
		if err != nil {
			return nil, err
		}

		if res.Status != http.StatusOK {
			return nil, fmt.Errorf("webauthn: metadata service answered %d", res.Status)
		}

		return res.Body, nil
	})
}

func buildMDSConfig(opts []MDSOption) mdsConfig {
	var cfg mdsConfig

	for _, opt := range opts {
		if opt == nil {
			cfg.fail("a metadata option is nil")
			continue
		}

		opt(&cfg)
	}

	if cfg.clock == nil {
		cfg.clock = clock.System()
	}

	if cfg.root == nil && cfg.err == nil {
		root, err := parseStdCert(metadata.ProductionMDSRoot)
		if err != nil {
			cfg.fail("the production metadata root does not parse")
		}

		cfg.root = root
	}

	return cfg
}

func parseStdCert(b64 string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

// metadataCache is the MetadataSource both constructors return.
type metadataCache struct {
	fetch func(ctx context.Context) ([]byte, error)
	root  *x509.Certificate
	clock clock.Clock
	err   error

	flight singleflight.Group

	mu      sync.Mutex
	current metadata.Provider
	number  int
	loaded  bool
	expires time.Time
}

func newMetadataCache(cfg mdsConfig, fetch func(ctx context.Context) ([]byte, error)) *metadataCache {
	return &metadataCache{fetch: fetch, root: cfg.root, clock: cfg.clock, err: cfg.err}
}

func (c *metadataCache) configErr() error {
	if c == nil {
		return errors.New("the metadata source is nil")
	}

	return c.err
}

var errMetadataUnavailable = errors.New("webauthn: attestation metadata unavailable")

// provider returns the cached metadata while it is fresh. Otherwise it joins
// the fetch in flight, or starts one, and waits for it as long as ctx allows.
//
// The fetch is shared by every caller that arrives while it runs, so it runs
// detached from the cancellation of the caller that started it: one caller
// giving up must not fail the others. It keeps that caller's context values,
// and is bounded by the fetch itself (the confined client's timeout for
// MetadataFromMDS). A caller whose context ends while it waits returns the
// context's error; the fetch carries on for the rest.
func (c *metadataCache) provider(ctx context.Context) (metadata.Provider, error) {
	if p := c.fresh(c.clock.Now()); p != nil {
		return p, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	detached := context.WithoutCancel(ctx)
	ch := c.flight.DoChan("blob", func() (any, error) { return c.refresh(detached) })

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("webauthn: waiting for attestation metadata: %w", ctx.Err())
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}

		p, ok := res.Val.(metadata.Provider)
		if !ok {
			return nil, errMetadataUnavailable
		}

		return p, nil
	}
}

// fresh returns the cached metadata if it has not expired at now.
func (c *metadataCache) fresh(now time.Time) metadata.Provider {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.current != nil && now.Before(c.expires) {
		return c.current
	}

	return nil
}

// refresh fetches, checks and caches the BLOB. Only one refresh runs at a
// time, as the single flight's function.
func (c *metadataCache) refresh(ctx context.Context) (metadata.Provider, error) {
	now := c.clock.Now()

	c.mu.Lock()
	if c.current != nil && now.Before(c.expires) {
		// A flight that ended after this caller looked has refreshed it.
		p := c.current
		c.mu.Unlock()

		return p, nil
	}

	// The cached BLOB has expired: it is dropped before the refetch, so a
	// failed refetch leaves nothing to fall back on.
	c.current = nil
	number, loaded := c.number, c.loaded
	c.mu.Unlock()

	raw, err := c.fetch(ctx)
	if err != nil {
		return nil, errMetadataUnavailable
	}

	parsed, err := decodeBlob(raw, c.root, now)
	if err != nil {
		return nil, errMetadataUnavailable
	}

	next := parsed.Parsed.NextUpdate
	if !next.After(now) || (loaded && parsed.Parsed.Number < number) {
		return nil, errMetadataUnavailable
	}

	p, err := memory.New(
		memory.WithMetadata(parsed.ToMap()),
		memory.WithValidateEntry(true),
		memory.WithValidateEntryPermitZeroAAGUID(false),
		memory.WithValidateTrustAnchor(true),
		memory.WithValidateStatus(true),
		memory.WithValidateAttestationTypes(true),
	)
	if err != nil {
		return nil, errMetadataUnavailable
	}

	expires := now.Add(MaxMetadataAge)
	if next.Before(expires) {
		expires = next
	}

	c.mu.Lock()
	c.current, c.number, c.loaded, c.expires = p, parsed.Parsed.Number, true, expires
	c.mu.Unlock()

	return p, nil
}

// blobSigningMethods are the JWS algorithms a BLOB may be signed with.
var blobSigningMethods = []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}

// decodeBlob checks raw, an MDS3 JWT, against root at now, and decodes its
// entries. Entries that do not parse are left out, so the authenticators they
// describe are refused.
//
// The signature and its certificate chain are checked here rather than by the
// verification library's decoder, because that decoder also looks up the
// revocation status of the chain over the network with an HTTP client of its
// own, outside the confined client. The chain is checked against root at now
// only; its revocation is not looked up.
func decodeBlob(raw []byte, root *x509.Certificate, now time.Time) (*metadata.Metadata, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(blobSigningMethods),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)

	if _, err := parser.ParseWithClaims(string(raw), claims, func(tok *jwt.Token) (any, error) {
		return blobSigningKey(tok.Header, root, now)
	}); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	var payload metadata.PayloadJSON
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return nil, err
	}

	d, err := metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors())
	if err != nil {
		return nil, err
	}

	return d.Parse(&payload)
}

// blobSigningKey returns the key a BLOB's signature is checked with: that of
// the first certificate of its x5c header, once the chain verifies to root at
// now, or root's own when the header carries no chain, as MDS3 allows.
func blobSigningKey(header map[string]any, root *x509.Certificate, now time.Time) (any, error) {
	if _, ok := header["x5u"]; ok {
		return nil, errors.New("webauthn: metadata x5u header is not supported")
	}

	raw, ok := header["x5c"]
	if !ok {
		return root.PublicKey, nil
	}

	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, errors.New("webauthn: metadata x5c header is malformed")
	}

	certs := make([]*x509.Certificate, 0, len(list))

	for _, entry := range list {
		s, ok := entry.(string)
		if !ok {
			return nil, errors.New("webauthn: metadata x5c header is malformed")
		}

		cert, err := parseStdCert(s)
		if err != nil {
			return nil, errors.New("webauthn: metadata x5c certificate does not parse")
		}

		certs = append(certs, cert)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, errors.New("webauthn: metadata signing chain does not verify to the metadata root")
	}

	return certs[0].PublicKey, nil
}

// configError wraps a source's wiring mistake for New.
func configError(err error) error {
	return fmt.Errorf("%w: webauthn trusted attestation: %s", passkey.ErrConfig, err.Error())
}
