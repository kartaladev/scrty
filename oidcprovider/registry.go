package oidcprovider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
)

//go:generate mockgen -source=registry.go -package=oidcprovider_test -destination=registry_mock_test.go -typed

// ClientSecret is one secret as a registry keeps it: its digest, never the
// secret.
type ClientSecret struct {
	// Digest is the secret's SHA-256 digest. It prints and marshals redacted.
	Digest SecretBytes
	// ExpiresAt is when the secret stops authenticating. Zero means never.
	ExpiresAt time.Time
}

// RegisteredClient is a client as a registry holds it.
type RegisteredClient struct {
	Client
	// Secrets holds at most two secrets, so a client can rotate without downtime.
	Secrets []ClientSecret
}

// ClientRegistry is where the provider reads its clients from.
type ClientRegistry interface {
	// Client returns the client, or ErrClientNotFound.
	Client(ctx context.Context, id string) (*RegisteredClient, error)
}

// ClientStore is a registry that can also be written.
type ClientStore interface {
	ClientRegistry
	Put(ctx context.Context, c Client) error
	Delete(ctx context.Context, id string) error
	GenerateSecret(ctx context.Context, clientID string) (string, error)
}

// sha256Size is the length of a held digest.
const sha256Size = sha256.Size

// generatedSecretBytes is the size of a generated secret: 256 bits.
const generatedSecretBytes = 32

// maxClientSecrets is how many secrets a client may hold, which is what a rotation
// without downtime needs.
const maxClientSecrets = 2

// NewClientSecret builds the record a registry holds for a secret the consumer
// supplies: its SHA-256 digest, and when it stops authenticating, with zero meaning
// never. A secret shorter than 32 bytes fails with ErrConfig. It is the one way to
// produce a digest the provider compares against, for a durable registry too.
func NewClientSecret(secret []byte, expiresAt time.Time) (ClientSecret, error) {
	if len(secret) < minSuppliedSecret {
		return ClientSecret{}, fmt.Errorf("%w: a supplied secret must be at least %d bytes", ErrConfig, minSuppliedSecret)
	}

	return ClientSecret{Digest: digestSecret(secret), ExpiresAt: expiresAt}, nil
}

func digestSecret(secret []byte) []byte {
	sum := sha256.Sum256(secret)

	return sum[:]
}

// matchesSecret reports whether secret is one of the client's live secrets at now.
// It compares digests in constant time, and checks every held secret whatever an
// earlier one answered, so the time taken says nothing about which one matched.
func (c *RegisteredClient) matchesSecret(secret []byte, now time.Time) bool {
	presented := digestSecret(secret)

	matched := 0
	for _, held := range c.Secrets {
		live := held.ExpiresAt.IsZero() || now.Before(held.ExpiresAt)
		if subtle.ConstantTimeCompare(presented, held.Digest) == 1 && live {
			matched = 1
		}
	}

	return matched == 1
}

// checkSecrets refuses what no registry may hold.
func (c *RegisteredClient) checkSecrets() error {
	if len(c.Secret) > 0 {
		return c.refuse("Secret", "a registry holds digests, never a secret")
	}
	if len(c.Secrets) > maxClientSecrets {
		return c.refuse("Secrets", fmt.Sprintf("a client holds at most %d", maxClientSecrets))
	}
	if len(c.Secrets) > 0 && !c.usesSecret() {
		return c.refuse("Secrets", fmt.Sprintf("%s takes no secret", c.AuthMethod))
	}
	for _, held := range c.Secrets {
		if len(held.Digest) != sha256Size {
			return c.refuse("Secrets", "a digest must be SHA-256")
		}
	}

	return nil
}

// clone returns a copy sharing nothing with c, so what a reader does to it stays
// its own.
func (c *RegisteredClient) clone() *RegisteredClient {
	out := *c
	out.Secret = slices.Clone(c.Secret)
	out.JWKS = slices.Clone(c.JWKS)
	out.RedirectURIs = slices.Clone(c.RedirectURIs)
	out.PostLogoutRedirectURIs = slices.Clone(c.PostLogoutRedirectURIs)
	out.Scopes = slices.Clone(c.Scopes)
	out.Resources = slices.Clone(c.Resources)
	out.DefaultAudience = slices.Clone(c.DefaultAudience)
	out.GrantTypes = slices.Clone(c.GrantTypes)
	out.Metadata = maps.Clone(c.Metadata)
	out.Secrets = slices.Clone(c.Secrets)
	for i := range out.Secrets {
		out.Secrets[i].Digest = slices.Clone(out.Secrets[i].Digest)
	}

	return &out
}

// MemoryRegistry is the default registry, kept in memory and lost with the
// process. A consumer needing clients to outlive it supplies its own ClientStore.
// It is safe for concurrent use, and its zero value is an empty registry ready to
// use.
type MemoryRegistry struct {
	mu      sync.RWMutex
	clients map[string]*RegisteredClient
}

var _ ClientStore = (*MemoryRegistry)(nil)

// NewMemoryRegistry builds a registry holding clients, each validated and each
// supplied secret reduced to its digest. The checks that need the provider's keys
// run when the registry is handed to New. A client using a secret may be registered
// with none, for GenerateSecret to give it one. An invalid client or a repeated
// identifier fails with ErrConfig.
func NewMemoryRegistry(clients []Client) (*MemoryRegistry, error) {
	r := &MemoryRegistry{clients: make(map[string]*RegisteredClient, len(clients))}
	for _, c := range clients {
		rc, err := newRegistered(c)
		if err != nil {
			return nil, err
		}
		if _, taken := r.clients[rc.ID]; taken {
			return nil, rc.refuse("ID", "is registered twice")
		}
		r.clients[rc.ID] = rc
	}

	return r, nil
}

// newRegistered validates c, and moves its supplied secret to a digest.
func newRegistered(c Client) (*RegisteredClient, error) {
	resolved, err := validateClient(c)
	if err != nil {
		return nil, err
	}

	rc := &RegisteredClient{Client: resolved}
	if len(resolved.Secret) > 0 {
		rc.Secrets = []ClientSecret{{Digest: digestSecret(resolved.Secret)}}
	}
	rc.Secret = nil

	return rc.clone(), nil
}

// Client returns a copy of the client, or ErrClientNotFound.
func (r *MemoryRegistry) Client(_ context.Context, id string) (*RegisteredClient, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rc, ok := r.clients[id]
	if !ok {
		return nil, ErrClientNotFound
	}

	return rc.clone(), nil
}

// Put adds or replaces a client, validated as NewMemoryRegistry validates one. A
// supplied Secret replaces the digests held, and no Secret keeps them, so changing
// a setting does not sign the client out. An algorithm the provider's keys cannot
// produce is reported when the client is next read, as an unknown client.
func (r *MemoryRegistry) Put(_ context.Context, c Client) error {
	rc, err := newRegistered(c)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if held, ok := r.clients[rc.ID]; ok && len(rc.Secrets) == 0 && rc.usesSecret() {
		rc.Secrets = held.Secrets
	}
	r.store(rc)

	return nil
}

// PutRegistered adds or replaces a client with exactly the secrets given, at most
// two, which is how a rotation is expressed: read the client, give the old secret
// an expiry, add the new one built by NewClientSecret. A failure leaves what was
// held unchanged.
func (r *MemoryRegistry) PutRegistered(_ context.Context, rc RegisteredClient) error {
	stored, err := validateRegistered(&rc)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.store(stored)

	return nil
}

// store holds rc, making the map first when the registry is a zero value. The
// caller holds the write lock.
func (r *MemoryRegistry) store(rc *RegisteredClient) {
	if r.clients == nil {
		r.clients = make(map[string]*RegisteredClient)
	}
	r.clients[rc.ID] = rc
}

// Delete removes a client, or answers ErrClientNotFound.
func (r *MemoryRegistry) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.clients[id]; !ok {
		return ErrClientNotFound
	}
	delete(r.clients, id)

	return nil
}

// GenerateSecret gives the client a new secret of 256 bits from a cryptographically
// secure source, replacing every secret it held, and returns it base64url encoded.
// This is the only time it can be read: the registry keeps its digest. To add a
// second secret instead, see PutRegistered. A client that uses no secret fails with
// ErrConfig, and an unknown one with ErrClientNotFound.
func (r *MemoryRegistry) GenerateSecret(_ context.Context, clientID string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rc, ok := r.clients[clientID]
	if !ok {
		return "", ErrClientNotFound
	}
	if !rc.usesSecret() {
		return "", rc.refuse("Secrets", fmt.Sprintf("%s takes no secret", rc.AuthMethod))
	}

	var raw [generatedSecretBytes]byte
	_, _ = rand.Read(raw[:]) // crypto/rand.Read never returns an error.
	secret := base64.RawURLEncoding.EncodeToString(raw[:])

	rc.Secrets = []ClientSecret{{Digest: digestSecret([]byte(secret))}}

	return secret, nil
}

// checkConfigured runs the checks that need the provider's keys over every client
// held, in a stable order so the first failure reported is always the same one.
func (r *MemoryRegistry) checkConfigured(limits keyLimits) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, id := range slices.Sorted(maps.Keys(r.clients)) {
		if err := r.clients[id].checkKeys(limits); err != nil {
			return err
		}
	}

	return nil
}

// validateRegistered validates what a registry holds, apart from the provider's
// keys, and returns a copy with its defaults resolved. rc is left as it was.
func validateRegistered(rc *RegisteredClient) (*RegisteredClient, error) {
	resolved, err := validateClient(rc.Client)
	if err != nil {
		return nil, err
	}

	out := (&RegisteredClient{Client: resolved, Secrets: rc.Secrets}).clone()
	if err := out.checkSecrets(); err != nil {
		return nil, err
	}
	out.Secret = nil

	return out, nil
}

// client reads a client through the registry, validated as it is read, because a
// consumer's registry could not be checked at construction (R13). A client failing
// that is logged with the setting and answered as unknown.
func (p *Provider) client(ctx context.Context, id string) (*RegisteredClient, error) {
	rc, err := p.registry.Client(ctx, id)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return nil, ErrClientNotFound
	case hangup.ByCaller(ctx, err):
		return nil, diag.Wrap(err, "oidcprovider: load client: the caller left", ctx.Err())
	case err != nil:
		return nil, diag.Wrap(err, "oidcprovider: load client", ErrDependency)
	case rc == nil:
		return nil, ErrClientNotFound
	}

	checked, err := p.checkRead(rc, id)
	if err != nil {
		p.logInvalidClient(ctx, id, err)

		return nil, ErrClientNotFound
	}

	return checked, nil
}

func (p *Provider) checkRead(rc *RegisteredClient, id string) (*RegisteredClient, error) {
	if rc.ID != id {
		return nil, rc.refuse("ID", "the registry answered with another client")
	}

	checked, err := validateRegistered(rc)
	if err != nil {
		return nil, err
	}
	if err := checked.checkKeys(p.limits); err != nil {
		return nil, err
	}

	return checked, nil
}

func (p *Provider) logInvalidClient(ctx context.Context, id string, err error) {
	attrs := []slog.Attr{slog.String("client", id)}

	var refused *clientError
	if errors.As(err, &refused) {
		attrs = append(attrs, slog.String("setting", refused.setting), slog.String("reason", refused.reason))
	}

	p.cfg.logger.LogAttrs(ctx, slog.LevelError, "oidcprovider: a registered client failed validation, and is treated as unknown", attrs...)
}
