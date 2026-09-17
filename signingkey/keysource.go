package signingkey

import (
	"crypto"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// KeySource supplies the key to sign with and the set to verify against.
// *KeyManager implements it, and it is the only contract token issuance and
// verification depend on.
//
// A consumer may supply any implementation instead — one backed by an external
// key service or an HSM, for example — and tokens are then issued and verified
// with its keys, with no KeyManager constructed at all. There is no default:
// something has to hold the keys, so the source is always supplied by the
// caller.
type KeySource interface {
	// GetSigner returns the key identifier and signer currently signing for
	// alg, and whether there is one. An implementation that does not hold a
	// key for alg reports false rather than substituting another algorithm.
	GetSigner(alg Alg) (kid string, signer crypto.Signer, ok bool)

	// JWKS returns the public keys verification selects from, each carrying
	// its key identifier, algorithm and signature use, and no private
	// material.
	JWKS() (jwk.Set, error)
}

// LifetimeReporter is the optional half of KeySource: a source that knows how
// long its keys live and how often it replaces them lets a token generator
// refuse at construction a token lifetime that would outlive the key signing
// it.
//
// A source that does not implement it simply gets no such check; nothing else
// about it changes.
type LifetimeReporter interface {
	// KeyLifetime reports how long a key stays published after creation.
	KeyLifetime() time.Duration

	// RotateInterval reports how often the source replaces its keys.
	RotateInterval() time.Duration
}

// KeyLifetime reports how long a key stays published after it was created,
// which is what WithLifetime configured.
func (km *KeyManager) KeyLifetime() time.Duration { return km.lifetime }

// RotateInterval reports how often a new key is minted, which is what
// WithRotateInterval configured.
func (km *KeyManager) RotateInterval() time.Duration { return km.rotateEvery }

var (
	_ KeySource        = (*KeyManager)(nil)
	_ LifetimeReporter = (*KeyManager)(nil)
)
