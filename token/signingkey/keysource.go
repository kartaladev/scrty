package signingkey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// PublicKey is one verification key: the public half of a key tokens were
// signed with, the identifier a token's header names it by, and the algorithm
// it verifies.
//
// It is a plain struct of standard-library types on purpose. KeySource is the
// port a consumer implements, and describing a key with a JOSE library's own
// type would oblige every such implementation to import that library, at the
// major version scrty happens to depend on, for no reason of its own: a bump
// there would then break implementations that never touch JOSE at all.
//
// Nothing here carries private material, and nothing here is shared with
// whatever holds the key. Key is the caller's own copy, so writing to it
// changes nothing on the other side.
type PublicKey struct {
	// Kid is the key identifier a token's header names to select this key. It
	// is unique among the keys a source publishes at any one moment;
	// verification matches on it, and never falls back to trying the rest of
	// the keys.
	Kid string

	// Alg is the one signature algorithm this key verifies, named as this
	// package's Alg constants name it. A token whose header declares another
	// algorithm is refused rather than checked against this key, which is
	// what stops a key being used under an algorithm it was not meant for.
	Alg Alg

	// Key is the public key itself: *rsa.PublicKey, *ecdsa.PublicKey or
	// ed25519.PublicKey for the algorithms this package supports.
	//
	// A consumer's own source may hand over some other type, because
	// crypto.PublicKey names no methods and nothing can check it here.
	// Whatever consumes the key decides whether it can use it, and reports
	// one it cannot as a failure to verify — an outage — rather than as a
	// token it has judged and refused.
	Key crypto.PublicKey
}

// clonePublicKey returns a copy of key that shares no structure with it.
//
// A crypto.PublicKey is never flat: an *rsa.PublicKey holds its modulus in a
// *big.Int, an *ecdsa.PublicKey holds two, and an ed25519.PublicKey is a
// slice. Handing any of them out as they are gives the caller a handle on the
// material this process verifies with, and a caller that normalises, caches or
// merely reuses what it was given then rewrites the key under everyone —
// after which every token that key signed stops verifying, for reasons that
// point at the wrong component entirely.
//
// An error means no copy could be made, and the caller reports it rather than
// falling back to the original: handing over the live key would defeat the
// only thing this function is for. Such an error is an outage on the
// verification path — the check did not happen — never a token judged and
// refused.
//
// A key of some other type is returned unchanged, and that is not an error.
// Nothing here can know how to copy a type it has never seen; refusing it
// would stop verifying the tokens it signed, which is a worse failure than
// sharing it, and dropping it silently would do the same without saying so. A
// source that supplies such a key is implemented outside this package and owns
// what happens to it.
func clonePublicKey(key crypto.PublicKey) (crypto.PublicKey, error) {
	switch pub := key.(type) {
	case *rsa.PublicKey:
		return &rsa.PublicKey{N: new(big.Int).Set(pub.N), E: pub.E}, nil
	case *ecdsa.PublicKey:
		// Curve is a stateless implementation shared process-wide — the
		// standard library's curves are singletons — so the copy shares it by
		// reference deliberately: ParseUncompressedPublicKey hands back a key
		// holding the very curve value it was given. The coordinates are the
		// only material here, and they are what has to be detached.
		//
		// They are detached by encoding the point and parsing it back, rather
		// than by reading X and Y into a key built from them. That round trip
		// is not merely the spelling that is not deprecated: parsing rejects a
		// point that is not on its curve, so what leaves here is a key this
		// process could verify with. Building a key from raw coordinates
		// checks nothing, and an off-curve key is exactly what a caller that
		// rewrote the coordinates it was handed would leave behind.
		encoded, err := pub.Bytes()
		if err != nil {
			return nil, fmt.Errorf("signingkey: encode ecdsa public key: %w", err)
		}

		clone, err := ecdsa.ParseUncompressedPublicKey(pub.Curve, encoded)
		if err != nil {
			return nil, fmt.Errorf("signingkey: parse ecdsa public key: %w", err)
		}

		return clone, nil
	case ed25519.PublicKey:
		return ed25519.PublicKey(slices.Clone(pub)), nil
	default:
		return key, nil
	}
}

// ErrNoKey is what a KeySource answers when it holds no key to sign with for
// the algorithm it was asked for. It is a fact about the source's keys, not a
// failure to reach them: Keys returns it for an algorithm it was not
// configured with, a key another replica published for that algorithm
// included, and a consumer's source returns it, or an error wrapping it, when
// it has no such key. Any other error from Signer means the source could not
// answer.
var ErrNoKey = errors.New("signingkey: no key for the algorithm")

// KeySource supplies the key to sign with and the set to verify against.
// *Keys implements it, and it is the only contract token issuance and
// verification depend on.
//
// A consumer may supply any implementation instead — one backed by an external
// key service or an HSM, for example — and tokens are then issued and verified
// with its keys, with no Keys constructed at all. There is no default:
// something has to hold the keys, so the source is always supplied by the
// caller.
//
// Every request carries the caller's context: issuing passes the context it
// was given, and verifying passes its own, with no context or deadline of the
// library's substituted. An implementation over a remote service should honour
// it, so the service call receives the request's deadline and cancellation.
// Keys does no input or output and answers whatever state the context is in.
//
// A remote service's quotas make a call per token impractical at scale, so such
// an implementation is expected to cache what it can — the verification keys
// above all — or to sign through a key it holds locally under envelope
// encryption.
type KeySource interface {
	// Signer returns the key identifier and signer currently signing for
	// alg.
	//
	// A source that holds no key for alg returns an error matching ErrNoKey,
	// rather than substituting another algorithm; issuing then fails as "no
	// current key for the algorithm". An error matching ErrNoKey is reported
	// as a missing key whatever else it wraps, so a source that cannot tell
	// whether it holds the key must not wrap ErrNoKey into its outage. Any
	// other error means the source could not answer — an outage — and issuing
	// fails with it behind fixed library text, never reported as a missing
	// key. So does a nil signer returned with a nil error. Whichever it is,
	// the endpoint that was issuing answers a dependency failure, not a
	// refusal.
	//
	// The library guards only against a nil signer. A non-nil signer whose
	// own methods panic, a wrapper around a nil key for example, is the
	// implementation's to fix: the library neither recovers nor translates
	// the panic.
	//
	// The signer serves the one issuance ctx belongs to. The generator asks
	// for a signer once for each token and never keeps or reuses it, so an
	// implementation over a remote signing service may return a crypto.Signer
	// bound to ctx, whose Sign call carries the request's deadline and
	// cancellation to the service.
	Signer(ctx context.Context, alg Alg) (kid string, signer crypto.Signer, err error)

	// VerificationKeys returns the public keys verification selects from,
	// each carrying its key identifier and the algorithm it verifies, and
	// none of them carrying private material. ctx is the verifying call's
	// own.
	//
	// It is asked on every verification, so an implementation that reaches a
	// remote key service is expected to cache. An error is an outage — the
	// check did not happen — and is never reported as a refused token, so an
	// implementation returns one rather than an empty result when it cannot
	// answer. The HTTP chain answers it as a dependency failure, 500 under the
	// default status mapping, and never as a request to authenticate again.
	//
	// The keys returned belong to the caller: an implementation that holds
	// its own keys hands over copies, because crypto.PublicKey is a pointer
	// or a slice into the material it verifies with.
	VerificationKeys(ctx context.Context) ([]PublicKey, error)
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
// which is what WithKeyLifetime configured.
func (km *Keys) KeyLifetime() time.Duration { return km.lifetime }

// RotateInterval reports how often a new key is minted, which is what
// WithRotateInterval configured.
func (km *Keys) RotateInterval() time.Duration { return km.rotateEvery }

var (
	_ KeySource        = (*Keys)(nil)
	_ LifetimeReporter = (*Keys)(nil)
)
