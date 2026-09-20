package signingkey

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// JWKS returns the keys the manager holds as the RFC 7517 JSON document a JWKS
// endpoint serves: an object with a "keys" array, one entry per key, each
// carrying its kid, the algorithm it verifies and use "sig".
//
// It answers in bytes rather than in a key-set type so serving the endpoint is
// a w.Write away and a consumer needs no JOSE library to publish what this
// process signs with — the same promise KeySource makes, kept here too, since
// a document that obliged its caller to import a JOSE library to hand it over
// would have kept none of it.
//
// Every key held is published, one stored for an algorithm this manager was
// not configured with included, exactly as VerificationKeys reports them and
// in the same order: a replica sharing the store may have written that key,
// and publishing it is what verifies the tokens it signed. Publishing a key is
// not signing with it — GetSigner hands out none of them — and a key stops
// being published once it is past the key lifetime, like any other. Nothing
// private is rendered: each entry is built from the public half alone, so the
// document is safe to serve to anyone who asks for it.
//
// This is the opinionated document, and it is the only one this package
// produces. A consumer whose infrastructure wants something else — a filtered
// set, another order, extra parameters such as x5c, or the whole thing wrapped
// in an object of its own — builds it from VerificationKeys, which hands over
// each key's identifier, algorithm and public half as standard-library types
// for exactly that purpose.
//
// Nothing is cached: every call renders the document afresh, under the same
// read lock the other read methods take, which for a handful of keys is a JSON
// encode and some base64. An endpoint served on every request by a fleet of
// verifiers should cache the bytes — as an HTTP cache header, typically — and
// keep that cache well inside the key lifetime, which is what keeps a replaced
// key published.
func (km *KeyManager) JWKS() ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	set := jwk.NewSet()
	for _, kid := range km.order {
		// PublicKey both copies the held key and strips whatever a public key
		// may not carry. The copy is what matters here: a jwk.Key is mutable,
		// and adding the manager's own to a set would let anything that
		// touched that set rewrite the key this process publishes. The
		// stripping costs nothing and means no future path that puts a
		// private key in an entry can reach this document.
		public, err := km.keys[kid].publicJWK.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("signingkey: publish key %q: %w", kid, err)
		}
		if err := set.AddKey(public); err != nil {
			return nil, fmt.Errorf("signingkey: publish key %q: %w", kid, err)
		}
	}

	doc, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("signingkey: marshal jwks: %w", err)
	}

	return doc, nil
}
