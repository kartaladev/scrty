// Package oplineage holds the type a provider's refresh-token lineages are kept
// behind, so that only scrty's own modules can make one out of a session store.
//
// The rule that makes it hold is Go's: this package can be imported from inside
// scrty's import path and nowhere else, and the type has nothing a caller outside this
// package could fill. A sign-in's session.Store therefore cannot be handed to the
// provider as a lineage store by mistake. oidcprovider.RefreshTokenStore is the name
// consumers see.
package oplineage

import (
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/session"
)

// Store is a session store set aside for refresh-token lineages. Its one field is
// unexported, and it has no method on purpose: a method would reach consumers through
// oidcprovider.RefreshTokenStore, so one returning the session store would let them
// hand lineages to a sign-in path. Sessions is the only way back, and it is a function
// of this package.
//
// The zero Store holds nothing, and the provider refuses it.
type Store struct {
	sessions session.Store
}

// New sets s aside as a lineage store. A nil s, typed nil included, gives the zero
// Store. The caller must have bound s to a place no sign-in reads.
func New(s session.Store) Store {
	if nilcheck.IsNil(s) {
		return Store{}
	}

	return Store{sessions: s}
}

// Sessions returns the session store behind s, and nil for the zero Store.
func Sessions(s Store) session.Store { return s.sessions }
