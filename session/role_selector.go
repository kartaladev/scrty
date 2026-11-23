package session

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/internal/porterr"
)

// RoleSelector is what a Store may also offer so a session can record the
// role its user chose to act as (Session.SelectedRole). It is optional, and a
// Store gains nothing it must implement; a feature that switches the active
// role needs it, and refuses at construction a store without it. The stores
// of this repository offer it, the memory store and the durable ones, and so
// does the store NewEncryptedStore returns when the store it wraps does.
//
//go:generate mockgen -source=role_selector.go -package=session_test -destination=role_selector_mock_test.go -typed
type RoleSelector interface {
	// SelectRole writes role as the SelectedRole of the session with this
	// identifier, and nothing else: no deadline, no other field. The empty
	// role clears the selection. It never inserts, so a session that was
	// deleted is not brought back.
	//
	// It writes only to a session that is stored, not superseded and before
	// both of its deadlines, judged by the store's own clock, in one atomic
	// conditional write. Otherwise it writes nothing and reports why: a
	// session that is not stored is ErrNotFound; a superseded one,
	// whether or not its grace window is open, is ErrSuperseded, since its
	// successor, not it, carries the family on; and an expired one is
	// ErrExpired.
	//
	// The store does not interpret role: it stores the name and returns it
	// unchanged. Whether the user holds a grant of that name is for the
	// caller to judge, before it records the choice and again whenever it
	// acts on it. A durable store may refuse text it cannot hold unchanged,
	// with an error that does not quote it.
	SelectRole(ctx context.Context, id string, role string) error
}

// SelectsRoles reports whether the manager's store offers RoleSelector, so a
// feature that records a selected role through SelectRole can refuse, when it
// is wired, a manager that could not record one. The answer is fixed when the
// manager is built.
func (m *Sessions) SelectsRoles() bool {
	_, ok := m.store.(RoleSelector)

	return ok
}

// SelectRole records role as the selected role of the session with this
// identifier through the store's RoleSelector, which writes it only to a
// stored, live session that is not superseded (see RoleSelector.SelectRole).
// The empty role clears the selection. It does not judge role: whether the
// user holds a grant of that name is the caller's to check first.
//
// The store's refusals pass through, matched by errors.Is: ErrNotFound,
// ErrSuperseded and ErrExpired come back bare, and a durable store's refusal
// of a role it cannot hold comes back as that store wraps it. Any other
// failure comes back behind fixed text of this package that never names the
// session identifier, still matching its cause. A manager whose store offers
// no RoleSelector refuses every selection with ErrConfig; SelectsRoles tells
// that at wiring time.
func (m *Sessions) SelectRole(ctx context.Context, id, role string) error {
	selector, ok := m.store.(RoleSelector)
	if !ok {
		return fmt.Errorf("%w: the session store does not record a selected role", ErrConfig)
	}

	err := porterr.SanitizeTo(ctx, m.logger, selector.SelectRole(ctx, id, role), porterr.ErrUnwalkable)

	return storeFailed(err, "session: the selected role could not be recorded")
}
