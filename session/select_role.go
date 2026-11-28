package session

import (
	"context"

	"github.com/kartaladev/scrty/internal/porterr"
)

// SelectRole records role as the selected role of the session with this
// identifier through the store's Store.SelectRole, which writes it only to a
// stored, live session that is not superseded. The empty role clears the
// selection. It does not judge role: whether the user holds a grant of that
// name is the caller's to check first.
//
// The store's refusals pass through, matched by errors.Is: ErrNotFound,
// ErrSuperseded and ErrExpired come back bare, and a durable store's refusal
// of a role it cannot hold comes back as that store wraps it. Any other
// failure comes back behind fixed text of this package that never names the
// session identifier, still matching its cause.
func (m *Sessions) SelectRole(ctx context.Context, id, role string) error {
	err := porterr.SanitizeTo(ctx, m.logger, m.store.SelectRole(ctx, id, role), porterr.ErrUnwalkable)

	return storeFailed(err, "session: the selected role could not be recorded")
}
