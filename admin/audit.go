package admin

import "context"

// Change is one committed administration change, as WithAudit delivers it.
//
// Before and After are values of User, Role, []Grant or
// []identity.AssignedRole: the administration records, none of which has a
// password hash field, so a hash cannot reach an audit sink. Before is nil for
// a creation and After is nil for a deletion. An import is delivered with no
// Before, since the import store does not return the record it replaced, and
// with the imported values as After, as a User without the hash. After is nil
// too when the record after a grant or assignment change could not be read,
// or was read at a later version than the change wrote. They are copies: an audit sink
// may keep or change them without touching what the caller received.
type Change struct {
	// Actor is who made the change, as ActorFrom reads it.
	Actor string
	// Action is the event name the change is reported under, such as
	// event.UserUpdated.
	Action string
	// Target is the user's identifier or the role's name.
	Target string
	// Before is the record before the change; nil for a creation.
	Before any
	// After is the record after the change; nil for a deletion.
	After any
}

// AuditSink receives each committed change with its before and after records.
// It is called synchronously after the store call and the event, with a
// context from which the caller's cancellation has been removed. Its error,
// and a panic in it, are logged with the action and the target only, and the
// call that made the change still succeeds: the change is committed and an
// audit failure cannot undo it.
type AuditSink func(ctx context.Context, change Change) error
