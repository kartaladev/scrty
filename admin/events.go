package admin

import (
	"context"
	"log/slog"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
)

// changeReport is what a service reports after a committed change.
type changeReport struct {
	actor string
	// name is the event name, and the audit record's action.
	name string
	// user is the user the change concerns, empty for a role.
	user identity.UserID
	// target is the user's identifier or the role's name.
	target string
	// changed names the changed fields, never their values.
	changed []string
	// before and after are the audit records, copied by the caller.
	before, after any
}

// report emits the event of a committed change, then delivers its audit
// record. Neither can fail the call: the change is committed.
func (c *common) report(ctx context.Context, r changeReport) {
	var changed []string
	if len(r.changed) > 0 {
		changed = append([]string(nil), r.changed...)
	}

	c.events.Report(ctx, event.Event{
		Name:    r.name,
		At:      c.clock.Now(),
		Outcome: event.OutcomeSuccess,
		User:    r.user,
		Actor:   r.actor,
		Target:  r.target,
		Changed: changed,
	}, c.logger)

	c.deliverAudit(ctx, r)
}

// deliverAudit hands the change to the audit sink, when one is configured. A
// failing sink is logged with the action and the target only.
func (c *common) deliverAudit(ctx context.Context, r changeReport) {
	if c.audit == nil {
		return
	}

	change := Change{Actor: r.actor, Action: r.name, Target: r.target, Before: r.before, After: r.after}

	if !c.callAudit(ctx, change) {
		c.logger.LogAttrs(ctx, slog.LevelError, msgAuditFailed,
			slog.String("action", r.name), slog.String("target", r.target))
	}
}

// callAudit calls the audit sink and reports whether it succeeded: a returned
// error and a panic are both failures. The panic's value is not logged; it may
// carry the change's values.
func (c *common) callAudit(ctx context.Context, change Change) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()

	return c.audit(context.WithoutCancel(ctx), change) == nil
}

// msgAuditFailed is logged for an audit sink that failed or panicked. The
// record carries the action and the target, never the error's text or the
// change's values, which the sink's error may repeat.
const msgAuditFailed = "admin: the audit sink failed; the change is committed"

// auditing reports whether an audit sink is configured, so a service reads a
// before record only when one will receive it.
func (c *common) auditing() bool { return c.audit != nil }

// afterUnread logs that the record after a committed change could not be read
// for the audit sink, or was read at a later version than the change wrote, so
// it holds another write too; the sink then receives the change with a nil
// After.
func (c *common) afterUnread(ctx context.Context, r changeReport) {
	c.logger.LogAttrs(ctx, slog.LevelWarn, "admin: the record after a change could not be read for the audit sink; it is delivered without an after record",
		slog.String("action", r.name), slog.String("target", r.target))
}
