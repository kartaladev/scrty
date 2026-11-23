package admin_test

import (
	"context"
	"log/slog"
	"sync"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/event"
)

// eventRecorder is an event.Sink that keeps every event it receives.
type eventRecorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *eventRecorder) sink(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, e)
}

func (r *eventRecorder) all() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]event.Event(nil), r.events...)
}

// auditRecorder is an admin.AuditSink that keeps every change it receives and
// answers with err.
type auditRecorder struct {
	mu      sync.Mutex
	changes []admin.Change
	err     error
}

func (r *auditRecorder) sink(_ context.Context, c admin.Change) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.changes = append(r.changes, c)

	return r.err
}

func (r *auditRecorder) all() []admin.Change {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]admin.Change(nil), r.changes...)
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
