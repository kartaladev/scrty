package admin

import (
	"fmt"
	"log/slog"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
)

// Option configures what every service of this package shares: the clock,
// the event sink, the audit sink and the logger. Every constructor accepts it
// beside the options of its own service. A nil Option is ignored.
type Option func(*common) error

// common is the configuration every service shares.
type common struct {
	clock      clock.Clock
	events     eventsink.Own
	audit      AuditSink
	auditGiven int
	logger     *slog.Logger
	loggerSet  bool
}

func (o Option) apply(c *common) error {
	if o == nil {
		return nil
	}

	return o(c)
}

func (o Option) applyUsers(c *usersConfig) error       { return o.apply(&c.common) }
func (o Option) applyImporter(c *importerConfig) error { return o.apply(&c.common) }
func (o Option) applyRoles(c *common) error            { return o.apply(c) }
func (o Option) applyGrants(c *common) error           { return o.apply(c) }
func (o Option) applyAssignments(c *common) error      { return o.apply(c) }

// WithClock sets the clock that stamps events and a password change. A nil
// clock fails the constructor with an error matching ErrConfig.
//
// Default: clock.System().
func WithClock(c clock.Clock) Option {
	return func(cfg *common) error {
		if nilcheck.IsNil(c) {
			return fmt.Errorf("%w: clock is nil", ErrConfig)
		}

		cfg.clock = c

		return nil
	}
}

// WithEventSink sets the sink each committed change is reported to, under the
// names of package event (event.UserCreated, event.AuthzAdmin, ...), with the
// actor, the target and the names of the changed fields, never a value. A
// refused or failed call, and a call that changed nothing, reports nothing.
//
// The sink is called synchronously after the store call returned, with a
// context from which the caller's cancellation has been removed; a panic in it
// is recovered and logged without the event's contents. On a request whose
// chain reports security events (httpsec.EnableSecurityEvents), the service
// reports through the chain instead, so the outcome is reported once.
//
// A nil sink, or the option given twice, fails the constructor with an error
// matching ErrConfig.
//
// Default: no sink; nothing is reported outside a reporting chain.
func WithEventSink(sink event.Sink) Option {
	return func(c *common) error {
		c.events.Set(sink)

		return nil
	}
}

// WithAudit sets the audit sink each committed change is also delivered to,
// with the record before and after the change (see Change). A failing or
// panicking audit sink is logged with the action and the target only, and the
// call still succeeds: the change is already committed. With a sink set, the
// before record is read first, and one at a version other than the caller's is
// ErrStaleUpdate with nothing written.
//
// A nil sink, or the option given twice, fails the constructor with an error
// matching ErrConfig.
//
// Default: no audit sink; no before or after value leaves the service.
func WithAudit(sink AuditSink) Option {
	return func(c *common) error {
		c.audit = sink
		c.auditGiven++

		return nil
	}
}

// WithLogger sets the logger a failing audit sink, a panicking event sink and
// a failed audit read are logged to. A nil logger fails the constructor with an
// error matching ErrConfig: leaving the option out already routes the records.
//
// Default: the logger of the chain handling the request, else slog.Default()
// when the record is written.
func WithLogger(logger *slog.Logger) Option {
	return func(c *common) error {
		c.logger, c.loggerSet = logger, true

		return nil
	}
}

// finish checks the shared options and fills in the defaults.
func (c *common) finish() error {
	if err := c.events.Err("admin.WithEventSink"); err != nil {
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}

	switch {
	case c.auditGiven > 1:
		return fmt.Errorf("%w: admin.WithAudit was given %d times; a service delivers to one audit sink", ErrConfig, c.auditGiven)
	case c.auditGiven == 1 && c.audit == nil:
		return fmt.Errorf("%w: admin.WithAudit was given no sink; leave the option out to deliver none", ErrConfig)
	}

	if c.loggerSet && c.logger == nil {
		return fmt.Errorf("%w: admin.WithLogger was given a nil logger; leave the option out to route to the chain's logger", ErrConfig)
	}

	if c.logger == nil {
		c.logger = ctxlog.Routing()
	}

	if c.clock == nil {
		c.clock = clock.System()
	}

	return nil
}
