// Package secevent carries the security-event sink of a request to the
// components that decide outcomes below the HTTP chain, and delivers events to
// a sink safely.
//
// The chain puts an Emitter on every request's context when the consumer gave
// it a sink (httpsec.EnableSecurityEvents). A component that decides an
// outcome on that request, the chain's own interceptors and the
// account-lockout policy alike, reports it with Send, and reports nothing on a
// request no sink watches. The emitter fills in what the request knows and the
// component does not, such as the resolved client address.
package secevent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/security"
)

// MsgSinkPanicked is the record a recovered sink panic is logged with. It
// carries no attribute: neither the event's contents nor the panic's value,
// which a sink may have built from them.
const MsgSinkPanicked = "scrty: the security event sink panicked; the event was dropped"

// Emitter delivers one request's events.
type Emitter func(ctx context.Context, e security.Event)

// emitterKey is the context key the request's Emitter is stored under.
type emitterKey struct{}

// With returns ctx carrying emit.
func With(ctx context.Context, emit Emitter) context.Context {
	return context.WithValue(ctx, emitterKey{}, emit)
}

// Send reports e through the Emitter ctx carries, and does nothing when ctx
// carries none.
func Send(ctx context.Context, e security.Event) {
	if emit, ok := ctx.Value(emitterKey{}).(Emitter); ok && emit != nil {
		emit(ctx, e)
	}
}

// Enabled reports whether ctx carries an Emitter, so a component can skip work
// only an event needs.
func Enabled(ctx context.Context) bool {
	emit, ok := ctx.Value(emitterKey{}).(Emitter)

	return ok && emit != nil
}

// Deliver calls sink with e, on ctx without its cancellation, and does
// nothing for a nil sink.
//
// A panic in the sink is recovered and logged through log at ERROR as
// MsgSinkPanicked, with no attribute, so the outcome the event reports stands
// and nothing of the event reaches the log.
func Deliver(ctx context.Context, sink security.Sink, e security.Event, log *slog.Logger) {
	if sink == nil {
		return
	}

	defer func() {
		if r := recover(); r != nil && log != nil {
			log.LogAttrs(ctx, slog.LevelError, MsgSinkPanicked)
		}
	}()

	sink(context.WithoutCancel(ctx), e)
}

// Own is the sink a component was given of its own, by its WithSecurityEvents
// option, for the outcomes it decides outside a chain. The zero value is no
// sink.
type Own struct {
	sink  security.Sink
	given int
}

// Set records the sink the option was given. Calling it a second time, or
// with a nil sink, is a configuration Err reports.
func (o *Own) Set(sink security.Sink) {
	o.sink = sink
	o.given++
}

// Err reports a configuration that is not one sink: option given a nil sink,
// or given more than once. The caller wraps it in its own configuration error.
func (o *Own) Err(option string) error {
	switch {
	case o.given > 1:
		return fmt.Errorf("%s was given %d times; a component reports to one sink", option, o.given)
	case o.given == 1 && o.sink == nil:
		return fmt.Errorf("%s was given no sink: give it the function that receives the events, "+
			"or leave the option out to report none", option)
	}

	return nil
}

// Sink is the sink Set recorded, and nil when none was.
func (o *Own) Sink() security.Sink { return o.sink }

// Report reports e, an outcome the component decided on ctx, exactly once:
// through the chain's delivery when ctx carries one, so a component a chain
// runs reports where the chain's other events go and its own sink is not
// called; otherwise to the component's own sink, through Deliver. With
// neither, nothing is reported.
func (o *Own) Report(ctx context.Context, e security.Event, log *slog.Logger) {
	if emit, ok := ctx.Value(emitterKey{}).(Emitter); ok && emit != nil {
		emit(ctx, e)

		return
	}

	Deliver(ctx, o.sink, e, log)
}

// GuardRefused reports err, a route guard's refusal, as security.AuthzFail
// when it is an authorization denial (authorize.ErrAccessDenied) and the
// request's own context had not ended, naming the caller ctx carries. Any
// other refusal, a caller that has not authenticated or an authorizer that
// could not answer, reports nothing.
func GuardRefused(ctx context.Context, err error) {
	if !Enabled(ctx) || !errors.Is(err, authorize.ErrAccessDenied) || hangup.ByCaller(ctx, err) {
		return
	}

	e := security.Event{Name: security.AuthzFail, Outcome: security.OutcomeFailure}
	if p, ok := identity.PrincipalFromContext(ctx); ok && p != nil {
		e.User = p.ID
	}

	Send(ctx, e)
}
