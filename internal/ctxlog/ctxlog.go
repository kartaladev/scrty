// Package ctxlog carries a logger on a context, for a component with no
// logger of its own that runs inside a chain and writes its records where the
// chain writes its own, and builds the routing logger ([Routing]) that
// resolves that destination for each record.
package ctxlog

import (
	"context"
	"log/slog"
)

// Key is the context key a logger is carried under. It is exported so a
// context that answers keys from its own Value method, as a chain's run
// context does, can answer it without storing it.
type Key struct{}

// With returns ctx carrying logger. A nil logger, or a routing logger
// ([Routing]), which names no destination of its own, returns ctx unchanged, so
// the logger already carried, if any, stays. That holds for a routing logger
// derived with With or WithGroup too: its attributes and groups do not ride on
// the context, and records resolved from it do not carry them. A caller who
// needs them on the context passes a concrete logger.
func With(ctx context.Context, logger *slog.Logger) context.Context {
	if logger == nil || isRouting(logger) {
		return ctx
	}

	return context.WithValue(ctx, Key{}, logger)
}

// From returns the logger ctx carries, or nil when it carries none, a value
// of another type or a typed nil is under Key, the logger under Key is itself a
// routing logger ([Routing]), or ctx is nil. A nil answer is the caller's to
// resolve; a routing logger resolves it to slog.Default() at record time.
func From(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return nil
	}

	logger, _ := ctx.Value(Key{}).(*slog.Logger)
	if logger == nil || isRouting(logger) {
		return nil
	}

	return logger
}
