// Package ctxlog carries a logger on a context, for a component with no
// logger of its own that runs inside a chain and writes its records where the
// chain writes its own.
package ctxlog

import (
	"context"
	"log/slog"
)

// Key is the context key a logger is carried under. It is exported so a
// context that answers keys from its own Value method, as a chain's run
// context does, can answer it without storing it.
type Key struct{}

// With returns ctx carrying logger. A nil logger returns ctx unchanged, so
// the logger already carried, if any, stays.
func With(ctx context.Context, logger *slog.Logger) context.Context {
	if logger == nil {
		return ctx
	}

	return context.WithValue(ctx, Key{}, logger)
}

// From returns the logger ctx carries, or nil when it carries none, a value
// of another type is under Key, or ctx is nil. A nil answer is the caller's
// to resolve, usually to slog.Default().
func From(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return nil
	}

	logger, _ := ctx.Value(Key{}).(*slog.Logger)

	return logger
}
