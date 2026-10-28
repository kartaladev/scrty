package oidc_test

import (
	"io"
	"log/slog"
)

// testTextLogger returns a text-handler logger writing to w at debug level,
// with the timestamp attribute stripped from every record.
//
// slog.NewTextHandler's default timestamp renders as decimal digits (e.g.
// "2026-09-25T18:52:31.842+07:00"), which can coincidentally contain a
// substring a test asserts is absent from the log (a claim value, a role
// name, ...). Dropping the timestamp removes that collision without
// weakening what the test actually checks.
func testTextLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
}
