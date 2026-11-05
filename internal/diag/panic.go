package diag

import (
	"fmt"
	"log/slog"
	"runtime"
	"strings"
)

// panicFrameLimit bounds the frames a panic's record names.
const panicFrameLimit = 32

// PanicAttrs returns the attributes a log record carries for a recovered panic: panic_type, the
// value's Go type; and frames, where it happened, as "function file:line" joined by "; ", innermost
// first, at most 32 of them. The frames start above PanicAttrs's caller, which is only the code
// writing the record. Call it from the deferred call that recovered the panic, or from a function
// that call calls, while the panicking stack is still there.
//
// It never holds the value, which can quote a secret from a consumer's code, nor debug.Stack's
// text, which quotes the arguments of the frames it lists.
func PanicAttrs(value any) []slog.Attr {
	var pcs [panicFrameLimit]uintptr

	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs[:])])

	named := make([]string, 0, panicFrameLimit)

	for {
		frame, more := frames.Next()
		if frame.Function != "" {
			named = append(named, fmt.Sprintf("%s %s:%d", frame.Function, frame.File, frame.Line))
		}

		if !more {
			break
		}
	}

	return []slog.Attr{
		slog.String("panic_type", fmt.Sprintf("%T", value)),
		slog.String("frames", strings.Join(named, "; ")),
	}
}
