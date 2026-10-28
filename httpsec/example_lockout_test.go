package httpsec_test

import (
	"context"
	"log/slog"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy/lockout"
)

// Form login and Basic record through the lockout policy's view, so its
// observer hears about every failure that locks an identifier.
func ExampleFormLoginDeps_lockoutReports() {
	lockoutPolicy, err := lockout.New(
		lockout.WithObserver(func(ctx context.Context, r lockout.Report) {
			slog.InfoContext(ctx, "lockout", "kind", r.Kind.String(), "failures", r.Failures)
		}),
	)
	if err != nil {
		panic(err)
	}

	deps := httpsec.FormLoginDeps{Attempts: lockoutPolicy.Attempts()}
	basic := httpsec.BasicAuthDeps{Attempts: lockoutPolicy.Attempts()}
	_, _ = deps, basic
}
