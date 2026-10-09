package httpsec_test

import (
	"context"
	"log/slog"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
)

// Form login and Basic record through the lockout policy's view, so its
// observer hears about every failure that locks an identifier.
func ExampleFormLoginDeps_lockoutReports() {
	lockout, err := policy.NewAccountLockoutPolicy(
		policy.WithLockoutObserver(func(ctx context.Context, r policy.LockoutReport) {
			slog.InfoContext(ctx, "lockout", "kind", r.Kind.String(), "failures", r.Failures)
		}),
	)
	if err != nil {
		panic(err)
	}

	deps := httpsec.FormLoginDeps{Attempts: lockout.Attempts()}
	basic := httpsec.BasicAuthDeps{Attempts: lockout.Attempts()}
	_, _ = deps, basic
}
