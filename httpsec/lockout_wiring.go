package httpsec

import (
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/policy"
)

// checkAttemptViews refuses a chain whose password logins record failures
// into a store other than a view a registered policy requires.
//
// A lockout policy with a cap (policy.WithLockoutCap) advances an identifier's
// consecutive count only when a failure is recorded through its own view,
// lockout.Attempts(). Form login or Basic handed the bare store would still
// lock by the window, but would never bring anyone closer to a hold: the
// configuration would read as a cap and enforce none. Nothing would show it,
// so it is refused here rather than documented, and there is no option to
// switch it off. A chain with no password login, or whose logins share the
// view, builds as before, and so does any store under a policy without a cap.
//
// A login records into one store, so when two registered policies require
// different views and a password login is enabled, construction fails naming
// both. Only policies registered in the engine before New runs are checked.
//
// Stores are compared as the password-change gate compares them (sameStore),
// so a view handed to both logins is one store.
func (c *config) checkAttemptViews() error {
	if c.engine == nil {
		return nil
	}

	required := c.engine.RequiredAttemptViews()
	if len(required) == 0 {
		return nil
	}

	logins := 0

	if err := eachInterceptor(c, func(*formLogin) error { logins++; return nil }); err != nil {
		return err
	}

	if err := eachInterceptor(c, func(*basicAuth) error { logins++; return nil }); err != nil {
		return err
	}

	// A login records into one store, so two policies that need different
	// views cannot both be satisfied. Without a password login nothing records.
	if logins > 0 {
		for _, r := range required[1:] {
			if !sameView(required[0].View, r.View) {
				return newConfigError("the %q and %q policies require different attempt views, "+
					"but a login records failures into only one store: register only one capped policy", required[0].Policy, r.Policy)
			}
		}
	}

	check := func(field string, attempts policy.AttemptStore) error {
		for _, r := range required {
			if !nilcheck.IsNil(attempts) && sameView(attempts, r.View) {
				continue
			}

			return newConfigError("%s records failures into a store other than the view the %q policy requires: "+
				"give it that policy's view (Attempts() for an account-lockout policy)", field, r.Policy)
		}

		return nil
	}

	if err := eachInterceptor(c, func(l *formLogin) error {
		return check("FormLoginDeps.Attempts", l.attempts)
	}); err != nil {
		return err
	}

	return eachInterceptor(c, func(b *basicAuth) error {
		return check("BasicAuthDeps.Attempts", b.attempts)
	})
}

// sameView reports whether a and b are the same store, and false when either
// is nil.
func sameView(a, b policy.AttemptStore) bool {
	return !nilcheck.IsNil(a) && !nilcheck.IsNil(b) && sameStore(a, b)
}
