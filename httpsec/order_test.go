package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// namedSlot pairs a built-in slot with the name a failure reports it by. It is
// a slice rather than a map keyed by the slot, because a map would silently
// collapse two constants that share a value — which is exactly the mistake
// these assertions exist to catch.
type namedSlot struct {
	name string
	slot httpsec.Order
}

func builtInSlots() []namedSlot {
	return []namedSlot{
		{"JWKS", httpsec.OrderJWKS},
		{"OIDC", httpsec.OrderOIDC},
		{"FormLogin", httpsec.OrderFormLogin},
		{"MagicLink", httpsec.OrderMagicLink},
		{"AccountRecoveryEndpoints", httpsec.OrderAccountRecoveryEndpoints},
		{"BasicAuth", httpsec.OrderBasicAuth},
		{"APIKey", httpsec.OrderAPIKey},
		{"MTLS", httpsec.OrderMTLS},
		{"BearerToken", httpsec.OrderBearerToken},
		{"MFAChallenge", httpsec.OrderMFAChallenge},
		{"PasswordChange", httpsec.OrderPasswordChange},
		{"Logout", httpsec.OrderLogout},
		{"SessionTouch", httpsec.OrderSessionTouch},
		{"Authorizer", httpsec.OrderAuthorizer},
	}
}

func TestOrder(t *testing.T) {
	t.Parallel()

	t.Run("every named slot is distinct", func(t *testing.T) {
		t.Parallel()

		taken := map[httpsec.Order]string{}
		for _, s := range builtInSlots() {
			if other, clash := taken[s.slot]; clash {
				assert.Failf(t, "two built-ins share a slot",
					"%s and %s are both at %d", other, s.name, s.slot)
				continue
			}
			taken[s.slot] = s.name
		}
	})

	t.Run("every named slot leaves its neighbours free", func(t *testing.T) {
		t.Parallel()

		named := map[httpsec.Order]string{}
		for _, s := range builtInSlots() {
			named[s.slot] = s.name
		}

		for _, s := range builtInSlots() {
			_, beforeTaken := named[httpsec.Before(s.slot)]
			_, afterTaken := named[httpsec.After(s.slot)]
			assert.False(t, beforeTaken, "the slot before %s is taken by another built-in", s.name)
			assert.False(t, afterTaken, "the slot after %s is taken by another built-in", s.name)
		}
	})

	t.Run("the plugin slots sit where the spec says", func(t *testing.T) {
		t.Parallel()

		// "an interceptor at the one-time link slot runs after form login and
		// before Basic authentication"
		assert.Greater(t, httpsec.OrderMagicLink, httpsec.OrderFormLogin)
		assert.Less(t, httpsec.OrderMagicLink, httpsec.OrderBasicAuth)

		// The recovery endpoints answer callers who cannot log in, between
		// the one-time link slot and Basic authentication.
		assert.Equal(t, httpsec.Order(375), httpsec.OrderAccountRecoveryEndpoints)
		assert.Greater(t, httpsec.OrderAccountRecoveryEndpoints, httpsec.OrderMagicLink)
		assert.Less(t, httpsec.OrderAccountRecoveryEndpoints, httpsec.OrderBasicAuth)

		// "The refusal SHALL come before the password-change gate, the
		// enrolment gate, the MFA challenge gate": the recovery gate runs
		// after bearer authentication has resolved the session and
		// immediately outside the enrolment gate.
		assert.Equal(t, httpsec.Before(httpsec.OrderMFAEnrolment), httpsec.OrderAccountRecovery)
		assert.Greater(t, httpsec.OrderAccountRecovery, httpsec.OrderBearerToken)
		assert.Less(t, httpsec.OrderAccountRecovery, httpsec.OrderMFAEnrolment)
		assert.Less(t, httpsec.OrderAccountRecovery, httpsec.OrderMFAChallenge)
		assert.Less(t, httpsec.OrderAccountRecovery, httpsec.OrderPasswordChange)

		// The authorization stage is innermost of the built-ins, so everything
		// it judges has already been resolved.
		for _, s := range builtInSlots() {
			if s.name == "Authorizer" {
				continue
			}
			assert.Less(t, s.slot, httpsec.OrderAuthorizer,
				"%s must run outside the authorization stage", s.name)
		}
	})
}

func TestBeforeAndAfter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		slot   httpsec.Order
		assert func(t *testing.T, before, after httpsec.Order)
	}

	cases := []testCase{
		{
			name: "either side of the bearer slot",
			slot: httpsec.OrderBearerToken,
			assert: func(t *testing.T, before, after httpsec.Order) {
				assert.Equal(t, httpsec.Order(499), before)
				assert.Equal(t, httpsec.Order(501), after)
			},
		},
		{
			name: "either side of the outermost slot",
			slot: httpsec.OrderJWKS,
			assert: func(t *testing.T, before, after httpsec.Order) {
				assert.Equal(t, httpsec.Order(99), before)
				assert.Equal(t, httpsec.Order(101), after)
			},
		},
		{
			name: "before is outside the slot and after is inside it",
			slot: httpsec.OrderSessionTouch,
			assert: func(t *testing.T, before, after httpsec.Order) {
				assert.Less(t, before, httpsec.OrderSessionTouch)
				assert.Greater(t, after, httpsec.OrderSessionTouch)
				assert.Less(t, after, httpsec.OrderAuthorizer,
					"the slot after session touch must still precede the next named slot")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, httpsec.Before(tc.slot), httpsec.After(tc.slot))
		})
	}
}

func TestRegisterInterceptor(t *testing.T) {
	t.Parallel()

	noop := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		return next(ex)
	})

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, regs []httpsec.Registration, err error)
	}

	cases := []testCase{
		{
			name: "nothing registered leaves no registrations",
			assert: func(t *testing.T, regs []httpsec.Registration, err error) {
				require.NoError(t, err)
				assert.Empty(t, regs)
			},
		},
		{
			name: "a registration keeps the interceptor and the slot it was given",
			opts: []httpsec.Option{httpsec.RegisterInterceptor(noop, httpsec.After(httpsec.OrderBearerToken))},
			assert: func(t *testing.T, regs []httpsec.Registration, err error) {
				require.NoError(t, err)
				require.Len(t, regs, 1)
				assert.Equal(t, httpsec.Order(501), regs[0].Order)
				assert.NotNil(t, regs[0].Interceptor)
			},
		},
		{
			name: "registrations at one slot are told apart by arrival",
			opts: []httpsec.Option{
				httpsec.RegisterInterceptor(noop, httpsec.OrderBearerToken),
				httpsec.RegisterInterceptor(noop, httpsec.OrderBearerToken),
			},
			assert: func(t *testing.T, regs []httpsec.Registration, err error) {
				require.NoError(t, err)
				require.Len(t, regs, 2)
				assert.Less(t, regs[0].Seq, regs[1].Seq,
					"two interceptors at one slot must be distinguishable by arrival order")
			},
		},
		{
			name: "a nil interceptor is refused at construction, naming the option",
			opts: []httpsec.Option{httpsec.RegisterInterceptor(nil, httpsec.OrderBearerToken)},
			assert: func(t *testing.T, regs []httpsec.Registration, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "RegisterInterceptor")
				assert.Empty(t, regs)
			},
		},
		{
			name: "an interface holding a typed nil is refused too",
			opts: []httpsec.Option{
				httpsec.RegisterInterceptor((*nilInterceptor)(nil), httpsec.OrderBearerToken),
			},
			assert: func(t *testing.T, regs []httpsec.Registration, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "RegisterInterceptor")
				assert.Empty(t, regs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			regs, err := httpsec.Registrations(tc.opts...)
			tc.assert(t, regs, err)
		})
	}
}

// nilInterceptor exists so a test can hand RegisterInterceptor an interface
// that is not nil but holds a nil pointer.
type nilInterceptor struct{}

func (*nilInterceptor) Intercept(ex *httpsec.Exchange, next httpsec.Next) error { return next(ex) }

// TestOrderMFAEnrolment pins where the enrolment gate runs: immediately
// outside the second-factor gate, so an enrolment-only session is refused
// before anything at the second-factor slot, the verify endpoint included, can
// answer it, and after every first factor has resolved the session.
//
// It is deliberately not one of builtInSlots: it is Before a named slot, which
// is the one position the spacing rule leaves for exactly this.
func TestOrderMFAEnrolment(t *testing.T) {
	t.Parallel()

	assert.Equal(t, httpsec.Before(httpsec.OrderMFAChallenge), httpsec.OrderMFAEnrolment)
	assert.Greater(t, httpsec.OrderMFAEnrolment, httpsec.OrderBearerToken,
		"the session it confines is resolved by then")
}
