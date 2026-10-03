package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/policy"
)

// redeemTwice builds a chain of one flow behind engine, with method as the one
// second-factor method, and presents one credential of that flow twice, from
// different sources.
type redeemTwice func(t *testing.T, engine *policy.Engine, method mfa.Method) (first, second served)

// redeemMagicLinkTwice is redeemTwice for a magic link.
func redeemMagicLinkTwice(t *testing.T, engine *policy.Engine, method mfa.Method) (first, second served) {
	t.Helper()

	h := newMagicLinkHarness(t)
	h.engine = engine
	h.chainOpts = []httpsec.Option{httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(h.tokens))}
	c := h.chain(t)

	link, nonce := h.link(t, c)

	return h.redeem(t, c, link, nonce), h.redeemFrom(t, c, "198.51.100.9", link, nonce)
}

// redeemHandoffTwice is redeemTwice for an OIDC handoff code.
func redeemHandoffTwice(t *testing.T, engine *policy.Engine, method mfa.Method) (first, second served) {
	t.Helper()

	h := newOIDCHarness(t)
	h.issueTokens()
	h.chainOpts = []httpsec.Option{
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(h.tokens)),
	}
	c := h.chain(t)

	code := h.issueHandoff(t, "")

	return serve(t, c, handoffRequest(t.Context(), oidcTestSource, code)),
		serve(t, c, handoffRequest(t.Context(), oidcAnotherSource, code))
}

// TestRedemptionMFAMethods pins when a login that spends a one-time credential
// looks up the methods its second-factor challenge offers: among the refusal
// checks that run before the credential is spent, and only there.
//
// A lookup that fails therefore refuses the login and leaves the credential
// redeemable, so the holder can use it once the enrolment store is back; and a
// lookup that succeeds is not repeated after the credential is spent.
//
// The policy raises the challenge without looking anything up itself, so every
// enrolment lookup counted here is the challenge's own.
func TestRedemptionMFAMethods(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		flow   redeemTwice
		failed bool // the first enrolment lookup fails
		assert func(t *testing.T, first, second served, lookups int32)
	}

	errLookup := errors.New("redemption_mfamethods_test: enrolment store unavailable for u-1")

	offered := []httpsec.MFAMethod{{Name: "totp", Channel: factor.AuthenticatorApp}}

	keptCredential := func(t *testing.T, first, second served, lookups int32) {
		t.Helper()

		require.ErrorIs(t, first.err, errLookup, "the failed lookup refuses the login")
		assert.NotContains(t, first.err.Error(), "u-1", "behind fixed text")
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(first.err))

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, second.err, &ch, "the credential was not spent by the refusal")
		assert.Equal(t, offered, ch.Methods)
		assert.Equal(t, int32(2), lookups, "one lookup per redemption")
	}

	lookedUpOnce := func(t *testing.T, first, second served, lookups int32) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, first.err, &ch)
		assert.Equal(t, offered, ch.Methods)
		assert.Error(t, second.err, "the credential was spent by the login")
		assert.Equal(t, int32(1), lookups, "the tail offers the methods the check looked up")
	}

	cases := []testCase{
		{name: "magic link: a failed lookup leaves the link redeemable", flow: redeemMagicLinkTwice, failed: true,
			assert: keptCredential},
		{name: "OIDC handoff: a failed lookup leaves the code redeemable", flow: redeemHandoffTwice, failed: true,
			assert: keptCredential},
		{name: "magic link: the methods are looked up once", flow: redeemMagicLinkTwice, assert: lookedUpOnce},
		{name: "OIDC handoff: the methods are looked up once", flow: redeemHandoffTwice, assert: lookedUpOnce},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var lookups atomic.Int32

			method := NewMockMethod(gomock.NewController(t))
			method.EXPECT().Name().Return("totp").AnyTimes()
			method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
			method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
			method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(context.Context, identity.UserID) (bool, error) {
					if lookups.Add(1) == 1 && tc.failed {
						return false, errLookup
					}

					return true, nil
				})

			challenges := engineOf(t, policyAnswering(t, policy.Decision{
				Outcome: policy.Challenge, Challenge: policy.ChallengeMFA,
			}))

			first, second := tc.flow(t, challenges, method)

			tc.assert(t, first, second, lookups.Load())
		})
	}
}

// TestRedemption_PostRedeemPolicyLookupFailureKeepsCredential pins that the
// login tail of a one-time credential reuses the decision its pre-consume
// check made, rather than evaluating the post-authentication policies again
// once the credential is spent.
//
// The policy is a real library MFA policy, which looks up enrolment itself,
// and the enrolment lookup fails on its third call. For a magic link it is the
// second-factor challenge policy; for an OIDC handoff it is the requirement
// policy, because the challenge policy lets a federated login through without
// a lookup by default, and a required user's unmet federated login is
// challenged by the requirement policy instead. Within one
// redemption the check makes two (the policy's, then the offered methods'),
// so a third can only come from the tail, after the spend: were it made, the
// lookup failure would cost the holder the credential.
func TestRedemption_PostRedeemPolicyLookupFailureKeepsCredential(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		flow   redeemTwice
		policy func(t *testing.T, methods []policy.MFAMethodLookup) policy.Policy
		assert func(t *testing.T, first, second served, lookups int32)
	}

	errLookup := errors.New("redemption_mfamethods_test: enrolment store unavailable")

	challengePolicy := func(t *testing.T, methods []policy.MFAMethodLookup) policy.Policy {
		t.Helper()

		p, err := policy.NewMFAPolicy(methods,
			policy.WithMFAExemption(func(factor.Kind) bool { return false }))
		require.NoError(t, err)

		return p
	}
	requirementPolicy := func(t *testing.T, methods []policy.MFAMethodLookup) policy.Policy {
		t.Helper()

		// The source answers the handoff's unasserted assurance as unmet;
		// OIDC login refuses to assemble a requirement policy without one.
		p, err := policy.NewMFARequirementPolicy(nil, methods, policy.WithMFARequiredForAll(),
			policy.WithFederatedAssuranceSource(newTestOIDCManager(t)))
		require.NoError(t, err)

		return p
	}

	decidedOnce := func(t *testing.T, first, second served, lookups int32) {
		t.Helper()

		var ch *httpsec.ChallengeError
		if first.err != nil && !errors.As(first.err, &ch) {
			require.ErrorAs(t, second.err, &ch,
				"a refused first redemption (%v) spent the credential", first.err)
		}

		require.ErrorAs(t, first.err, &ch, "the login ends in the challenge its check decided")
		assert.Equal(t, policy.ChallengeMFA, ch.Kind)
		assert.Equal(t, []httpsec.MFAMethod{{Name: "totp", Channel: factor.AuthenticatorApp}}, ch.Methods)
		assert.Error(t, second.err, "the credential was spent by the login")
		assert.GreaterOrEqual(t, lookups, int32(2), "the check looked up enrolment before the spend")
	}

	cases := []testCase{
		{name: "magic link", flow: redeemMagicLinkTwice, policy: challengePolicy, assert: decidedOnce},
		{name: "OIDC handoff", flow: redeemHandoffTwice, policy: requirementPolicy, assert: decidedOnce},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var lookups atomic.Int32

			method := NewMockMethod(gomock.NewController(t))
			method.EXPECT().Name().Return("totp").AnyTimes()
			method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
			method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
			method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(context.Context, identity.UserID) (bool, error) {
					if lookups.Add(1) == 3 {
						return false, errLookup
					}

					return true, nil
				})

			methods, err := mfa.LookupsFor(method)
			require.NoError(t, err)

			first, second := tc.flow(t, engineOf(t, tc.policy(t, methods)), method)

			tc.assert(t, first, second, lookups.Load())
		})
	}
}

// TestRedemption_DecisionBindsTheCheckedPrincipal pins that the decision a
// redemption's check made is only reused for the login it was made for.
//
// A redeemer is the consumer's to replace. One that runs the checks for one
// user, or one password-change time, and then returns another has not shown
// the returned login is permitted, so the login is refused before a session
// exists, as a redeemer that skipped the checks is. The comparison is by user
// reference and instant: a redeemer that reloads the same user, with the same
// password-change instant in another location, has returned the login it
// checked.
func TestRedemption_DecisionBindsTheCheckedPrincipal(t *testing.T) {
	t.Parallel()

	const (
		checkedID  identity.UserID = magicLinkUserID
		returnedID identity.UserID = "u-returned"
	)

	changed := time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC)
	elsewhere := time.FixedZone("redemption_mfamethods_test: UTC+7", 7*60*60)

	// login is what a redeemer hands a check, or returns.
	type login struct {
		principal identity.Principal
		changed   time.Time
	}

	checked := login{principal: identity.Principal{ID: checkedID}, changed: changed}

	// deniesReturned allows every login except returnedID's.
	deniesReturned := func(t *testing.T) *policy.Engine {
		t.Helper()

		p := NewMockPolicy(gomock.NewController(t))
		p.EXPECT().Name().Return("test: denies the returned user").AnyTimes()
		p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
		p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
			DoAndReturn(func(_ context.Context, in *policy.Input) policy.Decision {
				if in.User == returnedID {
					return policy.Decision{Outcome: policy.Deny, Reason: policy.ErrPolicyDenied}
				}

				return policy.Decision{Outcome: policy.Allow}
			})

		return engineOf(t, p)
	}

	// flow redeems one credential through a consumer redeemer that runs the
	// checks for checked and reports success for returned, and reports how
	// many sessions exist afterwards.
	type flow func(t *testing.T, returned login) (got served, sessions int)

	magicLink := func(t *testing.T, returned login) (served, int) {
		t.Helper()

		h := newMagicLinkHarness(t)
		link, nonce := h.link(t, h.chain(t))

		h.engine = deniesReturned(t)
		h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkRedeemer(redeemerFunc(func(
			ctx context.Context, _, _ string, checks ...magiclink.Check,
		) (magiclink.Redemption, error) {
			for _, check := range checks {
				if err := check(ctx, checked.principal, checked.changed); err != nil {
					return magiclink.Redemption{}, err
				}
			}

			return magiclink.Redemption{Principal: returned.principal, PasswordChangedAt: returned.changed}, nil
		})))

		got := h.redeem(t, h.chain(t), link, nonce)

		return got, h.activeSessions(t)
	}

	handoff := func(t *testing.T, returned login) (served, int) {
		t.Helper()

		h := newOIDCHarness(t)
		h.issueTokens()

		r := NewMockHandoffRedeemer(gomock.NewController(t))
		r.EXPECT().Redeem(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, _ string, checks ...oidc.RedeemCheck) (oidc.HandoffResult, error) {
				for _, check := range checks {
					if err := check(ctx, oidc.RedeemCandidate{Principal: checked.principal, PasswordChangedAt: checked.changed}); err != nil {
						return oidc.HandoffResult{}, err
					}
				}

				return oidc.HandoffResult{Principal: returned.principal, PasswordChangedAt: returned.changed}, nil
			})

		h.chainOpts = []httpsec.Option{httpsec.WithPolicyEngine(deniesReturned(t))}
		c := h.chain(t, httpsec.WithHandoffRedeemer(r))

		got := serve(t, c, handoffRequest(t.Context(), oidcTestSource, "any-code"))

		return got, h.activeSessions(t)
	}

	type testCase struct {
		name     string
		flow     flow
		returned login
		assert   func(t *testing.T, got served, sessions int)
	}

	refused := func(t *testing.T, got served, sessions int) {
		t.Helper()

		require.ErrorIs(t, got.err, policy.ErrPolicyDenied)
		assert.False(t, got.handlerRan)
		assert.Zero(t, sessions, "no session exists for a refused login")
	}

	completed := func(t *testing.T, got served, sessions int) {
		t.Helper()

		require.NoError(t, got.err, "the check's allow is reused for the same user")
		assert.Equal(t, 1, sessions)
	}

	// anotherUser is a different user reference, at the checked time.
	anotherUser := login{principal: identity.Principal{ID: returnedID}, changed: changed}

	// anotherTime is the checked user, with a password changed a second later
	// than the check saw.
	anotherTime := login{principal: identity.Principal{ID: checkedID}, changed: changed.Add(time.Second)}

	// reloaded is the checked user loaded again: a separate value that is not
	// deep-equal to the checked one, with the same password-change instant in
	// another location.
	reloaded := login{
		principal: identity.Principal{
			ID:       checkedID,
			Name:     "Reloaded User",
			Username: "reloaded@example.com",
			Roles:    []*identity.AssignedRole{},
		},
		changed: changed.In(elsewhere),
	}

	cases := []testCase{
		{name: "magic link: another principal is refused", flow: magicLink, returned: anotherUser, assert: refused},
		{name: "OIDC handoff: another principal is refused", flow: handoff, returned: anotherUser, assert: refused},
		{name: "magic link: a different password-change time with the same user is refused",
			flow: magicLink, returned: anotherTime, assert: refused},
		{name: "OIDC handoff: a different password-change time with the same user is refused",
			flow: handoff, returned: anotherTime, assert: refused},
		{name: "magic link: the same user reloaded is not refused", flow: magicLink, returned: reloaded, assert: completed},
		{name: "OIDC handoff: the same user reloaded is not refused", flow: handoff, returned: reloaded, assert: completed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, sessions := tc.flow(t, tc.returned)
			tc.assert(t, got, sessions)
		})
	}
}

// TestRedemption_EnrolmentOutageCountsUnderOptOut pins that the count-refusals
// opt-out does not exempt an enrolment-store outage while the check looks up
// the methods a raised challenge offers.
//
// The opt-out exempts the refusals the policy and the consumer's own checks
// produce. A lookup that fails is a failure of the check, not its refusal, and
// exempting it would give a source that can provoke one an unlimited supply of
// store reads.
func TestRedemption_EnrolmentOutageCountsUnderOptOut(t *testing.T) {
	t.Parallel()

	errLookup := errors.New("redemption_mfamethods_test: enrolment store unavailable")

	// sourceOutage redeems one credential eleven times from one source, with
	// the opt-out on and method's lookup failing, and returns the eleventh.
	type sourceOutage func(t *testing.T, engine *policy.Engine, method mfa.Method) served

	magicLink := func(t *testing.T, engine *policy.Engine, method mfa.Method) served {
		t.Helper()

		h := newMagicLinkHarness(t)
		h.engine = engine
		h.chainOpts = []httpsec.Option{httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(h.tokens))}
		h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkCountRefusals(false))
		c := h.chain(t)

		link, nonce := h.link(t, c)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, link, nonce).err, errLookup)
		}

		return h.redeemFrom(t, c, magicLinkSource, link, nonce)
	}

	handoff := func(t *testing.T, engine *policy.Engine, method mfa.Method) served {
		t.Helper()

		h := newOIDCHarness(t)
		h.issueTokens()
		h.chainOpts = []httpsec.Option{
			httpsec.WithPolicyEngine(engine),
			httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(h.tokens)),
		}
		c := h.chain(t, httpsec.WithHandoffCountRefusals(false))

		code := h.issueHandoff(t, "")

		for range 10 {
			require.ErrorIs(t, serve(t, c, handoffRequest(t.Context(), oidcTestSource, code)).err, errLookup)
		}

		return serve(t, c, handoffRequest(t.Context(), oidcTestSource, code))
	}

	type testCase struct {
		name   string
		flow   sourceOutage
		assert func(t *testing.T, eleventh served, lookups int32)
	}

	throttledWith := func(uniform error) func(t *testing.T, eleventh served, lookups int32) {
		return func(t *testing.T, eleventh served, lookups int32) {
			t.Helper()

			require.ErrorIs(t, eleventh.err, uniform, "the source is throttled")
			assert.False(t, eleventh.handlerRan)
			assert.Equal(t, int32(10), lookups, "the throttled redemption never reaches the check")
		}
	}

	cases := []testCase{
		{name: "magic link", flow: magicLink, assert: throttledWith(magiclink.ErrInvalidLink)},
		{name: "OIDC handoff", flow: handoff, assert: throttledWith(oidc.ErrInvalidHandoff)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var lookups atomic.Int32

			method := NewMockMethod(gomock.NewController(t))
			method.EXPECT().Name().Return("totp").AnyTimes()
			method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
			method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
			method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(context.Context, identity.UserID) (bool, error) {
					lookups.Add(1)

					return false, errLookup
				})

			challenges := engineOf(t, policyAnswering(t, policy.Decision{
				Outcome: policy.Challenge, Challenge: policy.ChallengeMFA,
			}))

			tc.assert(t, tc.flow(t, challenges, method), lookups.Load())
		})
	}
}
