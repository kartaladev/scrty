package httpsecconformance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// EnrolmentFixture is the enrolment path's wiring of one run, and the state
// Build brought the enrolling user to before the request was sent.
//
// Build drives the steps before the one a scenario is about directly against
// the method and the session manager, so the one request an adapter serves is
// that step, and the three frameworks are judged on it alone.
type EnrolmentFixture struct {
	// TOTP is the method EnableMFA and the path are given, over an in-memory
	// store, on the fixture's clock.
	TOTP *mfa.TOTP

	// Outbox is every message the path asked to send.
	Outbox *Outbox

	// Secret is the pending secret a begin produced, Generation the
	// generation it recorded on the session, and EmailedCode the code a
	// device proof emailed. Each is empty until Build reached that step.
	Secret      string
	Generation  id.ID
	EmailedCode string

	mu  sync.Mutex
	now time.Time
}

// Now is the instant the fixture's TOTP method reads.
func (f *EnrolmentFixture) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.now
}

// advance moves the fixture's clock on by d.
func (f *EnrolmentFixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.now = f.now.Add(d)
}

// code is what an authenticator holding the pending secret shows now.
func (f *EnrolmentFixture) code(t *testing.T) string {
	t.Helper()

	c, err := totp.GenerateCode(f.Secret, f.Now())
	require.NoError(t, err)

	return c
}

// Outbox is a sender that queues rather than delivers, as notify.QueuedSender
// does, and keeps every message so a scenario can read what the user was sent.
type Outbox struct {
	mu   sync.Mutex
	sent []notify.Message
}

// Send records m.
func (o *Outbox) Send(_ context.Context, m notify.Message) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.sent = append(o.sent, m)

	return nil
}

// NonBlocking reports that Send does not wait for delivery, which the path
// requires of a sender unless told otherwise.
func (*Outbox) NonBlocking() bool { return true }

// Messages is what was sent, in order.
func (o *Outbox) Messages() []notify.Message {
	o.mu.Lock()
	defer o.mu.Unlock()

	return append([]notify.Message(nil), o.sent...)
}

var _ notify.NonBlocking = (*Outbox)(nil)

// sixDigits finds a code standing on its own in a message body.
var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// newEnrolmentFixture wires the method and the outbox, and records them on e.
func newEnrolmentFixture(t *testing.T, e *Effects) *EnrolmentFixture {
	t.Helper()

	fx := &EnrolmentFixture{Outbox: &Outbox{}, now: time.Now().Truncate(time.Second)}

	method, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example", mfa.WithClock(fx.Now))
	require.NoError(t, err)

	fx.TOTP = method
	e.Enrolment = fx

	return fx
}

// enrolmentOptions is the wiring every enrolment scenario shares: the MFA
// requirement policy for every user with the enrolment path on, beside the
// second-factor challenge policy; bearer authentication; the verify endpoint;
// the enrolment path with its defaults; and logout.
func enrolmentOptions(t *testing.T, e *Effects) []httpsec.Option {
	t.Helper()

	fx := e.Enrolment

	lookup, err := mfa.LookupFor(fx.TOTP)
	require.NoError(t, err)

	challenge, err := policy.NewMFAPolicy(lookup)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirementPolicy(nil, lookup,
		policy.WithMFARequiredForAll(), policy.WithMFAEnrolmentPath())
	require.NoError(t, err)

	engine, err := policy.NewEngine(challenge, requirement)
	require.NoError(t, err)

	return append(bearerOptions(e),
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableMFA(fx.TOTP, httpsec.WithMFATokens(fixtureTokens{})),
		httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: fixtureUsers{}, Sender: fx.Outbox}),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: e.Sessions}),
	)
}

// The steps Build can bring the enrolling user to before the request.
type enrolmentStep int

const (
	// stepConfined is a password login sent to enrol: an enrolment-only
	// session, and nothing begun.
	stepConfined enrolmentStep = iota

	// stepBegun has begun an enrolment on the session's generation.
	stepBegun

	// stepProven has proven the device, and emailed a code.
	stepProven

	// stepCompleted has redeemed the emailed code, so the enrolment counts
	// and the session is waiting to verify.
	stepCompleted

	// stepVerified has verified a fresh code, so the session is left exactly
	// as the verify endpoint leaves one: the second factor satisfied, and the
	// enrolment marker cleared.
	stepVerified
)

// enrolmentBuild is the Build of an enrolment scenario, with the user brought
// to step before the request is sent.
func enrolmentBuild(step enrolmentStep) func(t *testing.T) ChainSpec {
	return func(t *testing.T) ChainSpec {
		effects := newEffects(t)
		fx := newEnrolmentFixture(t, effects)
		ctx := t.Context()

		s, err := effects.Sessions.Create(ctx, UserID, session.WithFirstFactor(factor.Password))
		require.NoError(t, err)

		effects.Sessions.MarkEnrolmentPending(s, 15*time.Minute)

		if step >= stepBegun {
			provisioning, gen, err := fx.TOTP.BeginEnrolmentGeneration(ctx, UserID, Username)
			require.NoError(t, err)

			fx.Secret, fx.Generation = provisioning.Secret, gen
			s.EnrolmentGeneration = gen
		}

		if step >= stepProven {
			fx.EmailedCode, err = fx.TOTP.ProveDevice(ctx, UserID, fx.Generation, fx.code(t), true, 10*time.Minute)
			require.NoError(t, err)
		}

		if step >= stepCompleted {
			require.NoError(t, fx.TOTP.RedeemEmailCode(ctx, UserID, fx.Generation, fx.EmailedCode))
			s.MFA = session.MFAPending

			// The proof spent this step's code; the verification presents the
			// next one.
			fx.advance(30 * time.Second)
		}

		if step >= stepVerified {
			require.NoError(t, fx.TOTP.Verify(ctx, UserID, fx.code(t)))
			s.MFA = session.MFASatisfied
			s.MFASatisfiedAt = fx.Now()

			// What the verify endpoint itself does next: give the deadlines
			// back and clear the marker, so the session this scenario sends
			// carries none.
			require.NoError(t, effects.Sessions.RestoreEnrolmentDeadlines(s))
		}

		require.NoError(t, effects.Sessions.Save(ctx, s))
		effects.SessionID = s.ID

		return ChainSpec{
			Options: enrolmentOptions(t, effects),
			Effects: effects,
			Routes: []Route{
				{Method: http.MethodGet, Path: RoutePath, Status: http.StatusOK, Body: RouteBody},
				{Method: http.MethodPost, Path: LogoutPath, Status: http.StatusCreated, Body: RouteBody},
			},
			NoRoute: true,
		}
	}
}

// enrolmentPost is a bearer POST of values to path, for the session Build
// created.
func enrolmentPost(path string, values func(ChainSpec) url.Values) func(ChainSpec) RequestSpec {
	return func(spec ChainSpec) RequestSpec {
		r := authenticatedRequest(http.MethodPost, path)(spec)
		r.Header["Content-Type"] = "application/x-www-form-urlencoded"

		if values != nil {
			r.Body = values(spec).Encode()
		}

		return r
	}
}

// codeField is a form carrying code.
func codeField(code func(spec ChainSpec) string) func(ChainSpec) url.Values {
	return func(spec ChainSpec) url.Values { return url.Values{"code": {code(spec)}} }
}

// enrolmentScenarios is every behaviour of the enrolment path that must be
// identical on every adapter: the gate, the one exemption it makes, and each
// step of the path from begin to the verification that ends it.
func enrolmentScenarios() []Scenario {
	return []Scenario{
		enrolmentGateRefusesAProtectedRoute(),
		enrolmentOnlySessionLogsOut(),
		enrolmentBeginAnswers(),
		enrolmentConfirmEmailsACode(),
		enrolmentEmailedCodeCompletes(),
		enrolmentVerifyGrantsAccess(),
		enrolmentSatisfiedSessionReachesRoute(),
	}
}

func enrolmentGateRefusesAProtectedRoute() Scenario {
	return Scenario{
		Name:    "the enrolment gate refuses a protected route",
		Build:   enrolmentBuild(stepConfined),
		Request: authenticatedRequest(http.MethodGet, RoutePath),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusForbidden, res.Status)
			assert.Empty(t, res.Body, "a refusal carries no error text")
			assert.False(t, res.RouteRan, "the route behind the gate did not run")

			var challenge *httpsec.ChallengeError
			require.ErrorAs(t, res.Refusal, &challenge)
			assert.Equal(t, policy.ChallengeMFAEnrolment, challenge.Kind)
			assert.Empty(t, challenge.Token, "a gate issues nothing")
		},
	}
}

func enrolmentOnlySessionLogsOut() Scenario {
	// Logout is the one route outside the path the gate lets through, so a
	// confined caller can always end the session.
	return Scenario{
		Name:    "an enrolment-only session logs out",
		Build:   enrolmentBuild(stepConfined),
		Request: authenticatedRequest(http.MethodPost, LogoutPath),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Empty(t, res.Body)
			assert.NoError(t, res.Refusal)
			assert.False(t, res.RouteRan, "the chain answered the logout itself")

			assert.Equal(t, 0, res.Effects.ActiveSessions(t),
				"the session was ended, so its token is refused from now on")
		},
	}
}

func enrolmentBeginAnswers() Scenario {
	return Scenario{
		Name:    "an enrolment begins",
		Build:   enrolmentBuild(stepConfined),
		Request: enrolmentPost(httpsec.DefaultEnrolmentBeginPath, nil),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"), "the document carries a secret")

			var doc struct {
				Secret string `json:"secret"`
				URI    string `json:"uri"`
			}
			require.NoError(t, json.Unmarshal([]byte(res.Body), &doc))
			assert.NotEmpty(t, doc.Secret)
			assert.True(t, strings.HasPrefix(doc.URI, "otpauth://"), "got %q", doc.URI)

			s := res.Effects.LoadSession(t, res.Effects.SessionID)
			assert.False(t, s.EnrolmentGeneration.IsZero(), "the session records the generation it began")
		},
	}
}

func enrolmentConfirmEmailsACode() Scenario {
	return Scenario{
		Name:  "a device proof emails a code",
		Build: enrolmentBuild(stepBegun),
		Request: enrolmentPost(httpsec.DefaultEnrolmentConfirmPath,
			codeField(func(spec ChainSpec) string {
				c, err := totp.GenerateCode(spec.Effects.Enrolment.Secret, spec.Effects.Enrolment.Now())
				if err != nil {
					return ""
				}

				return c
			})),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusNoContent, res.Status)
			assert.Empty(t, res.Body)

			sent := res.Effects.Enrolment.Outbox.Messages()
			require.Len(t, sent, 1, "the code was queued to the user")
			assert.Equal(t, Username, sent[0].To, "at the username, by default")
			assert.Regexp(t, sixDigits, sent[0].TextBody)

			enrolled, err := res.Effects.Enrolment.TOTP.Enrolled(t.Context(), UserID)
			require.NoError(t, err)
			assert.False(t, enrolled, "a proven device alone does not count")
			assert.Equal(t, session.MFAEnrolmentPending, res.Effects.LoadSession(t, res.Effects.SessionID).MFA)
		},
	}
}

func enrolmentEmailedCodeCompletes() Scenario {
	return Scenario{
		Name:  "the emailed code completes the enrolment",
		Build: enrolmentBuild(stepProven),
		Request: enrolmentPost(httpsec.DefaultEnrolmentEmailConfirmPath,
			codeField(func(spec ChainSpec) string { return spec.Effects.Enrolment.EmailedCode })),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusNoContent, res.Status)
			assert.Empty(t, res.Body)

			enrolled, err := res.Effects.Enrolment.TOTP.Enrolled(t.Context(), UserID)
			require.NoError(t, err)
			assert.True(t, enrolled)

			assert.Equal(t, session.MFAPending, res.Effects.LoadSession(t, res.Effects.SessionID).MFA,
				"completing an enrolment is not a second factor: the session goes on to verify")

			sent := res.Effects.Enrolment.Outbox.Messages()
			require.Len(t, sent, 1, "the user was told of the binding")
			assert.NotRegexp(t, sixDigits, sent[0].TextBody, "the notification carries no code")
		},
	}
}

func enrolmentVerifyGrantsAccess() Scenario {
	return Scenario{
		Name:  "verification ends the enrolment and grants a full session",
		Build: enrolmentBuild(stepCompleted),
		Request: enrolmentPost(httpsec.DefaultMFAVerifyPath,
			codeField(func(spec ChainSpec) string {
				c, err := totp.GenerateCode(spec.Effects.Enrolment.Secret, spec.Effects.Enrolment.Now())
				if err != nil {
					return ""
				}

				return c
			})),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusOK, res.Status)

			var body struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.Unmarshal([]byte(res.Body), &body))

			rotated, ok := strings.CutPrefix(body.AccessToken, tokenPrefix+Username+".")
			require.True(t, ok, "got %q", body.AccessToken)
			require.NotEqual(t, res.Effects.SessionID, rotated, "the session was rotated")

			_, err := res.Effects.Store.Load(t.Context(), res.Effects.SessionID)
			require.Error(t, err, "the enrolment-only handle is gone")

			s := res.Effects.LoadSession(t, rotated)
			assert.Equal(t, session.MFASatisfied, s.MFA)
			assert.True(t, s.EnrolmentOriginDeadline.IsZero(), "the enrolment marker is cleared")
			assert.True(t, s.AbsoluteExpiresAt.After(time.Now().Add(time.Hour)),
				"the deadline a login would have had is restored, not the enrolment one")
		},
	}
}

func enrolmentSatisfiedSessionReachesRoute() Scenario {
	// A session the verify endpoint left satisfied, with no enrolment marker,
	// is an ordinary session from here on: the per-request policy input must
	// carry its second factor forward, or the requirement policy would
	// challenge it all over again on the very next request.
	return Scenario{
		Name:    "a satisfied session reaches a protected route",
		Build:   enrolmentBuild(stepVerified),
		Request: authenticatedRequest(http.MethodGet, RoutePath),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, RouteBody, res.Body)
			assert.True(t, res.RouteRan, "the satisfied session reaches the route behind the gate")

			s := res.Effects.LoadSession(t, res.Effects.SessionID)
			assert.Equal(t, session.MFASatisfied, s.MFA)
			assert.True(t, s.EnrolmentOriginDeadline.IsZero(), "the session carries no enrolment marker")
		},
	}
}
