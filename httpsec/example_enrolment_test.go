package httpsec_test

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/password"
	"github.com/kartaladev/scrty/policy"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// exampleUserLoader is the smallest identity.UserLoader that satisfies the
// README's enrolment example: one user, whose username is also the address
// the enrolment path and the login itself use.
type exampleUserLoader struct{ details *identity.Details }

func (l exampleUserLoader) LoadByUsername(_ context.Context, username string) (*identity.Details, error) {
	if username != l.details.Username {
		return nil, identity.ErrUserNotFound
	}

	return l.details, nil
}

func (l exampleUserLoader) LoadByUserID(_ context.Context, id identity.UserID) (*identity.Details, error) {
	if id != l.details.ID {
		return nil, identity.ErrUserNotFound
	}

	return l.details, nil
}

// exampleRequirement always answers that the one user in the example must use
// a second factor, standing in for identity.MFARequirementLookup, which scrty
// ships no implementation of.
type exampleRequirement struct{}

func (exampleRequirement) Required(context.Context, identity.UserID) (bool, error) { return true, nil }

// exampleTokens is the smallest token.Generator that keeps this example free
// of a signing key: it issues the session identifier itself as the token and
// looks the claims up from it, which is enough to show the enrolment path's
// wiring and unfit for anything real.
type exampleTokens struct{}

func (exampleTokens) Generate(_ context.Context, id string, _ *identity.Principal) (string, error) {
	return id, nil
}

func (exampleTokens) Verify(_ context.Context, presented string) (*token.Claims, error) {
	return token.NewClaims("", presented), nil
}

// exampleSender only reports itself non-blocking, which is what
// EnableMFAEnrolment requires of a sender by default; a real deployment wraps
// its own Sender in notify.NewQueuedSender instead.
type exampleSender struct{}

func (exampleSender) Send(context.Context, notify.Message) error { return nil }
func (exampleSender) NonBlocking() bool                          { return true }

// ExampleEnableMFAEnrolment wires the enrolment path onto a chain that already
// authenticates with a password: policy.WithMFAEnrolmentPath on the requirement
// policy, and httpsec.EnableMFAEnrolment on the chain, both required together.
func ExampleEnableMFAEnrolment() {
	users := exampleUserLoader{details: &identity.Details{
		ID: "u-1", Username: "grace@example.com", Active: true,
	}}

	encoder, err := password.NewArgon2idEncoder()
	if err != nil {
		panic(err)
	}

	hash, err := encoder.Encode("correct horse battery staple")
	if err != nil {
		panic(err)
	}

	users.details.Password = hash

	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Co")
	if err != nil {
		panic(err)
	}

	lookups, err := mfa.LookupsFor(totp)
	if err != nil {
		panic(err)
	}

	requirementPolicy, err := policy.NewMFARequirementPolicy(exampleRequirement{}, lookups,
		policy.WithMFAEnrolmentPath())
	if err != nil {
		panic(err)
	}

	challengePolicy, err := policy.NewMFAPolicy(lookups)
	if err != nil {
		panic(err)
	}

	engine, err := policy.NewEngine(requirementPolicy, challengePolicy)
	if err != nil {
		panic(err)
	}

	sessions, err := session.NewManager()
	if err != nil {
		panic(err)
	}

	authn, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(encoder))
	if err != nil {
		panic(err)
	}

	chain, err := httpsec.New(
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn,
			Sessions:      sessions,
			Tokens:        exampleTokens{},
			Attempts:      policy.NewMemoryAttemptStore(),
		}),
		httpsec.EnableMFA([]mfa.Method{totp}, httpsec.WithMFATokens(exampleTokens{})),
		httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: users, Sender: exampleSender{}}),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(chain != nil)

	// Output: true
}
