package prblmsec

import (
	"context"
	"time"

	"github.com/kartaladev/prblm"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/recovery"
)

// Extension member names. Each is a valid prblm extension name, which New
// checks once (checkMembers), so setting one on a problem cannot fail.
const (
	memberChallenge   = "challenge"
	memberMethods     = "methods"
	memberMaxAge      = "max_age"
	memberRule        = "rule"
	memberAccessToken = "access_token"
	memberTokenType   = "token_type"
)

var memberNames = []string{
	memberChallenge, memberMethods, memberMaxAge, memberRule, memberAccessToken, memberTokenType,
}

// Sub-types the mapper sets members on.
const (
	subMFARequired       = "mfa-required"
	subReauthRequired    = "reauthentication-required"
	subPasswordRejected  = "password-rejected"
	subChallengeRequired = "challenge-required"
)

// method is one entry of the methods member. Its json tags name the members in
// both formats: prblm encodes XML from the JSON encoding.
type method struct {
	Name    string `json:"name"`
	Channel string `json:"channel"`
	Begins  bool   `json:"begins"`
}

// selector says when a type is chosen among the types of its status. A type
// with a challenge test answers a challenge of the kinds it accepts; a type with
// targets answers an error matching one of them; a type with neither is its
// status's default.
type selector struct {
	challenge func(policy.ChallengeKind) bool
	targets   []error
}

// challengeNames is the fixed vocabulary of the challenge member: the value
// each kind with a type of its own is named by. It is the library's own list,
// not policy.ChallengeKind's String, so the wire value does not change with a
// rename in the core. A kind not in it, a consumer's own included, has a type
// but no challenge member.
var challengeNames = map[policy.ChallengeKind]string{
	policy.ChallengeMFA:             "mfa",
	policy.ChallengePasswordChange:  "password-change",
	policy.ChallengeMFAEnrolment:    "mfa-enrolment",
	policy.ChallengeAccountRecovery: "account-recovery",
}

// namedKind reports whether k is a challenge kind with a type of its own.
func namedKind(k policy.ChallengeKind) bool {
	_, ok := challengeNames[k]
	return ok
}

func kind(want policy.ChallengeKind) func(policy.ChallengeKind) bool {
	return func(k policy.ChallengeKind) bool { return k == want }
}

// selectors gives, by sub-type, how each non-default type is chosen. Every
// type in typeTable that is not here is the default of its status.
var selectors = map[string]selector{
	"authentication-required": {targets: []error{
		httpsec.ErrAuthenticationRequired,
		authorize.ErrAuthenticationRequired,
		policy.ErrSessionIdle,
		oidcprovider.ErrReauthenticate,
	}},
	"second-factor-failed": {targets: []error{
		mfa.ErrInvalidCode,
		mfa.ErrVerifyThrottled,
		mfa.ErrEnrolmentThrottled,
		passkey.ErrRegistrationThrottled,
	}},
	"proof-of-possession-failed": {targets: []error{
		httpsec.ErrDPoPNonceRequired,
		httpsec.ErrInvalidDPoPProof,
		httpsec.ErrCertificateBinding,
	}},
	subMFARequired:              {challenge: kind(policy.ChallengeMFA)},
	subChallengeRequired:        {challenge: func(k policy.ChallengeKind) bool { return !namedKind(k) }},
	"password-change-required":  {challenge: kind(policy.ChallengePasswordChange)},
	"mfa-enrolment-required":    {challenge: kind(policy.ChallengeMFAEnrolment)},
	"account-recovery-required": {challenge: kind(policy.ChallengeAccountRecovery)},
	subReauthRequired: {targets: []error{
		httpsec.ErrReauthenticationRequired,
		recovery.ErrReauthenticationRequired,
		passkey.ErrReauthenticationRequired,
	}},
	"cross-site-request": {targets: []error{
		httpsec.ErrCrossSiteRequest,
		httpsec.ErrCrossSiteStream,
	}},
	"automation-challenge-required": {targets: []error{httpsec.ErrChallengeRequired}},
	// Only the disclosed refusal reaches it: a concealed one is joined to
	// authenticate.ErrAuthenticationFailed, which the core answers 401, and
	// types are chosen only among their status's.
	"account-inactive": {targets: []error{authenticate.ErrAccountInactive}},
	"account-locked": {targets: []error{
		lockout.ErrAccountLocked,
		lockout.ErrAccountHeld,
	}},
}

// candidate is one type and how it is chosen.
type candidate struct {
	sub string
	t   *prblm.Type
	sel selector
}

// statusTypes are the types of one status, in the order they are tried.
//
// specificTargets are the targets of specifics, candidate by candidate and
// each candidate's in its own order, prepared once for errwalk.Index; the
// target at position i belongs to specifics[specificOf[i]]. The first target,
// in that order, that any node matches chooses its candidate, exactly as
// trying each candidate's targets one errwalk.Is at a time would.
type statusTypes struct {
	challenges      []candidate
	specifics       []candidate
	specificTargets errwalk.Targets
	specificOf      []int
	fallback        *candidate
}

// groupByStatus orders the types of each status: challenge types, then
// specific types, each in typeTable's order, then the default. The first
// default of a status in typeTable's order wins; TestMapper_TypePerRefusal pins
// that every status has the one the spec names.
func groupByStatus(bySub map[string]*prblm.Type) map[int]*statusTypes {
	out := make(map[int]*statusTypes)
	for _, row := range typeTable {
		st := out[row.status]
		if st == nil {
			st = &statusTypes{}
			out[row.status] = st
		}
		c := candidate{sub: row.sub, t: bySub[row.sub], sel: selectors[row.sub]}
		switch {
		case c.sel.challenge != nil:
			st.challenges = append(st.challenges, c)
		case len(c.sel.targets) > 0:
			st.specifics = append(st.specifics, c)
		case st.fallback == nil:
			st.fallback = &c
		}
	}
	for _, st := range out {
		var targets []error
		for i, c := range st.specifics {
			for _, target := range c.sel.targets {
				targets = append(targets, target)
				st.specificOf = append(st.specificOf, i)
			}
		}
		st.specificTargets = errwalk.NewTargets(targets...)
	}
	return out
}

// checkMembers proves at construction that prblm accepts every member name,
// so the mapper's Set calls cannot fail at run time.
func checkMembers() error {
	probe := prblm.New(500)
	for _, name := range memberNames {
		if err := probe.Set(name, true); err != nil {
			return err
		}
	}
	return nil
}

// Mapper returns the prblm mapper that answers scrty's refusals.
//
// For an error the core recognises (httpsec.LookupStatus), it returns a
// problem whose status is httpsec.StatusForError's, of one of that status's
// types: a challenge's type by its kind first, then a specific refusal's type,
// then the status's default. A recognised status with no type of its own, such
// as 500, is answered about:blank with no detail. The error is attached as the
// problem's cause, so prblm's hooks still reach it, and no text of it appears
// in the problem. For any other error it returns nil, leaving the error to the
// handler's later mappers, prblm's built-ins and prblm's safe 500.
//
// prblm runs mappers in registration order, and Option registers this mapper
// where it appears among the handler's options; it does not move it ahead.
// Put p.Option() (or this mapper) before the application's own mappers: a
// mapper ahead of it that also matches one of scrty's refusals answers that
// refusal instead.
//
// The only extension members are challenge, methods, max_age, rule,
// access_token and token_type. The challenge member names the kind of a
// challenge by a fixed vocabulary (mfa, password-change, mfa-enrolment,
// account-recovery); a challenge of any other kind, a consumer's own included,
// gets its type but no challenge member. The rule member is the
// password.Rule the consumer's policy reported, passed through unchanged as
// the consumer's own data. A challenge problem whose challenge carries an
// access token delivers it as access_token, unless WithoutChallengeToken was
// given, and then also carries the response header Cache-Control: no-store.
// prblm's hooks (OnError, AddErrorHook) receive that problem, access_token
// included, so a hook that logs extensions logs the token.
//
// A chain the core's walk gives up on (a cycle, a fan-out past its budget, a
// link whose Unwrap, Is or As method panics) is not recognised, so the mapper
// returns nil for it and the lookup alone logs the abort. The mapper reads the
// chain with that same bounded, recovering walk, so it selects the challenge
// the core's status came from, and it never calls an error's Error method.
//
// The mapper never sets WWW-Authenticate: a challenge header the chain set on
// the response before refusing is kept by prblm.
//
// Mapper is for wiring the mapper alone; Option registers it together with the
// type definitions, which prblm's discovery needs.
func (p *Problems) Mapper() prblm.Mapper {
	p.mustBeBuilt()
	return prblm.MapperFunc(p.mapError)
}

// mustBeBuilt panics on a nil *Problems, at wiring time, so the mistake does
// not wait for the first refusal.
func (p *Problems) mustBeBuilt() {
	if p == nil {
		panic("prblmsec: nil *Problems; build it with New")
	}
}

func (p *Problems) mapError(_ context.Context, err error) *prblm.Problem {
	if p.byStatus == nil {
		// Not built by New: no types are defined, so nothing is answered.
		return nil
	}
	status, ok := httpsec.LookupStatus(err) //nolint:contextcheck // the core's lookup takes no context; its abort record goes to slog.Default() (design decision 11)
	if !ok {
		return nil
	}
	st := p.byStatus[status]
	if st == nil {
		return prblm.New(status, prblm.WithCause(err))
	}

	// The lookup recognised err, so its own walk finished. One more walk
	// serves every selector below. It gives up only on a chain that answers
	// differently each time it is asked; the lookup already reported what it
	// saw, so the mapper writes no record of its own and answers nothing.
	// Walked into this frame's own array: a chain of up to 16 nodes takes no
	// heap allocation, and a longer one only grows onto the heap.
	var buf [16]error

	chain, abort := errwalk.FlattenInto(buf[:], err)
	if abort != nil {
		return nil //nolint:nilerr // an abort answers nothing; the lookup logged it
	}

	// A challenge is chosen only when its type has the looked-up status, so a
	// challenge the core did not answer never changes the status.
	ch, found, abort := errwalk.As[*httpsec.ChallengeError](chain)
	if abort != nil {
		return nil //nolint:nilerr // see above
	}
	if found {
		for _, c := range st.challenges {
			if c.sel.challenge(ch.Kind) {
				return p.challengeProblem(c, ch, err)
			}
		}
	}
	// One scan over every specific target of the status, under one recover.
	i, abort := errwalk.Index(chain, st.specificTargets)
	if abort != nil {
		return nil //nolint:nilerr // see above
	}
	if i >= 0 {
		return p.specificProblem(st.specifics[st.specificOf[i]], chain, err)
	}
	if st.fallback == nil {
		return prblm.New(status, prblm.WithCause(err))
	}
	return p.specificProblem(*st.fallback, chain, err)
}

// detailOf is the fixed detail of a type.
func detailOf(sub string) string {
	for _, row := range typeTable {
		if row.sub == sub {
			return row.detail
		}
	}
	return ""
}

// set sets a member whose name checkMembers proved valid; Set cannot fail for
// it, so its error carries nothing.
func set(prob *prblm.Problem, name string, v any) {
	_ = prob.Set(name, v)
}

func (p *Problems) newProblem(c candidate, err error) *prblm.Problem {
	return c.t.New(prblm.WithDetail(detailOf(c.sub)), prblm.WithCause(err))
}

// specificProblem builds the problem of c, reading its members from chain. It
// returns nil when that scan gives up, which only a nondeterministic chain can
// cause.
func (p *Problems) specificProblem(c candidate, chain errwalk.Chain, err error) *prblm.Problem {
	prob := p.newProblem(c, err)
	switch c.sub {
	case subReauthRequired:
		r, found, abort := errwalk.As[*httpsec.ReauthenticationRequiredError](chain)
		if abort != nil {
			return nil //nolint:nilerr // see above
		}
		if found && r.Window > 0 {
			set(prob, memberMaxAge, int64(r.Window/time.Second))
		}
	case subPasswordRejected:
		rule, abort := ruleOf(chain)
		if abort != nil {
			return nil //nolint:nilerr // see above
		}
		if rule != "" {
			set(prob, memberRule, string(rule))
		}
	}
	return prob
}

func (p *Problems) challengeProblem(c candidate, ch *httpsec.ChallengeError, err error) *prblm.Problem {
	prob := p.newProblem(c, err)
	if name, ok := challengeNames[ch.Kind]; ok {
		set(prob, memberChallenge, name)
	}
	if c.sub == subMFARequired && ch.Methods != nil {
		methods := make([]method, 0, len(ch.Methods))
		for _, m := range ch.Methods {
			methods = append(methods, method{Name: m.Name, Channel: string(m.Channel), Begins: m.Begins})
		}
		set(prob, memberMethods, methods)
	}
	if !p.noToken && ch.Token != "" {
		set(prob, memberAccessToken, ch.Token)
		if ch.TokenType != "" {
			set(prob, memberTokenType, string(ch.TokenType))
		}
		if prob.Header == nil {
			prob.Header = make(map[string][]string)
		}
		prob.Header.Set("Cache-Control", "no-store")
	}
	return prob
}

// ruleOf returns the rule of the first password.RejectedError in the chain, as
// a value or a non-nil pointer, or "" when there is none. The abort is that of
// the scan, which only a nondeterministic chain can give.
func ruleOf(chain errwalk.Chain) (password.Rule, error) {
	rej, found, abort := errwalk.As[password.RejectedError](chain)
	if abort != nil {
		return "", abort
	}
	if found && rej.Rule != "" {
		return rej.Rule, nil
	}

	ptr, found, abort := errwalk.As[*password.RejectedError](chain)
	if abort != nil || !found {
		return "", abort
	}

	return ptr.Rule, nil
}
