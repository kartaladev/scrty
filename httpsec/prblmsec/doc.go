// Package prblmsec answers scrty's refusals as RFC 9457 problem details
// through github.com/kartaladev/prblm.
//
// The integration is opt-in: nothing changes until its mapper is registered
// with a prblm handler, for example with prblm.NewHandler(p.Option()) for a
// *Problems built by New. A consumer who never registers it keeps the
// responses the core and the framework adapters give today. The core module
// does not import prblm, and this module imports neither gin nor fiber.
//
// # What it is
//
// A *Problems, built by New, is three pieces for a prblm handler:
//
//   - the type definitions, from Problems.Types, which prblm's discovery
//     documents at each type's URL;
//   - the mapper, from Problems.Mapper, which turns an error scrty recognises
//     into a problem of one of those types;
//   - the prblm.Option that registers both with the same prefix,
//     Problems.Option.
//
// Everything else stays prblm's: content negotiation between JSON and XML,
// the instance member, the Vary and Cache-Control headers, enrichers, hooks,
// panic recovery and the framework adapters. A refusal that the core does not
// recognise is left to the consumer's later mappers and then to prblm's safe
// 500, with no detail.
//
// # Wiring
//
// On net/http, give the same handler's Write to the chain and to the guards,
// so a refusal at the chain and one at a guard are answered alike. The
// namespace is how a type's relative name becomes a URL:
//
//	p, err := prblmsec.New()
//	if err != nil {
//		return err
//	}
//	h := prblm.NewHandler(prblm.WithNamespace("/probs"), p.Option())
//
//	chain, err := httpsec.New(/* mechanisms */, httpsec.WithErrorHandler(h.Write))
//	guards, err := httpsec.NewGuards(authorizer, httpsec.WithGuardErrorHandler(h.Write))
//
// Example_netHTTP is this wiring, run.
//
// On gin, register ginprblm.Middleware(opts...) before ginsec.Middleware(chain)
// and pass it prblm.WithNamespace and p.Option(). No httpsec.WithErrorHandler
// is set, because the chain's handler governs net/http only, and no ginsec
// option is needed. Mirrors TestProblemParity in the scrty test module.
//
//	engine.Use(ginprblm.Middleware(prblm.WithNamespace("/probs"), p.Option()))
//	engine.Use(ginsec.Middleware(chain))
//
// On fiber, give fiberprblm.ErrorHandler(opts...) to fiber.Config.ErrorHandler
// in place of fibersec.ErrorHandler. Mirrors TestProblemParity in the scrty
// test module.
//
//	app := fiber.New(fiber.Config{
//		ErrorHandler: fiberprblm.ErrorHandler(prblm.WithNamespace("/probs"), p.Option()),
//	})
//	app.Use(fibersec.Middleware(chain))
//
// The same refusal then produces the same status, problem document and
// security headers on all three.
//
// # Problem types
//
// Every type is a sub-type under the prefix (default DefaultTypePrefix,
// "security"), resolved against the handler's namespace: with the namespace
// "/probs", "security/mfa-required" is sent as "/probs/security/mfa-required".
// The status of a problem always equals httpsec.StatusForError for the same
// error, whichever type is chosen; a type is chosen only among those whose
// status the core gave. A recognised status with no type of its own is
// answered about:blank, with that status and no detail, and a recognised 500
// is always about:blank with no detail.
//
//	Sub-type                       Status  What it answers
//	authentication-required        401     authentication required, an idle or expired session, a re-authentication refusal from the provider
//	authentication-failed          401     the status default: every form of failed authentication, a concealed lock, an unavailable user store, a throttled source, a refused magic link
//	second-factor-failed           401     an invalid or throttled second-factor attempt or enrolment, a throttled passkey registration begin
//	proof-of-possession-failed     401     a missing or invalid DPoP proof, a DPoP nonce required, a certificate-bound token without its certificate
//	mfa-required                   401     a challenge of the second-factor kind
//	challenge-required             401     a challenge of any other kind answered 401
//	password-change-required       403     a challenge of the password-change kind
//	mfa-enrolment-required         403     a challenge of the second-factor enrolment kind
//	account-recovery-required      403     a challenge of the account-recovery kind
//	reauthentication-required      403     any re-authentication-required refusal
//	cross-site-request             403     a cross-site request refused by CSRF protection or the signal stream
//	automation-challenge-required  403     a request refused by the automation-challenge verifier
//	access-denied                  403     the status default
//	invalid-request                400     the status default
//	not-found                      404     the status default
//	conflict                       409     the status default
//	request-too-large              413     the status default
//	password-rejected              422     the status default
//	account-locked                 429     the disclosed account lock
//	limit-reached                  429     the status default
//
// Where the core gives several refusals one status to conceal which of them
// occurred, the problem does not tell them apart either: a concealed account
// lock and an unavailable user store both get the problem a wrong password
// gets, byte for byte. A title and a detail are fixed library text, and no
// error's text appears in any member.
//
// # Extension members
//
// A problem's only extension members are challenge, methods, max_age, rule,
// access_token and token_type:
//
//   - challenge is the kind of a challenge, one of the fixed tokens mfa,
//     password-change, mfa-enrolment or account-recovery. A challenge of any
//     other kind, a consumer's own included, gets its type and no challenge
//     member, and so does every other refusal.
//   - methods is on mfa-required: the usable second-factor methods in the
//     challenge's order, each with name, channel and begins.
//   - max_age is on reauthentication-required: the required recency in whole
//     seconds, when the refusal carries one.
//   - rule is on password-rejected: the password.Rule the consumer's policy
//     reported, passed through unchanged. It is the consumer's data, and the
//     library does not interpret it.
//   - access_token and token_type are the challenge's credential, below.
//
// No member carries a session handle, a submitted credential, a credential ID,
// a DPoP proof, a certificate, a CSRF token, a candidate password, a user
// reference or a forwarded host.
//
// # The challenge credential
//
// A challenge raised at login supersedes the caller's credential, and the
// caller needs the new one to answer the challenge. By default a challenge
// problem whose *httpsec.ChallengeError carries a token delivers it as
// access_token, with token_type naming its type (Bearer or DPoP), and sets
// Cache-Control: no-store. A challenge raised on a later request carries no
// token and so neither member. Example_challengedLogin shows the response.
//
// WithoutChallengeToken withholds both members and changes nothing else; use
// it for cookie-only deployments or when the credential is delivered another
// way. ExampleWithoutChallengeToken shows the same challenge without them.
// Note that prblm's hooks (OnError, AddErrorHook) receive the problem as
// delivered, access_token included, so a hook that logs extension members logs
// the token unless it is withheld.
//
// # Ordering and overrides
//
// prblm runs mappers in registration order, and Problems.Option registers the
// integration's mapper where it appears among the handler's options. Register
// it ahead of the application's own mappers (ExampleProblems_Mapper), so that
// the application's mapper decides the application's errors and the
// integration decides scrty's. Register a consumer mapper ahead of it to
// replace one problem on purpose: the consumer's mapper answers the errors it
// recognises and every other refusal keeps the integration's problem.
// Example_override answers a disclosed account lock with 429 and Retry-After:
// 900 while a wrong password stays authentication-failed. A mapper that also
// matches one of scrty's refusals and is registered ahead of the integration
// answers that refusal instead, whether or not that was meant.
//
// Headers the chain set before refusing, such as WWW-Authenticate or
// DPoP-Nonce, survive in the problem response: the integration never sets
// WWW-Authenticate itself.
//
// # Always set a namespace
//
// Give the prblm handler a namespace (prblm.WithNamespace). Without one, a
// relative type is sent as given and prblm reports prblm.ErrInvalidType to its
// hooks. WithTypePrefix replaces the "security" prefix, and the definitions
// follow it, so discovery and the mapper never disagree (ExampleWithTypePrefix).
// An invalid prefix, a nil option or an option given twice is refused by New
// with ErrConfig, at construction.
//
// # Stated limits
//
//   - A port the consumer supplies (a user store, a verifier, any dependency
//     scrty calls) must not return a prblm.Describer or a *prblm.Problem, nor
//     wrap one: prblm answers a describer in the error chain before any mapper,
//     so its problem would replace the integration's and could tell apart
//     refusals whose status is shared to conceal them. Nor may a port return an
//     error wrapping one of scrty's own refusal sentinels, such as
//     authorize.ErrAccessDenied or lockout.ErrAccountLocked: that can steer
//     which type a refusal gets within its status.
//   - A *Problems comes only from New. A nil *Problems panics in Mapper, Types
//     and Option at wiring time, before any traffic; a zero value maps nothing,
//     leaving every error to the handler's later mappers.
//   - On gin, ginprblm renders the chain's own 404s, such as an unknown MFA
//     method or identity provider that matches no gin route, with or without
//     ginsec.WithRefusalsRendered(): it defers the response header, so the
//     problem is written before gin's default 404 body, which then finds the
//     response already written. The option is for a
//     consumer's own error middleware that writes the response immediately. A
//     gin deployment with no renderer at all gives those 404s an empty body.
//   - A context error scrty does not recognise, such as a deadline exceeded, is
//     prblm's to map: the integration reports no match and prblm's built-in
//     mappers and safe fallback decide it.
package prblmsec
