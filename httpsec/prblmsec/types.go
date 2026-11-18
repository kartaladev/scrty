package prblmsec

// typeRow defines one problem type. title and detail are fixed library text,
// never derived from an error; description documents the type at its URL.
type typeRow struct {
	sub         string
	status      int
	title       string
	detail      string
	description string
}

// typeTable is the single source of the problem types, used by New and by the
// mapper.
var typeTable = []typeRow{
	{"authentication-required", 401, "Authentication required",
		"Authentication is required to access this resource.",
		"The request carries no valid authenticated session. Authenticate, then retry."},
	{"authentication-failed", 401, "Authentication failed",
		"The credentials could not be verified.",
		"Authentication did not succeed. The response does not say why."},
	{"second-factor-failed", 401, "Second factor failed",
		"The second factor could not be verified.",
		"The second-factor code was refused, or too many attempts were made."},
	{"proof-of-possession-failed", 401, "Proof of possession failed",
		"The proof of possession is missing or invalid.",
		"The token is bound to a key or certificate that the request did not prove it holds."},
	{"mfa-required", 401, "Second factor required",
		"A second factor is required to complete authentication.",
		"Authentication needs a second factor. The methods member lists those the user can use."},
	{"challenge-required", 401, "Challenge required",
		"A further step is required to complete authentication.",
		"Authentication is paused on a challenge. The challenge member names it."},
	{"password-change-required", 403, "Password change required",
		"The password must be changed before continuing.",
		"The account must set a new password before any other action."},
	{"mfa-enrolment-required", 403, "Second factor enrolment required",
		"A second factor must be enrolled before continuing.",
		"The account must enrol a second factor before any other action."},
	{"account-recovery-required", 403, "Account recovery required",
		"The account must be recovered before continuing.",
		"The account must complete recovery before any other action."},
	{"reauthentication-required", 403, "Reauthentication required",
		"Recent authentication is required for this action.",
		"The session is too old for this action. Authenticate again, then retry."},
	{"cross-site-request", 403, "Cross-site request refused",
		"The request was refused as a cross-site request.",
		"The request did not pass cross-site request protection."},
	{"automation-challenge-required", 403, "Automation challenge required",
		"The request must pass an automation challenge.",
		"The request was refused until it passes the automation challenge."},
	{"access-denied", 403, "Access denied",
		"Access to this resource is denied.",
		"The caller is known but not allowed to perform this action."},
	{"invalid-request", 400, "Invalid request",
		"The request is invalid.",
		"The request is malformed or carries a value that is not accepted."},
	{"not-found", 404, "Not found",
		"The resource was not found.",
		"The requested resource does not exist."},
	{"conflict", 409, "Conflict",
		"The request conflicts with the current state.",
		"The request conflicts with the state of the resource."},
	{"request-too-large", 413, "Request too large",
		"The request is too large.",
		"The request exceeds the size the service accepts."},
	{"password-rejected", 422, "Password rejected",
		"The password does not satisfy the password policy.",
		"The candidate password was refused by a policy rule. The rule member names it."},
	{"account-locked", 429, "Account locked",
		"The account is temporarily locked.",
		"Too many failed attempts locked the account for a while."},
	{"limit-reached", 429, "Limit reached",
		"Too many requests. Try again later.",
		"A rate limit was reached."},
}
