package oidc

import (
	"errors"

	"github.com/kartaladev/scrty/authenticate"
)

// ErrConfig is wrapped by every error a constructor in this package returns
// for a wiring mistake, so a contradictory or meaningless configuration is
// refused before any traffic.
var ErrConfig = errors.New("oidc: invalid configuration")

// Authentication failures. Each is identifiable as itself and as
// authenticate.ErrAuthenticationFailed, so a caller matching either one
// matches, and the chain's status table maps it to 401 with no row of its own.
var (
	// ErrInvalidState is returned when a callback names no live login flow, or
	// one bound to another provider or state, or one already completed or
	// expired.
	ErrInvalidState = authFailure("oidc: invalid or expired login flow")

	// ErrInvalidIDToken is returned when the provider's ID token fails
	// verification.
	ErrInvalidIDToken = authFailure("oidc: invalid ID token")

	// ErrNoLinkedAccount is returned when a verified external identity resolves
	// to no user and provisioning does not apply.
	ErrNoLinkedAccount = authFailure("oidc: no linked account")

	// ErrProvisioningRefused is returned when just-in-time provisioning of a
	// user for a verified external identity is refused.
	ErrProvisioningRefused = authFailure("oidc: account provisioning refused")

	// ErrInvalidHandoff is returned for every refused handoff redemption,
	// whatever the cause, so the response reveals none of them.
	ErrInvalidHandoff = authFailure("oidc: invalid handoff code")
)

// Refusals with a status of their own, which wrap no authentication failure.
var (
	// ErrInvalidLogoutToken is returned when a back-channel logout token fails
	// verification. It maps to 400.
	ErrInvalidLogoutToken = errors.New("oidc: invalid logout token")

	// ErrUnknownProvider is returned for a provider name the registry does not
	// hold. It maps to 404.
	ErrUnknownProvider = errors.New("oidc: unknown identity provider")
)

// Provider failures. They are not refusals of the user, and map to 500.
var (
	// ErrExchangeFailed is returned when the provider's token endpoint cannot
	// be reached or does not answer with a usable token response. The
	// provider's own error text is logged, never returned.
	ErrExchangeFailed = errors.New("oidc: code exchange failed")

	// ErrDiscoveryFailed is returned when the provider's metadata or key set
	// cannot be fetched or is unusable.
	ErrDiscoveryFailed = errors.New("oidc: provider metadata unavailable")
)

// Store contract outcomes, which the stores in this package and the
// consumer's own return, and which the library converts before they reach a
// client.
var (
	// ErrLinkNotFound is returned by a LinkStore for an external identity with
	// no link.
	ErrLinkNotFound = errors.New("oidc: link not found")

	// ErrLinkExists is returned by a LinkStore asked to insert a link whose
	// external identity is already linked.
	ErrLinkExists = errors.New("oidc: link exists")

	// ErrHandoffNotFound is returned by a HandoffStore for a missing handoff
	// record, and by Consume for one already consumed.
	ErrHandoffNotFound = errors.New("oidc: handoff code not found")

	// ErrRetainSinceRequired is returned by a store asked to purge expired
	// records with the zero time as its cutoff. The zero time is what a caller
	// who forgot to compute a cutoff passes, so it is refused rather than
	// honoured.
	ErrRetainSinceRequired = errors.New("oidc: a retain-since cutoff is required")
)

// ErrFlowUnspent marks a callback failure that happened at or before the
// login flow was completed, so the flow and the cookie that names it are still
// live. It is joined onto another error, never returned alone.
var ErrFlowUnspent = errors.New("oidc: login flow not spent")

// authFailure builds a sentinel that is also
// authenticate.ErrAuthenticationFailed.
func authFailure(msg string) error { return &refusal{msg: msg} }

// refusal is an authentication failure with its own identity.
type refusal struct{ msg string }

func (r *refusal) Error() string { return r.msg }

func (r *refusal) Unwrap() error { return authenticate.ErrAuthenticationFailed }
