package oidc

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/password"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// BrokerOption customises a Broker at construction.
//
// Every option replaces a default that already works or enables a behaviour
// that is off by default. An option given nil, or naming an empty provider,
// fails construction with ErrConfig rather than being ignored. A nil option is
// ignored.
//
// The options are named after what they govern: the broker's logger, clock
// and identifier source are WithBroker… because the Manager has its own.
type BrokerOption func(*Broker) error

// WithBrokerLogger replaces the logger the broker writes refusals and
// failures to. The default is slog.Default(). No record carries a claim
// value, a subject, a user reference or a username; an email appears only as
// its domain.
func WithBrokerLogger(l *slog.Logger) BrokerOption {
	return func(b *Broker) error {
		if l == nil {
			return fmt.Errorf("%w: WithBrokerLogger was given nil", ErrConfig)
		}
		b.log = l
		return nil
	}
}

// WithBrokerClock replaces the clock that stamps a created link and paces the
// refusal log. The default is clock.System(). A nil clock, typed nil
// included, is a configuration error.
func WithBrokerClock(clk clock.Clock) BrokerOption {
	return func(b *Broker) error {
		if nilcheck.IsNil(clk) {
			return fmt.Errorf("%w: WithBrokerClock was given nil", ErrConfig)
		}
		b.clock = clk
		return nil
	}
}

// WithBrokerIDGenerator replaces the source of a created link's identifier.
// The default is id.NewV7Generator(). A nil generator, including a nil
// pointer inside a non-nil interface, is refused.
func WithBrokerIDGenerator(g id.Generator) BrokerOption {
	return func(b *Broker) error {
		if nilcheck.IsNil(g) {
			return fmt.Errorf("%w: WithBrokerIDGenerator was given nil", ErrConfig)
		}
		b.ids = g
		return nil
	}
}

// WithProvisioner sets the create-only user provisioner that just-in-time
// provisioning creates users through. There is no default: the library ships
// no provisioner, and one is required as soon as WithJIT enables provisioning
// for any provider, which NewBroker otherwise refuses as a missing port. A nil
// provisioner, including a nil pointer inside a non-nil interface, is refused.
func WithProvisioner(p identity.UserProvisioner) BrokerOption {
	return func(b *Broker) error {
		if nilcheck.IsNil(p) {
			return fmt.Errorf("%w: WithProvisioner was given nil", ErrConfig)
		}
		b.provisioner = p
		return nil
	}
}

// WithJIT enables just-in-time provisioning for provider: an identity from it
// with no link is created as a user through the provisioner and linked. The
// default is off for every provider, so an unlinked identity is refused with
// ErrNoLinkedAccount. Enabling one provider enables no other.
//
// A provisioned user's username and email are the identity's email exactly as
// presented. That is safe only because the email must be verified (see
// WithJITAllowUnverifiedEmail) and because Provision is create-only: a taken
// username is refused with ErrProvisioningRefused, never adopted. A provider
// name the manager's registry does not hold is refused by NewManager.
func WithJIT(provider string) BrokerOption {
	return func(b *Broker) error {
		if provider == "" {
			return fmt.Errorf("%w: WithJIT was given an empty provider name", ErrConfig)
		}
		b.jit[provider] = true
		b.nameProvider(provider)
		return nil
	}
}

// WithJITAllowUnverifiedEmail lets provider's identities be provisioned when
// their email_verified claim is not true. The default requires a verified
// email. The domain allowlist of WithJITEmailDomains still applies. The
// provider must also be enabled with WithJIT, or NewBroker refuses it.
func WithJITAllowUnverifiedEmail(provider string) BrokerOption {
	return func(b *Broker) error {
		if provider == "" {
			return fmt.Errorf("%w: WithJITAllowUnverifiedEmail was given an empty provider name", ErrConfig)
		}
		b.jitUnverified[provider] = true
		b.nameProvider(provider)
		return nil
	}
}

// WithJITEmailDomains restricts provisioning for provider to emails whose
// domain exactly equals one of domains, compared case-insensitively; a
// subdomain does not match its parent. The default is no allowlist. Called
// with no domains it configures an empty allowlist, which admits no one.
// Repeated calls for one provider add to its list. An empty domain is refused,
// and the provider must also be enabled with WithJIT, or NewBroker refuses it.
func WithJITEmailDomains(provider string, domains ...string) BrokerOption {
	return func(b *Broker) error {
		if provider == "" {
			return fmt.Errorf("%w: WithJITEmailDomains was given an empty provider name", ErrConfig)
		}
		if slices.Contains(domains, "") {
			return fmt.Errorf("%w: WithJITEmailDomains was given an empty domain for provider %q", ErrConfig, provider)
		}
		b.jitDomains[provider] = append(slices.Clip(b.jitDomains[provider]), domains...)
		b.nameProvider(provider)
		return nil
	}
}

// WithNameClaim sets the dotted claim path, such as "name" or
// "profile.display", whose string value becomes a provisioned user's display
// name for provider. The default is the identity's email, which is also used
// when the path does not resolve to a non-empty string. An empty provider or
// path is refused.
func WithNameClaim(provider, path string) BrokerOption {
	return func(b *Broker) error {
		if provider == "" || path == "" {
			return fmt.Errorf("%w: WithNameClaim needs a provider name and a claim path", ErrConfig)
		}
		b.nameClaims[provider] = path
		b.nameProvider(provider)
		return nil
	}
}

// WithDefaultRole sets the single role a user provisioned through a provider
// with no role claim path is created with. The default is none: such a user
// is created with no role. A provider with a WithRoleClaim path never falls
// back to it, and a provider's WithAllowedRoles applies to it too. An empty
// role is refused.
func WithDefaultRole(role string) BrokerOption {
	return func(b *Broker) error {
		if role == "" {
			return fmt.Errorf("%w: WithDefaultRole was given an empty role", ErrConfig)
		}
		b.defaultRole = role
		return nil
	}
}

// WithPasswordClaim maps the dotted claim path, such as
// "credentials.password_hash", to the stored password hash of a user
// provisioned through provider. The default maps no password claim, so a
// provisioned user has no password hash.
//
// The value is accepted only when it is a well-formed bcrypt hash whose cost,
// read from the hash, lies in the band of WithPasswordClaimCostRange; anything
// else, and an absent or non-string claim, is ignored without failing the
// login, and logged without the value. A mapping needs WithPasswordEncoder,
// and the application's own password authentication must use the same bcrypt
// encoder, or the mapped hash never verifies. A hash mapped only at
// provisioning keeps accepting a password the user later retires at the
// provider, unless WithClaimMirror refreshes it.
//
// An empty provider or path is refused, as is a path equal to the provider's
// display-name or role claim path, which would publish the hash.
func WithPasswordClaim(provider, path string) BrokerOption {
	return func(b *Broker) error {
		if provider == "" || path == "" {
			return fmt.Errorf("%w: WithPasswordClaim needs a provider name and a claim path", ErrConfig)
		}
		b.passwordClaims[provider] = path
		b.nameProvider(provider)
		return nil
	}
}

// WithPasswordEncoder sets the encoder whose hashes a mapped password-hash
// claim must match. There is no default, and one is required as soon as
// WithPasswordClaim maps a claim. NewBroker encodes a probe with it and
// refuses an encoder whose output is not a bcrypt hash, since a mapped bcrypt
// hash could never verify against, say, Argon2id. Pass the same encoder value
// to the application's password authentication:
//
//	enc, _ := password.NewBcryptEncoder()
//	broker, _ := oidc.NewBroker(links, users,
//		oidc.WithPasswordClaim("corp", "credentials.password_hash"),
//		oidc.WithPasswordEncoder(enc))
//	// ...and the same enc for the password authenticator.
//
// A nil encoder, including a nil pointer inside a non-nil interface, is
// refused.
func WithPasswordEncoder(enc password.Encoder) BrokerOption {
	return func(b *Broker) error {
		if nilcheck.IsNil(enc) {
			return fmt.Errorf("%w: WithPasswordEncoder was given nil", ErrConfig)
		}
		b.passwordEncoder = enc
		return nil
	}
}

// WithPasswordClaimCostRange replaces the inclusive bcrypt cost band a mapped
// password-hash claim must lie in. The default is 10 to 15. The band must lie
// within bcrypt's own range of 4 to 31 with minCost not above maxCost, or it
// is refused. A higher ceiling lets a federated user's claim buy more CPU on
// every verification: cost 31 is about two million times the work of cost 10.
func WithPasswordClaimCostRange(minCost, maxCost int) BrokerOption {
	return func(b *Broker) error {
		if minCost < bcryptMinCost || maxCost > bcryptMaxCost || minCost > maxCost {
			return fmt.Errorf("%w: WithPasswordClaimCostRange(%d, %d) is not a band within bcrypt's %d to %d",
				ErrConfig, minCost, maxCost, bcryptMinCost, bcryptMaxCost)
		}
		b.passwordMinCost, b.passwordMaxCost = minCost, maxCost
		return nil
	}
}

// WithClaimMirror turns claim mirroring on or off for provider. The default is
// off for every provider. With it on, every login that resolves through a link
// resolves the provider's mapped display-name and password-hash claims under
// the same rules as provisioning (see WithNameClaim and WithPasswordClaim)
// and, when a resolved value differs from the stored one, amends the user
// through the provisioner's Update, naming only the fields that differ. The
// login's principal then carries the mirrored values for those fields only.
// A failed update is logged at ERROR and does not fail the login. Mirroring
// never changes roles; see WithRoleSync.
//
// Turned on, it needs WithProvisioner and a display-name or password-hash
// claim path for provider, or NewBroker refuses it. Change detection assumes
// the provider returns its stored hash: one that re-hashes on every token
// writes on every login and should not be mirrored. A mirrored credential is
// not revoked by disabling the user at the provider. An empty provider is
// refused.
func WithClaimMirror(provider string, on bool) BrokerOption {
	return func(b *Broker) error {
		if provider == "" {
			return fmt.Errorf("%w: WithClaimMirror was given an empty provider name", ErrConfig)
		}
		b.mirrors[provider] = on
		b.nameProvider(provider)
		return nil
	}
}

// WithRoleClaim sets the dotted claim path, such as "realm_access.roles",
// whose value becomes the roles of a user provisioned through provider, and
// of every login when WithRoleSync is on. The default is no path, and a
// provisioned user gets the default role of WithDefaultRole.
//
// The value must be a non-empty string or an array of non-empty strings; any
// other shape yields no role and a sampled log record without the value,
// and does not fail the login. With a path configured, the roles never fall
// back to the default role, even when the path resolves to nothing, and a
// path configured empty ("") yields no role at all. The values pass through
// WithRoleMapping and then WithAllowedRoles. A provider that lets end users
// edit this claim hands them any local role unless an allowlist is set.
//
// An empty provider is refused, as is a path equal to the provider's
// password-hash claim path.
func WithRoleClaim(provider, path string) BrokerOption {
	return func(b *Broker) error {
		if provider == "" {
			return fmt.Errorf("%w: WithRoleClaim was given an empty provider name", ErrConfig)
		}
		b.roleClaims[provider] = path
		b.nameProvider(provider)
		return nil
	}
}

// WithRoleMapping translates provider's role claim values to local role
// names; a value with no entry is dropped. The default is no mapping: values
// pass through unchanged. A mapping with no entries, nil included, drops
// every value. Matching is exact and case-sensitive. The mapping is copied,
// and a later call for the same provider replaces it. An empty provider or an
// empty local role name is refused.
func WithRoleMapping(provider string, mapping map[string]string) BrokerOption {
	return func(b *Broker) error {
		if provider == "" {
			return fmt.Errorf("%w: WithRoleMapping was given an empty provider name", ErrConfig)
		}
		for _, local := range mapping {
			if local == "" {
				return fmt.Errorf("%w: WithRoleMapping maps a value to an empty role for provider %q", ErrConfig, provider)
			}
		}
		b.roleMappings[provider] = maps.Clone(mapping)
		if b.roleMappings[provider] == nil {
			b.roleMappings[provider] = map[string]string{}
		}
		b.nameProvider(provider)
		return nil
	}
}

// WithAllowedRoles restricts provider's roles to the local role names given,
// dropping any other, the default role of WithDefaultRole included. It
// applies after WithRoleMapping, at provisioning and at role sync. The
// default is no restriction. Called with no roles it configures an empty
// allowlist, which drops every role. Matching is exact and case-sensitive.
// Repeated calls for one provider add to its list. An empty provider or an
// empty role is refused.
func WithAllowedRoles(provider string, roles ...string) BrokerOption {
	return func(b *Broker) error {
		if provider == "" {
			return fmt.Errorf("%w: WithAllowedRoles was given an empty provider name", ErrConfig)
		}
		if slices.Contains(roles, "") {
			return fmt.Errorf("%w: WithAllowedRoles was given an empty role for provider %q", ErrConfig, provider)
		}
		b.allowedRoles[provider] = append(slices.Clip(b.allowedRoles[provider]), roles...)
		b.nameProvider(provider)
		return nil
	}
}

// WithRoleSync turns role sync on or off for provider. The default is off for
// every provider. With it on, every login through provider derives its roles
// from the WithRoleClaim path, through the same mapping and allowlist as
// provisioning, and they replace the stored roles on the principal the login
// produces. Each synced role carries only its name and whether it is primary:
// a stored super-role flag or validity window is not inherited. Synced roles
// are never written to the user store; the next login derives them again.
//
// Turned on, it needs a non-empty role claim path for provider, or NewBroker
// refuses it. A provider misconfiguration then removes roles from every
// federated user of that provider on their next login. The handoff
// conveyance rebuilds the principal from stored roles, so the HTTP chain
// refuses role sync unless the consumer conveys the login itself; it learns
// which providers sync from RoleSyncProviders. A later call for the same
// provider replaces an earlier one. An empty provider is refused.
func WithRoleSync(provider string, on bool) BrokerOption {
	return func(b *Broker) error {
		if provider == "" {
			return fmt.Errorf("%w: WithRoleSync was given an empty provider name", ErrConfig)
		}
		b.roleSync[provider] = on
		b.nameProvider(provider)
		return nil
	}
}
