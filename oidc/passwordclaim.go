package oidc

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"

	"golang.org/x/crypto/bcrypt"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
)

// The accepted bcrypt cost band of a mapped password-hash claim, by default
// and at its widest. The widest is bcrypt's own range.
const (
	defaultPasswordClaimMinCost = 10
	defaultPasswordClaimMaxCost = 15
	bcryptMinCost               = 4
	bcryptMaxCost               = 31
)

// bcryptHash matches exactly one bcrypt hash and nothing around it, capturing
// its two-digit cost.
var bcryptHash = regexp.MustCompile(`^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$`)

// passwordClaimReason names why a mapped password-hash claim was ignored. The
// once-then-quiet warning is kept per provider and per reason, so a malformed
// claim an attacker controls cannot use up the warning a cost problem needs.
type passwordClaimReason string

const (
	passwordClaimNotBcrypt   passwordClaimReason = "not a bcrypt hash" //nolint:gosec // G101: a rejection reason string, not a credential
	passwordClaimCostOutside passwordClaimReason = "cost outside the accepted band"
)

// mappedUserOptions resolves provider's mapped display-name and password-hash
// claims into user options. It is the one resolution provisioning and
// mirroring share, so the two cannot apply different mappings. A name is
// named only when its claim resolves to a non-empty string, and a password
// only when its claim is an accepted bcrypt hash.
func (b *Broker) mappedUserOptions(ctx context.Context, provider string, claims map[string]any) []identity.UserOption {
	var opts []identity.UserOption
	if path, ok := b.nameClaims[provider]; ok {
		if name, ok := stringClaimAt(claims, path); ok {
			opts = append(opts, identity.WithUserName(name))
		}
	}
	if hash, ok := b.passwordClaim(ctx, provider, claims); ok {
		opts = append(opts, identity.WithUserPassword([]byte(hash)))
	}
	return opts
}

// passwordClaim returns provider's mapped password-hash claim when it is a
// bcrypt hash whose cost lies in the band. Anything else is ignored and
// logged without the value.
func (b *Broker) passwordClaim(ctx context.Context, provider string, claims map[string]any) (string, bool) {
	path, ok := b.passwordClaims[provider]
	if !ok {
		return "", false
	}
	v, ok := claimAt(claims, path)
	if !ok {
		b.refusal(ctx, slog.LevelDebug, "the password-hash claim is absent", provider, "")
		return "", false
	}

	hash, _ := v.(string)
	if !bcryptHash.MatchString(hash) {
		b.passwordClaimIgnored(ctx, provider, passwordClaimNotBcrypt)
		return "", false
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		b.passwordClaimIgnored(ctx, provider, passwordClaimNotBcrypt)
		return "", false
	}
	if cost < b.passwordMinCost || cost > b.passwordMaxCost {
		b.passwordClaimIgnored(ctx, provider, passwordClaimCostOutside,
			slog.Int("cost", cost),
			slog.Int("min_cost", b.passwordMinCost),
			slog.Int("max_cost", b.passwordMaxCost))
		return "", false
	}
	return hash, true
}

// passwordClaimIgnored logs an ignored password-hash claim, never its value:
// at WARN the first time reason occurs for provider, and at DEBUG, through
// the sampler, afterwards.
func (b *Broker) passwordClaimIgnored(ctx context.Context, provider string, reason passwordClaimReason, attrs ...slog.Attr) {
	level := slog.LevelWarn
	key := "oidc.broker.password-claim:" + string(reason) + ":" + provider
	if _, warned := b.passwordWarned.LoadOrStore(key, struct{}{}); warned {
		level = slog.LevelDebug
		write, suppressed := b.sampler.Allow(key, b.now())
		if !write {
			return
		}
		attrs = append(attrs, slog.Int("suppressed", suppressed))
	}
	attrs = append([]slog.Attr{slog.String("provider", provider)}, attrs...)
	b.log.LogAttrs(ctx, level, "oidc: ignoring the password-hash claim: "+string(reason), attrs...)
}

// checkPasswordClaims refuses a password-hash mapping that could not be
// verified by the application, or that would publish a hash elsewhere.
func (b *Broker) checkPasswordClaims() error {
	if len(b.passwordClaims) > 0 && b.passwordEncoder == nil {
		return fmt.Errorf("%w: WithPasswordClaim needs a bcrypt password encoder from WithPasswordEncoder", ErrConfig)
	}
	if b.passwordEncoder != nil {
		probe, err := b.passwordEncoder.Encode("scrty password encoder probe")
		if err != nil {
			// ErrConfig already matched regardless of cause: every failure of
			// this probe is a construction error, so it is named as a kind
			// here rather than left to match only when it happens to be the
			// cause.
			return diag.Wrap(err, fmt.Sprintf("%s: WithPasswordEncoder: the encoder failed its probe", ErrConfig), ErrConfig)
		}
		if !bcryptHash.Match(probe) {
			return fmt.Errorf("%w: WithPasswordEncoder: the encoder does not produce bcrypt hashes, "+
				"so a mapped bcrypt hash could never be verified", ErrConfig)
		}
	}
	for provider, path := range b.passwordClaims {
		if b.nameClaims[provider] == path {
			return fmt.Errorf("%w: provider %q maps its display-name claim path to its password-hash claim path",
				ErrConfig, provider)
		}
		if b.roleClaims[provider] == path {
			return fmt.Errorf("%w: provider %q maps its role claim path to its password-hash claim path",
				ErrConfig, provider)
		}
	}
	return nil
}
