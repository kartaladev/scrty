package oidc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ascii"
)

// provision creates and links a user for ext, which has no link, when the
// consumer enabled provisioning for its provider and every gate admits it.
//
// The sequence is: the gates; a create-only Provision, where a taken username
// is a refusal and never an adoption; then the link insert, bound to the
// reference and username the provisioner returned. A crash or failure between
// the last two leaves a user with no link, and later logins of the identity
// are refused until an operator inserts the link.
func (b *Broker) provision(ctx context.Context, ext ExternalIdentity) (*identity.Principal, error) {
	if !b.jit[ext.Provider] {
		b.refusal(ctx, slog.LevelDebug, "no link for the external identity", ext.Provider, ext.Email)
		return nil, ErrNoLinkedAccount
	}
	if reason, ok := b.admits(ext); !ok {
		b.refusal(ctx, slog.LevelDebug, "provisioning refused: "+reason, ext.Provider, ext.Email)
		return nil, ErrProvisioningRefused
	}

	linkID, err := b.ids.NewID()
	if err != nil {
		return nil, fmt.Errorf("oidc: generating a link identifier: %w", err)
	}

	values := identifying{subject: ext.Subject, emails: []string{ext.Email}}
	det, err := b.provisioner.Provision(ctx, ext.Email, b.provisionOptions(ctx, ext)...)
	switch {
	case errors.Is(err, identity.ErrUserExists):
		b.refusal(ctx, slog.LevelWarn, "provisioning refused: the username is taken", ext.Provider, ext.Email)
		return nil, ErrProvisioningRefused
	case err != nil:
		return nil, fmt.Errorf("oidc: provisioning a user: %w", redact(err, values))
	case det == nil || det.ID == "":
		return nil, errors.New("oidc: the user provisioner returned no user reference")
	case !det.Active:
		// As on the linked path, an inactive user does not log in; it is not
		// linked either, so a later login is refused as a taken username.
		b.refusal(ctx, slog.LevelDebug, "a provisioned user is inactive", ext.Provider, ext.Email)
		return nil, ErrNoLinkedAccount
	}
	values.names = []string{det.Username, string(det.ID)}

	l := Link{
		ID: linkID, Provider: ext.Provider, Issuer: ext.Issuer, Subject: ext.Subject,
		UserID: det.ID, Username: det.Username, Email: ext.Email,
		CreatedAt: b.clock.Now(),
	}
	if err := b.links.Insert(ctx, l); err != nil {
		err = redact(err, values)
		b.log.LogAttrs(ctx, slog.LevelError,
			"oidc: a provisioned user could not be linked; later logins of this identity "+
				"are refused until an operator inserts the link",
			slog.String("provider", ext.Provider),
			slog.String("email_domain", emailDomain(ext.Email)),
			slog.String("error", err.Error())) //nolint:forbidigo // stated exception (design decision 6): err was already scrubbed by redact() above
		return nil, fmt.Errorf("oidc: linking a provisioned user: %w", err)
	}
	return b.principalFor(ctx, ext, det), nil
}

// admits applies the provisioning gates to ext, and names the one that
// refused it. An allowlist is told apart from no allowlist by a comma-ok read,
// so a configured-empty one admits no one.
func (b *Broker) admits(ext ExternalIdentity) (string, bool) {
	if ext.Email == "" {
		return "the identity has no email", false
	}
	if !ext.EmailVerified && !b.jitUnverified[ext.Provider] {
		return "the email is not verified", false
	}
	if domains, configured := b.jitDomains[ext.Provider]; configured {
		domain := emailDomain(ext.Email)
		allowed := domain != "" && containsFoldASCII(domains, domain)
		if !allowed {
			return "the email domain is not allowed", false
		}
	}
	return "", true
}

// provisionOptions names the fields of a provisioned user: the mapped
// display name, or the email when none resolves; the email as presented; the
// roles; and a mapped password hash when one is accepted.
func (b *Broker) provisionOptions(ctx context.Context, ext ExternalIdentity) []identity.UserOption {
	mapped := b.mappedUserOptions(ctx, ext.Provider, ext.Claims)
	opts := make([]identity.UserOption, 0, len(mapped)+3)
	if !identity.ApplyUserOptions(mapped...).IsSet(identity.FieldName) {
		opts = append(opts, identity.WithUserName(ext.Email))
	}

	opts = append(opts, mapped...)
	return append(opts,
		identity.WithUserEmail(ext.Email),
		identity.WithUserRoles(b.rolesFor(ctx, ext)...),
	)
}

// containsFoldASCII reports whether list holds s, compared ignoring ASCII
// letter case only.
//
// strings.EqualFold applies Unicode simple folding, which equates U+212A (the
// Kelvin sign) with "k" and U+017F with "s". An email domain spelled with one
// of them would then match an allowlist entry it is not, and a provider that
// presents such a domain would be provisioned on the strength of a name it does
// not own.
func containsFoldASCII(list []string, s string) bool {
	for _, v := range list {
		if ascii.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// mirroredField is one user field claim mirroring owns: how it is compared
// with the stored record, how the update names it, and how a mirrored value
// is copied back onto the login's details.
type mirroredField struct {
	field  identity.Field
	same   func(stored *identity.Details, proposed *identity.UserChange) bool
	option func(proposed *identity.UserChange) identity.UserOption
	copy   func(dst *identity.Details, src *identity.UserChange)
}

// mirroredFields is the one table comparison, the update and copy-back read,
// so the three cannot disagree about which fields mirroring owns. Roles are
// not among them: only role sync derives roles.
var mirroredFields = []mirroredField{
	{
		field:  identity.FieldName,
		same:   func(d *identity.Details, u *identity.UserChange) bool { return d.Name == u.Name },
		option: func(u *identity.UserChange) identity.UserOption { return identity.WithUserName(u.Name) },
		copy:   func(dst *identity.Details, src *identity.UserChange) { dst.Name = src.Name },
	},
	{
		field:  identity.FieldPassword,
		same:   func(d *identity.Details, u *identity.UserChange) bool { return bytes.Equal(d.Password, u.Password) },
		option: func(u *identity.UserChange) identity.UserOption { return identity.WithUserPassword(u.Password) },
		copy:   func(dst *identity.Details, src *identity.UserChange) { dst.Password = bytes.Clone(src.Password) },
	},
}

// mirror refreshes the mapped fields of det, the user a linked login of ext
// just loaded by reference, when mirroring is on for ext's provider and a
// mapped claim differs from what is stored. It returns the details the login
// continues with: det itself when nothing was written, or a copy of det
// carrying only the mirrored values. A failed update, or one returning no
// user, is logged and does not fail the login.
func (b *Broker) mirror(ctx context.Context, ext ExternalIdentity, l *Link, det *identity.Details) *identity.Details {
	if !b.mirrors[ext.Provider] {
		return det
	}
	mapped := b.mappedUserOptions(ctx, ext.Provider, ext.Claims)
	if len(mapped) == 0 {
		return det
	}

	proposed := identity.ApplyUserOptions(mapped...)
	var changed []mirroredField
	var opts []identity.UserOption
	for _, f := range mirroredFields {
		if proposed.IsSet(f.field) && !f.same(det, proposed) {
			changed = append(changed, f)
			opts = append(opts, f.option(proposed))
		}
	}
	if len(changed) == 0 {
		return det
	}

	updated, err := b.provisioner.Update(ctx, det.Username, opts...)
	if err == nil && updated == nil {
		err = errors.New("the user provisioner returned no user")
	}
	if err != nil {
		err = redact(err, identifying{
			subject: ext.Subject,
			emails:  []string{ext.Email, l.Email},
			names:   []string{det.Username, l.Username, string(det.ID)},
		})
		write, suppressed := b.sampler.Allow("oidc.broker:mirror-update-failed:"+ext.Provider, b.clock.Now())
		if write {
			b.log.LogAttrs(ctx, slog.LevelError,
				"oidc: claim mirroring could not update the user; the login continues with the stored values",
				slog.String("provider", ext.Provider),
				slog.String("error", err.Error()), //nolint:forbidigo // stated exception (design decision 6): err was already scrubbed by redact() above
				slog.Int("suppressed", suppressed))
		}
		return det
	}

	refreshed := *det
	for _, f := range changed {
		f.copy(&refreshed, proposed)
	}
	return &refreshed
}

// checkMirroring refuses mirroring that has nothing to write through or
// nothing to mirror.
func (b *Broker) checkMirroring() error {
	for provider, on := range b.mirrors {
		if !on {
			continue
		}
		if b.provisioner == nil {
			return fmt.Errorf("%w: WithBrokerClaimMirror for provider %q: %w",
				ErrConfig, provider, identity.MissingPort("user provisioner"))
		}
		_, name := b.nameClaims[provider]
		_, hash := b.passwordClaims[provider]
		if !name && !hash {
			return fmt.Errorf("%w: WithBrokerClaimMirror for provider %q needs a display-name or password-hash claim path",
				ErrConfig, provider)
		}
	}
	return nil
}
