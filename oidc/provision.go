package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/kartaladev/scrty/identity"
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
		CreatedAt: b.now(),
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
		allowed := domain != "" && containsFold(domains, domain)
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

// containsFold reports whether list holds s, compared case-insensitively.
func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
