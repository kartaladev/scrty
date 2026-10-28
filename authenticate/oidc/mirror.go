package oidc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kartaladev/scrty/identity"
)

// mirroredField is one user field claim mirroring owns: how it is compared
// with the stored record, how the update names it, and how a mirrored value
// is copied back onto the login's details.
type mirroredField struct {
	field  identity.Field
	same   func(stored *identity.Details, proposed *identity.NewUser) bool
	option func(proposed *identity.NewUser) identity.UserOption
	copy   func(dst *identity.Details, src *identity.NewUser)
}

// mirroredFields is the one table comparison, the update and copy-back read,
// so the three cannot disagree about which fields mirroring owns. Roles are
// not among them: only role sync derives roles.
var mirroredFields = []mirroredField{
	{
		field:  identity.FieldName,
		same:   func(d *identity.Details, u *identity.NewUser) bool { return d.Name == u.Name },
		option: func(u *identity.NewUser) identity.UserOption { return identity.WithUserName(u.Name) },
		copy:   func(dst *identity.Details, src *identity.NewUser) { dst.Name = src.Name },
	},
	{
		field:  identity.FieldPassword,
		same:   func(d *identity.Details, u *identity.NewUser) bool { return bytes.Equal(d.Password, u.Password) },
		option: func(u *identity.NewUser) identity.UserOption { return identity.WithUserPassword(u.Password) },
		copy:   func(dst *identity.Details, src *identity.NewUser) { dst.Password = bytes.Clone(src.Password) },
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
			return fmt.Errorf("%w: WithClaimMirror for provider %q: %w",
				ErrConfig, provider, identity.MissingPort("user provisioner"))
		}
		_, name := b.nameClaims[provider]
		_, hash := b.passwordClaims[provider]
		if !name && !hash {
			return fmt.Errorf("%w: WithClaimMirror for provider %q needs a display-name or password-hash claim path",
				ErrConfig, provider)
		}
	}
	return nil
}
