package admin

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kartaladev/scrty/identity"
)

type systemActorKey struct{}

// systemPrefix marks an actor that is a job, not a person, in events and audit.
const systemPrefix = "system:"

// WithSystemActor returns a copy of ctx naming a system actor, for a job with
// no authenticated principal, such as a synchronisation run. The actor reads as
// "system:" followed by name. A principal with an identifier in the context
// takes precedence.
//
// A blank name, one with a control character, or one that with its prefix is
// longer than MaxActorBytes is not an actor: ActorFrom
// refuses it with ErrNoActor, so a write never carries an actor nobody can
// attribute.
func WithSystemActor(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, systemActorKey{}, name)
}

// ActorFrom returns who is making a change: the identifier of the principal in
// ctx, else "system:" and the name WithSystemActor attached, else ErrNoActor.
// The services call it before every write.
//
// A principal with an empty identifier, like no principal, falls through to an
// attached system actor. A principal with a non-empty identifier must be a
// valid actor, and is never replaced by a system actor: an identifier that is
// blank, longer than MaxActorBytes, not valid UTF-8, holds a control
// character, or starts with "system:" (it would read as a system actor) is
// ErrNoActor. A system actor longer than MaxActorBytes with its prefix, or one
// WithSystemActor refuses, is ErrNoActor too.
func ActorFrom(ctx context.Context) (string, error) {
	if p, ok := identity.PrincipalFromContext(ctx); ok && p != nil && p.ID != "" {
		actor := string(p.ID)
		if !validActorText(actor) || strings.HasPrefix(actor, systemPrefix) {
			return "", ErrNoActor
		}

		return actor, nil
	}

	if name, ok := ctx.Value(systemActorKey{}).(string); ok && validActorText(systemPrefix+name) &&
		strings.TrimSpace(name) != "" {
		return systemPrefix + name, nil
	}

	return "", ErrNoActor
}

// validActorText reports whether s can name an actor: not blank, within
// MaxActorBytes, valid UTF-8 and free of control characters.
func validActorText(s string) bool {
	if strings.TrimSpace(s) == "" || len(s) > MaxActorBytes || !utf8.ValidString(s) {
		return false
	}

	return !strings.ContainsFunc(s, unicode.IsControl)
}

// MaxActorBytes bounds an actor as ActorFrom returns it: a principal's
// identifier, or "system:" and a system actor's name.
const MaxActorBytes = 256
