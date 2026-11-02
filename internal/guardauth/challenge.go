package guardauth

import "context"

// HeaderWriter is the part of a response a challenge is set on. The chain's
// own ResponseWriter, and each adapter's, satisfy it.
type HeaderWriter interface {
	// SetHeader replaces every value of the response header name with value.
	SetHeader(name, value string)

	// AddHeader adds value to the response header name, keeping the values
	// already set.
	AddHeader(name, value string)
}

// Challenger sets on w the challenge the chain answers the refusal err with,
// such as a WWW-Authenticate header, and returns the error the request fails
// with: err itself, or a dependency failure that kept the challenge from
// being set.
type Challenger func(ctx context.Context, w HeaderWriter, err error) error

// challengerKey is the context key a chain publishes its Challenger under.
type challengerKey struct{}

// WithChallenger returns ctx carrying c, the challenge the chain answers its
// own refusals with, so a guard behind the chain answers its refusals alike.
func WithChallenger(ctx context.Context, c Challenger) context.Context {
	return context.WithValue(ctx, challengerKey{}, c)
}

// Challenge sets on w the challenge the chain the request passed through
// would answer err with, and returns the error the request fails with. With
// no chain challenge published on ctx it sets nothing and returns err.
func Challenge(ctx context.Context, w HeaderWriter, err error) error {
	c, ok := ctx.Value(challengerKey{}).(Challenger)
	if !ok || c == nil {
		return err
	}

	return c(ctx, w, err)
}
