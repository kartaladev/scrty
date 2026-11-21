package guardauth

import (
	"context"

	"github.com/kartaladev/scrty/internal/porterr"
)

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
//
// err may be a consumer's, so a Challenger reads it through the library's
// bounded walk. It also returns the abort that stopped that walk, nil when
// none did, and writes no record of it: the guard that asked decides whether
// one is written (see LookupAborts). On an abort it sets no challenge and
// returns err as it came.
type Challenger func(ctx context.Context, w HeaderWriter, err error) (out, abort error)

// challengerKey is the context key a chain publishes its Challenger under.
type challengerKey struct{}

// WithChallenger returns ctx carrying c, the challenge the chain answers its
// own refusals with, so a guard behind the chain answers its refusals alike.
func WithChallenger(ctx context.Context, c Challenger) context.Context {
	return context.WithValue(ctx, challengerKey{}, c)
}

// Challenge sets on w the challenge the chain the request passed through
// would answer err with, and returns the error the request fails with and the
// abort that stopped the challenger's walk of err. With no chain challenge
// published on ctx it sets nothing and returns err and no abort.
func Challenge(ctx context.Context, w HeaderWriter, err error) (out, abort error) {
	c, ok := ctx.Value(challengerKey{}).(Challenger)
	if !ok || c == nil {
		return err, nil
	}

	return c(ctx, w, err)
}

// LookupKey is the context key a running chain answers with its status
// lookup, a Lookup. The chain's run context answers it from its own Value
// method, so publishing it costs a request nothing.
type LookupKey struct{}

// Lookup returns the abort that stopped the chain's status lookup of err, the
// classification a guard's default answer and the adapters' error handlers
// make, and nil when none did. It writes no record.
type Lookup func(err error) (abort error)

// LookupAborts reports whether the status lookup of the chain the request
// passed through aborts on err.
//
// A guard asks it to decide whether to report an abort its own walk met: when
// the lookup that answers the refusal aborts too, the lookup reports, and the
// guard stays quiet. With no chain lookup on ctx it reports false, so the
// guard reports what it met: over-reporting, never silence. A guard's own
// walks run only behind a chain, which always answers it.
func LookupAborts(ctx context.Context, err error) bool {
	lookup, ok := ctx.Value(LookupKey{}).(Lookup)
	if !ok || lookup == nil {
		return false
	}

	return lookup(err) != nil
}

// MsgClassificationAborted is the record a guard writes for an aborted
// classification it reports itself. It is the text the chain's own lookup
// writes, so one search finds every such record.
const MsgClassificationAborted = porterr.MsgClassificationAborted

// ReportAbort writes one Error record of abort, an abort a guard's walk met,
// through porterr.ReportAbort: the constant MsgClassificationAborted, the
// abort's reason and, for a recovered panic, the panic's Go type and the
// frames captured where it panicked; never the error's text or the panic's
// value. A guard holds no logger of its own, so the record goes to the logger
// of the chain handling the request, read from ctx, else slog.Default() when
// it is written.
func ReportAbort(ctx context.Context, abort error) {
	porterr.ReportAbort(ctx, nil, abort)
}
