package httpsec

import (
	"net/http"

	"github.com/kartaladev/scrty/recovery"
)

//go:generate mockgen -destination=recordstore_mock_test.go -package=httpsec_test -typed -mock_names=RecordStore=MockRecordStore github.com/kartaladev/scrty/recovery RecordStore

// finish answers a POST to the finish path of a held recovery.
//
// The body is read exactly as the complete endpoint reads its own: a
// URL-encoded form of at most 16 KiB, never the query, with the completion
// token given once. A request that cannot be read so, or carries no token, is
// recovery.ErrMalformed. Then the core finishes the recovery, and its error is
// returned unchanged: recovery.ErrNotYetCompletable before the hold is over,
// recovery.ErrRefused for a token that is unknown, spent, of another purpose
// or past its window, or whose recovery was cancelled.
//
// A finish that succeeds is answered exactly as a completion is: the access
// token for the recovery-pending session, through the recovery responder,
// with Cache-Control: no-store.
//
// No source guard stands in front of it. The completion token is a 256-bit
// one-time secret handed only to the client that presented both proofs, so
// there is nothing a source could guess, and the endpoint checks no proof a
// throttle would protect. A per-source allowance would add only a way for
// someone behind the same address to spend it and lock the user out of their
// own finish.
func (i *recoveryInterceptor) finish(ex *Exchange) error {
	token, err := readHoldToken(ex.Request, RecoveryCompletionTokenParam)
	if err != nil {
		return err
	}

	if token == "" {
		return recovery.ErrMalformed
	}

	res, err := i.recoverer.Finish(ex.Context(), token)
	if err != nil {
		return err
	}

	return i.answer(ex, res)
}

// cancel answers a POST to the cancel path of a held recovery.
//
// It answers 204 with an empty body whatever happened: a recovery cancelled,
// a token that is garbage, spent, of another purpose (a completion token
// included) or missing, a body that cannot be read, and a store that failed.
// The core logs each cause server-side and returns nothing, so nothing here
// could tell them apart even by accident, and the endpoint reveals nothing
// about which tokens or recoveries exist. For the same reason it has no source
// guard: a refusal would be an answer of its own.
func (i *recoveryInterceptor) cancel(ex *Exchange) error {
	if token, err := readHoldToken(ex.Request, RecoveryCancelTokenParam); err == nil && token != "" {
		i.recoverer.Cancel(ex.Context(), token)
	}

	ex.Writer.WriteHeader(http.StatusNoContent)

	return nil
}

// readHoldToken reads the single field name out of a finish or cancel body, by
// the same rules the complete endpoint reads its own: a URL-encoded form under
// recoveryBodyLimit, never the query. A body over the bound is
// ErrRequestTooLarge; one that is not such a form, does not parse, or carries
// the field more than once is recovery.ErrMalformed. An empty body, or one
// without the field, reads as an empty token.
func readHoldToken(r Request, name string) (string, error) {
	values, err := readRecoveryForm(r)
	if err != nil {
		return "", err
	}

	if len(values[name]) > 1 {
		return "", recovery.ErrMalformed
	}

	return values.Get(name), nil
}
