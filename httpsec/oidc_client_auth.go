package httpsec

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/ratelimit"
)

// How many failed authentications one source may make at an endpoint a client
// authenticates at, before its requests are refused unchecked. They are proposed
// values: a client's credentials are not guessed by accident, and a limit shared by
// clients behind one address must leave room for a misconfigured one.
const (
	defaultOIDCClientFailureLimit  = 10
	defaultOIDCClientFailureWindow = 15 * time.Minute
)

// oidcAuthorizationHeader is the header a client presents client_secret_basic in.
const oidcAuthorizationHeader = "Authorization"

// oidcQueryCredentials is what a client's credential in the query is named, which is
// all an endpoint hands the provider of the query, so that it can refuse them. Nothing
// is ever read from there to authenticate with.
var oidcQueryCredentials = []string{"client_secret", "client_assertion", "client_assertion_type"}

// queryNamesCredential reports whether the raw query names a client credential.
func queryNamesCredential(raw string) bool {
	return queryNamesAny(raw, oidcQueryCredentials)
}

// queryNamesAny reports whether the raw query names any of names, however the pairs
// parse. It splits on "&" and ";" both, so a pair one framework reads and another drops is
// judged alike, takes each piece's name before "=", and compares it decoded when it
// decodes and as sent when it does not. A name with no "=" counts, and so does one with an
// empty value, while a value that merely holds a name does not.
func queryNamesAny(raw string, names []string) bool {
	for piece := range strings.FieldsFuncSeq(raw, func(r rune) bool { return r == '&' || r == ';' }) {
		name, _, _ := strings.Cut(piece, "=")

		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}

		if slices.Contains(names, name) {
			return true
		}
	}

	return false
}

// oidcClientThrottle counts an endpoint's failed client authentications by source. It
// is a group's own, with a limiter the consumer may replace.
type oidcClientThrottle struct {
	flow string

	// limiter is the consumer's, and nil when the chain's factory builds it.
	limiter ratelimit.Limiter

	guard   sourceGuard
	sampler *logsample.Sampler
}

// settle builds the guard under flow, from a group's settle.
func (t *oidcClientThrottle) settle(c *config, flow string) error {
	guard, err := c.resolveSourceGuard(optionOIDCProvider, flow, t.limiter,
		defaultOIDCClientFailureLimit, defaultOIDCClientFailureWindow, c.refusalInterval)
	if err != nil {
		return err
	}

	t.flow = flow
	t.guard = guard

	return nil
}

// wire takes the chain's sampler, from a group's wire.
func (t *oidcClientThrottle) wire(ch *Chain) {
	t.sampler = ch.sampler
}

// flush reports what the guard is holding back, from a group's flushRefusalLogs.
func (t *oidcClientThrottle) flush() {
	if t.guard != nil {
		t.guard.Flush()
	}
}

// admit asks whether the request's source may be heard at all, before its credentials
// are read, so that a throttled source costs one bucket read and no secret comparison.
// False means the request is refused, and the caller chooses how it reads. At the token
// endpoints it is invalid_client, which is what a throttled source, a source that cannot
// be attributed and a limiter that cannot answer all read as to a client: nothing tells
// them from a wrong credential. At the authorization and resume endpoints it is
// ErrOIDCThrottled, which answers 429, because a browser is in front of those.
func (t *oidcClientThrottle) admit(ex *Exchange, op *oidcEndpoints) (ratelimit.Source, bool) {
	src, err := sourceThrottled(ex.Context(), t.guard, ex.Request.ClientIP(), t.flow, t.sampler, op.log, op.now())

	return src, err == nil
}

// charge counts one failed attempt against src, whether or not the caller is still
// there to hear about it.
func (t *oidcClientThrottle) charge(ctx context.Context, src ratelimit.Source) {
	recordSourceFailure(ctx, t.guard, src)
}

// answer ends a request the provider or the request's reading refused. A refusal the
// protocol names is written in its form, and invalid_client is charged to src. Any
// other error is no verdict on the client, is charged to no one, and goes to the
// chain's error handling.
func (t *oidcClientThrottle) answer(ex *Exchange, src ratelimit.Source, err error) error {
	var refusal *oidcprovider.Error
	if !errors.As(err, &refusal) {
		return err
	}

	if refusal.Code == oidcprovider.CodeInvalidClient {
		t.charge(ex.Context(), src)
	}

	return writeOIDCRefusal(ex, refusal.Code)
}

// readOIDCClientRequest reads a form POST to an endpoint a client authenticates at, into
// the credentials the provider judges. The form is the body's alone, never the query's,
// and the query carries over only what oidcQueryCredentials names.
//
// It answers an *oidcprovider.Error holding invalid_request when the body is not a form
// that parses, when the Authorization header is repeated, or when the raw query names a
// credential, which it finds whether or not the framework parsed the pair, and
// ErrRequestTooLarge for a body over limit, which is read before anything is parsed.
func readOIDCClientRequest(r Request, limit int64) (oidcprovider.ClientCredentials, error) {
	refused := func() (oidcprovider.ClientCredentials, error) {
		return oidcprovider.ClientCredentials{}, &oidcprovider.Error{Code: oidcprovider.CodeInvalidRequest}
	}

	if len(r.HeaderValues(oidcAuthorizationHeader)) > 1 || queryNamesCredential(r.RawQuery()) {
		return refused()
	}

	body, err := r.Body(limit)

	switch {
	case errors.Is(err, ErrRequestTooLarge):
		return oidcprovider.ClientCredentials{}, ErrRequestTooLarge
	case err != nil, !declaresForm(r.Header("Content-Type")):
		return refused()
	}

	form, err := url.ParseQuery(string(body))
	if err != nil {
		return refused()
	}

	query := url.Values{}

	for _, name := range oidcQueryCredentials {
		if values := r.QueryValues(name); len(values) > 0 {
			query[name] = values
		}
	}

	return oidcprovider.ClientCredentials{
		Authorization: r.Header(oidcAuthorizationHeader),
		Form:          form,
		Query:         query,
	}, nil
}

// setOIDCNoStore marks the response as one no cache may keep. An endpoint sets it first,
// so it holds for every answer, the chain's error handling included.
func setOIDCNoStore(w ResponseWriter) {
	w.SetHeader("Cache-Control", "no-store")
	w.SetHeader("Pragma", "no-cache")
}

// oidcRefusalDocument is a refusal's whole body: the code, and no description a client
// could learn which check failed from.
type oidcRefusalDocument struct {
	Error string `json:"error"`
}

// writeOIDCRefusal answers code as RFC 6749 section 5.2 says: 400, or 401 with a
// challenge for invalid_client, which is the one a client can answer with credentials.
func writeOIDCRefusal(ex *Exchange, code string) error {
	encoded, err := json.Marshal(oidcRefusalDocument{Error: code})
	if err != nil {
		return err
	}

	status := http.StatusBadRequest
	if code == oidcprovider.CodeInvalidClient {
		status = http.StatusUnauthorized
		ex.Writer.SetHeader(headerWWWAuthenticate, `Basic realm="oauth2"`)
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.WriteHeader(status)
	_, err = ex.Writer.Write(encoded)

	return err
}
