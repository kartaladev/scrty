package httpsec

import (
	"encoding/json"
	"net/http"
	"net/url"
)

//go:generate mockgen -destination=onetimestore_mock_test.go -package=httpsec_test -typed -mock_names=Store=MockOnetimeStore github.com/kartaladev/scrty/onetime Store

// start answers a POST to the start path.
//
// It answers identically whatever happened, and never passes the request on:
// 202 with an empty body and no cookie, for a code sent, an unknown or
// disabled username, a lookup that failed, a reached issuance limit, a token
// store or sender that failed, a body that could not be read, and a source
// that is throttled or cannot be attributed. The core logs each cause
// server-side; nothing here tells them apart.
//
// Every start is counted against its source, whatever it did, because what
// the guard bounds is how often one source asks for mail to be sent. A source
// over its allowance, or one that cannot be attributed, starts nothing.
func (i *recoveryInterceptor) start(ex *Exchange) error {
	ctx := ex.Context()

	src, err := sourceThrottled(ctx, i.startGuard, ex.Request.ClientIP(), recoveryStartFlow,
		i.sampler, i.log, i.now())
	if err == nil {
		recordSourceFailure(ctx, i.startGuard, src)

		// An empty username names no account, so there is nothing to start:
		// a body that could not be read is not a question about one.
		if username := readRecoveryStart(ex.Request); username != "" {
			i.recoverer.Start(ctx, username)
		}
	}

	ex.Writer.WriteHeader(http.StatusAccepted)

	return nil
}

// readRecoveryStart reads the submitted username from a URL-encoded form or a
// JSON body, and only from the body.
//
// Every failure degrades to an empty username rather than an error: a
// different answer for a malformed request is still a different answer, and a
// scanner would use it. That includes a body over the bound and a username
// given more than once.
func readRecoveryStart(r Request) string {
	body, err := r.Body(recoveryBodyLimit)
	if err != nil || len(body) == 0 {
		return ""
	}

	declared := r.Header("Content-Type")

	if declaresForm(declared) {
		values, err := url.ParseQuery(string(body))
		if err != nil || len(values[RecoveryUsernameParam]) != 1 {
			return ""
		}

		return values.Get(RecoveryUsernameParam)
	}

	if !declaresJSON(declared) {
		return ""
	}

	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		return ""
	}

	username, _ := fields[RecoveryUsernameParam].(string)

	return username
}
