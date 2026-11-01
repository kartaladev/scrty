package httpsec_test

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// signerDown is a consumer key source that cannot hand out a signing key: it
// fails Signer with err, as a key service that is unreachable does.
type signerDown struct {
	signingkey.KeySource

	err error
}

func (s signerDown) Signer(context.Context, signingkey.Alg) (string, crypto.Signer, error) {
	return "", nil, s.err
}

// TestFormLogin_KeySourceFailureWritesNoKeySourceText pins that a login whose
// token cannot be issued because the key source behind the real generator
// fails, writes no log record carrying the key source's text, and is answered
// as a dependency failure with the key source's error still reachable. The
// generator is real, because the text the key source's error reaches the chain
// with is the generator's to wrap.
func TestFormLogin_KeySourceFailureWritesNoKeySourceText(t *testing.T) {
	t.Parallel()

	errKMS := errors.New("kms: arn:aws:kms:eu-west-1:111122223333:key/abcd is unavailable")

	keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	require.NoError(t, err)

	gen, err := token.NewGenerator(signerDown{KeySource: keys, err: errKMS},
		token.WithIssuer("https://issuer.example"), token.WithAudience("orders-api"))
	require.NoError(t, err)

	h := newAuthHarness(t)

	sessions, err := session.New(session.WithStore(must.Must(session.NewMemoryStore())))
	require.NoError(t, err)

	h.sessions = sessions

	deps := h.formLoginDeps()
	deps.Tokens = gen

	h.expectAuthenticated(testPrincipal())
	h.attempts.EXPECT().Reset(t.Context(), "ada").Return(nil).AnyTimes()

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableFormLogin(deps),
	)
	require.NoError(t, err)

	out := serve(t, chain, formRequest(t.Context(), "/login", "username=ada&password=s3cret"))

	require.ErrorIs(t, out.err, errKMS, "the key source's error stays reachable")
	assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
	assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
	assert.NotContains(t, out.err.Error(), "kms", "the answer's text is the library's")
	assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
	assert.False(t, out.handlerRan)

	for i, rec := range h.logs.records() {
		assert.NotContains(t, recordText(rec), "kms", "record %d carries the key source's text", i)
		assert.NotContains(t, recordText(rec), "abcd", "record %d carries the key source's text", i)
	}
}
