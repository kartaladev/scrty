package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/kartaladev/scrty/oidc"
)

//go:generate mockgen -destination=linkstore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/oidc LinkStore
//go:generate mockgen -destination=identitybroker_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/oidc IdentityBroker

// logoutTokenParam is the form field a provider posts a back-channel logout
// token under, as OpenID Connect Back-Channel Logout names it.
const logoutTokenParam = "logout_token"

// The reasons a back-channel logout is logged under, each the tail of its
// sampler key.
const (
	backchannelBySessionID        = "session_id"
	backchannelBySubject          = "subject"
	backchannelAllSessions        = "all_sessions"
	backchannelSubjectUnresolved  = "subject_unresolved"
	backchannelInvalidToken       = "invalid_token"
	msgBackchannelLogout          = "httpsec: oidc back-channel logout"
	msgBackchannelRefused         = "httpsec: oidc back-channel logout token refused"
	msgBackchannelSubjectNoLookup = "httpsec: oidc back-channel logout named a subject " +
		"the broker has no link store to resolve; nothing was ended " +
		"(a consumer broker exposing Links() oidc.LinkStore resolves it)"
)

// errNilLink is what a link store that answers neither a link nor an error
// is reported as: a store fault, not an unlinked subject.
var errNilLink = errors.New("httpsec: the link store returned no link and no error")

// backchannel answers a provider's back-channel logout delivery: it verifies
// the logout token and ends the sessions it names.
//
// It needs no credential: the signed token is the credential. The token is
// read from a form body only, under the login body bound. A request that
// carries none, or one that fails verification, is one uniform refusal with
// Cache-Control: no-store; a verified token is always answered 200 with an
// empty body and no-store, however many sessions it ended, so the answer tells
// a caller nothing about the user. A store, link store or key-set failure is
// returned as itself, so it maps to a server error the provider will retry.
//
// A refused token leaves one sampled WARN record, keyed by the back-channel
// flow and reason invalid_token, naming the provider and the cause: the rule
// that failed, never the token or a claim value. It is how an operator hears
// of a provider whose clock has drifted past the leeway.
//
// A request cancelled before its token is verified ends nothing and returns
// the context error. Once the token has verified, the sessions it names are
// ended even if the caller has gone: the store and link-store calls run on a
// context detached from the request's cancellation. Ending a session the
// provider asked to end is the safe outcome, and the deletes are idempotent,
// so a provider that retries because it never heard the answer ends nothing
// twice.
func (i *oidcInterceptor) backchannel(ex *Exchange, provider string) error {
	ctx := ex.Context()

	// Checked before the body, so a delivery to a provider nobody registered
	// is reported as that whatever it carries.
	if !slices.Contains(i.manager.Providers(), provider) {
		return oidc.ErrUnknownProvider
	}

	// Neither a refusal nor the answer to a verified token may be cached.
	ex.Writer.SetHeader("Cache-Control", "no-store")

	token := i.readLogoutToken(ex.Request)
	if token == "" {
		i.logBackchannel(ctx, slog.LevelWarn, backchannelInvalidToken, provider,
			slog.String("cause", "no logout token in a form body"))

		return oidc.ErrInvalidLogoutToken
	}

	// A caller that has already gone has had nothing verified, so nothing is
	// ended for it; the error is a failure the provider retries.
	if err := ctx.Err(); err != nil {
		return err
	}

	claims, err := i.manager.VerifyLogoutToken(ctx, provider, token)
	if errors.Is(err, oidc.ErrInvalidLogoutToken) {
		// The cause names the rule that failed and never a claim value, so it
		// is logged; the response names no check.
		i.logBackchannel(ctx, slog.LevelWarn, backchannelInvalidToken, provider,
			slog.String("cause", err.Error()))

		return err
	}
	if err != nil {
		// A provider or context failure, returned as itself.
		return err
	}

	// The token has verified, so the sessions it names are ended whether or
	// not the caller is still there to hear it.
	if err := i.endBackchannelSessions(context.WithoutCancel(ctx), provider, claims); err != nil {
		return err
	}

	ex.Writer.WriteHeader(http.StatusOK)

	return nil
}

// endBackchannelSessions ends the sessions a verified token names.
//
// A session id is preferred whenever the token carries one, with or without a
// subject: it names exactly the provider session that ended. Only a token
// without one is resolved through the subject's link.
//
// ctx is the context the store and link-store calls run on, which the caller
// has detached from the request's cancellation.
func (i *oidcInterceptor) endBackchannelSessions(
	ctx context.Context, provider string, claims oidc.LogoutClaims,
) error {
	if claims.SessionID != "" {
		n, err := i.sessions.DeleteByExternalSession(ctx, claims.Issuer, claims.SessionID)
		if err != nil {
			return err
		}

		i.logBackchannel(ctx, slog.LevelInfo, backchannelBySessionID, provider, slog.Int("ended", n))

		return nil
	}

	links := i.manager.Links()
	if links == nil {
		// A consumer broker offers no way to resolve the subject. Nothing is
		// ended, which the provider cannot act on either, so the answer is
		// still a success and the gap is the operator's to hear about.
		i.logBackchannel(ctx, slog.LevelWarn, backchannelSubjectUnresolved, provider)

		return nil
	}

	link, err := links.FindByExternal(ctx, provider, claims.Issuer, claims.Subject)
	switch {
	case errors.Is(err, oidc.ErrLinkNotFound):
		// No user was ever linked to this subject, so none of its sessions
		// exist here. That is what the provider asked for.
		return nil
	case err != nil:
		return err
	case link == nil:
		return errNilLink
	}

	if i.scope == AllSessions {
		if err := i.sessions.DeleteByUser(ctx, link.UserID); err != nil {
			return err
		}

		i.logBackchannel(ctx, slog.LevelInfo, backchannelAllSessions, provider)

		return nil
	}

	n, err := i.sessions.DeleteByUserAndExternalIssuer(ctx, link.UserID, claims.Issuer)
	if err != nil {
		return err
	}

	i.logBackchannel(ctx, slog.LevelInfo, backchannelBySubject, provider, slog.Int("ended", n))

	return nil
}

// logBackchannel writes one sampled record under the back-channel flow and
// reason. It names the provider, a registered name, and never the token, the
// subject or the user.
func (i *oidcInterceptor) logBackchannel(
	ctx context.Context, level slog.Level, reason, provider string, attrs ...slog.Attr,
) {
	msg := msgBackchannelLogout
	switch reason {
	case backchannelSubjectUnresolved:
		msg = msgBackchannelSubjectNoLookup
	case backchannelInvalidToken:
		msg = msgBackchannelRefused
	}

	attrs = append([]slog.Attr{
		slog.String("flow", oidcBackchannelFlow),
		slog.String("reason", reason),
		slog.String("provider", provider),
	}, attrs...)

	logSampled(ctx, i.sampler, i.log, level, i.now(),
		oidcBackchannelFlow+sampleKeySeparator+reason, msg, attrs...)
}

// readLogoutToken reads the logout token out of a form body, and only out of
// it, under the interceptor's body bound. A body over the bound is refused
// without reading past it, and a body that is not a form reads as no token.
func (i *oidcInterceptor) readLogoutToken(r Request) string {
	if !declaresForm(r.Header("Content-Type")) {
		return ""
	}

	body, err := r.Body(i.bodyLimit)
	if err != nil {
		return ""
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return ""
	}

	return values.Get(logoutTokenParam)
}
