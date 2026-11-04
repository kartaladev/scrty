package oidcprovider

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

//go:generate mockgen -destination=grantstore_mock_test.go -package=oidcprovider_test -typed github.com/kartaladev/scrty/oidcprovider GrantStore
//go:generate mockgen -destination=lineagestore_mock_test.go -package=oidcprovider_test -typed -mock_names=Store=MockLineageSessionStore github.com/kartaladev/scrty/session Store

// The parameters a token request alone has, and the prefix of a refresh token (T6).
const (
	paramGrantType    = "grant_type"
	paramCodeVerifier = "code_verifier"

	refreshTokenPrefix = "rt."
)

// replayRevocationBudget bounds the writes a replay's revocation makes once it has stopped
// listening to its caller. It is a proposed value.
const replayRevocationBudget = 10 * time.Second

// Binding is the key a token request proved it holds, which httpsec fills in after
// verifying the DPoP proof or the certificate. The provider verifies neither.
type Binding struct {
	// JKT is the RFC 7638 thumbprint of the DPoP proof's key, or empty.
	JKT string
	// X5T is the SHA-256 thumbprint of the client certificate, or empty.
	X5T string
}

// TokenRequest is what the token endpoint hands the provider. It holds a code and a
// client's secrets, so it prints and logs redacted; read its fields to use it.
type TokenRequest struct {
	// Credentials authenticates the client. Left unset, its Form and Query are the
	// request's own below, which is what a caller almost always means.
	Credentials ClientCredentials
	// Form is the parsed request body. A parameter with no value counts as omitted, and
	// a repeated one is refused, apart from resource, which RFC 8707 lets repeat.
	Form url.Values
	// Query is the parsed query string. A credential in it is invalid_request.
	Query url.Values
	// Binding is the key the request proved it holds.
	Binding Binding
}

// Format writes the redacted form under every verb.
func (TokenRequest) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (TokenRequest) LogValue() slog.Value { return slog.StringValue(redacted) }

// TokenResponse is a successful token response. It holds tokens, so it prints and logs
// redacted; read its fields to use it.
type TokenResponse struct {
	// AccessToken is a JWT typed at+jwt, or at.<id>.<secret> for a client registered for
	// opaque tokens.
	AccessToken string
	// TokenType is how it is presented: DPoP when bound to a proof's key, and otherwise Bearer.
	TokenType string
	// ExpiresIn is the access token's lifetime in seconds, which is what its exp says. It is
	// not cut short at its grant's end, so a token may outlive its grant at a resource server
	// that verifies it offline; one that reads the provider's store through VerifyAccessToken
	// sees the grant end at once.
	ExpiresIn int
	// Scope is what the tokens were granted, space-separated.
	Scope string
	// IDToken is present when the grant's scopes hold openid.
	IDToken string
	// RefreshToken is rt.<family>.<secret>, present when the client is registered for
	// the refresh grant.
	RefreshToken string
}

// Format writes the redacted form under every verb.
func (TokenResponse) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (TokenResponse) LogValue() slog.Value { return slog.StringValue(redacted) }

// Token answers a token request. It authenticates the client before reading the grant, so
// a request that fails to changes nothing: a code stays unspent.
//
// A refusal is an *Error holding its code alone, so an exchange refused for any reason is
// the same invalid_grant, saying nothing of which check failed. A failing store matches
// ErrDependency behind fixed text, and a caller who left matches its own context's error.
// None of these carries a code, a secret or a token.
//
// An authorization_code request runs in the order the guarantees rest on, and where a request
// earns two refusals, the earlier step's is the one answered:
//
//  1. check the code, which writes nothing;
//  2. another client's code is spent, then refused, because a code it holds has leaked;
//  3. a wrong redirect URI, verifier or dpop_jkt is refused with the code unspent, since
//     the client may still hold what it should have sent;
//  4. a resource outside the client's allowlist or the code's grant is invalid_target, and
//     so is none named when the code's grant holds several, because no one of them is the
//     client's choice to make; more values than are read is invalid_request. The code is left
//     unspent. A grant holding one resource makes it the audience when none is named;
//  5. a revocation already recorded for the code's grant, a sign-in that has ended by its
//     deadline, and a missing or disabled user are refused, with the code unspent;
//  6. mint the tokens, for the grant family the code already names. Signing writes nothing,
//     so a key failure answers a dependency failure and the client may try again;
//  7. spend the code, of which exactly one of any number of racing requests succeeds, and the
//     losers discard what they signed;
//  8. write the grant row, which keeps any revocation that landed after step 5;
//  9. write the lineage, when the client may refresh;
//  10. store an opaque access token, whose grant is what it is judged by when it is read.
//
// There is no transaction across 8, 9 and 10. A lineage can never exist without its row, which
// is the state that would fail open, and every refresh reads the row first. A failure after
// the spend answers an error and burns the code, leaving records no one holds a token for: a
// row with no lineage is for the orphan sweep.
//
// A code presented after it was spent is refused too, and a valid replay revokes what it
// issued; see refuseSpentCode. The request that won step 7 never looks again, so of several
// racing requests exactly one is answered with tokens, even though the others' replay leaves
// those tokens' grant revoked. Which is why a resource is no part of what makes a replay valid:
// it is what a request asks for, and not what the code was issued for.
func (p *Provider) Token(ctx context.Context, r TokenRequest) (*TokenResponse, error) {
	if repeatedParam(r.Form) {
		return nil, refuseRequest()
	}

	creds := r.Credentials
	if creds.Form == nil {
		creds.Form = r.Form
	}
	if creds.Query == nil {
		creds.Query = r.Query
	}
	rc, err := p.AuthenticateClient(ctx, creds)
	if err != nil {
		return nil, err
	}

	grantType := GrantType(r.Form.Get(paramGrantType))
	switch grantType {
	case "":
		return nil, refuseRequest()
	case GrantAuthorizationCode, GrantRefreshToken:
	default:
		return nil, &Error{Code: CodeUnsupportedGrantType}
	}
	if !slices.Contains(rc.GrantTypes, grantType) {
		return nil, &Error{Code: CodeUnauthorizedClient}
	}
	if grantType != GrantAuthorizationCode {
		// A refresh is not answered yet.
		return nil, &Error{Code: CodeUnsupportedGrantType}
	}

	return p.exchangeCode(ctx, r, rc)
}

// repeatedParam reports a parameter given twice, which R11 refuses, apart from resource.
func repeatedParam(form url.Values) bool {
	for name, values := range form {
		if len(values) > 1 && name != paramResource {
			return true
		}
	}

	return false
}

func refuseGrant() error { return &Error{Code: CodeInvalidGrant} }

// exchangeCode runs the order Token describes.
func (p *Provider) exchangeCode(ctx context.Context, r TokenRequest, rc *RegisteredClient) (*TokenResponse, error) {
	code := r.Form.Get(paramCode)
	if code == "" {
		return nil, refuseRequest()
	}
	tokens, err := p.codeTokens()
	if err != nil {
		return nil, dependencyFailure(ctx, err, "oidcprovider: build the code tokens")
	}
	now := p.cfg.clock.Now()

	checked, err := tokens.Check(ctx, code, "")
	if err != nil {
		return nil, p.refuseSpentCode(ctx, r, rc, code)
	}
	record, err := p.loadCodeRecord(ctx, checked.Token().ID)
	if err != nil {
		return nil, err
	}
	if !now.Before(record.ExpiresAt) {
		return nil, refuseGrant()
	}

	if record.ClientID != rc.ID {
		if err := tokens.Consume(ctx, checked); err != nil {
			return nil, p.refuseSpentCode(ctx, r, rc, code)
		}

		return nil, refuseGrant()
	}

	if !codeBindingsHold(r, record, rc) {
		return nil, refuseGrant()
	}
	audience, err := resolveAudience(r.Form, record.Resources, rc, p.issuer, record.Scopes)
	if err != nil {
		return nil, err
	}
	expiresAt, holdsLineage, ok := grantLife(record, rc, now)
	if !ok {
		return nil, refuseGrant()
	}
	if err := p.judgeCodeNow(ctx, record); err != nil {
		return nil, err
	}

	grant := newGrant(record, rc, r.Binding, holdsLineage, now, expiresAt)
	access, err := p.mintAccessToken(ctx, grant, rc, r.Binding, audience, now)
	if err != nil {
		return nil, err
	}
	res := &TokenResponse{
		AccessToken: access.value,
		TokenType:   access.tokenType,
		ExpiresIn:   access.expiresIn,
		Scope:       strings.Join(grant.Scopes, " "),
	}
	if slices.Contains(grant.Scopes, scopeOpenID) {
		if res.IDToken, err = p.mintIDToken(ctx, grant, record.Nonce, rc); err != nil {
			return nil, err
		}
	}

	if err := tokens.Consume(ctx, checked); err != nil {
		return nil, p.refuseSpentCode(ctx, r, rc, code)
	}

	if err := p.stores.grants.Create(ctx, grant); err != nil {
		return nil, dependencyFailure(ctx, err, "oidcprovider: store the grant")
	}
	if holdsLineage {
		if res.RefreshToken, err = p.writeLineage(ctx, grant, rc); err != nil {
			return nil, err
		}
	}
	if access.record != nil {
		if err := p.stores.accessTokens.Create(ctx, access.record); err != nil {
			return nil, dependencyFailure(ctx, err, "oidcprovider: store the access token")
		}
	}

	return res, nil
}

// loadCodeRecord reads a code's request data. A token with no record is one whose issue
// failed part-way, whose secret no one was given.
func (p *Provider) loadCodeRecord(ctx context.Context, tokenID id.ID) (*CodeRecord, error) {
	record, err := p.stores.codes.Load(ctx, tokenID)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, refuseGrant()
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: load the code record")
	}

	return record, nil
}

// codeBindingsHold compares the request with what the code was issued for. The redirect URI
// is compared exactly, and always required, because an authorization request cannot leave
// it out. The verifier is judged by the code's challenge: see verifierHolds. A dpop_jkt must
// be the key the request proved it holds.
func codeBindingsHold(r TokenRequest, record *CodeRecord, rc *RegisteredClient) bool {
	return r.Form.Get(paramRedirectURI) == record.RedirectURI &&
		verifierHolds(r.Form.Get(paramCodeVerifier), record, rc) &&
		(record.DPoPJKT == "" || r.Binding.JKT == record.DPoPJKT)
}

// verifierHolds decides PKCE, which cannot be downgraded here (RFC 9700 §4.8.2): a code with
// a challenge needs its verifier, in RFC 7636's syntax, and a code without one refuses any
// verifier. A code without one exists only for a PKCEOrNonce client's nonce, so one with no
// nonce, or whose client has since returned to requiring PKCE, holds nothing that protects
// it. Only S256 can have been stored, because a request naming plain is never parked.
func verifierHolds(verifier string, record *CodeRecord, rc *RegisteredClient) bool {
	if record.Challenge == "" {
		return verifier == "" && record.Nonce != "" && rc.PKCE == PKCEOrNonce
	}
	if !validChallenge(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])

	return subtle.ConstantTimeCompare([]byte(computed), []byte(record.Challenge)) == 1
}

// grantLife decides how long the grant lives, and whether it holds a lineage, which it does
// when the client may refresh. It says false for a grant that would be over before it began.
//
// A grant holding no lineage expires exactly at the sign-in's deadline, so an ID-token-only
// client still gets its logout token (R10). A grant ending with its sign-in, which is any
// without offline_access and any of a client tied to its sign-in, expires by that deadline.
// One holding offline_access outlives it.
func grantLife(record *CodeRecord, rc *RegisteredClient, now time.Time) (time.Time, bool, bool) {
	deadline := record.SignIn.AbsoluteExpiresAt
	holdsLineage := slices.Contains(rc.GrantTypes, GrantRefreshToken)
	endsWithSignIn := !record.Offline || record.EndsWithSignIn || !holdsLineage
	if endsWithSignIn && !now.Before(deadline) {
		return time.Time{}, false, false
	}
	if !holdsLineage {
		return deadline, false, true
	}

	expiresAt := now.Add(rc.GrantAbsoluteLifetime)
	if endsWithSignIn && deadline.Before(expiresAt) {
		expiresAt = deadline
	}

	return expiresAt, true, true
}

// judgeCodeNow asks what may have changed since the code was issued. A revocation recorded
// for its grant's family, by an end of the sign-in, a revocation of the user's grants or
// a replay, refuses it, and so does a user no longer active. Both are read before the code
// is spent, because no request that spends it may afterwards be refused for anything but a
// failure: it is the one request allowed tokens.
func (p *Provider) judgeCodeNow(ctx context.Context, record *CodeRecord) error {
	recorded, err := p.stores.grants.Load(ctx, record.GrantFamily)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: read the code's grant")
	case recorded.Revoked:
		return refuseGrant()
	}

	details, err := p.users.LoadByUserID(ctx, record.SignIn.User)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		return refuseGrant()
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: load the code's user")
	case details == nil || details.ID != record.SignIn.User || !details.Active:
		return refuseGrant()
	}

	return nil
}

// newGrant builds the row a code's exchange writes. Its authentication facts are the
// sign-in's, copied from the code and never taken from the current time, because auth_time
// overstated by an exchange would mislead a relying party checking max_age. A public client's
// grant is bound to the key of the proof its first request carried, and a confidential
// client's is bound by its client authentication instead.
func newGrant(
	record *CodeRecord, rc *RegisteredClient, binding Binding, holdsLineage bool, now, expiresAt time.Time,
) *Grant {
	s := record.SignIn
	grant := &Grant{
		Family:            record.GrantFamily,
		User:              s.User,
		ClientID:          record.ClientID,
		Scopes:            slices.Clone(record.Scopes),
		Resources:         slices.Clone(record.Resources),
		AuthTime:          s.AuthenticatedAt,
		AMR:               slices.Clone(s.AMR),
		ACR:               s.ACR,
		CodeID:            record.TokenID,
		SignInFamily:      s.Family,
		ExternalIssuer:    s.ExternalIssuer,
		ExternalSessionID: s.ExternalSessionID,
		Offline:           record.Offline,
		EndsWithSignIn:    record.EndsWithSignIn,
		HoldsLineage:      holdsLineage,
		CreatedAt:         now,
		ExpiresAt:         expiresAt,
	}
	if rc.Type == Public {
		grant.KeyBinding = binding.JKT
	}

	return grant
}

// lineages builds the manager over the provider's lineage store, with the client's timeouts
// when one is given. It never takes WithUnusedSuccessorRecovery (decision 5). It holds
// nothing but what the arguments settle, so it is built where it is used.
func (p *Provider) lineages(rc *RegisteredClient) (*session.Sessions, error) {
	opts := []session.Option{
		session.WithStore(oplineage.Sessions(p.stores.lineage)),
		session.WithClock(p.cfg.clock),
		session.WithRandom(p.cfg.random),
		session.WithLogger(p.cfg.logger),
		session.WithTouchInterval(0),
	}
	if rc != nil {
		opts = append(opts,
			session.WithIdleTimeout(rc.GrantIdleTimeout),
			session.WithAbsoluteTimeout(rc.GrantAbsoluteLifetime),
		)
	}

	return session.New(opts...)
}

// writeLineage stores the grant's first refresh token, and returns it. The record's family
// is the grant's, so a refresh and a revocation can find one from the other, and its
// authentication time is the sign-in's, as the grant's is. Its deadline is the grant's.
func (p *Provider) writeLineage(ctx context.Context, grant *Grant, rc *RegisteredClient) (string, error) {
	manager, err := p.lineages(rc)
	if err != nil {
		return "", dependencyFailure(ctx, err, "oidcprovider: build the lineage manager")
	}

	s, err := manager.Create(ctx, grant.User, func(s *session.Session) {
		s.FamilyID = grant.Family
		s.AuthenticatedAt = grant.AuthTime
		s.AbsoluteExpiresAt = grant.ExpiresAt
		s.KeyBinding = session.KeyBinding{JKT: grant.KeyBinding}
	})
	if err != nil {
		return "", dependencyFailure(ctx, err, "oidcprovider: store the lineage")
	}

	return refreshTokenPrefix + grant.Family.String() + "." + s.ID, nil
}

// errCodeStoreUnanswered stands for a code-token store's failure, whose own error token/onetime
// keeps to itself and writes to the log. A code the store holds as good, and that a check or a
// spend still turned down, is the only trace of it left here.
var errCodeStoreUnanswered = errors.New("oidcprovider: the code-token store could not answer")

// refuseSpentCode answers a code that failed its check or lost its spend, and returns the
// error the request ends with. token/onetime answers every failure alike, on purpose, so this
// asks its store directly to tell them apart:
//
//   - a code that is no code, or whose secret is not the request's, is refused. A code's
//     identifier is not a credential, so nothing further is believed without the secret,
//     compared in constant time;
//   - an unspent code past its expiry is refused;
//   - an unspent code still good is no refusal: the store could not answer the check or the
//     spend, or the caller left while it did, so this answers that failure rather than tell the
//     client to discard a good code;
//   - a spent code is a replay. A valid one, from the client the code was issued to with
//     everything codeBindingsHold compares, is refused and first revokes what the code issued.
//     An invalid one only is refused, because whoever holds only a leaked code could otherwise
//     end the user's grant.
//
// The spent token's record, including the family the code chose at issue, is what names the
// grant, because it may not be stored yet. A replay is seen for as long as the code stores hold
// the code: see codeKeptPastExpiry.
//
// None of this depends on the caller still listening, from the first read to the last
// write: a replay that hangs up must not spare what it was evidence against.
func (p *Provider) refuseSpentCode(ctx context.Context, r TokenRequest, rc *RegisteredClient, code string) error {
	tokenID, secret, ok := splitCode(code)
	if !ok {
		return refuseGrant()
	}
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), replayRevocationBudget)
	defer cancel()

	tok, err := p.stores.codeTokens.FindByID(detached, tokenID)
	switch {
	case errors.Is(err, onetime.ErrTokenNotFound):
		return refuseGrant()
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: read the code's token")
	case tok == nil || tok.Purpose != codeTokenPurpose:
		return refuseGrant()
	}
	sum := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(sum[:], tok.SecretHash) != 1 {
		return refuseGrant()
	}

	// Read after the check or the spend read theirs, so what they found expired is still.
	now := p.cfg.clock.Now()
	if tok.ConsumedAt.IsZero() {
		if !now.Before(tok.ExpiresAt) {
			return refuseGrant()
		}

		return dependencyFailure(ctx, unansweredCause(ctx), "oidcprovider: check or spend the code")
	}

	// Read on the detached context so a caller who left still revokes, but judged on the
	// caller's: only the caller's own ending is a hang-up, and the budget running out is not.
	record, err := p.stores.codes.Load(detached, tokenID)
	switch {
	case errors.Is(err, ErrNotFound):
		return refuseGrant()
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: load the code record")
	}
	if record.ClientID != rc.ID || !codeBindingsHold(r, record, rc) {
		return refuseGrant()
	}
	if err := p.revokeReplayed(detached, record.GrantFamily, now); err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: revoke what a replayed code issued")
	}

	return refuseGrant()
}

// unansweredCause is why a good code was turned down: the caller's own ending when it has left,
// which is what a store would have answered, and the store's failure otherwise.
func unansweredCause(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return errCodeStoreUnanswered
}

// splitCode reads the token/onetime form of a code: "<identifier>.<secret>".
func splitCode(code string) (id.ID, string, bool) {
	rawID, secret, found := strings.Cut(code, ".")
	if !found || secret == "" {
		return id.Nil, "", false
	}
	tokenID, err := id.Parse(rawID)
	if err != nil {
		return id.Nil, "", false
	}

	return tokenID, secret, true
}

// revokeReplayed revokes the grant a replayed code issued, and its lineage. The grant's row
// comes first, as the tombstone a grant not stored yet is created over, and which every
// refresh reads first, so it alone ends the grant. Each write is tried whatever became of
// the other. A failure answers an error, and since the code stays spent, presenting it again
// tries both again. Opaque access tokens need nothing here, because their grant is checked
// when they are read.
func (p *Provider) revokeReplayed(ctx context.Context, family id.ID, now time.Time) error {
	grantErr := p.stores.grants.Revoke(ctx, family, CauseCodeReplay, now)

	manager, err := p.lineages(nil)
	if err != nil {
		return errors.Join(grantErr, err)
	}
	_, lineageErr := manager.RevokeFamily(ctx, family)

	return errors.Join(grantErr, lineageErr)
}
