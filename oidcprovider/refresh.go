package oidcprovider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// paramRefreshToken is the parameter a refresh names its token by.
const paramRefreshToken = "refresh_token"

// refreshAttempts bounds how often one refresh tries to rotate. Losing a race means another
// rotation of the same token has just landed, and the next attempt reads what that one left, which
// under one key is the very successor this refresh would have written. Only racers on providers
// whose keys differ need more than that, and each of their rounds has one winner, so this many are
// all served, and more than this many in one instant are told to try again rather than kept waiting.
// It is a proposed value, with no override: a client has nothing to gain from racing itself.
const refreshAttempts = 8

// minSuccessorKeyBytes and defaultSuccessorKeyBytes are the shortest key WithRefreshSuccessorKey
// takes, and how much New draws when it is not given.
const (
	minSuccessorKeyBytes     = 32
	defaultSuccessorKeyBytes = 32
)

// defaultSuccessorWindow is how long after its rotation a token presented again is answered the same
// successor. It is a proposed value, reasoned from the measured race between two tabs, which had
// faded by 100 ms, and from no standard.
const defaultSuccessorWindow = 10 * time.Second

// successorWalkLinks bounds how many records one walk to the head reads. Each link must have been
// rotated inside the window of the token before it, so this only limits a chain rotated many times
// in those seconds, which no pair of tabs makes. Past it the walk gives up, and the token presented
// is what any token with a moved-on successor is, reuse, so a long chain buys its holder nothing. It
// is a proposed value, with no override: WithRefreshSuccessorWindow is what a consumer sets.
const successorWalkLinks = 8

// successorKey is what a refresh token's successor is derived under.
type successorKey struct {
	key []byte
}

// derive is HMAC-SHA256(key, family, secret), the family being of fixed length and set apart from
// the secret. It holds what a session identifier is read from.
func (k *successorKey) derive(family id.ID, secret string) []byte {
	mac := hmac.New(sha256.New, k.key)
	mac.Write([]byte(family.String()))
	mac.Write([]byte{0})
	mac.Write([]byte(secret))

	return mac.Sum(nil)
}

// drawSuccessorKey fills in the default key, which a window of zero has no use for. A source that
// cannot supply it fails New, as a provider must not degrade silently, with the source's own text
// left out.
func (c *config) drawSuccessorKey() error {
	if c.successorKeySet || c.successorWindow == 0 {
		return nil
	}
	key := make([]byte, defaultSuccessorKeyBytes)
	if _, err := io.ReadFull(c.random, key); err != nil {
		return fmt.Errorf("%w: WithRandom: could not supply a refresh successor key; give WithRefreshSuccessorKey or a source that works", ErrConfig)
	}
	c.successorKey = &successorKey{key: key}

	return nil
}

// errRefreshContended stands for a rotation that lost every one of its attempts. It says nothing
// of the token, which still has the standing it had.
var errRefreshContended = errors.New("oidcprovider: a refresh token's rotations kept racing")

// errRefreshTooSlow stands for a request whose user load outlasted the grace of the token it
// presented in time. It says nothing of the token, which was not reused.
var errRefreshTooSlow = errors.New("oidcprovider: a refresh outlasted the grace of the token it presented")

// refresh answers a refresh request, in the order Token describes.
func (p *Provider) refresh(ctx context.Context, r TokenRequest, rc *RegisteredClient) (*TokenResponse, error) {
	raw := r.Form.Get(paramRefreshToken)
	if raw == "" {
		return nil, refuseRequest()
	}
	family, secret, ok := parseRefreshToken(raw)
	if !ok {
		return nil, refuseGrant()
	}
	now := p.cfg.clock.Now()

	grant, err := p.liveGrant(ctx, family, rc, now)
	if err != nil {
		return nil, err
	}
	if grant.KeyBinding != "" && r.Binding.JKT != grant.KeyBinding {
		return nil, &Error{Code: CodeInvalidDPoPProof}
	}
	record, err := p.requireFamilyMember(ctx, secret, family)
	if err != nil {
		return nil, err
	}
	if err := p.markReuse(ctx, record, now); err != nil {
		return nil, err
	}

	manager, err := p.lineages(rc)
	if err != nil {
		return nil, dependencyFailure(ctx, err, "oidcprovider: build the lineage manager")
	}
	current, err := manager.LoadForRenewal(ctx, secret)
	if err != nil {
		return nil, p.answerLineage(ctx, err, family, now, "oidcprovider: read the refresh token")
	}

	if lifetimeOver(current, rc, now) {
		return nil, refuseGrant()
	}
	if err := p.judgeGrantUser(ctx, grant, now); err != nil {
		return nil, err
	}
	scopes, err := refreshScopes(r.Form.Get(paramScope), grant, rc, p.cfg.bounds.Scope)
	if err != nil {
		return nil, err
	}
	audience, err := resolveAudience(r.Form, grant.Resources, rc, p.issuer, scopes)
	if err != nil {
		return nil, err
	}

	issued := *grant
	issued.Scopes = scopes
	mint := refreshMint{p: p, grant: &issued, rc: rc, binding: r.Binding, audience: audience, now: now}

	res, err := p.answerRefresh(ctx, manager, current, raw, rc, &mint, now)
	if err != nil {
		mint.discard(ctx)

		return nil, err
	}

	return res, nil
}

// answerRefresh moves the lineage, reads the row again, and answers mint's tokens.
func (p *Provider) answerRefresh(
	ctx context.Context, manager *session.Sessions, current *session.Session, raw string, rc *RegisteredClient, mint *refreshMint, now time.Time,
) (*TokenResponse, error) {
	refreshToken := raw
	if rc.DisableRotation && current.SupersededAt.IsZero() {
		if err := mint.once(ctx); err != nil {
			return nil, err
		}
		if err := manager.Touch(ctx, current); err != nil {
			return nil, p.answerLineage(ctx, err, current.FamilyID, now, "oidcprovider: record the refresh")
		}
	} else {
		var err error
		if refreshToken, err = p.rotateLineage(ctx, manager, current, rc, mint, now); err != nil {
			return nil, err
		}
	}

	if err := p.requireStillLive(ctx, current.FamilyID); err != nil {
		return nil, err
	}
	mint.res.RefreshToken = refreshToken

	return mint.res, nil
}

// parseRefreshToken reads rt.<family>.<secret>, in the one spelling the provider mints. A value
// of any other shape costs no lookup. The family is not a secret, and proves nothing.
func parseRefreshToken(raw string) (id.ID, string, bool) {
	rest, ok := strings.CutPrefix(raw, refreshTokenPrefix)
	if !ok {
		return id.Nil, "", false
	}
	family, secret, ok := splitCode(rest)
	if !ok || family.IsZero() || !strings.HasPrefix(rest, family.String()+".") || !session.ValidIdentifier(secret) {
		return id.Nil, "", false
	}

	return family, secret, true
}

// liveGrant reads the row a refresh token names, before anything changes state. What it refuses
// writes nothing, because the family a request names is no proof of anything (R8).
func (p *Provider) liveGrant(ctx context.Context, family id.ID, rc *RegisteredClient, now time.Time) (*Grant, error) {
	grant, err := p.stores.grants.Load(ctx, family)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, refuseGrant()
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: read the refresh token's grant")
	case grant.Revoked || grant.ClientID != rc.ID || !now.Before(grant.ExpiresAt):
		return nil, refuseGrant()
	}

	return grant, nil
}

// requireFamilyMember refuses a secret that is no record of family, writing nothing. It reads
// the store directly, because the manager's load is a verdict with effects: it marks a live
// record presented, and revokes the family of a superseded one past its grace. Those belong to
// whoever presents a token naming that family, whose grant was just checked to be the client's.
// Without this, a client could end another client's grant by naming its own family beside a
// stale secret of the other's.
//
// A secret with no record is what a forged one and a revoked grant's look like alike (H4, R8).
// Neither is a revocation to record, and the row's being live changes nothing: a failure between
// an exchange's two writes leaves exactly that, for a client that was given no token (R19).
func (p *Provider) requireFamilyMember(ctx context.Context, secret string, family id.ID) (*session.Session, error) {
	record, err := oplineage.Sessions(p.stores.lineage).Load(ctx, secret)
	switch {
	case errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrExpired):
		return nil, refuseGrant()
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: read the refresh token")
	case record == nil || record.FamilyID != family:
		return nil, refuseGrant()
	}

	return record, nil
}

// markReuse marks the grant's row revoked when record is a superseded token past its grace, ahead
// of the manager's verdict, which deletes the family. The row comes first because it alone is what
// ends the grant's opaque access tokens and answers a racing refresh's second read, and a
// presentation with the lineage gone could no longer mark it. A row that cannot be marked answers a
// dependency failure with the lineage intact, so presenting the token again tries again. It does
// not depend on the caller still listening.
func (p *Provider) markReuse(ctx context.Context, record *session.Session, now time.Time) error {
	if record.SupersededAt.IsZero() || insideGrace(record, now) {
		return nil
	}
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()
	if err := p.stores.grants.Revoke(detached, record.FamilyID, CauseReuse, now); err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: revoke a reused refresh token's grant")
	}

	return nil
}

// insideGrace reports a superseded record whose window is still open: it names a successor, and it
// is before the window's end. One naming no successor was knocked out, and its window has ended
// whatever its recorded end says. It reads as session's own verdict does.
func insideGrace(record *session.Session, now time.Time) bool {
	return len(record.SuccessorDigest) > 0 && now.Before(record.AcceptUntil)
}

// lifetimeOver judges a record by its client's lifetimes as they stand now, which a consumer may
// have shortened since the record's own deadlines were written, so that a shortened lifetime
// reaches grants already issued, on the path that only touches the record too. It is an ending,
// and no revocation. A superseded record's idle time counts from its rotation, which was its last
// use, as its last activity stopped being recorded then, so a token inside its grace is no way
// round a timeout its successor is refused by.
func lifetimeOver(record *session.Session, rc *RegisteredClient, now time.Time) bool {
	lastUse := record.LastAccessedAt
	if !record.SupersededAt.IsZero() {
		lastUse = record.SupersededAt
	}

	return !now.Before(lastUse.Add(rc.GrantIdleTimeout)) || !now.Before(record.FamilyCreatedAt.Add(rc.GrantAbsoluteLifetime))
}

// answerLineage turns what the lineage manager said into what the request ends with.
//
// Reuse has revoked the family, and is refused. markReuse marked the row of a token already past
// its grace. A verdict that markReuse could not see coming, a window that closed since it read or
// a successor that moved on inside the grace, leaves that to revokeOnReuse. When the family could
// not be deleted, the manager tells no observer, so the row is marked here, as it alone ends the
// grant, and the failure is answered as what it is. A gone or expired record is refused, and any
// other failure is no verdict on the token.
func (p *Provider) answerLineage(ctx context.Context, err error, family id.ID, now time.Time, text string) error {
	switch {
	case errors.Is(err, session.ErrReused):
		//nolint:errorlint // identity: the bare sentinel is the manager's word that the family went
		if err == session.ErrReused {
			return refuseGrant()
		}
		detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
		defer cancel()

		return dependencyFailure(ctx,
			errors.Join(err, p.stores.grants.Revoke(detached, family, CauseReuse, now)),
			"oidcprovider: revoke a reused refresh token's family")
	case errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrExpired):
		return refuseGrant()
	default:
		return dependencyFailure(ctx, err, text)
	}
}

// judgeGrantUser refuses a user who no longer exists or is disabled, and revokes the grant.
// It runs once the token is known to be real, so a forged one cannot revoke. A loader that cannot
// answer is no verdict on the user. The revocation does not depend on the caller still listening.
func (p *Provider) judgeGrantUser(ctx context.Context, grant *Grant, now time.Time) error {
	details, err := p.users.LoadByUserID(ctx, grant.User)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: load the grant's user")
	case details != nil && details.ID == grant.User && details.Active:
		return nil
	}

	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()
	if err := p.revokeGrant(detached, grant.Family, CauseUserDisabled, now); err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: revoke a grant whose user has gone")
	}

	return refuseGrant()
}

// refreshScopes decides what a refresh's tokens carry: what it asked for, or the grant's own when
// it asked for nothing. Asking outside the grant is invalid_scope. A scope of the grant the
// client is no longer allowed is left out, and comes back when it is allowed again, since the
// grant keeps it (R13). A refresh left with nothing is invalid_scope too, because no token can
// state it. A value past the bound an authorization request meets is invalid_request.
func refreshScopes(raw string, grant *Grant, rc *RegisteredClient, bound int) ([]string, error) {
	if len(raw) > bound {
		return nil, refuseRequest()
	}
	asked := words(raw)
	if len(asked) == 0 {
		asked = grant.Scopes
	}
	kept := make([]string, 0, len(asked))
	for _, scope := range asked {
		if !slices.Contains(grant.Scopes, scope) {
			return nil, &Error{Code: CodeInvalidScope}
		}
		if slices.Contains(rc.Scopes, scope) {
			kept = append(kept, scope)
		}
	}
	if len(kept) == 0 {
		return nil, &Error{Code: CodeInvalidScope}
	}

	return kept, nil
}

// refreshMint signs a refresh's tokens and stores an opaque one, at most once however many attempts
// its rotation takes. None of them names the lineage record, so an attempt that lost a race leaves
// them good. grant is a copy whose scopes are what this refresh was given, and the stored one stays
// as it is.
type refreshMint struct {
	p        *Provider
	grant    *Grant
	rc       *RegisteredClient
	binding  Binding
	audience []string
	now      time.Time

	// stored is the opaque token written for this refresh, which discard ends if it is not answered.
	stored *AccessTokenRecord
	res    *TokenResponse
	err    error
}

// once signs the tokens, then stores an opaque one, unless it already has. All of it comes before
// the rotation's write, so a key or access-token store failure leaves the presented token with the
// standing it had, rather than rotated with a successor no client holds, which a retry past the
// grace would read as theft. An ID token has no nonce to repeat, and keeps the authentication facts
// and sid of the grant, which copied them from the sign-in.
func (m *refreshMint) once(ctx context.Context) error {
	if m.res != nil {
		return nil
	}
	access, err := m.p.mintAccessToken(ctx, m.grant, m.rc, m.binding, m.audience, m.now)
	if err != nil {
		m.err = err

		return err
	}
	res := &TokenResponse{
		AccessToken: access.value,
		TokenType:   access.tokenType,
		ExpiresIn:   access.expiresIn,
		Scope:       strings.Join(m.grant.Scopes, " "),
	}
	if slices.Contains(m.grant.Scopes, scopeOpenID) {
		if res.IDToken, err = m.p.mintIDToken(ctx, m.grant, "", m.rc); err != nil {
			m.err = err

			return err
		}
	}
	if access.record != nil {
		if err := m.p.stores.accessTokens.Create(ctx, access.record); err != nil {
			m.err = dependencyFailure(ctx, err, "oidcprovider: store the access token")

			return m.err
		}
		m.stored = access.record
	}
	m.res = res

	return nil
}

// discard ends an opaque token stored for a refresh that was not answered. Nobody was given its
// value, and a revocation already ends it through its grant. This is what ends it where the grant
// lives on, as after a rotation lost or a read that failed, so a stored record never outlives the
// refresh it was minted for. It does not depend on the caller still listening. It can only be
// logged when it fails, as the refresh already has its answer, and the record then lasts until its
// own expiry with no one holding its secret.
func (m *refreshMint) discard(ctx context.Context) {
	if m.stored == nil {
		return
	}
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()
	if err := m.p.stores.accessTokens.Revoke(detached, m.stored.ID); err != nil {
		m.p.cfg.logger.LogAttrs(ctx, slog.LevelError, "oidcprovider: an access token no refresh answered could not be ended",
			append(diag.Failure("revoke_access_token", err), slog.String("family", m.grant.Family.String()))...)
	}
}

// rotateLineage supersedes current and returns its successor's refresh token. The tokens are
// signed, and an opaque one stored, in the rotation's step, ahead of its only write, so a failure of
// either leaves the presented token with the standing it had, and an outage is no theft alarm when
// it is presented later.
//
// A token's first rotation derives its successor's secret, rather than drawing it. A token presented
// again inside the same-successor window therefore derives what it was already answered, finds its
// digest stored, and gets the head of that chain with no write, which is what two tabs presenting
// one token need: one head remains, and whichever of them stores its answer last holds it (R20).
//
// The store's conditional write is what makes one successor of many racers: the manager holds no
// lock over this. A loser reads the record again, and the winner's write is usually its answer. So
// is the write of a tab landing after this one's read, which the rotator's own read finds, and which
// firstRotationOnly sends back here. A record the same answer does not reach, past the window, rotated
// under another key, or with a successor that cannot be answered, is rotated again if it is still
// inside its grace, under a successor drawn at random, since the derived one is already stored. That
// knocks out the previous successor, and presenting a knocked-out token is reuse, as RotateWithGrace
// documents, which is what catches a holder missing the window. A successor that has itself moved on
// makes that re-rotation reuse (session.ErrSuccessorAdvanced): the manager deletes the family and
// revokeOnReuse marks the row. A record a rotation lost to, and found past its grace when it read
// again, is reuse too, and one gone by then has been revoked.
//
// A request can wait on a user load for longer than a grace, so the record is read again before
// anything else, on the clock as it stands. A token superseded and past its grace by then was
// presented in time, as the manager judged it before the load, and is no reuse: the answer is a
// dependency failure with no verdict and nothing revoked, and a retry is judged afresh. That narrows
// the gap and does not close it, as this read and the rotation are still apart, and it costs one
// read per rotation. A token presented already past its grace never gets here: the manager's first
// read revoked it.
func (p *Provider) rotateLineage(
	ctx context.Context, manager *session.Sessions, current *session.Session, rc *RegisteredClient, mint *refreshMint, now time.Time,
) (string, error) {
	if err := p.requireInsideGrace(ctx, current); err != nil {
		return "", err
	}
	step := func(*session.Session) (string, error) { return "", mint.once(ctx) }
	tokenOf := func(secret string) string { return refreshTokenPrefix + current.FamilyID.String() + "." + secret }

	record := current
	for range refreshAttempts {
		successor, found, err := p.sameSuccessor(ctx, record)
		if err != nil {
			return "", err
		}
		if found {
			if err := mint.once(ctx); err != nil {
				return "", err
			}

			return tokenOf(successor), nil
		}

		rotator, err := p.rotatorOf(manager, record, rc)
		if err != nil {
			return "", dependencyFailure(ctx, err, "oidcprovider: build the lineage manager")
		}
		next, _, _, err := rotator.RotateWithGraceIssuing(ctx, record, rc.RefreshGrace, step)
		switch {
		case mint.err != nil:
			return "", mint.err
		case err == nil:
			return tokenOf(next.ID), nil
		case !errors.Is(err, session.ErrRenewalConflict):
			return "", p.answerLineage(ctx, err, current.FamilyID, now, "oidcprovider: rotate the refresh token")
		}

		if record, err = manager.LoadForRenewal(ctx, current.ID); err != nil {
			return "", p.answerLineage(ctx, err, current.FamilyID, now, "oidcprovider: read the refresh token")
		}
	}

	return "", dependencyFailure(ctx, errRefreshContended, "oidcprovider: rotate the refresh token")
}

// requireInsideGrace reads record again, straight from the store: the manager's load is a verdict
// with effects, and past the grace the effect is a revocation this token has not earned. A record
// superseded and past its grace is answered a dependency failure. A record gone is refused, as a
// revoked grant reads, and a read that fails is a dependency failure.
func (p *Provider) requireInsideGrace(ctx context.Context, record *session.Session) error {
	reread, err := oplineage.Sessions(p.stores.lineage).Load(ctx, record.ID)
	switch {
	case errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrExpired):
		return refuseGrant()
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: read the refresh token again")
	case reread == nil:
		return refuseGrant()
	case !reread.SupersededAt.IsZero() && !insideGrace(reread, p.cfg.clock.Now()):
		return dependencyFailure(ctx, errRefreshTooSlow, "oidcprovider: rotate the refresh token")
	}

	return nil
}

// sameSuccessor answers the secret of the head of the chain record starts, when the whole way there
// is what this provider's key derived, inside the same-successor window. The manager has judged
// record to be live or inside its grace. It costs one read per link, at most successorWalkLinks.
//
// Each link must be inside its own window, measured from its rotation on this provider's clock, as
// it stands now rather than when the request began: a request can wait on a user load for longer
// than a window. A rotation stamped ahead of the clock is judged by the size of the difference, so
// replicas a little apart still converge, and one lagging by the window or more does not stretch it.
// Every link is judged against the one configured window, from its own rotation, so the first link's
// window closing ends the walk whatever the later links have left. That is pinned on one clock. A row
// with the chain stamped by clocks that disagree is left out: it needs three clocks, and the check
// it would reach is the same symmetric one the lagging-replica rows already cover. A live record has no rotation to measure from, so a first rotation costs no read.
// A window of zero answers nothing, also on a clock behind the rotation's, and holds no key to read.
// A digest another key wrote, a successor gone, and one past its own grace end the walk with no
// answer, and what the store makes of a rotation decides those. A read that fails is a failure, and
// no reason to rotate.
func (p *Provider) sameSuccessor(ctx context.Context, record *session.Session) (string, bool, error) {
	if p.cfg.successorWindow == 0 {
		return "", false, nil
	}
	now := p.cfg.clock.Now()
	link := record
	for range successorWalkLinks {
		if age := now.Sub(link.SupersededAt); age >= p.cfg.successorWindow || age <= -p.cfg.successorWindow {
			return "", false, nil
		}
		secret := base64.RawURLEncoding.EncodeToString(p.cfg.successorKey.derive(link.FamilyID, link.ID))
		digest := sha256.Sum256([]byte(secret))
		if !hmac.Equal(link.SuccessorDigest, digest[:]) {
			return "", false, nil
		}

		successor, err := oplineage.Sessions(p.stores.lineage).Load(ctx, secret)
		switch {
		case errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrExpired):
			return "", false, nil
		case err != nil:
			return "", false, dependencyFailure(ctx, err, "oidcprovider: read the refresh token's successor")
		case successor == nil:
			return "", false, nil
		case successor.SupersededAt.IsZero():
			return secret, true, nil
		case !insideGrace(successor, now):
			return "", false, nil
		}
		link = successor
	}

	return "", false, nil
}

// rotatorOf is the manager a rotation of record goes through. A record not yet rotated takes the
// successor its key derives, through a manager reading its one identifier from that, so that a racer
// inside the window finds it. A window of zero has no racer to find it. Anything else takes manager's
// own, drawn at random, because the derived identifier may be stored already, on the record the
// re-rotation knocks out.
func (p *Provider) rotatorOf(manager *session.Sessions, record *session.Session, rc *RegisteredClient) (*session.Sessions, error) {
	if p.cfg.successorWindow == 0 || !record.SupersededAt.IsZero() {
		return manager, nil
	}

	return p.lineagesThrough(rc,
		firstRotationOnly{Store: oplineage.Sessions(p.stores.lineage)},
		bytes.NewReader(p.cfg.successorKey.derive(record.FamilyID, record.ID)))
}

// firstRotationOnly is the store of a rotator holding a derived identifier, which is good for a
// first rotation alone. rotatorOf chose it on a record read earlier, and the rotator reads again, so
// another rotation may have landed between, perhaps over a long user load. A rotation naming an
// observed successor shows that one did, and the identifier it carries is then already stored: the
// race is lost, and the loser reads again, where the same answer finds it.
type firstRotationOnly struct {
	session.Store
}

// Supersede implements session.Store.
func (s firstRotationOnly) Supersede(ctx context.Context, op session.Supersession) error {
	if len(op.ObservedSuccessor) > 0 {
		return session.ErrRenewalConflict
	}

	return s.Store.Supersede(ctx, op)
}

// requireStillLive reads the row again once the lineage has moved, so a revocation or a sign-in's
// end that landed since the first read answers no tokens. What this leaves stored is unusable
// anyway, since every refresh reads the row first. What the read saves is a JWT access token
// that a resource server verifying offline would accept until its exp. A revocation landing after
// this read is one the refresh came before, and its deletion of the family takes the successor.
//
// A read that fails fails closed, the lineage having moved: the client can retry inside its grace,
// and a false reuse alarm needs an outage outlasting the grace. Answering tokens on a row that could
// not be read would be worse.
func (p *Provider) requireStillLive(ctx context.Context, family id.ID) error {
	grant, err := p.stores.grants.Load(ctx, family)
	switch {
	case errors.Is(err, ErrNotFound):
		return refuseGrant()
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: read the refresh token's grant")
	case grant.Revoked:
		return refuseGrant()
	}

	return nil
}

// revokeOnReuse is the lineage manager's reuse observer: the family has gone, and this marks its
// grant, which is what ends its opaque access tokens and the JWTs read through the provider. For a
// token past its grace, markReuse already has, and this changes nothing. It is alone on the verdicts
// markReuse could not see coming: a window closing since it read, and a re-rotation the store
// refused because the successor moved on (ErrSuccessorAdvanced). It does not depend on the caller
// still listening. It can return nothing, so a failure is logged. On those verdicts the grant then
// reads as revoked at every later refresh, its lineage being gone (H4), and its opaque access tokens
// stay good until their own expiry, there being nothing left to present that could mark it.
func (p *Provider) revokeOnReuse(ctx context.Context, r session.ReuseReport) {
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()

	if err := p.stores.grants.Revoke(detached, r.Family, CauseReuse, r.DetectedAt); err != nil {
		p.cfg.logger.LogAttrs(ctx, slog.LevelError, "oidcprovider: a reused refresh token's grant could not be marked revoked",
			append(diag.Failure("revoke_grant", err), slog.String("family", r.Family.String()))...)
	}
}
