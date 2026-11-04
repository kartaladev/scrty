package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// orphanGrace is how old a grant must be before the orphan sweep may judge its lineage
// missing. The exchange writes the grant row first and the lineage after it, so a younger
// grant may be between the two writes.
const orphanGrace = 10 * time.Minute

// ExpiryTasks returns the tasks that delete the provider's expired state, to hand to an
// expiry.Runner or a scheduler next to a consumer's own. They sweep the stores the
// provider settled on, the consumer's or the in-memory defaults, and each judges time by
// the provider's clock:
//
//   - "oidc-provider.pending-requests": the parked requests past their deadline;
//   - "oidc-provider.browser-sessions": the sessions past either deadline;
//   - "oidc-provider.codes": the code records a minute past their expiry and the tokens
//     of those codes. A spent code is kept that long so a valid replay still revokes
//     what it issued, and a store's own purge goes by when a token was issued, so the
//     tokens' cutoff reaches back a code lifetime further. A code-token store that
//     cannot purge makes the task fail with an error matching expiry.ErrPurgeUnsupported;
//   - "oidc-provider.grants": the grants past their deadline, and the revoked ones once
//     no code could still name them, which is the longest code lifetime plus a minute
//     after the revocation, whatever WithCodeLifetime chose;
//   - "oidc-provider.refresh-tokens": the refresh-token lineages past their deadlines;
//   - "oidc-provider.orphaned-grants": a grant older than ten minutes that was issued a
//     lineage and has none live, which is what a failure between the exchange's two writes
//     leaves. A grant recorded to hold no lineage is never one, and neither is a grant
//     whose lineage is live. A lineage past a deadline counts as missing, as no refresh token
//     can use it any longer;
//   - "oidc-provider.access-tokens" and "oidc-provider.assertion-ids": the records past
//     their expiry.
//
// No task sets an Interval: only the deployment knows its cadence. A consumer renames a
// task by changing its Name before building the runner.
func ExpiryTasks(p *Provider) []expiry.Task {
	return []expiry.Task{
		{Name: "oidc-provider.pending-requests", Run: p.sweepPendingRequests},
		{Name: "oidc-provider.browser-sessions", Run: p.sweepBrowserSessions},
		{Name: "oidc-provider.codes", Run: p.sweepCodes},
		{Name: "oidc-provider.grants", Run: p.sweepGrants},
		{Name: "oidc-provider.refresh-tokens", Run: session.ExpiryTask(oplineage.Sessions(p.stores.lineage)).Run},
		{Name: "oidc-provider.orphaned-grants", Run: p.sweepOrphanedGrants},
		{Name: "oidc-provider.access-tokens", Run: p.sweepAccessTokens},
		{Name: "oidc-provider.assertion-ids", Run: p.sweepAssertionIDs},
	}
}

func (p *Provider) sweepPendingRequests(ctx context.Context) (int, error) {
	return p.stores.pendingRequests.DeleteExpired(ctx, p.cfg.clock.Now())
}

func (p *Provider) sweepBrowserSessions(ctx context.Context) (int, error) {
	return p.stores.browserSessions.DeleteExpired(ctx, p.cfg.clock.Now())
}

func (p *Provider) sweepAccessTokens(ctx context.Context) (int, error) {
	return p.stores.accessTokens.DeleteExpired(ctx, p.cfg.clock.Now())
}

func (p *Provider) sweepAssertionIDs(ctx context.Context) (int, error) {
	return p.stores.assertionIDs.DeleteExpired(ctx, p.cfg.clock.Now())
}

// sweepCodes deletes a code's token and its record together, each a minute past the code's
// expiry (R17). Both are tried whatever became of the other.
func (p *Provider) sweepCodes(ctx context.Context) (int, error) {
	now := p.cfg.clock.Now()

	var tokens int
	var tokenErr error
	if reaper, ok := p.stores.codeTokens.(onetime.Reaper); ok {
		// The cutoff is on when a token was issued, not on when it expires. A code issued
		// before now-lifetime-minute expired before now-minute, and no later one has.
		tokens, tokenErr = reaper.DeleteExpiredBefore(ctx, codeTokenPurpose, now.Add(-p.cfg.codeLifetime-codeKeptPastExpiry))
	} else {
		tokenErr = errors.Join(
			fmt.Errorf("oidcprovider: the code-token store %T cannot purge: %w", p.stores.codeTokens, onetime.ErrReapUnsupported),
			expiry.ErrPurgeUnsupported,
		)
	}
	records, recordErr := p.stores.codes.DeleteExpired(ctx, now.Add(-codeKeptPastExpiry))

	return tokens + records, errors.Join(tokenErr, recordErr)
}

// sweepGrants deletes the expired grants, keeping a revoked one until no code can name it.
func (p *Provider) sweepGrants(ctx context.Context) (int, error) {
	return p.stores.grants.DeleteExpired(ctx, p.cfg.clock.Now(), memoryKeepRevoked)
}

// sweepOrphanedGrants deletes the grants past orphanGrace whose lineage is gone.
func (p *Provider) sweepOrphanedGrants(ctx context.Context) (int, error) {
	now := p.cfg.clock.Now()
	lineages := oplineage.Sessions(p.stores.lineage)
	live := map[string]map[id.ID]bool{}

	// A family is live when its user has a live head of it. The answer for a user is kept
	// for the pass, so a user with many grants is listed once.
	exists := func(family id.ID) (bool, error) {
		g, err := p.stores.grants.Load(ctx, family)
		if errors.Is(err, ErrNotFound) {
			// Deleted meanwhile: there is nothing left to remove.
			return true, nil
		}
		if err != nil {
			return false, err
		}
		families, ok := live[string(g.User)]
		if !ok {
			sessions, err := lineages.ListByUser(ctx, g.User, now)
			if err != nil {
				return false, err
			}
			families = make(map[id.ID]bool, len(sessions))
			for _, s := range sessions {
				families[s.FamilyID] = true
			}
			live[string(g.User)] = families
		}

		return families[family], nil
	}

	return p.stores.grants.DeleteOrphans(ctx, exists, now.Add(-orphanGrace))
}
