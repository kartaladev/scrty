package oidcprovider

import (
	"context"
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// ExpiryTasks returns the tasks that delete the provider's expired state, to hand to an
// expiry.Runner or a scheduler next to a consumer's own. They sweep the stores the
// provider settled on, the consumer's or the in-memory defaults. The tasks over the
// pending requests, browser sessions, code records, grants, access tokens and assertion
// identifiers judge time by the provider's clock (WithClock). Two sweeps go by their
// store's clock instead: the refresh-token task, as every session store's own sweep does,
// and the code-token purge, which drops only the tokens the store itself finds expired.
// The tasks:
//
//   - "oidc-provider.pending-requests": the parked requests past their deadline;
//   - "oidc-provider.browser-sessions": the sessions past either deadline;
//   - "oidc-provider.codes": the code records a minute past their expiry and the tokens
//     of those codes. A spent code is kept that long so a valid replay still revokes
//     what it issued. A store's own purge goes by when a token was issued, and a redeploy
//     may have lowered WithCodeLifetime since, so the tokens' cutoff reaches back the
//     longest lifetime the option allows and a minute: a spent token can stay up to
//     eleven minutes, which costs nothing. A code-token store that cannot purge makes the
//     task fail with an error matching expiry.ErrPurgeUnsupported;
//   - "oidc-provider.grants": the grants past their deadline, and the revoked ones once
//     no code could still name them, which is the longest code lifetime plus a minute
//     after the revocation, whatever WithCodeLifetime chose. A grant whose refresh-token
//     lineage has gone idle or been swept stays until its own deadline or a revocation,
//     so a sign-in's end still reaches its client;
//   - "oidc-provider.refresh-tokens": the refresh-token lineages past their deadlines;
//   - "oidc-provider.access-tokens" and "oidc-provider.assertion-ids": the records past
//     their expiry.
//
// No task sets an Interval: only the deployment knows its cadence. A consumer overrides
// the set by editing the returned slice before building the runner: dropping a task
// leaves that state to the consumer's own sweep (a supplied store's DeleteExpired, or a
// scheduled job), changing a Name renames it, and replacing its Run swaps the sweep for
// the consumer's. Dropping the codes task also drops the sweep of the code records.
func ExpiryTasks(p *Provider) []expiry.Task {
	return []expiry.Task{
		{Name: "oidc-provider.pending-requests", Run: p.sweepPendingRequests},
		{Name: "oidc-provider.browser-sessions", Run: p.sweepBrowserSessions},
		{Name: "oidc-provider.codes", Run: p.sweepCodes},
		{Name: "oidc-provider.grants", Run: p.sweepGrants},
		{Name: "oidc-provider.refresh-tokens", Run: session.ExpiryTask(oplineage.Sessions(p.stores.lineage)).Run},
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

// sweepCodes deletes a code's record a minute past its expiry, and its token by a cutoff on
// the longest code lifetime, so a token can stay up to 11 minutes, whatever lifetime the
// provider now has (R17). Both are tried whatever became of the other.
func (p *Provider) sweepCodes(ctx context.Context) (int, error) {
	now := p.cfg.clock.Now()

	var tokens int
	var tokenErr error
	if reaper, ok := p.stores.codeTokens.(onetime.Reaper); ok {
		// The cutoff is on when a token was issued, not on when it expires. A code issued
		// before now-maxCodeLifetime-minute expired before now-minute under any lifetime
		// the option allows, so a redeploy that lowered it purges no code in flight.
		tokens, tokenErr = reaper.DeleteExpiredBefore(ctx, codeTokenPurpose, now.Add(-maxCodeLifetime-codeKeptPastExpiry))
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
