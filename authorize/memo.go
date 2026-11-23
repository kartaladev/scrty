package authorize

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/kartaladev/scrty/identity"
)

// memoBound is how many roles one memo remembers. A request checks one role
// in practice; the bound only stops a request that checks many role names
// from growing the memo without limit.
const memoBound = 32

// memoContextKey is unexported, so nothing outside this package can read the
// memo or plant one with results of its own choosing.
type memoContextKey struct{}

// memoKey identifies one remembered load: the authorizer that asked and the
// role name exactly as the loader was asked for it.
//
// The authorizer is part of the key because two privilege authorizers in one
// request — two members of a FirstOf over different loaders — must never
// answer from each other's data. The authorizer's pointer is always a valid
// map key, where the loader, a consumer's value, may not be comparable. The
// role name is keyed exactly, not under the authorizer's name comparer: the
// comparer applies to group, resource and privilege names, and the loader is
// handed the role name unchanged, so two spellings are two questions.
type memoKey struct {
	owner *PrivilegeAuthorizer
	role  string
}

// memoEntry is one load, in flight or finished. done closes when privileges,
// err and loaderEnded are final; none is written after that.
type memoEntry struct {
	done       chan struct{}
	privileges []*identity.ResourcePrivileges
	err        error

	// loaderEnded records whether the loading check's own context had ended
	// when the load returned. Only then is a failure someone else's to retry,
	// whatever its shape; a loader that failed while its context was live,
	// such as on a statement timeout, reports an outage every waiter shares.
	loaderEnded bool
}

// requestMemo remembers the privileges loaded for each role during one
// request. The loaded slices are shared by every check that reads them, which
// is safe because nothing in this package writes to them, and none is handed
// to a caller: HeldPrivileges reports fresh Holdings, never the loaded data.
type requestMemo struct {
	mu      sync.Mutex
	entries map[memoKey]*memoEntry
}

// WithRequestMemo returns a copy of ctx carrying a new, empty privilege memo.
//
// While a context carries a memo, the privilege authorizer and HeldPrivileges
// load each role's privileges at most once for it, including when checks run
// concurrently: the first check loads and the others wait for its result. A
// successful load and identity.ErrPrivilegesNotFound are remembered; any other
// error is not, so a later check in the same request tries again. A memo
// remembers at most 32 roles, and loads past that are not remembered.
//
// The default, a context without a memo, loads on every check. The httpsec
// chain installs a fresh memo on every request it authenticates; a consumer
// outside the chain, such as a background job, calls WithRequestMemo itself.
// Each call makes a new memo, replacing any ctx already carries, so a memo is
// never shared between requests and a privilege change made between two of
// them is seen by the second.
//
// A memo is scoped to the work ctx describes and lives as long as it does.
// Keep it to one request or one job: a long-lived context with a memo serves
// what it loaded first for as long as it lives, which is exactly the delayed
// revocation a per-request memo exists to avoid.
//
// The memo assumes a role's privileges depend only on the role name: it keys
// a load by the authorizer and the role name, and reuses the first answer for
// every check under it. A consumer role loader that also reads something from
// the context, such as a tenant, must not share one memo across contexts that
// differ in it; it installs one memo per tenant, or none.
func WithRequestMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, memoContextKey{}, &requestMemo{entries: make(map[memoKey]*memoEntry)})
}

// memoFromContext returns the memo ctx carries, or nil.
func memoFromContext(ctx context.Context) *requestMemo {
	memo, _ := ctx.Value(memoContextKey{}).(*requestMemo)

	return memo
}

// loadPrivileges returns role's privileges through the memo ctx carries, or
// straight from the loader when it carries none.
//
// The error it returns has been sanitized, so an unwalkable loader error is
// already the fixed fault before the memo asks whether it is a not-found.
func (a *PrivilegeAuthorizer) loadPrivileges(ctx context.Context, role string) ([]*identity.ResourcePrivileges, error) {
	load := func(ctx context.Context) ([]*identity.ResourcePrivileges, error) {
		granted, err := a.roles.LoadPrivileges(ctx, role)

		return granted, sanitizeLoadError(ctx, err)
	}

	memo := memoFromContext(ctx)
	if memo == nil {
		return load(ctx)
	}

	return memo.load(ctx, memoKey{owner: a, role: role}, load)
}

// load returns the remembered result for key, waiting for one in flight, or
// loads it with fn.
//
// A waiter whose own context ends stops waiting with its context's error, and
// leaves the entry for everyone else. A waiter whose load failed because the
// loading check's context ended, while its own is still live, loads again
// whatever error the loader returned: a driver closing its connection under a
// cancelled context reports an error that does not wrap the cancellation, and
// a live caller never inherits another caller's cancellation. A waiter whose
// own context has ended by the time it wakes returns its own context's error,
// not the loading check's. Each retry round ends a check whose context is
// over, so the loop ends with the checks. Any failure while the loading
// check's context was live, including a deadline the loader hit on its own, is
// returned to every waiter: it is an outage, and retrying it would make each
// waiter pay it again in turn.
func (m *requestMemo) load(
	ctx context.Context,
	key memoKey,
	fn func(context.Context) ([]*identity.ResourcePrivileges, error),
) ([]*identity.ResourcePrivileges, error) {
	for {
		m.mu.Lock()

		entry, inFlight := m.entries[key]
		if !inFlight {
			if len(m.entries) >= memoBound {
				m.mu.Unlock()

				return fn(ctx)
			}

			entry = &memoEntry{done: make(chan struct{})}
			m.entries[key] = entry
			m.mu.Unlock()

			return m.fill(ctx, key, entry, fn)
		}

		m.mu.Unlock()

		select {
		case <-entry.done:
		case <-ctx.Done():
			return nil, fmt.Errorf("authorize: waiting for the role's privileges: %w", ctx.Err())
		}

		// The waiter's own context decides first: once it has ended, the
		// answer is its own error, not the loading check's.
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("authorize: waiting for the role's privileges: %w", err)
		}

		if entry.loaderEnded && entry.err != nil {
			continue
		}

		return entry.privileges, entry.err
	}
}

// fill runs fn for entry and publishes the result.
//
// A result that is not remembered — an error other than not-found, or a panic
// in the loader — has its entry removed before done closes, so a check that
// arrives afterwards loads again instead of reading the failure. A panic is
// published to the waiters as an error and then continues in this check, so no
// waiter is left blocked on an entry nobody will finish.
func (m *requestMemo) fill(
	ctx context.Context,
	key memoKey,
	entry *memoEntry,
	fn func(context.Context) ([]*identity.ResourcePrivileges, error),
) (privileges []*identity.ResourcePrivileges, err error) {
	finished := false

	defer func() {
		if !finished {
			entry.err = errLoaderPanicked
		}

		if entry.err != nil && !errors.Is(entry.err, identity.ErrPrivilegesNotFound) {
			m.mu.Lock()
			delete(m.entries, key)
			m.mu.Unlock()
		}

		close(entry.done)
	}()

	entry.privileges, entry.err = fn(ctx)
	entry.loaderEnded = ctx.Err() != nil
	finished = true

	return entry.privileges, entry.err
}

// errLoaderPanicked is what the checks waiting on a load see when the loader
// panicked in the check that ran it. The panic itself continues in that check.
var errLoaderPanicked = errors.New("authorize: the role loader panicked")
