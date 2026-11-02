// Package depfault tells a refusal the library reached from a refusal it
// answered for a dependency that failed.
//
// Some paths fail closed: a store, a limiter or a risk hook that cannot answer
// is answered as the refusal the caller would have got for a bad proof, so the
// status and the text give an attacker nothing to tell the two apart. An event
// must still say what happened, and a dependency that failed refused no proof.
// This package keeps the difference where only the library can read it:
//
//   - [Refusal] answers a failure as a refusal and marks it with [ErrFailed],
//     which is unexported API of an internal package, so no consumer can
//     match it and the refusal's status, text and sentinels are unchanged;
//   - [Store] and [Watch] expose what a one-time token manager hides. The
//     manager answers a store that could not answer as an invalid token, by
//     design; the decorator records the failure beside the call, so the
//     caller can tell it from a token that was simply not good;
//   - [Silent] is what an event emitter asks: whether the error is one a
//     refusal event must not report.
package depfault

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// ErrFailed marks a refusal that answers a dependency's failure. A refusal
// event is not reported for an error that matches it.
var ErrFailed = errors.New("depfault: a dependency failed")

// Refusal answers cause, a dependency's failure, as kind: the error reads as
// kind's own text, matches kind and [ErrFailed], and keeps cause reachable
// through errors.Is and errors.As. A nil cause is nil.
func Refusal(cause, kind error) error {
	return diag.Wrap(cause, kind.Error(), kind, ErrFailed) //nolint:forbidigo // the library's own sentinel text, not the dependency's
}

// Silent reports whether a refusal event must not report err: it answers a
// dependency that failed, or the caller's own context ended before the
// verdict.
func Silent(ctx context.Context, err error) bool {
	return errors.Is(err, ErrFailed) || hangup.ByCaller(ctx, err)
}

type watchKey struct{}

// Watch holds the first failure a [Store] saw on the calls made with the
// context [Watching] returned.
type Watch struct {
	mu  sync.Mutex
	err error
}

// Watching returns ctx carrying a new Watch. Pass the context to a one-time
// token manager built over a [Store], then ask the Watch what its store did.
func Watching(ctx context.Context) (context.Context, *Watch) {
	w := new(Watch)

	return context.WithValue(ctx, watchKey{}, w), w
}

// Failure returns the first store failure seen, or nil when the store
// answered every call it got (a token it did not hold included).
func (w *Watch) Failure() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.err
}

func (w *Watch) note(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.err == nil {
		w.err = err
	}
}

// Store wraps s so that a lookup or a spend that failed is recorded on the
// Watch the call's context carries, if it carries one. A token the store does
// not hold (onetime.ErrTokenNotFound) is an answer, not a failure. Every call
// passes through unchanged. The wrapper offers onetime.Reaper exactly when s
// does.
func Store(s onetime.Store) onetime.Store {
	base := store{Store: s}
	if r, ok := s.(onetime.Reaper); ok {
		return reapingStore{store: base, reaper: r}
	}

	return base
}

type store struct{ onetime.Store }

func (s store) FindByID(ctx context.Context, tokenID id.ID) (*onetime.Token, error) {
	tok, err := s.Store.FindByID(ctx, tokenID)
	record(ctx, err)

	return tok, err
}

func (s store) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	err := s.Store.Consume(ctx, tokenID, at)
	record(ctx, err)

	return err
}

type reapingStore struct {
	store
	reaper onetime.Reaper
}

func (s reapingStore) DeleteExpiredBefore(ctx context.Context, purpose string, retainSince time.Time) (int, error) {
	return s.reaper.DeleteExpiredBefore(ctx, purpose, retainSince)
}

func record(ctx context.Context, err error) {
	if err == nil || errors.Is(err, onetime.ErrTokenNotFound) {
		return
	}

	if w, ok := ctx.Value(watchKey{}).(*Watch); ok {
		w.note(err)
	}
}
