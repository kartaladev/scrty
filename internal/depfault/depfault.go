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
	"log/slog"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/porterr"
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
//
// err is read through one bounded, recovering walk (internal/errwalk). An err
// whose chain cannot be walked (a cycle, a fan-out past the walk's budget, or
// a panicking Unwrap or Is) is not silent: its event is reported rather than
// dropped. Silent writes no record of the abort; the classification of the
// same refusal reports it.
func Silent(ctx context.Context, err error) bool {
	failed, abort := matches(err, ErrFailed)
	if abort != nil {
		return false
	}

	return failed || hangup.ByCaller(ctx, err)
}

// walkBuffer is how many nodes of a chain a walk holds on its caller's stack
// before it grows onto the heap.
const walkBuffer = 16

// matches reports whether err's chain holds target, as errors.Is would, read
// through one bounded, recovering walk. abort is the walk's abort, and when it
// is set, matched is false.
func matches(err, target error) (matched bool, abort error) {
	var buf [walkBuffer]error

	chain, abort := errwalk.FlattenInto(buf[:], err)
	if abort != nil {
		return false, abort
	}

	return errwalk.Is(chain, target)
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
// not hold (onetime.ErrTokenNotFound) is an answer, not a failure. The wrapper
// offers onetime.Reaper exactly when s does.
//
// Every error s returns is the consumer's, so every call the wrapper forwards
// passes it through porterr.SanitizeTo before anything reads it, the Watch
// included: an error whose chain can be walked is returned as the same value,
// and one that cannot (a cycle, a fan-out, a panicking Unwrap) is returned,
// and recorded, as a porterr fault matching porterr.ErrUnwalkable, with one
// abort record on logger (when logger is nil: the logger of the chain handling
// the request, else slog.Default() when the record is written). Such a fault
// never matches onetime.ErrTokenNotFound, so it reads as the failure it may
// be. Every other value a call returns passes through unchanged.
func Store(s onetime.Store, logger *slog.Logger) onetime.Store {
	base := store{Store: s, logger: logger}
	if r, ok := s.(onetime.Reaper); ok {
		return reapingStore{store: base, reaper: r}
	}

	return base
}

type store struct {
	onetime.Store
	logger *slog.Logger
}

func (s store) Insert(ctx context.Context, tok onetime.Token) error {
	err := s.Store.Insert(ctx, tok)

	return porterr.SanitizeTo(ctx, s.logger, err, porterr.ErrUnwalkable)
}

func (s store) InsertWithin(ctx context.Context, tok onetime.Token, since time.Time, limit int) (bool, error) {
	stored, err := s.Store.InsertWithin(ctx, tok, since, limit)

	return stored, porterr.SanitizeTo(ctx, s.logger, err, porterr.ErrUnwalkable)
}

func (s store) FindByID(ctx context.Context, tokenID id.ID) (*onetime.Token, error) {
	tok, err := s.Store.FindByID(ctx, tokenID)
	err = porterr.SanitizeTo(ctx, s.logger, err, porterr.ErrUnwalkable)
	record(ctx, err)

	return tok, err
}

func (s store) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	err := s.Store.Consume(ctx, tokenID, at)
	err = porterr.SanitizeTo(ctx, s.logger, err, porterr.ErrUnwalkable)
	record(ctx, err)

	return err
}

func (s store) CountRecentBySubject(ctx context.Context, purpose, subject string, since time.Time) (int, error) {
	n, err := s.Store.CountRecentBySubject(ctx, purpose, subject, since)

	return n, porterr.SanitizeTo(ctx, s.logger, err, porterr.ErrUnwalkable)
}

type reapingStore struct {
	store
	reaper onetime.Reaper
}

func (s reapingStore) DeleteExpiredBefore(ctx context.Context, purpose string, retainSince time.Time) (int, error) {
	removed, err := s.reaper.DeleteExpiredBefore(ctx, purpose, retainSince)

	return removed, porterr.SanitizeTo(ctx, s.logger, err, porterr.ErrUnwalkable)
}

// record notes err on the Watch ctx carries, unless err is nil or the store's
// answer that it holds no such token. An err whose chain cannot be walked is
// not that answer, so it is noted as the failure it may be; record writes no
// record of the abort.
func record(ctx context.Context, err error) {
	if err == nil {
		return
	}

	w, ok := ctx.Value(watchKey{}).(*Watch)
	if !ok {
		return
	}

	if notFound, abort := matches(err, onetime.ErrTokenNotFound); notFound && abort == nil {
		return
	}

	w.note(err)
}
