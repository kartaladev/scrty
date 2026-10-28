package storekit

//go:generate mockgen -source=session_tx.go -destination=session_tx_mock_test.go -package=storekit_test -typed

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/session"
)

// Transactor is one store's driver side of Atomically, for one call: Q is the
// handle its statements run on. A store makes a fresh one per call, so Begin
// may keep the transaction it begins for Commit and Rollback.
//
// Every error a Transactor returns is the store's own, already wrapped with
// its prefix and the operation's name, and Atomically returns it as it is.
type Transactor[Q any] interface {
	// Begin begins a transaction of the store's own, beside q, the handle the
	// call resolved to, and returns the handle its statements run on.
	Begin(ctx context.Context, q Q) (Q, error)
	// Commit commits the transaction Begin began.
	Commit(ctx context.Context) error
	// Rollback rolls back the transaction Begin began, ignoring the outcome.
	// It runs on every way out but a commit, a panic included, and after a
	// commit it runs and does nothing. Whether it detaches from ctx is the
	// driver's to decide.
	Rollback(ctx context.Context)
	// SavepointName is the name of a new savepoint, distinct from any other
	// the store has open on the caller's transaction.
	SavepointName() string
	// ExecSavepoint runs stmt, a SAVEPOINT, ROLLBACK TO SAVEPOINT or RELEASE
	// SAVEPOINT statement, on q, a caller's transaction.
	ExecSavepoint(ctx context.Context, q Q, stmt string) error
}

// Atomically runs fn as one unit on q, the handle the call resolved to. When
// ambient, q is a caller's transaction and fn runs under a savepoint of its
// own; otherwise fn runs in a transaction t begins, which is committed when
// fn succeeds and rolled back on every other way out, a panic in fn
// included, so the transaction and the row locks it holds never outlive the
// call. An error fn returns is returned as it is, so a sentinel stays bare.
//
// Under a savepoint, a failure of fn rolls back to the savepoint, undoing
// fn's writes and clearing the aborted state a failed statement leaves, so
// the caller's transaction stays usable with its earlier writes intact, and
// then releases it; a failure to close the savepoint is joined to fn's. A
// panic in fn, or in a statement that closes the savepoint, rolls back to it
// and releases it before the panic goes on. The statements that close the
// savepoint run even when ctx is done, since leaving it open would leave the
// caller's transaction aborted, or commit fn's writes with the caller's.
func Atomically[Q any](ctx context.Context, t Transactor[Q], q Q, ambient bool, fn func(q Q) error) error {
	if ambient {
		return underSavepoint(ctx, t, q, fn)
	}

	tx, err := t.Begin(ctx, q)
	if err != nil {
		return err
	}
	defer t.Rollback(ctx)

	if err := fn(tx); err != nil {
		return err
	}

	return t.Commit(ctx)
}

// underSavepoint runs fn on q, a caller's transaction, under a savepoint of
// its own, as Atomically describes.
func underSavepoint[Q any](ctx context.Context, t Transactor[Q], q Q, fn func(q Q) error) error {
	name := t.SavepointName()

	if err := t.ExecSavepoint(ctx, q, "SAVEPOINT "+name); err != nil {
		return err
	}

	closeCtx := context.WithoutCancel(ctx)
	exec := func(stmt string) error { return t.ExecSavepoint(closeCtx, q, stmt+name) }

	// open is cleared by every normal return, which has already closed the
	// savepoint or tried to; only a panic leaves it set.
	open := true
	defer func() {
		if open {
			BestEffort(func() { _ = exec("ROLLBACK TO SAVEPOINT ") })
			BestEffort(func() { _ = exec("RELEASE SAVEPOINT ") })
		}
	}()

	err := fn(q)

	if err != nil {
		rbErr := exec("ROLLBACK TO SAVEPOINT ")
		if rbErr == nil {
			rbErr = exec("RELEASE SAVEPOINT ")
		}
		open = false
		if rbErr != nil {
			return errors.Join(err, rbErr)
		}

		return err
	}

	relErr := exec("RELEASE SAVEPOINT ")
	open = false

	return relErr
}

// SessionTx is one store's driver side of Supersede, for one call: its
// transaction, its statements, and the encodings only the driver knows.
// Every error a method returns is the store's own, and is returned as it is.
type SessionTx[Q any] interface {
	Transactor[Q]
	// Exec runs stmt with args on q, and reports how many rows it changed.
	Exec(ctx context.Context, q Q, stmt string, args ...any) (int64, error)
	// QueryInt runs stmt with args on q, and reads the one integer it selects.
	QueryInt(ctx context.Context, q Q, stmt string, args ...any) (int, error)
	// InsertSuccessor inserts the supersession's successor on q, and reports
	// false when its identifier is stored already, having written nothing.
	InsertSuccessor(ctx context.Context, q Q) (bool, error)
	// NullTime is t as the driver binds a nullable timestamp: NULL for the
	// zero time.
	NullTime(t time.Time) any
	// Failed is err, a refusal Supersede judged, wrapped as the store wraps
	// the failures of the operation.
	Failed(err error) error
}

// CheckSupersession refuses a supersession no store runs, before any
// statement: one with no successor, a successor with no family (the nil
// family) or no family start time, or a retention deadline before the end of its window.
func CheckSupersession(op session.Supersession) error {
	switch {
	case op.Successor == nil:
		return errors.New("a supersession needs a successor")
	case op.Successor.FamilyID.IsZero():
		return errors.New("a successor with no family cannot be stored")
	case op.Successor.FamilyCreatedAt.IsZero():
		return errors.New("a successor with no family start time cannot be stored")
	case op.RetainUntil.Before(op.AcceptUntil):
		return errors.New("the retention deadline is before the end of the window")
	default:
		return nil
	}
}

// Supersede runs the supersession op on q, the handle the call resolved to,
// as one unit through Atomically.
//
// It locks Old and its observed previous successor, then updates Old,
// conditional on what the supersession observed. When that changes no row,
// the refusal is read and mapped by SupersedeRefusal: nothing is written.
// It then supersedes the observed previous successor, if any, where no row
// changed is session.ErrSuccessorAdvanced; and it inserts the successor,
// where an identifier stored already is an error. Each outcome is the
// first refusal met, and a refusal rolls everything back.
//
// op is refused by CheckSupersession first, wrapped by tx.Failed.
func Supersede[Q any](ctx context.Context, tx SessionTx[Q], q Q, ambient bool, op session.Supersession) error {
	if err := CheckSupersession(op); err != nil {
		return tx.Failed(err)
	}
	oldDigest := SessionDigest(op.Old)
	observed := OptionalDigestArg(op.ObservedSuccessor)
	retainUntil := tx.NullTime(op.RetainUntil)

	return Atomically(ctx, tx, q, ambient, func(q Q) error {
		if _, err := tx.Exec(ctx, q, pgschema.SessionLockSupersession, oldDigest, observed); err != nil {
			return err
		}

		n, err := tx.Exec(ctx, q, pgschema.SessionSupersedeOld, oldDigest, observed, Time(op.Now),
			Time(op.AcceptUntil), SessionDigest(op.Successor.ID), retainUntil)
		if err != nil {
			return err
		}
		if n == 0 {
			cause, err := tx.QueryInt(ctx, q, pgschema.SessionSupersedeRefusal, oldDigest)
			if err != nil {
				return err
			}

			return SupersedeRefusal(cause, tx.Failed(errors.New("a session with no family cannot be superseded")))
		}

		if len(op.ObservedSuccessor) > 0 {
			n, err := tx.Exec(ctx, q, pgschema.SessionSupersedePrevious, op.ObservedSuccessor, Time(op.Now),
				op.RequireUnpresentedSuccessor, retainUntil)
			if err != nil {
				return err
			}
			if n == 0 {
				return session.ErrSuccessorAdvanced
			}
		}

		inserted, err := tx.InsertSuccessor(ctx, q)
		if err != nil {
			return err
		}
		if !inserted {
			return tx.Failed(errors.New("the successor's identifier is already in use"))
		}

		return nil
	})
}
