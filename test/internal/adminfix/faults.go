package adminfix

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The fault hooks install a row trigger on scrty_resource_privileges that
// fires only on an insert for one role and resource, so a fault stays with the
// case that named it, and remove it in the fixture's test cleanup.

// stallBound is how long a stalled grant write sleeps before it fails on its
// own: a case that never cancels the call cannot hold the transaction, and the
// locks it took, past it.
const stallBound = 120 * time.Second

// stallPoll is how often StallGrantWrite looks for the stalled session.
const stallPoll = 20 * time.Millisecond

// FailGrantWrite makes every later insert of a privilege of role on
// group/resource raise an error, so ReplaceGrants fails inside its transaction
// at that resource, after it removed the resource's old grants and wrote every
// resource listed before it. The trigger is removed when f.T ends.
func (f Fixture) FailGrantWrite(ctx context.Context, role, group, resource string) error {
	_, err := f.installGrantFault(ctx, role, group, resource,
		`RAISE EXCEPTION 'adminfix: injected grant write failure';`)

	return err
}

// StallGrantWrite makes the next insert of a privilege of role on
// group/resource sleep inside its transaction until the statement is
// cancelled (or stallBound passes, then fail). The returned channel is closed
// once a session is seen sleeping there in pg_stat_activity: the trigger names
// its session through application_name, local to its transaction, so the
// watch finds exactly this fault's session. The trigger is removed, and the
// watch stopped, when f.T ends.
func (f Fixture) StallGrantWrite(ctx context.Context, role, group, resource string) (<-chan struct{}, error) {
	marker := "adminfix-stall-" + strings.ToLower(rand.Text())
	body := fmt.Sprintf(`PERFORM set_config('application_name', %s, true);
PERFORM pg_sleep(%d);
RAISE EXCEPTION 'adminfix: stalled grant write was never cancelled';`,
		quoteLiteral(marker), int(stallBound/time.Second))

	if _, err := f.installGrantFault(ctx, role, group, resource, body); err != nil {
		return nil, err
	}

	stalled := make(chan struct{})
	watchCtx, stop := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})

	go func() {
		defer close(done)
		f.watchStall(watchCtx, marker, stalled)
	}()

	f.T.Cleanup(func() {
		stop()
		<-done
	})

	return stalled, nil
}

// watchStall closes stalled once a session whose application_name is marker
// waits in pg_sleep, polling until ctx ends.
func (f Fixture) watchStall(ctx context.Context, marker string, stalled chan<- struct{}) {
	ticker := time.NewTicker(stallPoll)
	defer ticker.Stop()

	for {
		var sleeping bool
		err := f.DB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
WHERE application_name = $1 AND wait_event = 'PgSleep')`, marker).Scan(&sleeping)
		if err == nil && sleeping {
			close(stalled)

			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// installGrantFault creates a trigger function running body, and a BEFORE
// INSERT row trigger on scrty_resource_privileges that calls it for role on
// group/resource only, in one transaction, and registers their removal in
// f.T's cleanup. It returns the name both share.
func (f Fixture) installGrantFault(ctx context.Context, role, group, resource, body string) (string, error) {
	if f.T == nil {
		return "", errors.New("adminfix: the fault hooks need Fixture.T to remove what they install")
	}
	for _, v := range []string{role, group, resource} {
		if strings.ContainsRune(v, 0) {
			return "", errors.New("adminfix: a fault target holds a NUL byte")
		}
	}

	// A name of the fixture's own, never from input: lower-case base32.
	name := "adminfix_fault_" + strings.ToLower(rand.Text())

	stmts := []string{
		fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $fault$
BEGIN
%s
RETURN NEW;
END
$fault$`, name, body),
		fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON scrty_resource_privileges FOR EACH ROW
WHEN (NEW.role_name = %s AND NEW.resource_group = %s AND NEW.resource = %s)
EXECUTE FUNCTION %s()`, name, quoteLiteral(role), quoteLiteral(group), quoteLiteral(resource), name),
	}

	tx, err := f.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("adminfix: install grant fault: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return "", fmt.Errorf("adminfix: install grant fault: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("adminfix: install grant fault: %w", err)
	}

	cleanupCtx := context.WithoutCancel(ctx)
	f.T.Cleanup(func() { f.removeGrantFault(cleanupCtx, name) })

	return name, nil
}

// removeGrantFault drops the trigger and its function, failing f.T when it
// cannot. Cleanup runs after the test's context is cancelled, so the caller
// passes a context detached from that cancellation; it is bounded here.
func (f Fixture) removeGrantFault(parent context.Context, name string) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	for _, stmt := range []string{
		fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON scrty_resource_privileges`, name),
		fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, name),
	} {
		if _, err := f.DB.ExecContext(ctx, stmt); err != nil && !errors.Is(err, sql.ErrConnDone) {
			f.T.Errorf("adminfix: remove grant fault: %v", err)
		}
	}
}

// quoteLiteral is s as a PostgreSQL string literal, for a server with
// standard_conforming_strings on (the default since 9.1): its single quotes
// are doubled. s holds no NUL byte; the caller refuses one.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
