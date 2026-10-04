// Package expiry deletes expired security state through the purge operations of
// the components that own it.
//
// # Tasks
//
// A Task pairs a stable name with a Run that asks one owner to delete its
// expired state: sessions, one-time tokens of a purpose, login attempts past
// the lockout window, and so on. Each owning package provides a constructor for
// its own task, and a consumer writes a Task for state of their own.
//
// # No retention window
//
// No Task field, runner option or constructor parameter accepts a retention
// window, cutoff or time. The cutoff always belongs to the owner, which derives
// it from the window it is configured with. This is what keeps a sweep from
// freeing quota: deleting login attempts or issued tokens before the owner's
// window has passed would reset counts that rate limits, issuance limits and
// account lockout decide on. A consumer who wants a shorter or longer window
// configures the owner, not the sweep.
//
// # Manual and scheduled runs
//
// A Runner runs its tasks sequentially on the caller's goroutine, isolating
// each task's failure or panic in its Result. RunOnce runs every task and
// returns errors.Join of the failures, for a manual caller such as a CronJob's
// main that should exit non-zero. RunTask runs one task by name, which is what
// a scheduler calls on each task's Interval. The runner itself never schedules
// anything and starts no goroutine.
//
// A task already running in a runner is skipped with ErrTaskBusy, whether the
// second call comes from a scheduler tick or a concurrent manual run, so one
// task never runs twice at once in one runner.
//
// # Reporting
//
// Every run produces a Result: logged at DEBUG with its count on success, at
// ERROR on failure, and at WARN when skipped, then handed to the observer
// registered with WithObserver. A Run that removed records and then failed is a
// failure that keeps its count. A log record carries a fixed reason and the
// error's type, not the error's text; the observer and the caller get the
// full error in the Result.
//
// # Stated limits
//
// A purge that ignores its context is not interrupted. WithRunTimeout gives
// each run a context deadline, but the runner starts no goroutine to enforce it:
// a Run that does not watch its context keeps going, and the next task starts
// once it returns. Whether a running DELETE stops at the deadline is up to the
// store's driver.
//
// Each run calls the owner's purge once, with no batch size or cap. On a table
// that has never been swept, the first run is one large delete. Run the first
// sweep manually in a maintenance window, or supply a Run whose purge bounds
// itself.
package expiry
