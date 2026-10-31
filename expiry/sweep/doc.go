// Package sweep runs the tasks of an expiry.Runner on a gocron v2 schedule.
//
// It is a separate module so that the core module carries no scheduler: an
// application that sweeps from a CronJob, or from a job system of its own,
// calls expiry.Runner directly and never depends on gocron.
//
//	runner, err := expiry.NewRunner(tasks)
//	// ...
//	sweeper, err := sweep.New(runner, sweep.WithDefaultInterval(15*time.Minute))
//	// ...
//	if err := sweeper.Start(ctx); err != nil { /* ... */ }
//	defer sweeper.Shutdown(context.WithoutCancel(ctx))
//
// # Jobs
//
// Each task gets one gocron job, named JobPrefix + the task's name
// ("sweep:sessions"), that calls Runner.RunTask on the task's Interval, or on
// the sweeper's default interval when the task's Interval is zero. A tick that
// arrives while the same task is still running is dropped, not queued, so a
// slow purge never has deletes stacked up behind it. The runner logs and
// reports every run; see expiry.WithLogger and expiry.WithObserver.
//
// # Defaults
//
//   - No interval: the library picks no cadence. A task with no Interval on a
//     sweeper without WithDefaultInterval fails New with ErrNoInterval.
//   - No sweep at start: each task's first run waits one interval. The first
//     sweep of a table that has never been swept can be one very large delete,
//     so run it manually in a maintenance window (expiry.Runner.RunOnce)
//     before relying on the schedule, or before turning on
//     WithRunImmediately.
//   - No lock: every replica running a Sweeper sweeps the same tables. Pass a
//     locker with WithDistributedLocker to have each run take a lock keyed by
//     its job name first. This package's tests prove the locker is consulted
//     with that key before each run; whether two replicas actually serialise
//     depends on the locker.
//
// # Lifecycle
//
// gocron starts a goroutine as soon as New builds the scheduler, so a Sweeper
// must be shut down even if it is never started. Shutdown is idempotent: the
// scheduler is shut down once, and every call waits for that shutdown and
// returns its result. It waits for a run in progress up to the stop timeout
// (WithStopTimeout, default 10 seconds) or its own context, whichever ends
// first. Start after Shutdown, or after a Start that
// failed partway, returns ErrAlreadyShutdown; a sweeper is never restarted.
package sweep
