package expiry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
)

// Runner runs a fixed set of tasks, manually through RunOnce and RunTask or
// from a scheduler that calls RunTask on each task's interval.
//
// Tasks run one after another on the caller's goroutine; the runner starts no
// goroutine of its own. A task that fails or panics is recorded in its Result
// and the next task still runs. A task already running in this runner, whether
// started by a scheduler or by a concurrent manual call, is not run again: the
// second call is skipped with ErrTaskBusy rather than queued.
//
// A Runner is safe for concurrent use. Build one with NewRunner.
type Runner struct {
	tasks    []Task
	byName   map[string]int
	timeout  time.Duration
	observer func(Result)
	logger   *slog.Logger
	clock    clock.Clock

	mu      sync.Mutex
	running map[string]bool
}

// Option configures a Runner. Every default NewRunner applies has an Option
// here that replaces it. An option handed a meaningless value makes NewRunner
// fail with ErrInvalidOption.
type Option func(*Runner) error

// WithRunTimeout bounds each task run: the task's Run receives a context whose
// deadline is at most d after that task started. Default: 0, no deadline beyond
// the caller's context. A negative d fails construction with ErrInvalidOption.
//
// The deadline is advisory. The runner cannot interrupt a Run that ignores its
// context, and starts no goroutine to try: such a Run keeps going past the
// deadline, and the next task starts once it returns. Whether a running DELETE
// stops at the deadline is up to the store's driver.
func WithRunTimeout(d time.Duration) Option {
	return func(r *Runner) error {
		if d < 0 {
			return fmt.Errorf("%w: run timeout %s is negative", ErrInvalidOption, d)
		}
		r.timeout = d
		return nil
	}
}

// WithObserver registers fn to receive the Result of every task run, manual
// and scheduled alike, skipped results included. Default: no observer; results
// are only logged. A nil fn fails construction with ErrInvalidOption.
//
// fn is called synchronously on the run's goroutine, after the result's log
// record is written. It must neither block nor panic, because the next task
// waits for it. A consumer feeding results to slower code hands them off
// without blocking:
//
//	results := make(chan expiry.Result, 64)
//	runner, err := expiry.NewRunner(tasks, expiry.WithObserver(func(r expiry.Result) {
//		select {
//		case results <- r:
//		default: // never block a sweep on a slow consumer
//		}
//	}))
func WithObserver(fn func(Result)) Option {
	return func(r *Runner) error {
		if fn == nil {
			return fmt.Errorf("%w: observer is nil", ErrInvalidOption)
		}
		r.observer = fn
		return nil
	}
}

// WithLogger sets where each task run is logged. Default: slog.Default().
// A successful run is logged at DEBUG with its removed count, a failed run at
// ERROR, and a skipped run at WARN. Every record names the task. A failed or
// skipped record says what went wrong with a fixed reason (purge, panic,
// purge-unsupported, busy or cancelled) and the error's Go type, never the
// error's text, which comes from the owner's store; the full error is in the
// Result. A nil l fails construction with ErrInvalidOption.
func WithLogger(l *slog.Logger) Option {
	return func(r *Runner) error {
		if l == nil {
			return fmt.Errorf("%w: logger is nil", ErrInvalidOption)
		}
		r.logger = l
		return nil
	}
}

// WithClock sets the clock a task run's Elapsed is measured with. Default:
// clock.System(). It does not drive WithRunTimeout's deadline, which is a
// context deadline on real time. A nil c, including a typed nil, fails
// construction with ErrInvalidOption.
func WithClock(c clock.Clock) Option {
	return func(r *Runner) error {
		if nilcheck.IsNil(c) {
			return fmt.Errorf("%w: clock is nil", ErrInvalidOption)
		}
		r.clock = c
		return nil
	}
}

// NewRunner builds a Runner over tasks, which run in the order given.
//
// It fails, before any task runs, when the configuration would give a runner
// that appears to work while reclaiming nothing:
//   - no tasks: ErrNoTasks;
//   - a task with an empty name, a nil Run or a negative Interval:
//     ErrInvalidTask, naming the task;
//   - two tasks with the same name: ErrDuplicateTask, naming it;
//   - a nil option, a negative run timeout, or a nil observer, logger or clock:
//     ErrInvalidOption.
//
// The task slice is copied, so a caller reusing it afterwards does not change
// the runner.
func NewRunner(tasks []Task, opts ...Option) (*Runner, error) {
	if len(tasks) == 0 {
		return nil, ErrNoTasks
	}
	byName := make(map[string]int, len(tasks))
	for i, t := range tasks {
		switch {
		case t.Name == "":
			return nil, fmt.Errorf("%w: task at index %d has an empty name", ErrInvalidTask, i)
		case t.Run == nil:
			return nil, fmt.Errorf("%w: task %q has no Run", ErrInvalidTask, t.Name)
		case t.Interval < 0:
			return nil, fmt.Errorf("%w: task %q has a negative interval %s", ErrInvalidTask, t.Name, t.Interval)
		}
		if _, dup := byName[t.Name]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateTask, t.Name)
		}
		byName[t.Name] = i
	}

	r := &Runner{
		tasks:   slices.Clone(tasks),
		byName:  byName,
		running: make(map[string]bool, len(tasks)),
		logger:  slog.Default(),
		clock:   clock.System(),
	}
	for i, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: option at index %d is nil", ErrInvalidOption, i)
		}
		if err := opt(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Tasks returns a copy of the runner's tasks, in their declared order, for a
// scheduler to read names and intervals from. Changing the returned slice does
// not change the runner.
func (r *Runner) Tasks() []Task { return slices.Clone(r.tasks) }

// RunOnce runs every task once, in declared order, and returns one Result per
// task together with errors.Join of every result's error, nil when all
// succeeded. That includes skipped results: a busy task and a task not reached
// after cancellation each add their error (ErrTaskBusy, ctx.Err()) to it. A
// manual caller, such as a CronJob's main, can exit non-zero on that error.
//
// ctx is checked before each task. Once it is done no further task starts, and
// every task not reached is reported Skipped with ctx.Err(), even one that is
// running elsewhere. A task already running in this runner, while ctx is not
// done, is reported Skipped with ErrTaskBusy. A task's
// Interval is ignored.
func (r *Runner) RunOnce(ctx context.Context) (Report, error) {
	rep := Report{Results: make([]Result, 0, len(r.tasks))}
	var errs []error
	for _, t := range r.tasks {
		res := r.runOne(ctx, t)
		rep.Results = append(rep.Results, res)
		if res.Err != nil {
			errs = append(errs, res.Err)
		}
	}
	return rep, errors.Join(errs...)
}

// RunTask runs the task called name once and returns its Result, with the
// result's Err as the error. A name the runner does not have fails with
// ErrUnknownTask and runs nothing. A task already running in this runner is
// not run again: the result is Skipped with ErrTaskBusy. A ctx already done
// skips the task with ctx.Err(), whether or not the task is running elsewhere.
func (r *Runner) RunTask(ctx context.Context, name string) (Result, error) {
	i, ok := r.byName[name]
	if !ok {
		return Result{Task: name}, fmt.Errorf("%w: %q", ErrUnknownTask, name)
	}
	res := r.runOne(ctx, r.tasks[i])
	return res, res.Err
}

// runOne runs t unless ctx is done or t is already running, then reports the
// result. ctx is checked first, so a done context is never reported as busy and
// never marks the task as running.
func (r *Runner) runOne(ctx context.Context, t Task) Result {
	var res Result
	switch {
	case ctx.Err() != nil:
		res = Result{Task: t.Name, Skipped: true, Err: ctx.Err()}
	case r.acquire(t.Name):
		res = r.executeAndRelease(ctx, t)
	default:
		res = Result{Task: t.Name, Skipped: true, Err: fmt.Errorf("%w: %q", ErrTaskBusy, t.Name)}
	}
	r.report(ctx, res)
	return res
}

// executeAndRelease runs t and clears its busy mark in a defer, so no way out
// of execute, a recovered panic included, leaves t marked as running.
func (r *Runner) executeAndRelease(ctx context.Context, t Task) Result {
	defer r.release(t.Name)
	return r.execute(ctx, t)
}

// acquire marks name as running, and reports false when it already was.
func (r *Runner) acquire(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running[name] {
		return false
	}
	r.running[name] = true
	return true
}

// release clears name's busy mark.
func (r *Runner) release(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, name)
}

// execute runs t on the caller's goroutine under the run timeout, turning a
// panic into ErrTaskPanicked. It skips t when ctx is already done.
func (r *Runner) execute(ctx context.Context, t Task) (res Result) {
	res.Task = t.Name
	if err := ctx.Err(); err != nil {
		res.Skipped, res.Err = true, err
		return res
	}
	start := r.clock.Now()
	defer func() {
		if v := recover(); v != nil {
			res.Err = fmt.Errorf("%w: %s: %v", ErrTaskPanicked, t.Name, v)
		}
		res.Elapsed = r.clock.Now().Sub(start)
	}()
	runCtx := ctx
	if r.timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}
	res.Removed, res.Err = t.Run(runCtx)
	return res
}

// report logs res, then hands it to the observer.
//
// A failed or skipped record names what failed through diag.Failure: a fixed
// reason and the error's Go type, never the error's text, which comes from the
// owner's store and can quote values the library never saw. The full error is
// in the Result the observer and the caller receive.
func (r *Runner) report(ctx context.Context, res Result) {
	task := slog.String("task", res.Task)
	switch {
	case res.Skipped:
		attrs := append([]slog.Attr{task}, diag.Failure(skipReason(res.Err), res.Err)...)
		r.logger.LogAttrs(ctx, slog.LevelWarn, "expiry task skipped", attrs...)
	case res.Err != nil:
		attrs := append([]slog.Attr{task, slog.Int("removed", res.Removed), slog.Duration("elapsed", res.Elapsed)},
			diag.Failure(failReason(res.Err), res.Err)...)
		r.logger.LogAttrs(ctx, slog.LevelError, "expiry task failed", attrs...)
	default:
		r.logger.LogAttrs(ctx, slog.LevelDebug, "expiry task finished",
			task, slog.Int("removed", res.Removed), slog.Duration("elapsed", res.Elapsed))
	}
	if r.observer != nil {
		r.observer(res)
	}
}

// skipReason is the fixed word a skipped record carries.
func skipReason(err error) string {
	if errors.Is(err, ErrTaskBusy) {
		return "busy"
	}
	return "cancelled"
}

// failReason is the fixed word a failed record carries.
func failReason(err error) string {
	switch {
	case errors.Is(err, ErrTaskPanicked):
		return "panic"
	case errors.Is(err, ErrPurgeUnsupported):
		return "purge-unsupported"
	default:
		return "purge"
	}
}
