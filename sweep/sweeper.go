package sweep

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"

	"github.com/kartaladev/scrty/expiry"
)

// JobPrefix starts the name of every job a Sweeper schedules: the job for the
// task "sessions" is "sweep:sessions". gocron passes the job name to a
// distributed locker as the lock key, so this is the key a consumer's locker
// sees.
const JobPrefix = "sweep:"

var (
	// ErrNoInterval is wrapped by New's error when a task has no Interval and
	// the sweeper has no default interval. The message names the task.
	ErrNoInterval = errors.New("sweep: task has no interval")

	// ErrAlreadyStarted is returned by Start on a sweeper already started.
	ErrAlreadyStarted = errors.New("sweep: already started")

	// ErrAlreadyShutdown is returned by Start on a sweeper that was shut
	// down, including one whose earlier Start failed partway.
	ErrAlreadyShutdown = errors.New("sweep: already shut down")

	// ErrInvalidOption is wrapped by New's error for a nil runner, a nil
	// option, or an option handed a meaningless value, and by the error of
	// Start or Shutdown for a nil context.
	ErrInvalidOption = errors.New("sweep: invalid option")
)

// Option configures a Sweeper. Every default New applies has an Option here
// that replaces it. An option handed a meaningless value makes New fail with
// ErrInvalidOption.
type Option func(*config) error

type config struct {
	defaultInterval time.Duration
	runImmediately  bool
	stopTimeout     time.Duration
	locker          gocron.Locker
	clock           clockwork.Clock
	logger          *slog.Logger

	// extraSchedOpts is a test seam (WithSchedulerOptionsForTest): scheduler
	// options appended after the ones New derives. No exported option sets it.
	extraSchedOpts []gocron.SchedulerOption
}

// WithDefaultInterval sets how often a task whose Interval is zero runs.
// Default: none. Without it, every task must carry its own Interval, or New
// fails with ErrNoInterval naming the first task that has none: the library
// does not pick a cadence, because one it picked would look like one the
// deployment chose. A zero or negative d fails construction with
// ErrInvalidOption.
func WithDefaultInterval(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: default interval %s is not positive", ErrInvalidOption, d)
		}
		c.defaultInterval = d
		return nil
	}
}

// WithRunImmediately makes each task run once as soon as Start is called,
// then on its interval from there. Default: off; each task's first run waits
// one interval.
//
// The default is off because the first sweep of a table that has never been
// swept can be one very large delete, and a sweep at start fires on every
// replica each time a deployment rolls out. Run the first sweep manually in a
// maintenance window (expiry.Runner.RunOnce) before turning this on.
func WithRunImmediately() Option {
	return func(c *config) error {
		c.runImmediately = true
		return nil
	}
}

// WithDistributedLocker has each run first take a lock from l, keyed by the
// job name (JobPrefix + task name), and skip the run when l refuses. A lock
// failure is logged at ERROR with the task and job names, and the task runs
// again at its next tick. Default: no lock, so every process running a
// Sweeper sweeps independently, and replicas sweep the same tables
// concurrently.
//
// The lock is gocron's: l is handed to gocron.WithDistributedLocker, which
// holds it for the length of the run. Whether two replicas actually serialise
// depends on l. This package's tests prove the locker is consulted with the
// job name before each run; they do not, and cannot, prove that a given
// locker excludes a second replica. A nil l, including a typed nil, fails
// construction with ErrInvalidOption.
func WithDistributedLocker(l gocron.Locker) Option {
	return func(c *config) error {
		if isNil(l) {
			return fmt.Errorf("%w: nil distributed locker", ErrInvalidOption)
		}
		c.locker = l
		return nil
	}
}

// WithClock sets the clock gocron schedules runs with. Default:
// clockwork.NewRealClock(). Tests pass a clockwork.FakeClock to drive the
// schedule.
//
// It takes a clockwork.Clock, unlike the rest of scrty, which takes the
// standard-library-typed clock.Clock: the clock goes straight to gocron's own
// WithClock, which requires exactly that type, and adapting a narrower clock
// would mean inventing behaviour for timer methods scrty never reads. It does
// not set the clock a run's Elapsed is measured with; that is the runner's
// (expiry.WithClock). A nil c, including a typed nil, fails construction with
// ErrInvalidOption.
func WithClock(c clockwork.Clock) Option {
	return func(cfg *config) error {
		if isNil(c) {
			return fmt.Errorf("%w: nil clock", ErrInvalidOption)
		}
		cfg.clock = c
		return nil
	}
}

// WithLogger sets where the sweeper logs a distributed lock failure.
// Default: slog.Default(). A run's own outcome is logged by the runner
// (expiry.WithLogger), not here. A lock failure record carries the task and
// job names, a fixed reason and the error's Go type, never the error's text,
// which comes from the consumer's locker. When the error is, or wraps,
// context.Canceled or context.DeadlineExceeded, the record also carries
// cancelled=true, so a lock abandoned at shutdown can be told from a refusal.
// A nil l fails construction with ErrInvalidOption.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) error {
		if l == nil {
			return fmt.Errorf("%w: nil logger", ErrInvalidOption)
		}
		c.logger = l
		return nil
	}
}

// defaultStopTimeout is how long Shutdown waits for a running purge when
// WithStopTimeout is not given. It is gocron's own default.
const defaultStopTimeout = 10 * time.Second

// WithStopTimeout sets how long Shutdown waits for a running purge to return
// after cancelling its context. Default: 10 seconds, gocron's own default.
// Shutdown waits up to this timeout or until its own ctx is done, whichever
// ends first; a purge still running when the timeout elapses keeps running,
// and Shutdown returns an error wrapping gocron.ErrStopJobsTimedOut. d is
// handed to gocron.WithStopTimeout and measured on the sweeper's clock
// (WithClock). gocron also arms a real-time backstop of d plus one second: on
// a clock that does not advance, such as a fake clock nobody moves, Shutdown
// gives up when the backstop fires and returns an error wrapping
// gocron.ErrStopExecutorTimedOut instead; the backstop is also what ensures
// the shutdown always completes. A zero or negative d fails construction
// with ErrInvalidOption.
func WithStopTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: stop timeout %s is not positive", ErrInvalidOption, d)
		}
		c.stopTimeout = d
		return nil
	}
}

// isNil reports whether v is nil or an interface holding a nil pointer, map,
// slice, func or channel.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	default:
		return false
	}
}

type state int

const (
	stateNew state = iota
	stateStarted
	stateShutdown
)

type job struct {
	task     string
	interval time.Duration
}

// Sweeper runs each task of an expiry.Runner on its own gocron job.
//
// Each task gets one job, named JobPrefix + the task's name, which calls
// Runner.RunTask on the task's Interval, or on the default interval when the
// task's is zero. A tick that arrives while the same task is still running is
// dropped, not queued (gocron's singleton mode with LimitModeReschedule), so a
// slow purge never has runs stacked up behind it. The runner logs and reports
// every run's Result; the sweeper adds only the log record for a refused
// distributed lock.
//
// Without WithDistributedLocker, every replica sweeps. Without
// WithRunImmediately, the first run of each task waits one interval.
//
// gocron starts its goroutine when New builds the scheduler, so a Sweeper
// must be shut down even if it is never started.
//
// A Sweeper is safe for concurrent use. Build one with New.
type Sweeper struct {
	runner *expiry.Runner
	sched  gocron.Scheduler
	jobs   []job
	cfg    config

	mu    sync.Mutex
	state state

	// shutdownDone is closed once the one gocron shutdown has returned, and
	// shutdownErr then holds its result. shutdownErr is written only before
	// the close and read only after it.
	shutdownDone chan struct{}
	shutdownErr  error
}

// New builds a Sweeper over r. It fails, before anything is scheduled, when:
//   - r is nil, an option is nil, or an option is handed a meaningless value:
//     ErrInvalidOption;
//   - a task has no Interval and no default interval is set: ErrNoInterval,
//     naming the task.
//
// New builds the gocron scheduler, which starts a goroutine; call Shutdown to
// release it whether or not Start is called.
func New(r *expiry.Runner, opts ...Option) (*Sweeper, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil runner", ErrInvalidOption)
	}

	cfg := config{clock: clockwork.NewRealClock(), logger: slog.Default(), stopTimeout: defaultStopTimeout}
	for i, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: option %d is nil", ErrInvalidOption, i)
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	tasks := r.Tasks()
	jobs := make([]job, 0, len(tasks))
	for _, t := range tasks {
		interval := t.Interval
		if interval == 0 {
			interval = cfg.defaultInterval
		}
		if interval <= 0 {
			return nil, fmt.Errorf("%w: task %q, and no default interval is set", ErrNoInterval, t.Name)
		}
		jobs = append(jobs, job{task: t.Name, interval: interval})
	}

	schedOpts := []gocron.SchedulerOption{gocron.WithClock(cfg.clock), gocron.WithStopTimeout(cfg.stopTimeout)}
	if cfg.locker != nil {
		schedOpts = append(schedOpts, gocron.WithDistributedLocker(cfg.locker))
	}
	schedOpts = append(schedOpts, cfg.extraSchedOpts...)
	sched, err := gocron.NewScheduler(schedOpts...)
	if err != nil {
		return nil, fmt.Errorf("sweep: building the scheduler: %w", err)
	}

	return &Sweeper{runner: r, sched: sched, jobs: jobs, cfg: cfg, shutdownDone: make(chan struct{})}, nil
}

// Start schedules one job per task and starts the scheduler. It returns
// ErrAlreadyStarted on a second call and ErrAlreadyShutdown after Shutdown.
// A nil ctx is refused with ErrInvalidOption and changes nothing, so a later
// Start with a real context still works.
//
// ctx bounds each run: it is the parent of the context every run receives,
// and once it is done no further run starts and a running purge sees its
// cancellation. The sweeper's goroutines are released only by Shutdown, which
// is still required after ctx is done.
//
// If scheduling fails partway, Start shuts the sweeper down before returning
// the error, so no task is left half-scheduled, and a retry gets
// ErrAlreadyShutdown rather than registering jobs twice.
func (s *Sweeper) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidOption)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case stateStarted:
		return ErrAlreadyStarted
	case stateShutdown:
		return ErrAlreadyShutdown
	}

	for _, j := range s.jobs {
		if err := s.schedule(ctx, j); err != nil {
			// The scheduler was never started, so its shutdown only stops
			// its goroutine; the scheduling error is the one to report.
			s.beginShutdownLocked(ctx)
			return fmt.Errorf("sweep: scheduling task %q: %w", j.task, err)
		}
	}

	s.sched.Start()
	s.state = stateStarted
	return nil
}

func (s *Sweeper) schedule(ctx context.Context, j job) error {
	name := JobPrefix + j.task
	opts := []gocron.JobOption{
		gocron.WithName(name),
		// Never WithLimitConcurrentJobs: combined with singleton mode,
		// cancellation can skip cleanup (gocron issue #959).
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithContext(ctx),
		gocron.WithEventListeners(gocron.AfterLockError(s.lockFailed(ctx, j.task))),
	}
	if s.cfg.runImmediately {
		opts = append(opts, gocron.WithStartAt(gocron.WithStartImmediately()))
	}

	task := j.task
	_, err := s.sched.NewJob(
		gocron.DurationJob(j.interval),
		gocron.NewTask(func(ctx context.Context) {
			// The runner logs and reports the Result; its error is the
			// Result's own.
			_, _ = s.runner.RunTask(ctx, task)
		}),
		opts...,
	)
	return err
}

// lockFailed returns the listener gocron calls when the distributed locker
// refuses a run of task. ctx is Start's, handed to the logger with the record.
func (s *Sweeper) lockFailed(ctx context.Context, task string) func(uuid.UUID, string, error) {
	return func(_ uuid.UUID, jobName string, err error) {
		attrs := []slog.Attr{
			slog.String("task", task),
			slog.String("job", jobName),
			// A fixed reason and the error's type, never its text: the
			// locker is the consumer's, and its text can quote anything.
			slog.String("reason", "lock"),
			slog.String("error_type", fmt.Sprintf("%T", err)),
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			attrs = append(attrs, slog.Bool("cancelled", true))
		}
		s.cfg.logger.LogAttrs(ctx, slog.LevelError,
			"sweep: distributed lock failed; run skipped", attrs...)
	}
}

// Shutdown stops scheduling, cancels the context of any run in progress, and
// waits for it to return, then releases the scheduler's goroutines. It does so
// whether or not Start was called.
//
// The scheduler is shut down exactly once, by the first call. Every call,
// concurrent or later, waits for that one shutdown to finish and returns its
// result: nil, or the error that says a running purge outlasted the stop
// timeout. Each call's wait is bounded by its own ctx; a call whose ctx ends
// first returns an error wrapping ctx.Err(), and the shutdown carries on, so
// a later call still waits for it and gets its result.
//
// The wait for a running purge is bounded by the stop timeout (WithStopTimeout,
// default 10 seconds) and by ctx, whichever ends first. A purge that ignores
// its context and outlasts either keeps running, and Shutdown returns the
// error that says so. On a clock that does not advance, gocron gives up after
// the stop timeout plus one second of real time, with an error wrapping
// gocron.ErrStopExecutorTimedOut; that backstop also ensures the shutdown
// always completes.
//
// A nil ctx is refused with ErrInvalidOption and changes nothing, so a later
// Shutdown with a real context still shuts the sweeper down.
func (s *Sweeper) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidOption)
	}

	s.mu.Lock()
	s.beginShutdownLocked(ctx)
	s.mu.Unlock()

	// Prefer a finished shutdown over a ctx that is already done.
	select {
	case <-s.shutdownDone:
		return s.shutdownResult()
	default:
	}
	select {
	case <-s.shutdownDone:
		return s.shutdownResult()
	case <-ctx.Done():
		return fmt.Errorf("sweep: shutting down: %w", ctx.Err())
	}
}

// beginShutdownLocked moves the sweeper to stateShutdown and starts the one
// gocron shutdown on its own goroutine, unless that has already happened. The
// caller holds s.mu. The shutdown keeps ctx's values but not its
// cancellation, so one caller giving up does not cut it short for the others;
// gocron bounds it by the stop timeout.
func (s *Sweeper) beginShutdownLocked(ctx context.Context) {
	if s.state == stateShutdown {
		return
	}
	s.state = stateShutdown
	// Detached here rather than inside the goroutine, so a bad ctx panics on
	// the caller's goroutine, where it can be seen, not on one nothing joins.
	detached := context.WithoutCancel(ctx)
	go func() {
		s.shutdownErr = s.sched.ShutdownWithContext(detached)
		close(s.shutdownDone)
	}()
}

func (s *Sweeper) shutdownResult() error {
	if s.shutdownErr != nil {
		return fmt.Errorf("sweep: shutting down: %w", s.shutdownErr)
	}
	return nil
}

// setInterval is the test seam behind SetIntervalForTest.
func (s *Sweeper) setInterval(task string, d time.Duration) {
	for i := range s.jobs {
		if s.jobs[i].task == task {
			s.jobs[i].interval = d
		}
	}
}
