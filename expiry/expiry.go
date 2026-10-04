package expiry

import (
	"context"
	"errors"
	"time"
)

// Task is one kind of expired state and the purge that deletes it.
//
// A Task has no retention window, cutoff or time field, and none can be added
// through the runner: Run asks the component that owns the state to delete what
// that component deems deletable, by the window it is configured with. Built-in
// tasks come from their owning packages. A consumer adds a task for state of
// their own by supplying Run, and owns its cutoff.
type Task struct {
	// Name identifies the task in logs, results and a scheduler's lock key. It
	// is required and unique within a runner. Built-in tasks carry stable
	// default names; a consumer may rename one, for example to tell two
	// instances of the same owner apart.
	Name string

	// Interval is how often a scheduler runs the task. Zero means the
	// scheduler's default. Manual runs ignore it. Built-in tasks leave it zero,
	// because only the deployment knows its cadence. It must not be negative.
	Interval time.Duration

	// Run deletes the expired state through its owner and returns how many
	// records it removed. It is required. A Run that removed some records and
	// then failed returns both the count and the error; the run is reported as
	// a failure that keeps the count. Run should honour ctx: the runner cannot
	// interrupt a Run that ignores it.
	Run func(ctx context.Context) (removed int, err error)
}

// Result is the outcome of one task run.
type Result struct {
	// Task is the task's name.
	Task string
	// Removed is the count Run returned, kept even when Err is set.
	Removed int
	// Skipped reports that Run was not called: the task was already running
	// in this runner (Err wraps ErrTaskBusy), or the context was done before
	// the task started (Err is the context's error).
	Skipped bool
	// Err is the task's failure, nil on success. A recovered panic wraps
	// ErrTaskPanicked and carries the panic value in its message.
	Err error
	// Elapsed is how long Run took, measured with the runner's clock. It is
	// zero for a skipped result.
	Elapsed time.Duration
}

// Report holds the results of a RunOnce, one per task, in declared order.
type Report struct{ Results []Result }

var (
	// ErrNoTasks is returned by NewRunner given no tasks, because a runner with
	// none would appear to work while reclaiming nothing.
	ErrNoTasks = errors.New("expiry: a runner needs at least one task")

	// ErrInvalidTask is wrapped by NewRunner's error for a task with an empty
	// name, a nil Run or a negative Interval. The message names the task.
	ErrInvalidTask = errors.New("expiry: invalid task")

	// ErrDuplicateTask is wrapped by NewRunner's error when two tasks share a
	// name. The message names it.
	ErrDuplicateTask = errors.New("expiry: duplicate task name")

	// ErrUnknownTask is wrapped by RunTask's error for a name the runner does
	// not have. No task runs.
	ErrUnknownTask = errors.New("expiry: unknown task")

	// ErrTaskBusy is wrapped by the error of a skipped result whose task was
	// already running in the same runner.
	ErrTaskBusy = errors.New("expiry: task already running")

	// ErrTaskPanicked is wrapped by the error of a result whose Run panicked.
	// The message carries the task name and the panic value.
	ErrTaskPanicked = errors.New("expiry: task panicked")

	// ErrPurgeUnsupported is matched, alongside the owner's own sentinel, by
	// the error of any built-in task whose owner's store cannot purge. Such a
	// task fails; it never reports zero removed. Alerting on this one sentinel
	// covers every owner.
	ErrPurgeUnsupported = errors.New("expiry: the owner's store cannot purge")

	// ErrInvalidOption is wrapped by NewRunner's error for a nil option or an
	// option handed a meaningless value.
	ErrInvalidOption = errors.New("expiry: invalid option")
)
