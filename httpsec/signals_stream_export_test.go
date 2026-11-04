package httpsec

import (
	"context"
	"encoding/json"
	"time"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// StreamRules is streamRules, what a stream's set and configuration decide about its time.
type StreamRules struct{ Warning, Assurance, ReasonWindow time.Duration }

func (r StreamRules) in() streamRules {
	return streamRules{warning: r.Warning, assurance: r.Assurance, reasonWindow: r.ReasonWindow}
}

// HeldSignIn is heldSignIn, what a stream holds of its sign-in between reloads.
type HeldSignIn struct {
	State     session.SignInState
	Warned    string
	LapsedFor time.Time
}

func (h HeldSignIn) in() heldSignIn {
	return heldSignIn{state: h.State, warned: h.Warned, lapsedFor: h.LapsedFor}
}

// StreamRead is streamRead, what one reload found.
type StreamRead struct {
	State               session.SignInState
	Gone, UserGone      bool
	SessionErr, UserErr error
}

// StreamVerdict is streamVerdict, what a reload decides.
type StreamVerdict struct {
	End                       string
	Alive, Failed, Unreported bool
}

// StreamEvent is one event a stream's held state says is due, its data as JSON.
type StreamEvent struct{ Name, Data string }

// StreamReportGrace is how long a stream waits for an end's report once a read has said gone.
const StreamReportGrace = streamReportGrace

// Jittered is jittered.
func Jittered(d time.Duration, fraction, roll float64) time.Duration {
	return jittered(d, fraction, roll)
}

// EarlierDeadline is earlierDeadline.
func EarlierDeadline(s session.SignInState) (string, time.Time) { return earlierDeadline(s) }

// Speak is streamRules.speak, and returns the state it leaves.
func (r StreamRules) Speak(h HeldSignIn, now time.Time) ([]StreamEvent, HeldSignIn) {
	held := h.in()
	events := r.in().speak(&held, now)

	out := make([]StreamEvent, 0, len(events))

	for _, e := range events {
		data, err := json.Marshal(e.data)
		if err != nil {
			panic(err)
		}

		out = append(out, StreamEvent{Name: e.name, Data: string(data)})
	}

	return out, HeldSignIn{State: held.state, Warned: held.warned, LapsedFor: held.lapsedFor}
}

// NextSpeech is streamRules.nextSpeech.
func (r StreamRules) NextSpeech(h HeldSignIn, now time.Time) time.Time {
	return r.in().nextSpeech(h.in(), now)
}

// Judge is streamRules.judge. A notice is a reason and when it was received, and nil for none.
func (r StreamRules) Judge(h HeldSignIn, read StreamRead, reuse, notice *EndNotice, now time.Time) StreamVerdict {
	v := r.in().judge(h.in(), streamRead{
		state: read.State, gone: read.Gone, userGone: read.UserGone,
		sessionErr: read.SessionErr, userErr: read.UserErr,
	}, reuse.in(), notice.in(), now)

	return StreamVerdict{End: v.end, Alive: v.alive, Failed: v.failed, Unreported: v.unreported}
}

// EndNotice is endNotice.
type EndNotice struct {
	Reason string
	At     time.Time
}

func (n *EndNotice) in() *endNotice {
	if n == nil {
		return nil
	}

	return &endNotice{reason: n.Reason, at: n.At}
}

// SignalReloadCounts is what the stream counted of its reloads: every failure, and the
// failures in a row of the streams now open.
func SignalReloadCounts(c *Chain) (total, consecutive uint64) {
	return c.signalsEndpoint().reloadCounts()
}

// StreamAnswer hands a stream's body a read's answer saying the sign-in is gone, with a report of
// ended held, and its stream told to close first when closing is true, and returns why it closed.
func StreamAnswer(ctx context.Context, c *Chain, w EventWriter, closing bool) string {
	e := c.signalsEndpoint()
	st := newSignalStream("u-1", id.ID{}, "", "", signalFilter{})

	st.noteEnd(endNotice{reason: reasonEnded, at: e.clock.Now()})

	if closing {
		close(st.closing)
	}

	l := &streamLoop{e: e, w: w, start: streamStart{stream: st}, rules: e.streamRules(st)}

	l.held.state.IdleDeadline = time.Now().Add(time.Hour)
	l.held.state.AbsoluteDeadline = l.held.state.IdleDeadline

	return l.answer(ctx, streamRead{gone: true})
}
