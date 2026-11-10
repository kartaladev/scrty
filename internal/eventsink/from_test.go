package eventsink_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/eventsink"
)

func TestFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ctx    func(ctx context.Context, emit eventsink.Emitter) context.Context
		assert func(t *testing.T, got eventsink.Emitter, called *int)
	}{
		{
			name: "a context carrying an emitter returns it",
			ctx:  func(ctx context.Context, emit eventsink.Emitter) context.Context { return eventsink.With(ctx, emit) },
			assert: func(t *testing.T, got eventsink.Emitter, called *int) {
				t.Helper()
				if assert.NotNil(t, got) {
					got(t.Context(), event.Event{})
					assert.Equal(t, 1, *called, "the emitter returned is the one the context carries")
				}
			},
		},
		{
			name: "a context carrying none returns nil",
			ctx:  func(ctx context.Context, _ eventsink.Emitter) context.Context { return ctx },
			assert: func(t *testing.T, got eventsink.Emitter, _ *int) {
				t.Helper()
				assert.Nil(t, got)
			},
		},
		{
			name: "a nil emitter set over one returns nil",
			ctx: func(ctx context.Context, emit eventsink.Emitter) context.Context {
				return eventsink.With(eventsink.With(ctx, emit), nil)
			},
			assert: func(t *testing.T, got eventsink.Emitter, _ *int) {
				t.Helper()
				assert.Nil(t, got)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var called int
			emit := func(context.Context, event.Event) { called++ }
			tt.assert(t, eventsink.From(tt.ctx(t.Context(), emit)), &called)
		})
	}
}
