package onetime_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// TestTokensIssue_DependencyErrorTextIsFixed pins that an error from the
// consumer's random reader or id generator reaches the caller behind the
// library's own text. It shares ptMintRun with the port-error rows of this
// package.
func TestTokensIssue_DependencyErrorTextIsFixed(t *testing.T) {
	cause := errors.New("hsm slot u-123 offline")

	tests := []struct {
		name   string
		source ptMintSource
	}{
		{name: "random reader fails", source: ptReader},
		{name: "id generator fails", source: ptGenerator},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := ptMintRun(t, tc.source, false, cause)

			require.False(t, out.ok)
			assert.NotContains(t, out.text, "u-123")
		})
	}
}

// TestTokensIssue_GeneratorFailureIsNotErrNil pins that only the generator
// answering the nil identifier matches idgen.ErrNil; a consumer's own error
// keeps its cause for errors.Is, carries none of its text, and never matches
// the library sentinel.
func TestTokensIssue_GeneratorFailureIsNotErrNil(t *testing.T) {
	cause := errors.New("rng down u-123")

	tests := []struct {
		name   string
		id     id.ID
		err    error
		assert func(t *testing.T, err error)
	}{
		{
			name: "a consumer error does not match ErrNil",
			err:  cause,
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, idgen.ErrNil)
				assert.ErrorIs(t, err, cause)
				assert.NotContains(t, err.Error(), "u-123")
			},
		},
		{
			name: "the nil identifier matches ErrNil",
			id:   id.Nil,
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, idgen.ErrNil)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gen := NewMockGenerator(gomock.NewController(t))
			gen.EXPECT().NewID().Return(tc.id, tc.err)

			m, err := onetime.New("gen-purpose", onetime.WithIDGenerator(gen))
			require.NoError(t, err)

			_, _, err = m.Issue(t.Context(), "ada@example.com")
			tc.assert(t, err)
		})
	}
}
