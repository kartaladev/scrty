package prblmsec

import (
	"context"

	"github.com/kartaladev/prblm"
)

// Mapper returns the prblm mapper that answers scrty's refusals.
func (p *Problems) Mapper() prblm.Mapper {
	return prblm.MapperFunc(func(context.Context, error) *prblm.Problem { return nil })
}
