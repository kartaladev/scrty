package noaliasgorm

import (
	"context"

	"gorm.io/gorm"

	"github.com/kartaladev/scrty/store/gormstore"
)

// WithGormTx binds a GORM transaction to ctx through the GORM backend.
func WithGormTx(ctx context.Context, tx *gorm.DB) context.Context {
	return gormstore.WithTx(ctx, tx)
}
