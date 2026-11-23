package pgxstore_test

import (
	"context"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/store/pgxstore"
)

// linkRemover is the single-link removal a store offers beside oidc.LinkStore.
type linkRemover interface {
	DeleteLink(ctx context.Context, link oidc.Link) (bool, error)
}

var _ linkRemover = (*pgxstore.LinkStore)(nil)
