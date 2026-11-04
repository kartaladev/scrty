package httpsec

import "net/http"

// oidcNotBuilt answers an endpoint whose handler its lane has not yet written. It
// refuses rather than passes on, so the application behind the chain never sees a
// request meant for the provider. It goes once the last stub file does.
func oidcNotBuilt(ex *Exchange, _ Next) error {
	ex.Writer.WriteHeader(http.StatusNotImplemented)

	return nil
}
