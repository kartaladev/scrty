package httpsec

// This file is the stream's cross-site rule. Dispatch C2b owns it.

// crossSiteAllowed refuses, with an error matching ErrCrossSiteStream, a stream from an
// origin the chain does not trust, and answers nil otherwise.
//
// byCookie is true for a stream whose credential the browser sends on its own, and comes
// from streamByCookie: every stream but one whose recorded credential
// (Exchange.RecordPresentedToken) is what its Authorization header carries. Recording
// alone does not make a bearer, because a consumer's cookie authenticator records too.
//
// e.cors is the chain's CORS policy, nil with none, and e.log and e.sampler log the
// refusal. It runs after authentication and before anything is read or registered. It
// sets Vary: Origin on a response echoing an origin. The stub allows everything.
func (e *sessionSignals) crossSiteAllowed(*Exchange, bool) error {
	return nil
}
