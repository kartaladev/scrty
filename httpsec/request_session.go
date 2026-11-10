package httpsec

import "github.com/kartaladev/scrty/session"

// requestSession is the session a built-in judges for the request ex carries:
// the session this chain resolved for it, ex.Session, or, when it resolved
// none, the session already on the request's context.
//
// Only an enclosing chain can have put a session on the context: the key is
// this package's own (sessionKey), so a consumer cannot write it. A chain
// mounted inside another builds an exchange of its own, with no session on
// it, and without this a gate of the inner chain would judge nothing while
// its handler read the enclosing chain's session from the context, owing a
// challenge or not. The chain's own session wins, because publishing puts it
// on the context too, so it is also the one the handler reads.
//
// A nil session on the context reads as no session, as SessionFromContext
// reports it. Built-ins that write a session back keep writing ex.Session.
func requestSession(ex *Exchange) *session.Session {
	if ex.Session != nil {
		return ex.Session
	}

	s, _ := SessionFromContext(ex.Context())

	return s
}
