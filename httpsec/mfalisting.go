package httpsec

// This file holds the opt-in method-listing endpoint: a GET a session owing a
// second factor sends to learn which methods it can answer the challenge with,
// and the settings that configure it.

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kartaladev/scrty/session"
)

// DefaultMFAMethodListingPath is the path the method-listing endpoint answers
// GET requests on when the consumer names none. The endpoint is off unless
// WithMFAMethodListing is given.
const DefaultMFAMethodListingPath = "/mfa/methods"

// MFAListingResponder writes the response to a method listing. methods are the
// methods the session's user can use, in the order EnableMFA was given them:
// the same list, from the same decision, an MFA ChallengeError carries.
//
// It is called instead of the downstream handler, because the listing
// endpoint is the library's own. An error it returns leaves the chain as the
// request's refusal.
type MFAListingResponder func(ex *Exchange, methods []MFAMethod) error

// listingConfig is the method-listing endpoint's configuration. It is
// unexported, so its settings can be written only through the ListingSetting
// values WithMFAMethodListing applies, and nowhere else.
type listingConfig struct {
	path    string
	respond MFAListingResponder
}

// ListingSetting configures the method-listing endpoint. Each replaces one of
// the defaults named on WithMFAMethodListing, and only WithMFAMethodListing
// applies one.
type ListingSetting func(*listingConfig) error

// ListingPath answers the listing on path instead.
//
// Default: DefaultMFAMethodListingPath. Only GET on exactly path is the
// listing. An empty path is refused rather than read as the default, and so
// is one that does not start with "/", which matches no request path. New
// also refuses a path the chain's logout answers, or one at or under the MFA
// verify or begin prefix, since each of those endpoints claims its path.
func ListingPath(path string) ListingSetting {
	return func(l *listingConfig) error {
		switch {
		case path == "":
			return newConfigError("ListingPath was given no path; omit the setting to keep %q",
				DefaultMFAMethodListingPath)
		case !strings.HasPrefix(path, "/"):
			return newConfigError("ListingPath was given %q, which does not start with \"/\" "+
				"and so matches no request path", path)
		}

		l.path = path

		return nil
	}
}

// ListingResponder writes the listing with fn instead.
//
// Default: a 200 JSON document,
// {"methods":[{"name":…,"channel":…,"begins":…}]}, which no cache may keep.
// "begins" is true for a method with a begin step. An absent fn is refused
// rather than read as the default.
func ListingResponder(fn MFAListingResponder) ListingSetting {
	return func(l *listingConfig) error {
		if fn == nil {
			return newConfigError("ListingResponder was given no function; omit the setting " +
				"to keep the default document")
		}

		l.respond = fn

		return nil
	}
}

// WithMFAMethodListing turns on the method-listing endpoint, which the
// endpoint is off without: a GET a session owing a second factor sends to
// learn which methods its user can answer with.
//
// It answers only GET on its exact path, and never reads the URL query or the
// body: the session decides whose methods are listed. A request with no
// session is refused with ErrAuthenticationRequired, and a session that owes
// no second factor, a fully authenticated one included, with
// ErrNoMFAChallengePending (403). An enrolment-only session never reaches it:
// the enrolment gate refuses it first, like any other route. The MFA gate
// lets the listing through for a session that owes a second factor.
//
// The list is decided by policy.UsableMFAMethods over the methods EnableMFA
// was given, which is the decision the policies and the MFA challenge make,
// so the three never disagree. A lookup that fails is a refusal behind fixed
// text, with the lookup's error reachable through errors.Is and errors.As,
// and never a shorter or empty list. The lookups succeeding with nothing
// usable is an empty list.
//
// Defaults, each replaced by the setting named: the path is
// DefaultMFAMethodListingPath (ListingPath), and the response the JSON
// document ListingResponder describes (ListingResponder). A setting is
// written only here; an explicitly empty path or absent responder is refused.
func WithMFAMethodListing(settings ...ListingSetting) MFAOption {
	return func(i *mfaInterceptor) error {
		l := &listingConfig{path: DefaultMFAMethodListingPath, respond: writeMethodListing}

		for _, set := range settings {
			if set == nil {
				continue
			}
			if err := set(l); err != nil {
				return err
			}
		}

		i.listing = l

		return nil
	}
}

// checkListing refuses a listing path another second-factor endpoint claims:
// every POST at or under the verify and begin prefixes is that endpoint's, so
// a path there would name a method, or nothing, rather than the listing.
func (i *mfaInterceptor) checkListing(option string) error {
	if i.listing == nil {
		return nil
	}

	for _, p := range []struct{ name, prefix string }{
		{"verify", i.verifyPrefix},
		{"begin", i.beginPrefix},
	} {
		if underPrefix(i.listing.path, p.prefix) {
			return newConfigError("%s's WithMFAMethodListing path %q is under the %s prefix %q, "+
				"which that endpoint claims", option, i.listing.path, p.name, p.prefix)
		}
	}

	return nil
}

// isListingRequest reports whether r asks for the method listing: the
// listing is on, and r is a GET on exactly its path. Any other method passes
// on to the gate and the application, as a GET to a verify path does.
func (i *mfaInterceptor) isListingRequest(r Request) bool {
	return i.listing != nil && r.Method() == http.MethodGet && r.Path() == i.listing.path
}

// list answers the method listing for the session's user.
func (i *mfaInterceptor) list(ex *Exchange) error {
	s := ex.Session
	if s == nil {
		return ErrAuthenticationRequired
	}

	if s.MFA != session.MFAPending {
		return ErrNoMFAChallengePending
	}

	methods, err := i.usableMethods(ex.Context(), s.UserID, s.FirstFactor)
	if err != nil {
		return err
	}

	return i.listing.respond(ex, methods)
}

// methodListingDocument is the default listing's body. Its member names are
// the documented contract of the endpoint.
type methodListingDocument struct {
	Methods []methodListingEntry `json:"methods"`
}

type methodListingEntry struct {
	Name    string `json:"name"`
	Channel string `json:"channel"`
	Begins  bool   `json:"begins"`
}

// writeMethodListing is the listing's response when the consumer supplies no
// responder: 200, the methods as JSON, an empty list as [] rather than null.
func writeMethodListing(ex *Exchange, methods []MFAMethod) error {
	doc := methodListingDocument{Methods: make([]methodListingEntry, 0, len(methods))}
	for _, m := range methods {
		doc.Methods = append(doc.Methods, methodListingEntry{
			Name:    m.Name,
			Channel: string(m.Channel),
			Begins:  m.Begins,
		})
	}

	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.SetHeader("Cache-Control", "no-store")
	ex.Writer.WriteHeader(http.StatusOK)
	_, err = ex.Writer.Write(body)

	return err
}
