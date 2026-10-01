package passkey

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// RelyingParty is the WebAuthn relying party. None of its fields has a
// default.
//
// ID is a host name with no scheme, port, path or trailing dot; an IP address
// is not one, because WebAuthn scopes credentials to a domain. Changing it
// orphans every registered passkey, because authenticators scope their
// credentials to it.
//
// Each of Origins is an absolute https origin, or an http origin on a loopback
// host (localhost or a name under .localhost), whose host equals ID or ends
// with "." and ID, compared without regard to case. The set must not be empty.
type RelyingParty struct {
	ID      string
	Name    string
	Origins []string
}

// Validate returns an error wrapping ErrConfig, naming the field at fault,
// when the relying party is incomplete or malformed.
func (rp RelyingParty) Validate() error {
	if err := validateRPID(rp.ID); err != nil {
		return err
	}

	if strings.TrimSpace(rp.Name) == "" {
		return fmt.Errorf("%w: relying-party name is required", ErrConfig)
	}

	if len(rp.Origins) == 0 {
		return fmt.Errorf("%w: relying-party origins are required", ErrConfig)
	}

	rpID := strings.ToLower(rp.ID)
	for i, o := range rp.Origins {
		if err := validateOrigin(o, rpID); err != nil {
			return fmt.Errorf("%w: relying-party origin %d (%q) %s", ErrConfig, i, o, err.Error()) //nolint:forbidigo // validateOrigin returns only library-written text, never a dependency's
		}
	}

	return nil
}

func validateRPID(rpID string) error {
	if rpID == "" {
		return fmt.Errorf("%w: relying-party ID is required", ErrConfig)
	}

	if net.ParseIP(rpID) != nil {
		return fmt.Errorf("%w: relying-party ID must be a host name, not an IP address", ErrConfig)
	}

	for label := range strings.SplitSeq(rpID, ".") {
		if label == "" || strings.ContainsFunc(label, invalidHostRune) {
			return fmt.Errorf(
				"%w: relying-party ID must be a host name with no scheme, port, path or trailing dot", ErrConfig)
		}
	}

	return nil
}

// invalidHostRune reports a rune that has no place in a host name label.
func invalidHostRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		return false
	default:
		return true
	}
}

// validateOrigin returns a description of what is wrong with origin for the
// lowercase relying-party ID rpID, or nil.
func validateOrigin(origin, rpID string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return errors.New("is not an absolute origin")
	}

	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("must be scheme, host and port only")
	}

	if origin != u.Scheme+"://"+u.Host || strings.HasSuffix(u.Host, ":") || isDefaultPort(u) {
		return errors.New("must be written as scheme://host[:port], with no empty port or fragment and no default port")
	}

	host := strings.ToLower(u.Hostname())
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return errors.New("is outside the relying-party ID")
	}

	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if host == "localhost" || strings.HasSuffix(host, ".localhost") {
			return nil
		}

		return errors.New("must use https outside a loopback host")
	default:
		return errors.New("must use https")
	}
}

// isDefaultPort reports an explicit port that is the default of u's scheme,
// which a serialised origin leaves out.
func isDefaultPort(u *url.URL) bool {
	switch u.Port() {
	case "443":
		return u.Scheme == "https"
	case "80":
		return u.Scheme == "http"
	default:
		return false
	}
}
