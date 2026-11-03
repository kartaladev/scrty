package password

//go:generate mockgen -source=breach.go -destination=breach_mock_test.go -package=password_test -typed

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // the range API is keyed by SHA-1; the hash protects nothing here
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/outbound"
)

// ErrLookupUnavailable fails a check whose breach lookup failed — a timeout,
// a non-success status or a body that does not parse — when the policy was
// built with [Refuse]. It is a dependency failure, not a password refusal:
// it does not match [ErrPasswordRejected]. Its text is fixed; the source's
// own error stays reachable through [errors.Is] and [errors.As].
var ErrLookupUnavailable = errors.New("password: breach lookup unavailable")

// BreachSource answers a range query over a corpus of breached passwords.
//
// The policy hands it only the first five hexadecimal characters of the
// candidate's SHA-1 hash, and matches the rest itself, so a source never sees
// the candidate or its full hash. [PwnedPasswords] queries the public range
// API; a consumer with an offline copy of the corpus supplies their own.
type BreachSource interface {
	// Range returns the corpus entries whose SHA-1 hash starts with prefix,
	// five upper-case hexadecimal characters: each entry maps the remaining
	// 35 hexadecimal characters to the number of times the password was seen.
	// The policy matches a suffix without regard to case, so a source may key
	// its entries in either.
	// An entry with a count of zero is padding and matches nothing. A lookup
	// that could not be answered is an error, never an empty map.
	Range(ctx context.Context, prefix string) (map[string]int, error)
}

// LookupFailure is what the breach check does with a candidate when the
// lookup fails. It has no default: the zero value fails construction.
type LookupFailure int

const (
	// Refuse fails the check with [ErrLookupUnavailable]: no password is set
	// while the corpus cannot be asked.
	Refuse LookupFailure = iota + 1
	// Accept lets the candidate through the breach rule, and the next rule
	// runs: an outage of the corpus does not stop password changes.
	Accept
)

type breachRule struct {
	src       BreachSource
	onFailure LookupFailure
	logger    *slog.Logger // set by NewPolicy from WithPolicyLogger
}

// Breached adds the breach check: a candidate found in src with a count above
// zero is refused as breached.
//
// onFailure is required, because the safe answer and the convenient one
// differ and the choice is the consumer's: [Refuse] or [Accept]. Whichever is
// chosen, a caller whose own context ended during the lookup gets an error
// matching the context's error.
//
// Default: no breach check. A nil source, typed nil included, or a failure
// mode that is neither [Refuse] nor [Accept] fails construction.
func Breached(src BreachSource, onFailure LookupFailure) PolicyOption {
	return func(c *policyConfig) {
		c.breach = &breachRule{src: src, onFailure: onFailure}
	}
}

// validate refuses a breach check that cannot work.
func (r *breachRule) validate() error {
	if nilcheck.IsNil(r.src) {
		return fmt.Errorf("%w: the breach check needs a lookup source", ErrConfig)
	}

	if r.onFailure != Refuse && r.onFailure != Accept {
		return fmt.Errorf("%w: the breach check needs a failure mode, Refuse or Accept", ErrConfig)
	}

	return nil
}

// check refuses candidate when the source lists it with a count above zero.
func (r *breachRule) check(ctx context.Context, candidate string) error {
	sum := sha1.Sum([]byte(candidate)) //nolint:gosec // see the import
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	entries, err := r.src.Range(ctx, prefix)
	if err != nil {
		if hangup.ByCaller(ctx, err) {
			return ctx.Err()
		}

		if r.onFailure == Accept {
			r.logger.LogAttrs(ctx, slog.LevelError, breachLookupAcceptedMsg, diag.Failure("breach-lookup", err)...)

			return nil
		}

		return diag.Wrap(err, lookupUnavailableText, ErrLookupUnavailable)
	}

	for s, count := range entries {
		if count > 0 && strings.EqualFold(s, suffix) {
			return RejectedError{Rule: RuleBreached}
		}
	}

	return nil
}

// breachLookupAcceptedMsg is the fixed message of the ERROR record a failed
// lookup leaves when the policy accepts the candidate unchecked.
const breachLookupAcceptedMsg = "password: breach lookup failed; the candidate was accepted unchecked"

// lookupUnavailableText is ErrLookupUnavailable's text, the fixed text of the
// error a failed lookup returns.
const lookupUnavailableText = "password: breach lookup unavailable"

// PwnedPasswordsRangeURL is the range API [PwnedPasswords] queries, with the
// five-character prefix appended.
const PwnedPasswordsRangeURL = "https://api.pwnedpasswords.com/range/" //nolint:gosec // G101: the public Pwned Passwords range URL, not a credential

// PwnedPasswords returns a [BreachSource] over the public Pwned Passwords
// range API, sent through c so the request is confined, bounded in time and
// bounded in size as c is configured. Each request carries `Add-Padding:
// true`, so the response size does not reveal the prefix.
//
// A non-success status (429 included) and a body that is not lines of a
// 35-character hexadecimal suffix, a colon and a count are lookup failures,
// as are c's own refusals and its timeout.
//
// A nil c returns a nil source, which [Breached] refuses at construction.
func PwnedPasswords(c *outbound.Client) BreachSource {
	if c == nil {
		return nil
	}

	return &pwnedPasswords{client: c}
}

type pwnedPasswords struct{ client *outbound.Client }

// errRangeResponse is a range response the source could not use. Its text
// carries the status at most, never the body.
var errRangeResponse = errors.New("password: unusable range response")

// sha1SuffixLen is the length of a SHA-1 hash in hexadecimal, less the prefix.
const sha1SuffixLen = 35

// Range implements [BreachSource].
func (s *pwnedPasswords) Range(ctx context.Context, prefix string) (map[string]int, error) {
	header := http.Header{"Add-Padding": {"true"}}

	res, err := s.client.Get(ctx, PwnedPasswordsRangeURL+prefix, header)
	if err != nil {
		return nil, err
	}

	if res.Status < 200 || res.Status > 299 {
		return nil, fmt.Errorf("%w: status %d", errRangeResponse, res.Status)
	}

	return parseRange(res.Body)
}

// parseRange reads lines of SUFFIX:COUNT, CRLF or LF terminated. Anything
// else, an empty body included, is an unusable response.
func parseRange(body []byte) (map[string]int, error) {
	lines := bytes.Split(bytes.TrimRight(body, "\r\n"), []byte("\n"))
	entries := make(map[string]int, len(lines))

	for _, line := range lines {
		suffix, count, ok := bytes.Cut(bytes.TrimSuffix(line, []byte("\r")), []byte(":"))
		if !ok || len(suffix) != sha1SuffixLen || !isHex(suffix) {
			return nil, fmt.Errorf("%w: a line is not a suffix and a count", errRangeResponse)
		}

		n, err := strconv.Atoi(string(count))
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%w: a count is not a number", errRangeResponse)
		}

		entries[strings.ToUpper(string(suffix))] = n
	}

	return entries, nil
}

func isHex(b []byte) bool {
	for _, c := range b {
		switch {
		case '0' <= c && c <= '9', 'a' <= c && c <= 'f', 'A' <= c && c <= 'F':
		default:
			return false
		}
	}

	return true
}
