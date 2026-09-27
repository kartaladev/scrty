package magiclink

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/onetime"
)

const (
	defaultConfirmPath   = "/login/magic/confirm"
	defaultIssuanceLimit = 5

	// bindingNonceBytes is how much randomness a binding value carries. Its
	// base64 raw-URL encoding is BindingNonceLength characters long.
	bindingNonceBytes = 16
)

// Manager runs the magic-link flow: it issues and sends links, and redeems
// them.
//
// Build one with NewManager. A Manager holds no mutable state after
// construction, and is safe for concurrent use as far as the token store, user
// loader and sender it was given are.
type Manager struct {
	tokens *onetime.Manager
	users  identity.UserLoader
	sender notify.Sender

	baseURL       string
	confirmPath   string
	issuanceLimit int
	resolver      AddressResolver
	renderer      Renderer
	binding       bool
	random        io.Reader
	logger        *slog.Logger

	acceptSyncDelivery bool
}

// NewManager builds the magic-link flow.
//
// linkBaseURL is where the emailed link points — the origin of the page that
// will post the token back. It is required and must be absolute https, with
// one exception: http on a loopback host, for local development. An emailed
// link that is host-relative cannot be followed at all, and one over cleartext
// carries a live credential past anyone on the path. It is an origin and
// nothing more: a scheme, a host and an optional port.
//
// Defaults, each replaceable: /login/magic/confirm (WithConfirmPath), 5 links
// per user per the token manager's issuance window (WithIssuanceLimit), the
// submitted address passed to the user loader as a username
// (WithAddressResolver), a neutral plain-text message naming no product
// (WithRenderer), same-device binding on (WithSameDeviceBinding), crypto/rand
// for the binding value (WithRandom), slog.Default for the log (WithLogger),
// and delivery that must not block (WithSynchronousDelivery accepts one that
// does).
//
// The link's lifetime is the token manager's TTL, configured there rather than
// here: there is one place a one-time credential's lifetime is set.
//
// Every refusal below wraps ErrConfig, so a wiring mistake is seen here and
// never on the first request that needs it.
func NewManager(
	tokens *onetime.Manager,
	users identity.UserLoader,
	sender notify.Sender,
	linkBaseURL string,
	opts ...Option,
) (*Manager, error) {
	m := &Manager{
		tokens:        tokens,
		users:         users,
		sender:        sender,
		confirmPath:   defaultConfirmPath,
		issuanceLimit: defaultIssuanceLimit,
		renderer:      defaultRenderer,
		binding:       true,
		random:        rand.Reader,
		logger:        slog.Default(),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}

	if m.tokens == nil {
		return nil, fmt.Errorf("%w: a one-time token manager is required", ErrConfig)
	}
	if nilcheck.IsNil(m.users) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("user loader"))
	}
	if nilcheck.IsNil(m.sender) {
		return nil, fmt.Errorf("%w: a message sender is required", ErrConfig)
	}
	if err := requireNonBlocking(m.sender, m.acceptSyncDelivery); err != nil {
		return nil, err
	}

	baseURL, err := normalizeBaseURL(linkBaseURL)
	if err != nil {
		return nil, err
	}
	m.baseURL = baseURL

	if err := validateConfirmPath(m.confirmPath); err != nil {
		return nil, err
	}
	if m.issuanceLimit < 1 {
		return nil, fmt.Errorf(
			"%w: WithIssuanceLimit was given %d, which would refuse every request; it must be at least 1",
			ErrConfig, m.issuanceLimit)
	}
	if m.renderer == nil {
		return nil, fmt.Errorf("%w: WithRenderer was given no renderer", ErrConfig)
	}
	if nilcheck.IsNil(m.random) {
		return nil, fmt.Errorf("%w: WithRandom was given no random source", ErrConfig)
	}

	if m.resolver == nil {
		m.resolver = m.loadByUsername
	}

	return m, nil
}

// requireNonBlocking refuses a sender that would put delivery time into the
// caller's response.
//
// A request that waited for the mail server would take measurably longer for
// an address that has an account than for one that does not, which is the one
// thing the whole request path is built not to reveal. The refusal is at
// construction because the alternative — documenting that deployments should
// wrap their sender — closes the channel only for the deployments that
// remember.
func requireNonBlocking(sender notify.Sender, accepted bool) error {
	if accepted {
		return nil
	}

	nb, ok := sender.(notify.NonBlocking)
	if !ok || !nb.NonBlocking() {
		return fmt.Errorf(
			"%w: this sender waits for delivery, and synchronous delivery reveals which "+
				"addresses have accounts; wrap it in notify.NewQueuedSender, or accept the "+
				"channel with WithSynchronousDelivery", ErrConfig)
	}

	return nil
}

// normalizeBaseURL checks the link base URL and returns it with no trailing
// slash, so the confirmation path can simply be appended.
//
// The scheme and host rules are the ones the redirect allowlist already
// applies to a declared origin, reused rather than restated: https everywhere,
// http only where the request never leaves the machine.
func normalizeBaseURL(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf(
			"%w: a link base URL is required; a host-relative link in an email cannot be followed",
			ErrConfig)
	}

	// NewAllowlist validates a declared origin: absolute, no userinfo, no
	// path, query or fragment, https or http on a loopback host.
	if _, err := origin.NewAllowlist(nil, []string{raw}, "", "the link base URL"); err != nil {
		return "", fmt.Errorf("%w: %w", ErrConfig, err)
	}

	scheme, host, port, ok := origin.Normalize(raw)
	if !ok {
		return "", fmt.Errorf("%w: the link base URL %q is not an absolute http or https origin",
			ErrConfig, raw)
	}

	// Normalize hands back an IPv6 literal without its brackets, which a URL
	// needs back before a port can be told from the address.
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}

	return scheme + "://" + host, nil
}

// validateConfirmPath accepts a host-relative path and nothing else.
//
// The link carries a live credential, so where it points is not somewhere a
// configuration mistake may quietly widen. A second slash or a backslash after
// the first character is refused because a browser reads either as the start
// of a host, and whitespace and control characters are refused because they
// are how those shapes are smuggled past a reader.
func validateConfirmPath(path string) error {
	switch {
	case path == "":
		return fmt.Errorf("%w: WithConfirmPath was given an empty path", ErrConfig)
	case !strings.HasPrefix(path, "/"):
		return fmt.Errorf(
			"%w: WithConfirmPath entry %q is not host-relative; the link points at the "+
				"configured base URL and nowhere else", ErrConfig, path)
	case len(path) > 1 && (path[1] == '/' || path[1] == '\\'):
		return fmt.Errorf(
			"%w: WithConfirmPath entry %q is not host-relative: a browser reads a second "+
				"slash or a backslash here as the start of a host", ErrConfig, path)
	case strings.ContainsFunc(path, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}):
		return fmt.Errorf("%w: WithConfirmPath entry %q contains whitespace or a control character",
			ErrConfig, path)
	}

	return nil
}

// loadByUsername is the default AddressResolver: the submitted address is the
// username, passed on exactly as it arrived — never trimmed, never case-folded.
func (m *Manager) loadByUsername(ctx context.Context, address string) (*identity.Details, error) {
	return m.users.LoadByUsername(ctx, address)
}

// BindingEnabled reports whether links are bound to the device that asked for
// them. It is true unless WithSameDeviceBinding(false) was given.
func (m *Manager) BindingEnabled() bool { return m.binding }

// TTL is how long an issued link stays redeemable.
//
// It is the token manager's time-to-live rather than a setting of this
// package: a one-time credential's lifetime is configured in one place, with
// onetime.WithTTL.
func (m *Manager) TTL() time.Duration { return m.tokens.TTL() }

// Request issues and sends a sign-in link for the submitted address.
//
// It returns no error, and every branch returns a result of the same shape.
// That is the point: an unknown address, a disabled user, a loader outage, a
// reached issuance limit, a failed token write and a failed send are
// indistinguishable to the caller, so a caller cannot leak the difference to
// the client even by accident. Each cause is logged server-side, and no record
// carries the submitted address.
//
// next is the redirect target to carry through the link. It is passed on as
// the caller supplied it: sanitising it against a redirect allowlist belongs
// to whoever accepted it from the client, which knows what the client is
// allowed to reach.
//
// A small timing difference remains: the store read and the token insert run
// only for an address that resolves. The non-blocking sender removes the
// largest part of it — the delivery — and the rest is documented rather than
// closed here.
func (m *Manager) Request(ctx context.Context, address, next string) RequestResult {
	// The binding value is drawn before anything about the address is known,
	// so the shape of what is returned cannot depend on what is learned
	// afterwards. When no link goes out it is a decoy binding nothing, and the
	// caller sets the same cookie it would have set for a real one.
	var result RequestResult

	if m.binding {
		nonce, err := m.newBindingNonce()
		if err != nil {
			m.logger.LogAttrs(ctx, slog.LevelError,
				"magiclink: the random source failed and no link was issued",
				diag.Failure("random-source", err)...)

			return RequestResult{}
		}

		result.BindingNonce = nonce
	}

	details, ok := m.resolve(ctx, address)
	if !ok {
		return result
	}

	// D7: the link records the user reference, not the address it was asked
	// for. An address is a reusable handle; a reference is not.
	subject := string(details.ID)

	count, err := m.tokens.IssuedCount(ctx, subject)
	if err != nil {
		m.logger.LogAttrs(ctx, slog.LevelError,
			"magiclink: issuance count unavailable", diag.Failure("token-count", err)...)

		return result
	}

	if count >= m.issuanceLimit {
		m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: issuance limit reached",
			slog.Int("limit", m.issuanceLimit))

		return result
	}

	var issueOpts []onetime.IssueOption
	if result.BindingNonce != "" {
		issueOpts = append(issueOpts, onetime.WithBinding(result.BindingNonce))
	}

	presented, _, err := m.tokens.Issue(ctx, subject, issueOpts...)
	if err != nil {
		m.logger.LogAttrs(ctx, slog.LevelError,
			"magiclink: the link could not be issued", diag.Failure("token-issue", err)...)

		return result
	}

	msg := m.renderer(m.buildLink(presented, next), next)

	// Forced, whatever the renderer returned. A renderer is for wording; a
	// renderer that could choose the recipient could mail a live sign-in link
	// for one account to another address.
	msg.To = address

	if err := m.sender.Send(ctx, msg); err != nil {
		m.logger.LogAttrs(ctx, slog.LevelError,
			"magiclink: the sign-in message could not be sent", diag.Failure("sender", err)...)
	}

	return result
}

// resolve turns a submitted address into user details, or reports that the
// request goes no further.
//
// Every refusal is logged and none is returned: the caller of Request is not
// told which of them happened. No record quotes the address — a debug line
// that did would put every address anyone typed into the log, which is the
// enumeration this flow exists to prevent, moved one layer down.
func (m *Manager) resolve(ctx context.Context, address string) (*identity.Details, bool) {
	details, err := m.resolver(ctx, address)

	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: no account for the submitted address")

		return nil, false
	case err != nil:
		m.logger.LogAttrs(ctx, slog.LevelError,
			"magiclink: the submitted address could not be resolved", diag.Failure("resolver", err)...)

		return nil, false
	case details == nil || !details.Active:
		m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: the account is not active")

		return nil, false
	case details.ID == "":
		// Without a reference there is nothing to mint the link against, and a
		// link that recorded an empty subject would be one no redemption could
		// bind to a user.
		m.logger.LogAttrs(ctx, slog.LevelError, "magiclink: the resolved account carries no user reference")

		return nil, false
	}

	return details, true
}

// newBindingNonce draws the value a link is bound to.
func (m *Manager) newBindingNonce() (string, error) {
	raw := make([]byte, bindingNonceBytes)
	if _, err := io.ReadFull(m.random, raw); err != nil {
		return "", fmt.Errorf("magiclink: read random source: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// buildLink assembles the URL the message carries.
//
// next is query-escaped, so a target with its own query string arrives intact
// rather than merging into the link's own parameters.
func (m *Manager) buildLink(token, next string) string {
	q := url.Values{}
	q.Set("token", token)
	q.Set("next", next)

	return m.baseURL + m.confirmPath + "?" + q.Encode()
}

// Redeem spends a link and reports who it authenticates.
//
// The order is the one-time-token capability's: the token is checked, the
// refusal checks run, and the token is consumed last and atomically. Account
// resolution is placed inside that ordering as the first refusal check, so a
// user who has been deleted, disabled or reassigned costs the holder nothing —
// the link stays redeemable until it expires — and of several racing
// redemptions of one link at most one succeeds.
//
// bindingNonce is the value RequestResult carried back from the device that
// asked for the link. It is ignored when WithSameDeviceBinding(false) was
// given.
//
// Every failure except a consumer check's is ErrInvalidLink: a caller cannot
// tell a wrong token from a disabled user from a store outage. A consumer
// check's error is returned unchanged.
func (m *Manager) Redeem(ctx context.Context, token, bindingNonce string, checks ...Check) (Redemption, error) {
	var (
		resolved Redemption

		// refusal holds whatever a check returned. onetime.Redeem hands that
		// error straight back, and capturing it here is what lets a consumer's
		// own error be told apart from the capability's own refusals without
		// guessing from an error's shape.
		refusal error
	)

	all := make([]onetime.Check, 0, len(checks)+1)

	// The account resolver goes first. Placing it here rather than before the
	// call is what puts it under the capability's ordering guarantee: it runs
	// before the consume, and its refusal leaves the token unspent.
	all = append(all, func(ctx context.Context, tok onetime.Token) error {
		details, err := m.resolveRedemption(ctx, tok)
		if err != nil {
			refusal = err

			return err
		}

		principal := identity.PrincipalFromDetails(details)
		resolved = Redemption{Principal: *principal, PasswordChangedAt: details.PasswordChangedAt}

		return nil
	})

	for _, check := range checks {
		if check == nil {
			continue
		}

		all = append(all, func(ctx context.Context, _ onetime.Token) error {
			if err := check(ctx, resolved.Principal, resolved.PasswordChangedAt); err != nil {
				refusal = err

				return err
			}

			return nil
		})
	}

	if !m.binding {
		bindingNonce = ""
	}

	if _, err := m.tokens.Redeem(ctx, token, bindingNonce, all...); err != nil {
		return Redemption{}, m.redemptionError(ctx, err, refusal)
	}

	return resolved, nil
}

// resolveRedemption loads the user the link was minted for.
//
// D7: the token's subject is the user reference, and the reference is what is
// loaded. A username or an address is a reusable handle — reissued to somebody
// else, it would let a link minted for the first person authenticate the
// second — so the recorded reference is the only thing trusted here, and a
// loader that answers with a different one is refused rather than believed.
func (m *Manager) resolveRedemption(ctx context.Context, tok onetime.Token) (*identity.Details, error) {
	user := identity.UserID(tok.Subject)

	details, err := m.users.LoadByUserID(ctx, user)

	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: the link's user no longer exists")

		return nil, ErrInvalidLink
	case err != nil:
		m.logger.LogAttrs(ctx, slog.LevelError,
			"magiclink: the link's user could not be loaded", diag.Failure("user-loader", err)...)

		return nil, ErrInvalidLink
	case details == nil || !details.Active:
		m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: the link's user is not active")

		return nil, ErrInvalidLink
	case details.ID != user:
		m.logger.LogAttrs(ctx, slog.LevelError,
			"magiclink: the loader returned a different user than the link records")

		return nil, ErrInvalidLink
	}

	return details, nil
}

// redemptionError maps a failure from the token capability to what the caller
// sees.
//
// A consumer's own check error passes through unchanged, because it is the
// consumer's contract with their own caller and the library has no business
// rewriting it. Everything else becomes ErrInvalidLink, logged at debug for
// the traffic that is simply wrong and at error for the traffic that means
// something is broken. No record here carries the presented token or the
// binding value.
func (m *Manager) redemptionError(ctx context.Context, err, refusal error) error {
	switch {
	case err == nil:
		return nil

	case refusal != nil:
		// A check refused, and onetime.Redeem returned its error verbatim.
		if errors.Is(refusal, ErrInvalidLink) {
			// One of this package's own refusals, already logged where it was
			// decided.
			return ErrInvalidLink
		}

		return refusal

	case errors.Is(err, onetime.ErrInvalidToken):
		// The capability reports a wrong, expired, consumed, wrongly bound or
		// unreadable token identically, and so does this package. A store
		// failure behind it was logged there, at error.
		m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: the presented link is not redeemable")

		return ErrInvalidLink

	default:
		// Defensive: onetime.Redeem's documented contract returns only
		// ErrInvalidToken or a check's own error, both handled above, so this
		// branch is unreachable today. diag.Failure keeps it safe if that
		// contract ever widens.
		m.logger.LogAttrs(ctx, slog.LevelError,
			"magiclink: redeeming the link failed", diag.Failure("token-store", err)...)

		return ErrInvalidLink
	}
}
