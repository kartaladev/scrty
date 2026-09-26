package notify

import (
	"crypto/tls"
	"log/slog"
	"net/smtp"
	"time"
)

const (
	// defaultSMTPPort is the submission port. 587 is where a mail server
	// expects a client that authenticates and upgrades with STARTTLS, which is
	// what this sender is. 25 is relay traffic between servers and 465 is
	// implicit TLS, and neither is what a library sending its own mail wants
	// by default.
	defaultSMTPPort = 587

	// defaultSMTPTimeout bounds one whole send, dial included. Thirty seconds
	// is long enough for a slow server on a slow network and short enough that
	// a stalled connection does not hold a caller — or a queue worker — for a
	// noticeable part of a request.
	defaultSMTPTimeout = 30 * time.Second

	// ehloName is the name the sender introduces itself with. A submission
	// server authenticates the client rather than trusting this string, and a
	// name that identified the library or the consumer's host would tell every
	// hop what software sent the message and buy nothing.
	ehloName = "localhost"
)

// SMTPOption configures an SMTPSender. Every option names the default it
// replaces, and every default works with no configuration at all.
type SMTPOption func(*SMTPSender)

// WithSMTPPort replaces the port the sender connects to. The default is 587,
// the submission port. A port outside 1 to 65535 is a configuration error
// rather than a send-time surprise.
func WithSMTPPort(port int) SMTPOption { return func(s *SMTPSender) { s.port = port } }

// WithSMTPTimeout replaces the bound on one whole send, covering the dial and
// the entire exchange. The default is 30 seconds. Zero or less is a
// configuration error: there is no way to send without a bound, because a
// server that accepts a connection and then says nothing would otherwise hold
// the caller forever.
//
// The caller's own context deadline still applies, and the earlier of the two
// wins. This option can only lengthen what the sender allows, never remove it.
func WithSMTPTimeout(d time.Duration) SMTPOption { return func(s *SMTPSender) { s.timeout = d } }

// WithSMTPFrom replaces the sender address used for a message that names none.
// The default is no default address, in which case such a message fails before
// any network activity. A message's own From always wins.
func WithSMTPFrom(addr string) SMTPOption { return func(s *SMTPSender) { s.from = addr } }

// WithSMTPAuth replaces the credentials presented to the server. The default
// is no AUTH at all, which is what a relay on the same host usually wants.
//
// The credentials are presented with SMTP PLAIN, which refuses to travel over
// an unencrypted connection to anything but a loopback host. With the default
// required STARTTLS that refusal never comes up; with
// WithSMTPOpportunisticTLS against a remote server that offers no STARTTLS,
// the send fails rather than sending the password in the clear.
//
// A consumer whose server wants a different mechanism supplies the whole
// exchange instead by implementing Sender.
func WithSMTPAuth(username, password string) SMTPOption {
	return func(s *SMTPSender) { s.auth = smtp.PlainAuth("", username, password, s.host) }
}

// WithSMTPOpportunisticTLS replaces the required-STARTTLS default with
// opportunistic encryption: the sender upgrades when the server offers
// STARTTLS and otherwise continues in plaintext.
//
// This gives up protection against an on-path attacker, who can strip the
// STARTTLS offer and then read every message — and the messages this library
// sends carry live sign-in links. It exists for a relay reached over a
// loopback interface or a private link the consumer already trusts, and for
// tests. The safe behaviour is the default precisely because this one has to
// be chosen deliberately.
func WithSMTPOpportunisticTLS() SMTPOption { return func(s *SMTPSender) { s.opportunis = true } }

// WithSMTPTLSConfig replaces the TLS settings the STARTTLS upgrade uses. The
// default verifies the server's certificate against the host given to
// NewSMTPSender and requires TLS 1.2 or better.
//
// Use it for a server whose certificate is issued by a private authority, or
// to pin one. A configuration that leaves ServerName empty verifies against
// whatever name the connection was made to, which for a consumer who also
// replaced the dialler may not be the configured host — set ServerName when
// that matters. Setting InsecureSkipVerify turns certificate checking off
// altogether and gives up exactly the protection required STARTTLS exists to
// provide; the library does not stop a consumer doing it, and does not pretend
// the guarantee survives it.
//
// A nil configuration is ignored, leaving the default in place.
func WithSMTPTLSConfig(c *tls.Config) SMTPOption {
	return func(s *SMTPSender) {
		if c != nil {
			s.tlsConfig = c
		}
	}
}

// WithSMTPDialer replaces how the connection to the server is opened. The
// default is a net.Dialer. A nil dialler is a configuration error.
//
// Use it to reach the server through a proxy, a fixed resolver or a network of
// the consumer's own. The context it is handed already carries the send's
// single deadline, so a dialler that honours its context needs no bound of its
// own.
func WithSMTPDialer(d DialFunc) SMTPOption { return func(s *SMTPSender) { s.dial = d } }

// WithSMTPLogger replaces where the sender writes its logs. The default is
// slog.Default, captured when the sender is built, so a consumer who
// configures nothing still hears about mail that was never delivered.
//
// Records name the server host and the failure by a fixed reason and the
// error's Go type. They never carry the error's own text, the recipient, the
// message body or the subject: a mail server's own reply routinely quotes the
// recipient, and the body of a sign-in message is a live credential. The
// returned error carries the same fixed text naming the stage that failed;
// the server's reply stays reachable as its cause, through errors.As to
// *textproto.Error, for a consumer who wants it deliberately.
//
// A consumer who wants this sender silent passes a logger over a discarding
// handler, for example slog.New(slog.DiscardHandler). Silence is available,
// but it is chosen at the wiring rather than inherited from a default, because
// a failed delivery no caller is told of is otherwise invisible.
func WithSMTPLogger(l *slog.Logger) SMTPOption {
	return func(s *SMTPSender) {
		if l != nil {
			s.logger = l
		}
	}
}
