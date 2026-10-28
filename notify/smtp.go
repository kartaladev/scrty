package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
)

// errRcptStage tags an exchange failure that happened while presenting the
// recipient to the server, so Send can log it under its own reason without
// reading the error's text — a server's RCPT refusal routinely quotes the
// recipient.
var errRcptStage = errors.New("notify: rcpt refused")

// DialFunc opens the connection to the SMTP server.
//
// The library uses a net.Dialer when the consumer supplies none. A consumer
// replaces it to route submission through a proxy, a fixed resolver or a
// network namespace of their own; whatever it returns is bound by the same
// single deadline as the rest of the send, and the context it is given already
// carries that deadline.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// SMTPSender delivers a Message over SMTP submission.
//
// It requires STARTTLS by default, bounds the whole send — dial included — by
// one deadline, and refuses header values that could inject headers. It does
// not implement NonBlocking: Send waits for the server, and a flow that must
// not wait wraps it in a QueuedSender.
//
// An SMTPSender is safe for concurrent use: it holds no per-send state and
// opens a fresh connection for every message.
type SMTPSender struct {
	host       string
	port       int
	from       string
	auth       smtp.Auth
	timeout    time.Duration
	opportunis bool
	dial       DialFunc
	logger     *slog.Logger
	tlsConfig  *tls.Config
}

// NewSMTPSender builds a sender for host.
//
// Defaults: port 587 (WithSMTPPort), no AUTH (WithSMTPAuth), no default sender
// address (WithSMTPFrom), a 30-second bound on the whole send
// (WithSMTPTimeout), STARTTLS required (WithSMTPOpportunisticTLS relaxes it),
// a net.Dialer (WithSMTPDialer) and slog's default logger (WithSMTPLogger).
//
// Construction fails, wrapping ErrConfig, when host is empty, when the port is
// outside 1 to 65535, when the timeout is zero or less, or when the dialler is
// nil. Each is a wiring mistake that would otherwise only surface at the first
// send, which for a sign-in link means in production, for one user, silently.
func NewSMTPSender(host string, opts ...SMTPOption) (*SMTPSender, error) {
	s := &SMTPSender{
		host:    host,
		port:    defaultSMTPPort,
		timeout: defaultSMTPTimeout,
		dial:    (&net.Dialer{}).DialContext,
		logger:  slog.Default(),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	if s.host == "" {
		return nil, fmt.Errorf("%w: smtp sender requires a host", ErrConfig)
	}

	if s.port < 1 || s.port > 65535 {
		return nil, fmt.Errorf("%w: smtp port %d is outside 1-65535", ErrConfig, s.port)
	}

	if s.timeout <= 0 {
		return nil, fmt.Errorf("%w: smtp timeout must be positive, got %s", ErrConfig, s.timeout)
	}

	if s.dial == nil {
		return nil, fmt.Errorf("%w: smtp dialler must not be nil", ErrConfig)
	}

	if s.tlsConfig == nil {
		// The certificate is verified against the host the consumer named, not
		// against whatever the dialler happened to connect to.
		s.tlsConfig = &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}
	}

	return s, nil
}

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

// Port reports the port the sender connects to. Default: 587.
func (s *SMTPSender) Port() int { return s.port }

// Timeout reports the bound on a whole send. Default: 30s.
func (s *SMTPSender) Timeout() time.Duration { return s.timeout }

// Send delivers msg and waits for the server to accept it.
//
// A recipient, sender or subject carrying a carriage return or line feed is
// refused with ErrUnsafeHeaderValue before anything is dialled, and so is a
// message that names no sender address when the sender has no default.
//
// One absolute deadline then bounds everything that follows: the earlier of
// the configured timeout from now and the caller's own context deadline, fixed
// before the dial and applied to the connection, so a slow dial cannot buy a
// stalled server a second helping of the bound. Cancelling ctx aborts a send
// in progress, mid-transfer included.
//
// A failure is logged to the configured logger. The record names the server
// host, whether a recipient was given, and the failure through [diag.Failure]:
// a fixed reason ("rcpt" when the server refused the recipient, "send"
// otherwise) and the error's Go type — never the error's own text, the
// subject or the body. A mail server's own RCPT refusal routinely quotes the
// recipient, and the body of a sign-in message is a live credential; neither
// reaches the record. A consumer who wants the server's own reply reaches it
// deliberately, from the returned error, as the paragraph below describes.
//
// Every failure Send returns — the dial and each stage of the exchange
// (the greeting, EHLO, STARTTLS, AUTH, MAIL FROM, RCPT, DATA and the message
// itself) — comes back behind fixed library text naming the stage, never the
// server's own reply: a mail server's rejection routinely quotes the
// recipient or the sender in its wording. The failing stage's own error, a
// dial's or a *textproto.Error from the server, is still reachable through
// errors.Is and errors.As; an RCPT refusal is also still matched by
// errors.Is against errRcptStage, which is what keeps the failure record's
// reason "rcpt".
func (s *SMTPSender) Send(ctx context.Context, msg Message) error {
	err := s.send(ctx, msg)
	if err != nil {
		reason := "send"
		if errors.Is(err, errRcptStage) {
			reason = "rcpt"
		}

		attrs := append([]slog.Attr{
			slog.String("host", s.host),
			slog.Bool("has_recipient", msg.To != ""),
		}, diag.Failure(reason, err)...)

		s.logger.LogAttrs(ctx, slog.LevelError, "notify: smtp send failed", attrs...)
	}

	return err
}

func (s *SMTPSender) send(ctx context.Context, msg Message) error {
	if err := refuseUnsafeHeaders(msg); err != nil {
		return err
	}

	from := msg.From
	if from == "" {
		from = s.from
	}

	if from == "" {
		return fmt.Errorf("%w: message names no sender address and the sender has no default", ErrConfig)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	// One absolute deadline, fixed before the dial and never recomputed. A
	// dial timeout followed by a fresh exchange deadline would let a slow
	// server have nearly twice the bound the consumer configured.
	deadline := time.Now().Add(s.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))

	conn, err := s.dial(ctx, "tcp", addr)
	if err != nil {
		return diag.Wrap(err, fmt.Sprintf("notify: dial %s failed", addr))
	}
	defer func() { _ = conn.Close() }()

	// The same deadline governs every read and write of the exchange, so a
	// server that greets and then stalls is bounded exactly as one that never
	// greets.
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("notify: setting the connection deadline: %w", err)
	}

	// net/smtp blocks in a read that no context reaches. Forcing the deadline
	// to now is what unblocks it, so a cancelled request does not hold a
	// worker until the deadline it would otherwise wait for.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	return s.exchange(conn, from, msg)
}

// upgrade applies the sender's encryption rule to an established client.
//
// Required (the default) means the server must offer STARTTLS and the upgrade
// must succeed; anything else fails the send before AUTH or any message data.
// Opportunistic upgrades when the server offers it and otherwise continues in
// plaintext, which exists for a relay on the same host and is documented as
// giving up on-path protection.
func (s *SMTPSender) upgrade(c *smtp.Client) error {
	ok, _ := c.Extension("STARTTLS")

	if !ok {
		if s.opportunis {
			return nil
		}

		return fmt.Errorf("notify: %s does not offer STARTTLS and encryption is required", s.host)
	}

	if err := c.StartTLS(s.tlsConfig); err != nil {
		return diag.Wrap(err, fmt.Sprintf("notify: STARTTLS upgrade to %s failed", s.host))
	}

	return nil
}

// exchange runs the SMTP conversation on an established connection.
//
// It takes no context and consults none: net/smtp reaches for no context, and
// what bounds and cancels this conversation is the connection deadline send
// fixed before dialling — which is also what the caller's cancellation reaches
// through. Threading a context here would suggest otherwise.
func (s *SMTPSender) exchange(conn net.Conn, from string, msg Message) error {
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return diag.Wrap(err, fmt.Sprintf("notify: the greeting from %s failed", s.host))
	}
	defer func() { _ = c.Close() }()

	if err := c.Hello(ehloName); err != nil {
		return diag.Wrap(err, fmt.Sprintf("notify: EHLO to %s failed", s.host))
	}

	// Before AUTH and before any message data: credentials and a sign-in link
	// are exactly what must not cross the wire in the clear.
	if err := s.upgrade(c); err != nil {
		return err
	}

	if s.auth != nil {
		if err := c.Auth(s.auth); err != nil {
			return diag.Wrap(err, fmt.Sprintf("notify: AUTH to %s failed", s.host))
		}
	}

	if err := c.Mail(from); err != nil {
		return diag.Wrap(err, "notify: the server refused the sender")
	}

	if err := c.Rcpt(msg.To); err != nil {
		return diag.Wrap(err, "notify: the server refused the recipient", errRcptStage)
	}

	w, err := c.Data()
	if err != nil {
		return diag.Wrap(err, "notify: the server refused to accept message data")
	}

	if _, err := w.Write(build(from, msg)); err != nil {
		return diag.Wrap(err, "notify: writing the message failed")
	}

	if err := w.Close(); err != nil {
		return diag.Wrap(err, "notify: the server refused the message")
	}

	if err := c.Quit(); err != nil {
		return diag.Wrap(err, "notify: the server refused to end the session")
	}

	return nil
}

// build renders msg as the RFC 5322 message to hand to DATA.
//
// The subject is Q-encoded when it is not ASCII, because a header field is
// ASCII without SMTPUTF8 and raw bytes there are mangled or rejected. The body
// is normalised to CRLF, because a bare LF in SMTP data is not a line ending
// and servers disagree about what to do with one. No header names the library
// or any product: a header like that tells anyone with the message which
// software sent it, and buys the consumer nothing.
func build(from string, msg Message) []byte {
	var b bytes.Buffer

	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + msg.To + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", msg.Subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(normalizeCRLF(msg.TextBody))

	return b.Bytes()
}

// normalizeCRLF turns every line ending into one CRLF: CRLF, a bare LF and a
// bare CR alike. A bare CR must not reach the transfer, because servers differ
// on whether it ends a line, and a body such as "\r.\r" would then end the data
// on one and not on another (RFC 5321 section 2.3.8). A body that already uses
// CRLF is not doubled.
func normalizeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")

	return strings.ReplaceAll(s, "\n", "\r\n")
}
