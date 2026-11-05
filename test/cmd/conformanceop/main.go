package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("conformanceop", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("conformanceop", flag.ContinueOnError)
	addr := fs.String("addr", ":9443", "address to listen on")
	issuer := fs.String("issuer", "https://localhost:9443", "the provider's public https URL")
	suite := fs.String("suite-url", "https://localhost.emobix.co.uk:8443", "the conformance suite's public https URL")
	alias := fs.String("alias", "scrty", "the alias the plans run under")
	sans := fs.String("san", "", "further comma-separated host names or addresses for the certificate")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}

	u, err := url.Parse(*issuer)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("the issuer %q is not a URL", *issuer)
	}

	hosts := []string{u.Hostname(), "localhost", "127.0.0.1"}
	for _, h := range strings.Split(*sans, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}

	cert, err := selfSignedCertificate(hosts)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := newServer(ctx, config{Issuer: *issuer, SuiteURL: *suite, Alias: *alias})
	if err != nil {
		return err
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	hs := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}

	done := make(chan error, 1)

	go func() { done <- hs.ServeTLS(ln, "", "") }()

	slog.Info("conformanceop serving", "addr", ln.Addr().String(), "issuer", *issuer, "suite", *suite, "alias", *alias)

	select {
	case err := <-done:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	err = errors.Join(hs.Shutdown(shutdown), srv.Shutdown(shutdown))

	return err
}
