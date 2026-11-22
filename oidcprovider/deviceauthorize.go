package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"time"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/porterr"
)

// maxUserCodeAttempts is how many user codes AuthorizeDevice tries in all, the first
// included, before it gives up on finding one no live authorization holds.
const maxUserCodeAttempts = 5

// errUserCodesTaken stands for a store that found every code tried held. It carries no code.
var errUserCodesTaken = errors.New("oidcprovider: no free user code was found")

// DeviceAuthorizationRequest is a device authorization request (RFC 8628 section 3.1) as
// the endpoint received it. It holds the client's secret and the scope asked for, so it
// prints and logs redacted; read its fields to use it.
type DeviceAuthorizationRequest struct {
	// Credentials is what the request presented to authenticate its client. Its Form and
	// Query are those below when left nil.
	Credentials ClientCredentials
	// Form is the parsed request body. A parameter with no value counts as omitted.
	Form url.Values
	// Query is the parsed query string. It may name no client credential.
	Query url.Values
}

// Format writes the redacted form under every verb.
func (DeviceAuthorizationRequest) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redacted))
}

// LogValue is the redacted form.
func (DeviceAuthorizationRequest) LogValue() slog.Value { return slog.StringValue(redacted) }

// DeviceAuthorizationResponse is what the device is answered (RFC 8628 section 3.2). It
// holds both codes, so it prints and logs redacted; read its fields to use it.
type DeviceAuthorizationResponse struct {
	// DeviceCode is the code the device polls the token endpoint with.
	DeviceCode string
	// UserCode is the code the user enters, in its displayed form.
	UserCode string
	// VerificationURI is the code-entry page.
	VerificationURI string
	// VerificationURIComplete is the code-entry page with UserCode in its query, and is
	// empty unless the client is registered for it (Client.DeviceCompleteURI).
	VerificationURIComplete string
	// ExpiresIn is how long both codes last, in whole seconds, and Interval how long the
	// device must wait between polls, in whole seconds.
	ExpiresIn, Interval int
}

// Format writes the redacted form under every verb.
func (DeviceAuthorizationResponse) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redacted))
}

// LogValue is the redacted form.
func (DeviceAuthorizationResponse) LogValue() slog.Value { return slog.StringValue(redacted) }

// AuthorizeDevice answers a device authorization request: it authenticates the client as
// the token endpoint does, validates the scope and resource asked for as the
// authorization endpoint does, and stores a new authorization holding only the digests of
// its device code and user code.
//
// A refusal is an *Error holding its code alone, never a value from the request:
// invalid_request for a repeated parameter, a credential in the query, a scope or resource
// that no store could hold or past its bound, and a request naming no scope;
// invalid_client when the client's credential is wrong; unauthorized_client for a client
// not registered for the device grant, and for every client of a provider that has not
// enabled it; invalid_scope and invalid_target as at the authorization endpoint. Nothing is
// stored for any of them. Unknown parameters are ignored, whatever their size.
//
// Any other error is not a verdict on the request. A failing registry, store or random
// source, and a store that holds every user code tried, match ErrDependency behind fixed
// text, with no code, digest or source text in it; a caller who left matches its own
// context's error. A context already done is refused before anything is stored. A user
// code a live authorization holds is drawn again, at most 5 codes in all, and any other
// store error ends the request at once.
//
// The clock is the provider's: the authorization expires at its reading plus the lifetime
// (WithDeviceLifetime).
func (p *Provider) AuthorizeDevice(ctx context.Context, req DeviceAuthorizationRequest) (*DeviceAuthorizationResponse, error) {
	if !p.DeviceEnabled() {
		return nil, &Error{Code: CodeUnauthorizedClient}
	}
	if repeatedParam(req.Form) {
		return nil, refuseRequest()
	}

	creds := req.Credentials
	if creds.Form == nil {
		creds.Form = req.Form
	}
	if creds.Query == nil {
		creds.Query = req.Query
	}
	rc, err := p.AuthenticateClient(ctx, creds)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(rc.GrantTypes, GrantDeviceCode) {
		return nil, &Error{Code: CodeUnauthorizedClient}
	}

	scopes, resources, err := p.readDeviceRequest(req.Form, rc)
	if err != nil {
		return nil, err
	}

	// The caller who has left gets no authorization stored for them.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("oidcprovider: issue a device authorization: the caller left: %w", err)
	}

	return p.issueDevice(ctx, rc, scopes, resources)
}

// readDeviceRequest reads the scope and resources of a device authorization request by the
// authorization endpoint's rules, over those two parameters alone, so that every other
// parameter is unknown and ignored.
func (p *Provider) readDeviceRequest(form url.Values, rc *RegisteredClient) ([]string, []string, error) {
	params := url.Values{}
	for _, name := range []string{paramScope, paramResource} {
		if values, ok := form[name]; ok {
			params[name] = values
		}
	}
	reading := &requestReading{params: params, client: rc, bounds: p.cfg.bounds, req: &PendingRequest{}}
	for _, step := range []func(*requestReading) string{
		(*requestReading).readBounds,
		(*requestReading).readScopes,
		(*requestReading).readResources,
	} {
		if code := step(reading); code != "" {
			return nil, nil, &Error{Code: code}
		}
	}

	return reading.req.Scopes, reading.req.Resources, nil
}

// issueDevice mints the codes and stores the authorization, drawing the user code again
// while a live authorization holds it.
func (p *Provider) issueDevice(ctx context.Context, rc *RegisteredClient, scopes, resources []string) (*DeviceAuthorizationResponse, error) {
	cfg := p.cfg.device

	deviceCode, deviceDigest, err := mintDeviceCode(p.cfg.random)
	if err != nil {
		return nil, p.deviceDependency(ctx, err, "oidcprovider: mint a device code")
	}
	recordID, err := idgen.New(p.cfg.ids)
	if err != nil {
		return nil, p.deviceDependency(ctx, err, "oidcprovider: mint a device authorization identifier")
	}

	now := p.cfg.clock.Now()
	record := &DeviceAuthorization{
		ID:               recordID,
		DeviceCodeDigest: deviceDigest,
		ClientID:         rc.ID,
		Scopes:           scopes,
		Resources:        resources,
		IssuedAt:         now,
		ExpiresAt:        now.Add(cfg.lifetime),
		Interval:         cfg.interval,
		State:            DeviceIssued,
	}

	for range maxUserCodeAttempts {
		// A caller who left during a collision gets no further attempt, so nothing is
		// stored for them.
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("oidcprovider: issue a device authorization: the caller left: %w", err)
		}
		raw, err := cfg.format.generate(p.cfg.random)
		if err != nil {
			return nil, p.deviceDependency(ctx, err, "oidcprovider: mint a user code")
		}
		// Each attempt is a record of its own, so that a store keeping the pointer it was
		// given never sees a later attempt's digest through it. The digest is of the raw
		// code, which is what an entered code reads back to.
		attempt := *record
		attempt.UserCodeDigest = cfg.userCodeDigest(raw)

		err = cfg.store.Create(ctx, &attempt, now)
		switch {
		case err == nil:
			p.reportDevice(ctx, event.DeviceAuthorizationIssued, "", rc.ID)

			return p.deviceResponse(rc, deviceCode, cfg.format.display(raw), &attempt), nil
		case errors.Is(err, ErrUserCodeTaken):
			continue
		default:
			return nil, p.deviceDependency(ctx, err, "oidcprovider: store a device authorization")
		}
	}

	return nil, dependencyFailure(ctx, errUserCodesTaken, "oidcprovider: store a device authorization")
}

// deviceDependency sanitizes a failure of a port, as the other entry points do, and answers
// it as a dependency failure behind fixed text.
func (p *Provider) deviceDependency(ctx context.Context, err error, text string) error {
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)

	return dependencyFailure(ctx, err, text)
}

// deviceResponse builds the answer, with the complete URI for a client registered for it.
func (p *Provider) deviceResponse(rc *RegisteredClient, deviceCode, userCode string, record *DeviceAuthorization) *DeviceAuthorizationResponse {
	entry := p.cfg.device.entryURL
	resp := &DeviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: entry.String(),
		ExpiresIn:       int(record.ExpiresAt.Sub(record.IssuedAt) / time.Second),
		Interval:        int(record.Interval / time.Second),
	}
	if rc.DeviceCompleteURI {
		complete := *entry
		query := complete.Query()
		query.Set("user_code", userCode)
		complete.RawQuery = query.Encode()
		resp.VerificationURIComplete = complete.String()
	}

	return resp
}
