package main

import (
	"crypto/subtle"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

// The pages are forms and nothing else: no script, no fetch, because the suite's browser is
// HtmlUnit. Its configuration (test/conformance/oidcc.json) finds the fields by name and the
// buttons by class, so those are part of the contract with it.
var pageTemplates = template.Must(template.New("pages").Parse(`
{{define "head"}}<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>{{.Title}}</title></head><body><h1>{{.Title}}</h1>{{if .Message}}<p class="message">{{.Message}}</p>{{end}}{{end}}
{{define "tail"}}</body></html>{{end}}
{{define "login"}}{{template "head" .}}<form method="post" action="/login"><input type="hidden" name="req" value="{{.Handle}}"><p><label>Username <input type="text" name="username" autocomplete="username"></label></p><p><label>Password <input type="password" name="password" autocomplete="current-password"></label></p><p><button type="submit" class="login-submit">Sign in</button></p></form>{{template "tail"}}{{end}}
{{define "consent"}}{{template "head" .}}<p>{{.Client}} asks for your consent to: {{range .Scopes}}<code>{{.}}</code> {{end}}</p><form method="post" action="/consent"><input type="hidden" name="req" value="{{.Handle}}"><p><button type="submit" name="decision" value="allow" class="login-submit">Allow</button> <button type="submit" name="decision" value="deny" class="deny-submit">Deny</button></p></form>{{template "tail"}}{{end}}
{{define "logout"}}{{template "head" .}}<form method="post" action="/logout"><input type="hidden" name="req" value="{{.Handle}}"><p><button type="submit" name="confirmed" value="true" autofocus>Yes, sign me out</button> <button type="submit" name="confirmed" value="false">No, stay signed in</button></p></form>{{template "tail"}}{{end}}
{{define "message"}}{{template "head" .}}{{template "tail"}}{{end}}
`))

// pageData is what the templates read.
type pageData struct {
	Title, Message, Handle, Client string
	Scopes                         []string
}

// render writes a page. Nothing here may be cached or framed: a form carries a handle.
func render(w http.ResponseWriter, status int, name string, data pageData) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)

	if err := pageTemplates.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("conformanceop: rendering a page", "page", name, "error", err)
	}
}

// refusalPage shows a person what the chain refused, for a request a browser made. It names the
// kind of request and nothing the library knows.
func refusalPage(w http.ResponseWriter, r *http.Request, err error) {
	status := httpsec.StatusForError(err)

	if !acceptsHTML(r) {
		w.WriteHeader(status)

		return
	}

	msg := "The request was refused."

	switch {
	case errors.Is(err, httpsec.ErrOIDCInvalidAuthorization):
		msg = "The authorization request was refused: the redirect URI is not registered, or the client is unknown."
	case errors.Is(err, httpsec.ErrOIDCInvalidEndSession):
		msg = "The end-session request was refused: the id_token_hint could not be validated."
	}

	render(w, status, "message", pageData{Title: "Request refused", Message: msg})
}

func acceptsHTML(r *http.Request) bool {
	for _, v := range r.Header.Values("Accept") {
		if strings.Contains(v, "text/html") {
			return true
		}
	}

	return false
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}

	return c.Value
}

// setBrowserSession sets the cookie single sign-on rests on, as the README requires: HttpOnly,
// Secure, SameSite=Lax, Path=/, and no Domain, which is what the __Host- prefix demands.
func setBrowserSession(w http.ResponseWriter, secret string) {
	http.SetCookie(w, &http.Cookie{
		Name:     httpsec.OIDCBrowserSessionCookie,
		Value:    secret,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearBrowserSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     httpsec.OIDCBrowserSessionCookie,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func fail(w http.ResponseWriter, status int, msg string) {
	render(w, status, "message", pageData{Title: "Error", Message: msg})
}

// login shows the sign-in form for a parked request, and resumes the request when it is posted.
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handle := r.URL.Query().Get(oidcprovider.HandleParam)
		if _, err := s.provider.PendingRequest(r.Context(), handle, cookieValue(r, httpsec.OIDCFlowCookie)); err != nil {
			s.pageError(w, err)

			return
		}

		render(w, http.StatusOK, "login", pageData{Title: "Sign-in", Handle: handle})
	case http.MethodPost:
		s.signIn(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *server) signIn(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, "The form could not be read.")

		return
	}

	handle := r.PostForm.Get("req")
	ctx := r.Context()

	user, err := fixtureUsers{}.LoadByUsername(ctx, r.PostForm.Get("username"))
	// Both halves are compared whatever the first found, so a wrong name costs what a wrong
	// password costs.
	nameOK := subtle.ConstantTimeCompare([]byte(r.PostForm.Get("username")), []byte(userName)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(r.PostForm.Get("password")), []byte(userPassword)) == 1

	if err != nil || !nameOK || !passOK {
		render(w, http.StatusUnauthorized, "login", pageData{Title: "Sign-in", Message: "Wrong username or password.", Handle: handle})

		return
	}

	created, err := s.sessions.Create(ctx, user.ID, session.WithFirstFactor(factor.Password))
	if err != nil {
		slog.Error("conformanceop: creating the session", "error", err)
		fail(w, http.StatusInternalServerError, "Sign-in is unavailable.")

		return
	}

	res, err := s.provider.Resume(ctx, oidcprovider.ResumeInput{
		Handle:     handle,
		FlowSecret: cookieValue(r, httpsec.OIDCFlowCookie),
		SignIn: &oidcprovider.SignIn{
			User:              created.UserID,
			Family:            created.FamilyID,
			AuthenticatedAt:   created.AuthenticatedAt,
			AMR:               []string{"pwd"},
			ACR:               loginACR,
			AbsoluteExpiresAt: created.AbsoluteExpiresAt,
		},
		BrowserSessionSecret: cookieValue(r, httpsec.OIDCBrowserSessionCookie),
		IdleTimeout:          s.sessions.IdleTimeout(),
	})
	if err != nil {
		// The request was not resumed, so nothing will end this sign-in: end it here.
		_, _ = s.sessions.RevokeFamily(r.Context(), created.FamilyID)

		s.pageError(w, err)

		return
	}

	if res.BrowserSessionSecret != "" {
		setBrowserSession(w, res.BrowserSessionSecret)
	}

	http.Redirect(w, r, res.RedirectTo, http.StatusSeeOther)
}

// consent shows what a client asks for, and answers the consent stage when the form is posted.
// The browser session answers for the user, so the form carries no credential.
func (s *server) consent(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handle := r.URL.Query().Get(oidcprovider.HandleParam)

		view, err := s.provider.PendingRequest(r.Context(), handle, cookieValue(r, httpsec.OIDCFlowCookie))
		if err != nil {
			s.pageError(w, err)

			return
		}

		render(w, http.StatusOK, "consent", pageData{
			Title: "Authorize", Handle: handle, Client: view.ClientName, Scopes: view.Scopes,
		})
	case http.MethodPost:
		s.answerConsent(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *server) answerConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, "The form could not be read.")

		return
	}

	handle := r.PostForm.Get("req")
	flow := cookieValue(r, httpsec.OIDCFlowCookie)
	ctx := r.Context()

	view, err := s.provider.PendingRequest(ctx, handle, flow)
	if err != nil {
		s.pageError(w, err)

		return
	}

	answer := &oidcprovider.ConsentAnswer{Deny: r.PostForm.Get("decision") != "allow"}
	if !answer.Deny {
		answer.Scopes = view.Scopes
	}

	res, err := s.provider.Resume(ctx, oidcprovider.ResumeInput{
		Handle:               handle,
		FlowSecret:           flow,
		BrowserSessionSecret: cookieValue(r, httpsec.OIDCBrowserSessionCookie),
		IdleTimeout:          s.sessions.IdleTimeout(),
		Answer:               answer,
	})
	if err != nil {
		s.pageError(w, err)

		return
	}

	http.Redirect(w, r, res.RedirectTo, http.StatusSeeOther)
}

// logout asks the user whether to sign out, for an end-session request the provider could not
// answer by itself, and ends the sign-in when the form is posted.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		render(w, http.StatusOK, "logout", pageData{
			Title: "Sign-out", Message: "Do you want to sign out?", Handle: r.URL.Query().Get(oidcprovider.HandleParam),
		})
	case http.MethodPost:
		s.confirmLogout(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *server) confirmLogout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, "The form could not be read.")

		return
	}

	ctx := r.Context()

	res, err := s.provider.ConfirmLogout(ctx, r.PostForm.Get("req"),
		cookieValue(r, httpsec.OIDCFlowCookie), cookieValue(r, httpsec.OIDCBrowserSessionCookie),
		r.PostForm.Get("confirmed") == "true")
	if err != nil {
		s.pageError(w, err)

		return
	}

	if res.Ended != nil {
		// What the chain's own end-session does: the browser session goes, and so do the
		// sign-in's first-party sessions, which the provider does not hold.
		clearBrowserSession(w)

		if _, err := s.sessions.Logout(ctx, res.User, res.Ended.Family); err != nil && !errors.Is(err, session.ErrNotFound) {
			slog.Error("conformanceop: deleting the ended sign-in's sessions", "error", err)
			fail(w, http.StatusInternalServerError, "Sign-out is unavailable.")

			return
		}
	}

	http.Redirect(w, r, res.RedirectTo, http.StatusSeeOther) //nolint:gosec // G710: the provider built the URL: a registered URI, or a page of its own
}

func (*server) loggedOut(w http.ResponseWriter, _ *http.Request) {
	render(w, http.StatusOK, "message", pageData{Title: "Sign-out Success", Message: "You are signed out."})
}

// pageError answers a provider refusal a page can show.
func (*server) pageError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, oidcprovider.ErrUnknownHandle):
		fail(w, http.StatusBadRequest, "This request is unknown, expired or already answered. Start again from the application.")
	case errors.Is(err, oidcprovider.ErrReauthenticate):
		fail(w, http.StatusUnauthorized, "Your sign-in is no longer valid. Start again from the application.")
	case errors.Is(err, oidcprovider.ErrConsentMalformed):
		fail(w, http.StatusBadRequest, "The answer does not fit the request.")
	default:
		slog.Error("conformanceop: a provider call failed", "error", err)
		fail(w, http.StatusInternalServerError, "The provider could not answer.")
	}
}
