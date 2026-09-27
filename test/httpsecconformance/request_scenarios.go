package httpsecconformance

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/session"
)

// requestScenarios is every behaviour of how the chain reads a request that
// must be identical on every adapter, whatever that adapter's framework does
// with a field present in both the body and the URL query.
func requestScenarios() []Scenario {
	return []Scenario{
		verifyCodeInTheQueryIsNotRead(),
		verifyBodyCodeWinsOverTheQuery(),
		formFieldInBodyAndQueryAnswersTheBody(),
		formFieldOnlyInTheQueryAnswersTheQuery(),
		multipartFormFieldInBodyAndQueryAnswersTheBody(),
		aGETWithABodyReadsTheQuery(),
		readingAFieldLeavesTheBodyReadable(),
		aFieldReadDoesNotWidenABodyLimit(),
		anEarlierLargerBodyReadDoesNotWidenALaterLimit(),
		anOversizedUploadIsLeftIntact(),
	}
}

// verifyBuild is a user with a confirmed authenticator-app enrolment, and a
// password session owing its second factor, behind a chain with bearer
// authentication and the verify endpoint.
func verifyBuild(t *testing.T) ChainSpec {
	effects := newEffects(t)
	fx := newEnrolmentFixture(t, effects)
	ctx := t.Context()

	provisioning, err := fx.TOTP.BeginEnrolment(ctx, UserID, Username)
	require.NoError(t, err)

	fx.Secret = provisioning.Secret
	require.NoError(t, fx.TOTP.ConfirmEnrolment(ctx, UserID, fx.code(t)))

	// The confirmation spent this step's code; the request presents the next.
	fx.advance(30 * time.Second)

	s, err := effects.Sessions.Create(ctx, UserID, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	s.MFA = session.MFAPending
	require.NoError(t, effects.Sessions.Save(ctx, s))
	effects.SessionID = s.ID

	return ChainSpec{
		Options: append(bearerOptions(effects),
			httpsec.EnableMFA(fx.TOTP, httpsec.WithMFATokens(fixtureTokens{}))),
		Effects: effects,
		Routes:  []Route{{Method: http.MethodPost, Path: httpsec.DefaultMFAVerifyPath, Status: http.StatusCreated, Body: RouteBody}},
		NoRoute: true,
	}
}

// validVerifyCode is what the enrolled authenticator shows at the fixture's
// instant. An error yields a code that verifies nothing, which the scenario's
// assertions then report.
func validVerifyCode(spec ChainSpec) string {
	c, err := totp.GenerateCode(spec.Effects.Enrolment.Secret, spec.Effects.Enrolment.Now())
	if err != nil {
		return ""
	}

	return c
}

// wrongVerifyCode is a code the enrolled authenticator shows in none of the
// steps around the fixture's instant, so it is refused however much clock skew
// the method tolerates.
func wrongVerifyCode(spec ChainSpec) string {
	fx := spec.Effects.Enrolment

	near := map[string]bool{}

	for _, d := range []time.Duration{-time.Minute, -30 * time.Second, 0, 30 * time.Second, time.Minute} {
		if c, err := totp.GenerateCode(fx.Secret, fx.Now().Add(d)); err == nil {
			near[c] = true
		}
	}

	for _, c := range []string{"000000", "111111", "222222", "333333", "444444", "555555"} {
		if !near[c] {
			return c
		}
	}

	return "999999"
}

// verifyPost is a bearer POST to the verify path for the session Build
// created, with query appended to the path and body sent as a URL-encoded form.
func verifyPost(query, body func(ChainSpec) string) func(ChainSpec) RequestSpec {
	return func(spec ChainSpec) RequestSpec {
		r := authenticatedRequest(http.MethodPost, httpsec.DefaultMFAVerifyPath+"?"+query(spec))(spec)
		r.Header["Content-Type"] = "application/x-www-form-urlencoded"

		if body != nil {
			r.Body = body(spec)
		}

		return r
	}
}

func verifyCodeInTheQueryIsNotRead() Scenario {
	// A code in a URL has already reached access logs, proxy logs and the
	// Referer the next page sends. The verify endpoint reads the body alone, on
	// every adapter, so a code that arrives only in the query was not presented.
	return Scenario{
		Name:  "a verify code in the URL query is not read",
		Build: verifyBuild,
		Request: verifyPost(func(spec ChainSpec) string {
			return "code=" + validVerifyCode(spec)
		}, nil),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusBadRequest, res.Status)
			assert.Empty(t, res.Body)
			require.ErrorIs(t, res.Refusal, httpsec.ErrCredentialsMissing)
			assert.False(t, res.RouteRan)

			assert.Equal(t, session.MFAPending, res.Effects.LoadSession(t, res.Effects.SessionID).MFA,
				"the challenge stays pending under the same handle")
		},
	}
}

func verifyBodyCodeWinsOverTheQuery() Scenario {
	// A valid code in the query must not rescue a wrong one in the body, on an
	// adapter whose framework prefers the query any more than on one whose
	// framework prefers the body.
	return Scenario{
		Name:  "a wrong verify code in the body is judged, whatever the query carries",
		Build: verifyBuild,
		Request: verifyPost(func(spec ChainSpec) string {
			return "code=" + validVerifyCode(spec)
		}, func(spec ChainSpec) string {
			return "code=" + wrongVerifyCode(spec)
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.Empty(t, res.Body)
			require.ErrorIs(t, res.Refusal, mfa.ErrInvalidCode)
			assert.False(t, res.RouteRan)

			assert.Equal(t, session.MFAPending, res.Effects.LoadSession(t, res.Effects.SessionID).MFA,
				"the challenge stays pending under the same handle")
		},
	}
}

// formFieldPath is the route the form-field-precedence scenarios send to. No
// option answers it and no route is mounted behind it: the echoing
// interceptor is the only thing that ever runs, and it answers directly.
const formFieldPath = "/form-field"

// formFieldEchoOption is a consumer interceptor that reads field "x" through
// the framework-neutral abstraction and answers with what it read. It is the
// case the framework-adapters precedence promise exists for: a consumer
// reading a field must get the same value whichever adapter carries the
// chain.
func formFieldEchoOption() httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
			ex.Writer.WriteHeader(http.StatusOK)
			_, _ = ex.Writer.Write([]byte(ex.Request.FormValue("x")))

			return nil
		}),
		httpsec.OrderJWKS,
	)
}

// formFieldEchoBuild wires nothing but the echoing interceptor: the chain has
// no built-in endpoint and no application route to reach.
func formFieldEchoBuild(t *testing.T) ChainSpec {
	effects := newEffects(t)

	return ChainSpec{Options: []httpsec.Option{formFieldEchoOption()}, Effects: effects}
}

func formFieldInBodyAndQueryAnswersTheBody() Scenario {
	// net/http and gin already answer the body; fiber's own FormValue searches
	// the query first, so this is the row that catches it.
	return Scenario{
		Name:  "a form field in the body and the query answers with the body",
		Build: formFieldEchoBuild,
		Request: sending(RequestSpec{
			Method:        http.MethodPost,
			Path:          formFieldPath + "?x=query",
			Header:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:          "x=body",
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.NoError(t, res.Refusal)
			assert.Equal(t, "body", res.Body)
		},
	}
}

func formFieldOnlyInTheQueryAnswersTheQuery() Scenario {
	return Scenario{
		Name:  "a form field only in the query answers with the query",
		Build: formFieldEchoBuild,
		Request: sending(RequestSpec{
			Method:        http.MethodPost,
			Path:          formFieldPath + "?x=query",
			Header:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.NoError(t, res.Refusal)
			assert.Equal(t, "query", res.Body)
		},
	}
}

// multipartFormRequest builds a POST whose body is a multipart/form-data
// envelope carrying one field, with the boundary computed the way
// mime/multipart itself computes it, in the Content-Type header.
func multipartFormRequest(path, field, value string) RequestSpec {
	var buf bytes.Buffer

	w := multipart.NewWriter(&buf)
	_ = w.WriteField(field, value)
	_ = w.Close()

	return RequestSpec{
		Method:        http.MethodPost,
		Path:          path,
		Header:        map[string]string{"Content-Type": w.FormDataContentType()},
		Body:          buf.String(),
		ClientAddress: ClientAddress,
	}
}

func multipartFormFieldInBodyAndQueryAnswersTheBody() Scenario {
	// net/http's own FormValue parses the posted form after the query, so a
	// multipart POST carrying x=body alongside x=query in the URL answers
	// "query" — gin shares the same net/http adapter. fiber already answers
	// "body" for a multipart body, so this is the row that catches net/http
	// and gin disagreeing with the shared precedence: the posted form, of
	// either encoding, before the query.
	return Scenario{
		Name:    "a form field in a multipart body and the query answers with the body",
		Build:   formFieldEchoBuild,
		Request: sending(multipartFormRequest(formFieldPath+"?x=query", "x", "body")),
		Assert: func(t *testing.T, res Result) {
			assert.NoError(t, res.Refusal)
			assert.Equal(t, "body", res.Body)
		},
	}
}

func aGETWithABodyReadsTheQuery() Scenario {
	// fasthttp's posted arguments read the body whatever the method, so
	// fiber answered "body" here before it restricted its own posted-form
	// read to POST, PUT and PATCH, matching net/http's own FormValue.
	return Scenario{
		Name:  "a GET with a body reads the query",
		Build: formFieldEchoBuild,
		Request: sending(RequestSpec{
			Method:        http.MethodGet,
			Path:          formFieldPath + "?x=query",
			Header:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:          "x=body",
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.NoError(t, res.Refusal)
			assert.Equal(t, "query", res.Body)
		},
	}
}

// formFieldThenBodyOption is a consumer interceptor that reads field "x"
// through FormValue and then the whole body through Body, and answers with
// both, joined by "|". It is the case the "body still readable" promise
// exists for: a consumer interceptor that reads one field before reading the
// body must still see the body in full, whichever adapter carries the chain.
func formFieldThenBodyOption() httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
			field := ex.Request.FormValue("x")

			body, err := ex.Request.Body(1 << 20)
			if err != nil {
				return err
			}

			ex.Writer.WriteHeader(http.StatusOK)
			_, _ = ex.Writer.Write([]byte(field + "|" + string(body)))

			return nil
		}),
		httpsec.OrderJWKS,
	)
}

// formFieldThenBodyBuild wires nothing but the field-then-body interceptor:
// the chain has no built-in endpoint and no application route to reach.
func formFieldThenBodyBuild(t *testing.T) ChainSpec {
	effects := newEffects(t)

	return ChainSpec{Options: []httpsec.Option{formFieldThenBodyOption()}, Effects: effects}
}

func readingAFieldLeavesTheBodyReadable() Scenario {
	// net/http's own form parsing drains the request body, so a Body call
	// after FormValue answered nothing on that adapter (and on gin, which
	// shares it) before FormValue started reading through the same buffered,
	// restoring path Body itself uses.
	return Scenario{
		Name:  "reading a field leaves the body readable",
		Build: formFieldThenBodyBuild,
		Request: sending(RequestSpec{
			Method:        http.MethodPost,
			Path:          formFieldPath,
			Header:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:          "x=body",
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.NoError(t, res.Refusal)
			assert.Equal(t, "body|x=body", res.Body)
		},
	}
}

// fieldReadingOption is a consumer interceptor that reads field "x" through
// FormValue and passes the request on, placed outside every library endpoint so
// its read happens first.
func fieldReadingOption() httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			_ = ex.Request.FormValue("x")

			return next(ex)
		}),
		httpsec.OrderJWKS,
	)
}

// oversizedVerifyPadding makes a verify body of about 8 KiB, twice the 4 KiB
// the verify endpoint reads a code from.
const oversizedVerifyPadding = 8 << 10

func aFieldReadDoesNotWidenABodyLimit() Scenario {
	// The net/http adapter once read FormValue's body through the same cache
	// Body kept, whose first read answered every later one: a consumer's field
	// read made first widened the verify endpoint's 4 KiB read to FormValue's
	// own cap, and a valid code in an 8 KiB body was accepted. fiber checks
	// each caller's limit, so it refused already.
	return Scenario{
		Name: "a field read does not widen a body limit",
		Build: func(t *testing.T) ChainSpec {
			spec := verifyBuild(t)
			spec.Options = append(spec.Options, fieldReadingOption())

			return spec
		},
		Request: verifyPost(func(ChainSpec) string { return "" }, func(spec ChainSpec) string {
			return "code=" + validVerifyCode(spec) + "&x=" + strings.Repeat("a", oversizedVerifyPadding)
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusRequestEntityTooLarge, res.Status)
			require.ErrorIs(t, res.Refusal, httpsec.ErrRequestTooLarge)
			assert.False(t, res.RouteRan)

			assert.Equal(t, session.MFAPending, res.Effects.LoadSession(t, res.Effects.SessionID).MFA,
				"a code in a body over the endpoint's limit is never judged")
		},
	}
}

// bodyReadingOption is a consumer interceptor that reads the body under limit
// and passes the request on, whatever its read answered, placed outside every
// library endpoint so its read happens first.
func bodyReadingOption(limit int64) httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			_, _ = ex.Request.Body(limit)

			return next(ex)
		}),
		httpsec.OrderJWKS,
	)
}

func anEarlierLargerBodyReadDoesNotWidenALaterLimit() Scenario {
	// The net/http adapter once answered every Body call with its first
	// call's outcome: a consumer's 64 KiB read made first let the verify
	// endpoint's 4 KiB read accept an 8 KiB body, and gin shares that adapter.
	// fiber checks each caller's limit, so it refused already.
	return Scenario{
		Name: "an earlier, larger body read does not widen a later limit",
		Build: func(t *testing.T) ChainSpec {
			spec := verifyBuild(t)
			spec.Options = append(spec.Options, bodyReadingOption(64<<10))

			return spec
		},
		Request: verifyPost(func(ChainSpec) string { return "" }, func(spec ChainSpec) string {
			return "code=" + validVerifyCode(spec) + "&x=" + strings.Repeat("a", oversizedVerifyPadding)
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusRequestEntityTooLarge, res.Status)
			require.ErrorIs(t, res.Refusal, httpsec.ErrRequestTooLarge)
			assert.False(t, res.RouteRan)

			assert.Equal(t, session.MFAPending, res.Effects.LoadSession(t, res.Effects.SessionID).MFA,
				"a code in a body over the endpoint's limit is never judged")
		},
	}
}

// uploadFileSize is the file part of the oversized upload: past the 32 MiB a
// field read parses a multipart body under, by one MiB.
const uploadFileSize = 33 << 20

// oversizedUpload is a multipart POST carrying field x=body and a file part of
// uploadFileSize bytes. It is built once: every adapter sends the same bytes.
var oversizedUpload = sync.OnceValue(func() RequestSpec {
	var buf bytes.Buffer

	w := multipart.NewWriter(&buf)
	_ = w.WriteField("x", "body")

	if part, err := w.CreateFormFile("upload", "upload.bin"); err == nil {
		_, _ = io.Copy(part, io.LimitReader(repeatingReader('a'), uploadFileSize))
	}

	_ = w.Close()

	return RequestSpec{
		Method:        http.MethodPost,
		Path:          formFieldPath + "?x=query",
		Header:        map[string]string{"Content-Type": w.FormDataContentType()},
		Body:          buf.String(),
		ClientAddress: ClientAddress,
	}
})

// repeatingReader reads the same byte forever.
type repeatingReader byte

func (r repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}

	return len(p), nil
}

// uploadReaderOption is a consumer interceptor that reads field "x" through
// FormValue, then parses the whole upload from Body the way a handler behind
// it would, and answers with the field and the size of the file part it
// parsed, joined by "|". It answers every outcome itself, a failed read
// included, so a status other than 200 is never the chain's.
func uploadReaderOption() httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
			field := ex.Request.FormValue("x")

			ex.Writer.WriteHeader(http.StatusOK)
			_, _ = ex.Writer.Write([]byte(field + "|" + parsedUploadSize(ex.Request)))

			return nil
		}),
		httpsec.OrderJWKS,
	)
}

// parsedUploadSize parses the whole multipart body and names the size of its
// "upload" file part, or what stopped the parse.
func parsedUploadSize(r httpsec.Request) string {
	body, err := r.Body(2 * uploadFileSize)
	if err != nil {
		return "body: " + err.Error()
	}

	_, params, err := mime.ParseMediaType(r.Header("Content-Type"))
	if err != nil {
		return "content type: " + err.Error()
	}

	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])

	for {
		part, err := mr.NextPart()
		if err != nil {
			return "parse: " + err.Error()
		}

		if part.FormName() != "upload" {
			continue
		}

		n, err := io.Copy(io.Discard, part)
		if err != nil {
			return fmt.Sprintf("parse after %d bytes: %v", n, err)
		}

		return strconv.FormatInt(n, 10)
	}
}

func anOversizedUploadIsLeftIntact() Scenario {
	// The net/http adapter once read FormValue's body through Body's cache
	// with a 32 MiB cap: an upload over it was consumed up to the cap, the
	// refusal was remembered, and a handler behind the field read could no
	// longer parse the upload at all.
	//
	// An adapter runs this row only when its framework accepts a body this
	// large: fiber's own BodyLimit, 4 MiB by default, refuses it before the
	// chain is reached, so fiber's adapter sets a limit above the upload.
	return Scenario{
		Name: "an oversized upload is left intact",
		Build: func(t *testing.T) ChainSpec {
			return ChainSpec{Options: []httpsec.Option{uploadReaderOption()}, Effects: newEffects(t)}
		},
		Request: func(ChainSpec) RequestSpec { return oversizedUpload() },
		Assert: func(t *testing.T, res Result) {
			assert.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, "query|"+strconv.Itoa(uploadFileSize), res.Body,
				"the field read answered from the query, and the upload stayed whole for the handler")
		},
	}
}
