package mfa

// ResponseKind names how a method's verification response is carried in the
// request body.
type ResponseKind int

const (
	// ResponseFormField is one field of a URL-encoded body. The method receives
	// that field's value.
	ResponseFormField ResponseKind = iota + 1

	// ResponseJSONBody is a whole body declared as JSON. The method receives
	// the body's bytes unchanged.
	ResponseJSONBody
)

// ResponseFormat is how a method's verification response is carried, and the
// largest body it accepts.
//
// It is built only through FormField or JSONBody; the zero value is not a
// format, and LookupsFor refuses it. The library reads the response with a
// reader of its own and hands the method only the response bytes, so a method
// never reads the request.
type ResponseFormat struct {
	kind  ResponseKind
	field string
	limit int64
}

// FormField declares a response carried as the field name of a URL-encoded
// body, in a body of at most limit bytes.
//
// The limit must be in (0, 1 MiB] and name must not be empty; LookupsFor
// refuses a method declaring anything else.
func FormField(name string, limit int64) ResponseFormat {
	return ResponseFormat{kind: ResponseFormField, field: name, limit: limit}
}

// JSONBody declares a response carried as a whole JSON body of at most limit
// bytes.
//
// The limit must be in (0, 1 MiB]; LookupsFor refuses a method declaring
// anything else.
func JSONBody(limit int64) ResponseFormat {
	return ResponseFormat{kind: ResponseJSONBody, limit: limit}
}

// Kind reports how the response is carried. The zero format reports 0, which is
// neither kind.
func (f ResponseFormat) Kind() ResponseKind { return f.kind }

// Field reports the form field's name, or "" for a JSON body.
func (f ResponseFormat) Field() string { return f.field }

// Limit reports the largest body accepted, in bytes.
func (f ResponseFormat) Limit() int64 { return f.limit }
