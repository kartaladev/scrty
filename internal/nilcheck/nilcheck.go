// Package nilcheck detects the nil a plain comparison misses.
//
// Every constructor in scrty refuses a port it was handed as nil, and they all
// ask this one function so that they all refuse the same set of values. It is
// internal because the answer is only ever needed while checking wiring, and
// exporting it would make a detail of how those checks are written part of what
// consumers depend on.
package nilcheck

import "reflect"

// IsNil reports whether v is nil, including an interface holding a nil pointer.
//
// A constructor that only writes `if v == nil` accepts the second shape, which
// is exactly what an unchecked constructor error hands over: the caller passes
// the nil result of a failed New, the interface is non-nil because it carries a
// type, and the first method call panics on a request instead of failing at
// wiring time.
func IsNil(v any) bool {
	if v == nil {
		return true
	}

	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
