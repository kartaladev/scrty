// Package idgenmock holds a generated mock of [id.Generator] for the store
// suites of this test module. It lives here, not beside the generator, so the
// core module's production build never carries the mock or gomock.
//
//go:generate mockgen -source=../../../pkg/id/generator.go -destination=generator_mock.go -package=idgenmock -typed
package idgenmock
