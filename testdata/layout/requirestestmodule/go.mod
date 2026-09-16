module example.com/fixture

go 1.26

require github.com/kartaladev/scrty/test v0.0.0 // indirect

replace github.com/kartaladev/scrty/test => ./stub/test
