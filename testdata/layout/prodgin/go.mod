module example.com/fixture

go 1.26

// Marked indirect on purpose: this fixture is the shape the guard used to miss.
// A production file imports the module while go.mod still calls the requirement
// indirect, which is exactly the state this project leaves requirements in
// between adding a dependency and its first `go mod tidy`.
require github.com/gin-gonic/gin v0.0.0 // indirect

replace github.com/gin-gonic/gin => ./stub/gin
