module example.com/fixture

go 1.26

require github.com/gin-gonic/gin v0.0.0

replace github.com/gin-gonic/gin => ./stub/gin
