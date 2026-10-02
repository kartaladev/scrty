module example.com/fixture

go 1.26

require example.com/forbidden v0.0.0

replace example.com/forbidden => ./stub/forbidden
