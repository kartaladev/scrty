module example.com/core/test

go 1.26

require (
	example.com/core v0.0.0
	example.com/driver v0.0.0
)

replace (
	example.com/core => ../core
	example.com/driver => ../driver
)
