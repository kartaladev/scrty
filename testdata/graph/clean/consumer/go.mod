module example.com/consumer

go 1.26

require example.com/core v0.0.0

replace (
	example.com/core => ../core
	example.com/core/test => ../helpers
	example.com/driver => ../driver
)
