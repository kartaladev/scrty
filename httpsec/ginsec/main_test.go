package ginsec_test

import (
	"os"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestMain puts gin in test mode, so a test's output is the test's and not
// gin's start-up banner.
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	os.Exit(m.Run())
}
