// Package app imports an integration module from a production file.
package app

import "github.com/gin-gonic/gin"

// Answer reaches into the framework, which no production build may do.
func Answer() int { return gin.New() }
