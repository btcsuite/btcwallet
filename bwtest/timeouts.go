package bwtest

import "time"

const (
	// defaultTestTimeout is a shared default timeout for polling and setup
	// steps in integration tests.
	defaultTestTimeout = 30 * time.Second
)
