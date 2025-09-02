//go:build !info && !debug && !trace && !warn && !error && !critical && !off
// +build !info,!debug,!trace,!warn,!error,!critical,!off

package build

// LogLevel specifies the default log level.
var LogLevel = "info"
