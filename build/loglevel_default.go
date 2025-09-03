//go:build !info && !debug && !trace && !warn && !error && !critical && !off && !nolog
// +build !info,!debug,!trace,!warn,!error,!critical,!off,!nolog

package build

// LogLevel specifies the default log level.
var LogLevel = "info"
