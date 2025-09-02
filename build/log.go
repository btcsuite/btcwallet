// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package build

import (
	"os"

	"github.com/btcsuite/btclog"
)

// LogType is an indicating the type of logging specified by the build flag.
type LogType byte

const (
	// LogTypeNone indicates no logging.
	LogTypeNone LogType = iota

	// LogTypeStdOut all logging is written directly to stdout.
	LogTypeStdOut

	// LogTypeDefault logs to both stdout and a given io.PipeWriter.
	LogTypeDefault
)

// String returns a human readable identifier for the logging type.
func (t LogType) String() string {
	switch t {
	case LogTypeNone:
		return "none"
	case LogTypeStdOut:
		return "stdout"
	case LogTypeDefault:
		return "default"
	default:
		return "unknown"
	}
}

// NewSubLogger constructs a new subsystem log from the current LogWriter
// implementation. This is primarily intended for use with stdlog, as the actual
// writer is shared amongst all instantiations.
func NewSubLogger(subsystem string,
	genSubLogger func(string) btclog.Logger) btclog.Logger {

	switch Deployment {

	// For production builds, generate a new subsystem logger from the
	// primary log backend. If no function is provided, logging will be
	// disabled.
	case Production:
		if genSubLogger != nil {
			return genSubLogger(subsystem)
		}

	// For development builds, we must handle two distinct types of logging:
	// unit tests and running the live daemon, e.g. for integration testing.
	case Development:
		switch LoggingType {

		// Default logging is used when running the standalone daemon.
		// We'll use the optional sublogger constructor to mimic the
		// production behavior.
		case LogTypeDefault:
			if genSubLogger != nil {
				return genSubLogger(subsystem)
			}

		// Logging to stdout is used in unit tests. It is not important
		// that they share the same backend, since all output is written
		// to std out.
		case LogTypeStdOut:
			backend := btclog.NewBackend(os.Stdout)
			logger := backend.Logger(subsystem)

			// Set the logging level of the stdout logger to use the
			// configured logging level specified by build flags.
			level, _ := btclog.LevelFromString(LogLevel)
			logger.SetLevel(level)

			return logger
		}
	}

	// For any other configurations, we'll disable logging.
	return btclog.Disabled
}
