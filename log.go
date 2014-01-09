/*
 * Copyright (c) 2013, 2014 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"fmt"
	"github.com/conformal/seelog"
	"os"
)

var (
	log = seelog.Disabled
)

// logClosure is used to provide a closure over expensive logging operations
// so don't have to be performed when the logging level doesn't warrant it.
type logClosure func() string

// String invokes the underlying function and returns the result.
func (c logClosure) String() string {
	return c()
}

// newLogClosure returns a new closure over a function that returns a string
// which itself provides a Stringer interface so that it can be used with the
// logging system.
func newLogClosure(c func() string) logClosure {
	return logClosure(c)
}

// newLogger creates a new seelog logger using the provided logging level and
// log message prefix.
func newLogger(level string, prefix string) seelog.LoggerInterface {
	//<seelog type="adaptive" mininterval="2000000" maxinterval="100000000"
	//      critmsgcount="500" minlevel="%s">

	fmtstring := `
        <seelog type="sync" minlevel="%s">
                <outputs formatid="all">
                        <console/>
                </outputs>
                <formats>
                        <format id="all" format="%%Time %%Date [%%LEV] %s: %%Msg%%n" />
                </formats>
        </seelog>`
	config := fmt.Sprintf(fmtstring, level, prefix)

	logger, err := seelog.LoggerFromConfigAsString(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v", err)
		os.Exit(1)
	}

	return logger
}

// useLogger sets the btcd logger to the passed logger.
func useLogger(logger seelog.LoggerInterface) {
	log = logger
}

// setLogLevel sets the log level for the logging system.  It initializes a
// logger for each subsystem at the provided level.
func setLogLevel(logLevel string) []seelog.LoggerInterface {
	var loggers []seelog.LoggerInterface

	// Define sub-systems.
	subSystems := []struct {
		level     string
		prefix    string
		useLogger func(seelog.LoggerInterface)
	}{
		{logLevel, "BTCW", useLogger},
	}

	// Configure all sub-systems with new loggers while keeping track of
	// the created loggers to return so they can be flushed.
	for _, s := range subSystems {
		newLog := newLogger(s.level, s.prefix)
		loggers = append(loggers, newLog)
		s.useLogger(newLog)
	}

	return loggers
}
