//go:build darwin || linux

package bwtest

import (
	"fmt"
	"syscall"
)

const (
	// desiredNoFileLimit is the target soft descriptor limit for test runs that
	// launch bitcoind.
	desiredNoFileLimit = 4096

	// assumedInfinityThreshold is the cutoff used to treat RLIMIT_NOFILE values
	// as effectively infinite and normalize them to a finite limit.
	assumedInfinityThreshold = 1 << 60
)

// raiseNoFileLimit attempts to increase the current process file descriptor
// limit.
//
// This is a best-effort helper intended for integration tests that launch
// external processes like bitcoind. Some systems have a low default soft limit,
// which can cause bitcoind to fail during startup.
//
// This helper is still needed because bitcoind validates RLIMIT_NOFILE on
// startup. Normalizing extreme/low values keeps CI environments predictable.
func raiseNoFileLimit() error {
	var rlim syscall.Rlimit

	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim)
	if err != nil {
		return fmt.Errorf("get rlimit: %w", err)
	}

	newCur, ok := desiredNoFileCur(rlim)
	if !ok {
		return nil
	}

	rlim.Cur = newCur

	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim)
	if err != nil {
		return fmt.Errorf("set rlimit: %w", err)
	}

	return nil
}

// desiredNoFileCur computes the desired RLIMIT_NOFILE soft value and reports
// whether Setrlimit should be called.
func desiredNoFileCur(rlim syscall.Rlimit) (uint64, bool) {
	// Some environments report RLIMIT_NOFILE as effectively infinite. Bitcoind
	// fails fast if the value cannot be represented correctly. Normalizing this
	// to a finite limit avoids startup failures.
	if rlim.Cur >= assumedInfinityThreshold {
		newCur := uint64(desiredNoFileLimit)
		if rlim.Max > 0 && newCur > rlim.Max {
			newCur = rlim.Max
		}

		return newCur, true
	}

	// Nothing to do if we're already above our desired limit.
	if rlim.Cur >= desiredNoFileLimit {
		return 0, false
	}

	// Increase the soft limit, but don't exceed the hard limit.
	newCur := uint64(desiredNoFileLimit)
	if rlim.Max > 0 && newCur > rlim.Max {
		newCur = rlim.Max
	}

	if newCur <= rlim.Cur {
		return 0, false
	}

	return newCur, true
}
