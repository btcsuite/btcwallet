// Package port provides functionality for managing network ports, including
// finding available ports and ensuring exclusive access using lock files.
package port

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	// defaultTimeout is the default timeout that is used for the wait
	// package.
	defaultTimeout = 30 * time.Second

	// ListenerFormat is the format string that is used to generate local
	// listener addresses.
	ListenerFormat = "127.0.0.1:%d"

	// defaultNodePort is the start of the range for listening ports of
	// harness nodes. Ports are monotonically increasing starting from this
	// number and are determined by the results of NextAvailablePort().
	defaultNodePort int = 10000

	// uniquePortFile is the name of the file that is used to store the
	// last port that was used by a node. This is used to make sure that
	// the same port is not used by multiple nodes at the same time. The
	// file is located in the temp directory of a system.
	uniquePortFile = "rpctest-port"

	// filePerms is the file permission used for the lock file and port
	// file.
	filePerms = 0600

	// retryInterval is the interval to wait before retrying to acquire the
	// lock file.
	retryInterval = 10 * time.Millisecond

	// maxPort is the maximum valid port number.
	maxPort = 65535
)

var (
	// portFileMutex is a mutex that is used to make sure that the port file
	// is not accessed by multiple goroutines of the same process at the
	// same time. This is used in conjunction with the lock file to make
	// sure that the port file is not accessed by multiple processes at the
	// same time either. So the lock file is to guard between processes and
	// the mutex is to guard between goroutines of the same process.
	portFileMutex sync.Mutex
)

// NextAvailablePort returns the first port that is available for listening by a
// new node, using a lock file to make sure concurrent access for parallel tasks
// on the same system don't re-use the same port.
func NextAvailablePort() int {
	portFileMutex.Lock()
	defer portFileMutex.Unlock()

	lockFile := filepath.Join(os.TempDir(), uniquePortFile+".lock")
	lockFile = filepath.Clean(lockFile)
	lockFileHandle := acquireLockFile(lockFile)

	// Release the lock file when we're done.
	defer func() {
		// Always close file first, Windows won't allow us to remove it
		// otherwise.
		_ = lockFileHandle.Close()

		err := os.Remove(lockFile)
		if err != nil {
			panic(fmt.Errorf("couldn't remove lock file: %w", err))
		}
	}()

	portFile := filepath.Join(os.TempDir(), uniquePortFile)
	portFile = filepath.Clean(portFile)

	port, err := os.ReadFile(portFile)
	if err != nil {
		if !os.IsNotExist(err) {
			panic(fmt.Errorf("error reading port file: %w", err))
		}

		port = []byte(strconv.Itoa(defaultNodePort))
	}

	lastPort, err := strconv.Atoi(string(port))
	if err != nil {
		panic(fmt.Errorf("error parsing port: %w", err))
	}

	// lastPort has reached the max allowed port, we start with the default
	// node port.
	if lastPort >= maxPort {
		lastPort = defaultNodePort
	}

	// Determine the first port to try.
	nextPort := lastPort + 1

	availablePort := findAvailablePort(nextPort)

	err = os.WriteFile(
		portFile, []byte(strconv.Itoa(availablePort)), filePerms,
	)
	if err != nil {
		panic(fmt.Errorf("error updating port file: %w", err))
	}

	return availablePort
}

// findAvailablePort searches for an available port starting from the given
// port. If it reaches the maximum port number, it wraps around to the default
// node port and continues searching until it has checked the entire range.
func findAvailablePort(startPort int) int {
	currentPort := startPort
	for {
		// If there are no errors while attempting to listen on this
		// port, close the socket and return it as available. While it
		// could be the case that some other process picks up this port
		// between the time the socket is closed, and it's reopened in
		// the harness node, in practice in CI servers this seems much
		// less likely than simply some other process already being
		// bound at the start of the tests.
		addr := fmt.Sprintf(ListenerFormat, currentPort)

		lc := &net.ListenConfig{}

		l, err := lc.Listen(context.Background(), "tcp4", addr)
		if err == nil {
			_ = l.Close()
			return currentPort
		}

		currentPort++

		// Start from the beginning if we reached the end of the port
		// range. We need to do this because the lock file now is
		// persistent across runs on the same machine during the same
		// boot/uptime cycle. So in order to make this work on
		// developer's machines, we need to reset the port to the
		// default value when we reach the end of the range.
		if currentPort > maxPort {
			currentPort = defaultNodePort
		}

		// If we reached the start port again, it means no ports are
		// available.
		if currentPort == startPort {
			break
		}
	}

	// No ports available? Must be a mistake.
	panic("no ports available for listening")
}

// acquireLockFile attempts to acquire the lock file. If it already exists, it
// waits for a bit and retries until the timeout is reached. If the process is
// killed before the lock file is removed, this function will timeout and panic.
// In that case, the lock file must be manually removed.
func acquireLockFile(lockFile string) *os.File {
	timeout := time.After(defaultTimeout)

	var (
		lockFileHandle *os.File
		err            error
	)
	for {
		// Attempt to acquire the lock file. If it already exists, wait
		// for a bit and retry.
		//
		//nolint:gosec // lockFile is constructed from os.TempDir() and
		// a constant, not from user input.
		lockFileHandle, err = os.OpenFile(
			lockFile, os.O_CREATE|os.O_EXCL, filePerms,
		)
		if err == nil {
			// Lock acquired.
			return lockFileHandle
		}

		// Wait for a bit and retry.
		select {
		case <-timeout:
			str := "timeout waiting for lock file: " + lockFile
			panic(str)
		case <-time.After(retryInterval):
		}
	}
}
