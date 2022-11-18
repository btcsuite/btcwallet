package chain

import "github.com/lightninglabs/neutrino"

var _ rescanner = (*neutrino.Rescan)(nil)

// rescanner is an interface that abstractly defines the public methods of
// a *neutrino.Rescan.  The interface is private because it is only ever
// intended to be implemented by a *neutrino.Rescan.
type rescanner interface {
	starter
	updater

	// WaitForShutdown blocks until the underlying rescan object is shutdown.
	// Close the quit channel before calling WaitForShutdown.
	WaitForShutdown()
}

// updater is the interface that wraps the Update method of a rescan object.
type updater interface {
	// Update targets a long-running rescan/notification client with
	// updateable filters.  Attempts to update the filters will fail
	// if either the rescan is no longer running or the shutdown signal is
	// received prior to sending the update.
	Update(...neutrino.UpdateOption) error
}

// starter is the interface that wraps the Start method of a rescan object.
type starter interface {
	// Start initializes the rescan goroutine, which will begin to scan the chain
	// according to the specified rescan options.  Start returns a channel that
	// communicates any startup errors.  Attempts to start a running rescan
	// goroutine will error.
	Start() <-chan error
}

// newRescanFunc defines a constructor that accepts rescan options and returns
// an object that satisfies rescanner interface.
type newRescanFunc func(...neutrino.RescanOption) rescanner
