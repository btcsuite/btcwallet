package rescan

import "github.com/lightninglabs/neutrino"

var _ Interface = (*neutrino.Rescan)(nil)

type Updater interface {
	Update(...neutrino.UpdateOption) error
}

type Starter interface {
	Start() <-chan error
}

// Interface encapsulates the public
// methods of a *neutrino.Rescan used by the NeutrinoClient.
type Interface interface {
	Starter
	Updater

	// WaitForShutdown blocks until the underlying rescan object is shutdown.
	// Close the quit channel before calling WaitForShutdown.
	WaitForShutdown()
}

// NewFunc defines a constructor that accepts rescan options and returns a
// struct that satisfies Interface
type NewFunc func(...neutrino.RescanOption) Interface
