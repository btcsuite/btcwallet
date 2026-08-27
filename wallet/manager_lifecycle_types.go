package wallet

import "errors"

var (
	// ErrWalletNotManaged is returned when a lifecycle request names a Wallet
	// pointer that is not the Manager's current runtime instance.
	ErrWalletNotManaged = errors.New("wallet not managed")

	// ErrWalletStopped is returned when StartWallet is called for a runtime
	// that is stopping or has reached its terminal stopped state.
	ErrWalletStopped = errors.New("wallet stopped")
)

// walletLifecycleCoordinator owns every multi-step transition for one exact
// Manager-published Wallet runtime.
type walletLifecycleCoordinator struct {
	manager  *Manager
	entry    *walletRuntimeEntry
	requests chan struct{}
}

// newWalletLifecycleCoordinator constructs the lazy lifecycle coordinator.
func newWalletLifecycleCoordinator(
	manager *Manager, entry *walletRuntimeEntry) *walletLifecycleCoordinator {

	return &walletLifecycleCoordinator{
		manager:  manager,
		entry:    entry,
		requests: make(chan struct{}, 1),
	}
}
