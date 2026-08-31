package wallet

import "context"

// runStop terminally settles a runtime that was stopped before startup.
func (c *walletLifecycleCoordinator) runStop() {
	defer close(c.entry.terminalDone)

	err := c.entry.wallet.state.toStopping()
	if err != nil {
		c.entry.teardownErr = err

		return
	}

	c.finishRuntime()
}

// abortStart cancels and joins setup before publishing the winning Start
// result and completing terminal teardown.
func (c *walletLifecycleCoordinator) abortStart(result chan<- error,
	cancelSetup context.CancelFunc, setupDone <-chan error,
	startErr error) {

	err := c.entry.wallet.state.toStopping()
	if err != nil {
		startErr = err
	}

	cancelSetup()

	<-setupDone

	result <- startErr

	c.finishRuntime()
}

// failStart publishes a setup or worker-publication failure and completes
// terminal teardown.
func (c *walletLifecycleCoordinator) failStart(result chan<- error,
	startErr error) {

	err := c.entry.wallet.state.toStopping()
	if err != nil {
		startErr = err
	}

	result <- startErr

	c.finishRuntime()
}

// stopRuntime stops a successfully published runtime.
func (c *walletLifecycleCoordinator) stopRuntime() {
	err := c.entry.wallet.state.toStopping()
	if err != nil {
		c.entry.teardownErr = err

		return
	}

	c.finishRuntime()
}

// finishRuntime joins workers and records terminal Vault locking before the
// coordinator exits. The coordinator is not a runtime worker, so waiting here
// cannot join itself or race a later worker publication.
func (c *walletLifecycleCoordinator) finishRuntime() {
	c.entry.teardownErr = c.entry.wallet.finishRuntime()
}
