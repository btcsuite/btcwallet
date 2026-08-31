package wallet

import "context"

// runStart owns startup arbitration and remains alive until the accepted
// runtime reaches its terminal state.
func (c *walletLifecycleCoordinator) runStart(ctx context.Context,
	result chan<- error) {

	defer close(c.entry.terminalDone)

	w := c.entry.wallet

	err := w.state.toStarting()
	if err != nil {
		result <- err

		c.entry.teardownErr = err

		return
	}

	setupCtx, cancelSetup := context.WithCancel(
		context.WithoutCancel(ctx),
	)
	defer cancelSetup()

	setupDone := make(chan error, 1)
	go func() {
		setupDone <- w.performRuntimeSetup(setupCtx)
	}()

	for {
		select {
		case <-ctx.Done():
			c.abortStart(
				result, cancelSetup, setupDone, ctx.Err(),
			)

			return

		case <-c.requests:
			c.abortStart(
				result, cancelSetup, setupDone, ErrWalletStopped,
			)

			return

		case err := <-setupDone:
			if err != nil {
				c.failStart(result, err)

				return
			}

			err = c.publishStart(ctx, result)
			if err != nil {
				c.failStart(result, err)

				return
			}

			<-c.requests
			c.stopRuntime()

			return
		}
	}
}

// publishStart makes caller cancellation, Stop admission, worker publication,
// and the successful Start result one Manager-serialized decision.
func (c *walletLifecycleCoordinator) publishStart(ctx context.Context,
	result chan<- error) error {

	if hooks := c.manager.lifecycleTestHooks; hooks != nil &&
		hooks.beforeStartPublication != nil {

		hooks.beforeStartPublication(c)
	}

	c.manager.Lock()
	defer c.manager.Unlock()

	if c.entry.stopAccepted {
		return ErrWalletStopped
	}

	err := ctx.Err()
	if err != nil {
		return err
	}

	err = c.entry.wallet.publishRuntimeWorkers()
	if err != nil {
		return err
	}

	result <- nil

	return nil
}
