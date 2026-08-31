package wallet

import "context"

// StartWallet starts the exact current Wallet runtime managed by m. A stopped
// runtime is terminal and must be replaced through Load before it can start.
func (m *Manager) StartWallet(ctx context.Context, w *Wallet) error {
	m.Lock()

	entry, err := m.currentWalletEntry(w)
	if err != nil {
		m.Unlock()

		return err
	}

	if entry.stopAccepted {
		m.Unlock()

		return ErrWalletStopped
	}

	lc := lifecycle(w.state.lifecycle.Load())
	switch lc {
	case lifecycleStarting, lifecycleStarted:
		m.Unlock()

		return ErrWalletAlreadyStarted

	case lifecycleStopping, lifecycleStopped:
		m.Unlock()

		return ErrWalletStopped

	case lifecycleCreated:
		if entry.startAccepted {
			m.Unlock()

			return ErrWalletAlreadyStarted
		}
	}

	err = ctx.Err()
	if err != nil {
		m.Unlock()

		return err
	}

	result := make(chan error, 1)

	entry.startAccepted = true
	entry.coordinator = newWalletLifecycleCoordinator(m, entry)
	coordinator := entry.coordinator

	go coordinator.runStart(ctx, result)

	m.Unlock()

	return <-result
}

// StopWallet terminally stops the exact current Wallet runtime managed by m.
// Caller cancellation only bounds that caller's wait for shared teardown.
func (m *Manager) StopWallet(ctx context.Context, w *Wallet) error {
	m.Lock()

	entry, err := m.currentWalletEntry(w)
	if err != nil {
		m.Unlock()

		return err
	}

	if entry.stopAccepted {
		m.Unlock()

		return waitForWalletTerminal(ctx, entry)
	}

	lc := lifecycle(w.state.lifecycle.Load())
	if lc == lifecycleStopping || lc == lifecycleStopped {
		m.Unlock()

		return waitForWalletTerminal(ctx, entry)
	}

	entry.stopAccepted = true

	coordinator := entry.coordinator
	if coordinator == nil {
		coordinator = newWalletLifecycleCoordinator(m, entry)
		entry.coordinator = coordinator

		go coordinator.runStop()

		m.Unlock()

		return waitForWalletTerminal(ctx, entry)
	}

	done := entry.terminalDone

	m.Unlock()

	select {
	case coordinator.requests <- struct{}{}:
	case <-done:
	}

	return waitForWalletTerminal(ctx, entry)
}

// currentWalletEntry returns the cache entry for w while the Manager lock is
// held and rejects foreign or replaced runtime pointers.
func (m *Manager) currentWalletEntry(w *Wallet) (*walletRuntimeEntry, error) {
	if w == nil {
		return nil, ErrWalletNotManaged
	}

	entry := m.wallets[w.cfg.Name]
	if entry == nil || entry.wallet != w {
		return nil, ErrWalletNotManaged
	}

	return entry, nil
}

// waitForWalletTerminal waits for caller-independent teardown and returns the
// result recorded before terminal completion was closed.
func waitForWalletTerminal(ctx context.Context,
	entry *walletRuntimeEntry) error {

	select {
	case <-entry.terminalDone:
		return entry.teardownErr

	default:
	}

	select {
	case <-entry.terminalDone:
		return entry.teardownErr

	case <-ctx.Done():
		return ctx.Err()
	}
}
