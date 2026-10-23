package wallet

import (
	"context"
	"time"
)

// newManagedWallet constructs a Wallet from backend-validated storage data.
// The backend remains the owner of every resource referenced by data.
func newManagedWallet(cfg Config, data *walletData) *Wallet {
	lockTimer := time.NewTimer(0)
	if !lockTimer.Stop() {
		<-lockTimer.C
	}

	lifetimeCtx, cancel := context.WithCancel(context.Background())

	// Allocate before publication so Manager and the worker retain opposite
	// ends of one bounded mailbox governed by the existing Wallet lifetime.
	chainEventChan := make(chan any, 1)

	w := &Wallet{
		cfg:               cfg,
		id:                data.id,
		addrStore:         data.addressStore,
		store:             data.store,
		cache:             newStoreRuntimeCache(data.store),
		keyVault:          data.vault,
		txStore:           data.transactionStore,
		requestChan:       make(chan any),
		chainEventChan:    chainEventChan,
		lifetimeCtx:       lifetimeCtx,
		cancel:            cancel,
		lockTimer:         lockTimer,
		masterFingerprint: data.masterFingerprint,
		isWatchOnly:       data.isWatchOnly,
	}

	w.sync = newSyncer(
		cfg, w.addrStore, w.txStore, w, w.store, w.id, chainEventChan,
	)
	w.state = newWalletState(w.sync)

	return w
}
