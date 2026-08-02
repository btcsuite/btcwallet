package wallet

import (
	"context"
	"time"
)

// newManagedWallet constructs a Wallet from backend-validated storage data.
// The backend remains the owner of every resource referenced by data.
func newManagedWallet(cfg Config, data *walletData) *Wallet {
	if cfg.AutoLockDuration == 0 {
		cfg.AutoLockDuration = defaultLockDuration
	}

	lockTimer := time.NewTimer(0)
	if !lockTimer.Stop() {
		<-lockTimer.C
	}

	lifetimeCtx, cancel := context.WithCancel(context.Background())

	w := &Wallet{
		cfg:               cfg,
		id:                data.id,
		addrStore:         data.addressStore,
		store:             data.store,
		cache:             newStoreRuntimeCache(data.store),
		keyVault:          data.vault,
		txStore:           data.transactionStore,
		requestChan:       make(chan any),
		lifetimeCtx:       lifetimeCtx,
		cancel:            cancel,
		lockTimer:         lockTimer,
		masterFingerprint: data.masterFingerprint,
		isWatchOnly:       data.isWatchOnly,
	}

	w.sync = newSyncer(
		cfg, w.addrStore, w.txStore, w, w.store, w.id,
	)
	w.state = newWalletState(w.sync)

	return w
}
