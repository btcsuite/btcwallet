// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sqlwallet

import (
	"context"

	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// BehavioralWallet contains only backend-neutral wallet behavior. It is the
// Workstream B interface both the legacy KV wallet and the SQL wallet are meant
// to satisfy, so callers depend on behavior rather than on a concrete storage
// type. This minimal harness declares the lifecycle and derivation subset the
// Phase 2B exit gate exercises; the full method list is frozen from the
// existing backend-neutral callers when the interface is promoted to the wallet
// package.
//
// Crucially, it contains no Database(), AddrManager(), exported Manager/TxStore
// accessor, or raw walletdb callback: a value held as a BehavioralWallet cannot
// reach a bucket or a concrete manager.
type BehavioralWallet interface {
	// Unlock derives the private key material from the private passphrase.
	Unlock(ctx context.Context, privPassphrase []byte) error

	// Lock zeroes the private key material.
	Lock()

	// NextAddress derives and commits the next chained address for one
	// account branch.
	NextAddress(ctx context.Context, scope waddrmgr.KeyScope, account,
		branch uint32) (Address, error)

	// SyncedTip returns the wallet's synced block reconstructed from durable
	// state.
	SyncedTip() walletstore.BlockRef

	// Close releases the wallet's resources.
	Close() error
}

// Compile-time assertion that the SQL wallet implements the backend-neutral
// behavioral surface. Go has no direct negative interface assertion, so the
// absence of the storage escape hatches (Database, AddrManager, exported
// Manager/TxStore, raw callbacks) is enforced by the reflection-based
// API-surface test in this package rather than a compile-time check.
var _ BehavioralWallet = (*SQLWallet)(nil)
