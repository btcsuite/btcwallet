// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

//nolint:staticcheck // Remove with the kvdb backend.
import (
	"github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
)

// usesKVDBStore reports whether the wallet runs on the legacy kvdb Store, which
// has no batch allocator or address-use tracking. Delete it together with the
// kvdb backend.
func (w *Wallet) usesKVDBStore() bool {
	_, ok := w.store.(*kvdb.Store) //nolint:staticcheck // Remove with kvdb.

	return ok
}
