//go:build !js

package kvdb

// Native Manager creation uses bdb registration. Keep its mmap and file-lock
// dependency out of JS RPC builds, which do not open native wallet storage.
import _ "github.com/btcsuite/btcwallet/walletdb/bdb" // Register native bdb.
