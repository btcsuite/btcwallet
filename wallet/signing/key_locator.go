package signing

import "github.com/btcsuite/btcwallet/waddrmgr"

// KeyLocator identifies a key using one of the supported locator variants.
type KeyLocator interface {
	// isKeyLocator seals KeyLocator to variants defined in this package.
	isKeyLocator()
}

// FullHDKeyLocator identifies a wallet-root derivation address using the
// existing waddrmgr address scope type.
type FullHDKeyLocator struct {
	// AddrScope identifies the wallet-root derivation address.
	AddrScope waddrmgr.AddrScope
}

// isKeyLocator implements the sealed KeyLocator interface.
func (FullHDKeyLocator) isKeyLocator() {}

// AccountKeyLocator identifies a child under a persisted account row.
type AccountKeyLocator struct {
	// AccountID is the persisted account row identifier.
	AccountID uint32

	// Branch is the branch within the account.
	Branch uint32

	// Index is the key index within the branch.
	Index uint32
}

// isKeyLocator implements the sealed KeyLocator interface.
func (AccountKeyLocator) isKeyLocator() {}

// ScriptPubKeyLocator identifies a raw imported row by script pubkey.
type ScriptPubKeyLocator struct {
	// ScriptPubKey is the raw locking script.
	ScriptPubKey []byte
}

// isKeyLocator implements the sealed KeyLocator interface.
func (ScriptPubKeyLocator) isKeyLocator() {}

// Ensure the locator variants implement KeyLocator.
var _ KeyLocator = FullHDKeyLocator{}
var _ KeyLocator = AccountKeyLocator{}
var _ KeyLocator = ScriptPubKeyLocator{}
