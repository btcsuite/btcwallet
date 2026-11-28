package signing

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

// ErrInvalidKeySelector reports a selector that names no key.
var ErrInvalidKeySelector = errors.New("invalid key selector")

// KeySelector names one private key in a wallet: a DerivedKey or an
// ImportedKey. A selector holds no Store row ID and no wallet ID; the vault
// resolves it within its own wallet.
type KeySelector interface {
	// Validate checks that the selector names a key.
	Validate() error

	// isKeySelector seals the interface to the selectors of this package.
	isKeySelector()
}

// DerivedKey selects the child key at DerivationPath of a wallet-derived
// account in KeyScope. DerivationPath.InternalAccount is the unhardened BIP44
// account number; the vault uses the account's stored extended private key, so
// the hardened account step is not repeated. Only Branch and Index are
// derived.
type DerivedKey struct {
	// KeyScope is the key scope of the account.
	KeyScope waddrmgr.KeyScope

	// DerivationPath names the account and the child within it.
	DerivationPath waddrmgr.DerivationPath
}

// ImportedKey selects the raw imported private key stored for ScriptPubKey.
// The vault reads the script only during the call.
type ImportedKey struct {
	// ScriptPubKey is the output script the imported key pays.
	ScriptPubKey []byte
}

// isKeySelector implements KeySelector.
func (DerivedKey) isKeySelector() {}

// isKeySelector implements KeySelector.
func (ImportedKey) isKeySelector() {}

// ValidateKeySelector checks that sel is a DerivedKey or an ImportedKey value
// that names a key. A nil selector, and a pointer to either type, nil or not,
// return ErrInvalidKeySelector: the vaults resolve selectors by value type
// only, so such a selector would name no key.
func ValidateKeySelector(sel KeySelector) error {
	switch s := sel.(type) {
	case DerivedKey:
		return s.Validate()

	case ImportedKey:
		return s.Validate()

	default:
		return fmt.Errorf("%w: unsupported selector %T",
			ErrInvalidKeySelector, sel)
	}
}

// Validate implements KeySelector. Every derivation path names a key.
func (DerivedKey) Validate() error {
	return nil
}

// Validate implements KeySelector. The script pubkey must be set.
func (k ImportedKey) Validate() error {
	if len(k.ScriptPubKey) == 0 {
		return fmt.Errorf("%w: empty script pubkey",
			ErrInvalidKeySelector)
	}

	return nil
}
