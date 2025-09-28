package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// Signer provides an interface for common, safe cryptographic operations,
// including signing and key derivation.
type Signer interface {
	// DerivePubKey derives a public key from a full BIP-32 derivation
	// path.
	DerivePubKey(ctx context.Context, path BIP32Path) (
		*btcec.PublicKey, error)

	// ECDH performs a scalar multiplication (ECDH-like operation) between
	// a key from the wallet and a remote public key.
	ECDH(ctx context.Context, path BIP32Path, pub *btcec.PublicKey) (
		[32]byte, error)
}

// UnsafeSigner provides an interface for security-sensitive cryptographic
// operations that export raw private key material. This interface should be
// used with extreme care and only when absolutely necessary.
type UnsafeSigner interface {
	Signer
}

// BIP32Path contains the full information needed to derive a key from the
// wallet's master seed, as defined by BIP-32. It combines the high-level key
// scope with the specific derivation path.
type BIP32Path struct {
	// KeyScope specifies the key scope (e.g., P2WKH, P2TR, or lnd's custom
	// scope).
	KeyScope waddrmgr.KeyScope

	// DerivationPath specifies the full derivation path within the scope.
	DerivationPath waddrmgr.DerivationPath
}
