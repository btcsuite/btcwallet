package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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

	// SignMessage signs a message based on the provided intent. The
	// returned Signature is a marker interface that can be asserted to the
	// concrete signature types, ECDSASignature or SchnorrSignature.
	SignMessage(ctx context.Context, path BIP32Path,
		intent *SignMessageIntent) (Signature, error)
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

// SignMessageIntent represents the user's intent to sign a message. It
// serves as a blueprint for the Signer, bundling all the parameters
// required to produce a signature into a single, coherent structure.
//
// # Usage Examples
//
// ## Standard ECDSA Signature (DER Encoded)
// To produce a standard ECDSA signature, set CompactSig to false and leave the
// Schnorr field nil.
//
//	intent := &wallet.SignMessageIntent{
//	    Msg:        []byte("a message"),
//	    DoubleHash: true,
//	    CompactSig: false,
//	}
//	rawSig, err := signer.SignMessage(ctx, path, intent)
//	// Type-assert the result to ECDSASignature.
//	ecdsaSig := rawSig.(wallet.ECDSASignature)
//
// ## Compact, Recoverable ECDSA Signature
// To produce a compact, recoverable signature, set CompactSig to true.
//
//	intent := &wallet.SignMessageIntent{
//	    Msg:        []byte("a message"),
//	    DoubleHash: true,
//	    CompactSig: true,
//	}
//	rawSig, err := signer.SignMessage(ctx, path, intent)
//	// Type-assert the result to CompactSignature.
//	compactSig := rawSig.(wallet.CompactSignature)
//
// ## Schnorr Signature
// To produce a Schnorr signature, populate the Schnorr field. When this field
// is non-nil, all ECDSA-related fields (like CompactSig) are ignored.
//
//	intent := &wallet.SignMessageIntent{
//	    Msg: []byte("a message"),
//	    Schnorr: &wallet.SchnorrSignOpts{
//	        Tag: []byte("my_protocol_tag"),
//	    },
//	}
//	rawSig, err := signer.SignMessage(ctx, path, intent)
//	// Type-assert the result to SchnorrSignature.
//	schnorrSig := rawSig.(wallet.SchnorrSignature)
type SignMessageIntent struct {
	// Msg is the raw message to be signed.
	Msg []byte

	// DoubleHash specifies whether the message should be double-hashed
	// (SHA256d) before signing. If false, a single SHA256 hash is used.
	DoubleHash bool

	// CompactSig specifies whether the signature should be returned in the
	// compact, recoverable format. This is only valid for ECDSA signatures.
	CompactSig bool

	// Schnorr specifies the options for a Schnorr signature. If this is
	// nil, an ECDSA signature will be produced.
	Schnorr *SchnorrSignOpts
}

// SchnorrSignOpts contains the specific parameters for a Schnorr signature.
type SchnorrSignOpts struct {
	// Tweak is an optional private key tweak to be applied before signing.
	Tweak []byte

	// Tag is an optional BIP-340 tagged hash to use. If nil, the standard
	// SHA256 hash of the message is used.
	Tag []byte
}

// Signature is an interface that represents a cryptographic signature.
// It is a marker interface to allow returning different signature types.
type Signature interface {
	// isSignature is a marker method to ensure that only the types defined
	// in this package can implement this interface.
	isSignature()
}

// ECDSASignature wraps an ecdsa.Signature to implement the Signature interface.
type ECDSASignature struct {
	*ecdsa.Signature
}

// CompactSignature wraps a compact signature byte slice to implement the
// Signature interface.
type CompactSignature []byte

// SchnorrSignature wraps a schnorr.Signature to implement the Signature
// interface.
type SchnorrSignature struct {
	*schnorr.Signature
}

// isSignature implements the Signature marker interface.
func (ECDSASignature) isSignature() {}

// isSignature implements the Signature marker interface.
func (CompactSignature) isSignature() {}

// isSignature implements the Signature marker interface.
func (SchnorrSignature) isSignature() {}
