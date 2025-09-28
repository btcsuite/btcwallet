package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

var (
	// ErrUnknownSignMethod is returned when a transaction is signed with an
	// unknown sign method.
	ErrUnknownSignMethod = errors.New("unknown sign method")
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

	// ComputeUnlockingScript generates the full sigScript and witness
	// required to spend a UTXO. The resulting UnlockingScript struct
	// contains the raw witness and/or sigScript, which can be used to
	// populate the final transaction input.
	//
	// This method is designed for spending single-signature outputs, which
	// are outputs that can be spent with a single signature from a single
	// private key. This includes P2PKH, P2WKH, NP2WKH, and P2TR key-path
	// spends. For more complex script-based spends, such as P2SH or P2WSH
	// multisig, the ComputeRawSig method should be used to generate the raw
	// signature, which can then be manually assembled into the final
	// witness.
	ComputeUnlockingScript(ctx context.Context,
		params *UnlockingScriptParams) (*UnlockingScript, error)

	// ComputeRawSig generates a raw signature for a single transaction
	// input. The caller is responsible for assembling the final witness.
	//
	// This method is a low-level specialist function that should only be
	// used when the caller needs to generate a raw signature for a
	// specific key, without the wallet assembling the final witness. This
	// is useful for multi-party protocols like multisig or Lightning,
	// where signatures may need to be exchanged and combined before the
	// final witness is created. For most common, single-signature spends,
	// ComputeUnlockingScript should be used instead.
	ComputeRawSig(ctx context.Context, params *RawSigParams) (
		RawSignature, error)
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

// UnlockingScript is a struct that contains the witness and sigScript for a
// transaction input.
type UnlockingScript struct {
	// Witness is the witness stack for the input. For non-SegWit inputs,
	// this will be nil.
	Witness wire.TxWitness

	// SigScript is the signature script for the input. For native SegWit
	// inputs, this will be nil.
	SigScript []byte
}

// PrivKeyTweaker is a function type that can be used to pass in a callback for
// tweaking a private key before it's used to sign an input.
type PrivKeyTweaker func(*btcec.PrivateKey) (*btcec.PrivateKey, error)

// UnlockingScriptParams provides all the necessary parameters to generate an
// unlocking script (witness and sigScript) for a transaction input.
type UnlockingScriptParams struct {
	// Tx is the transaction containing the input to be signed.
	Tx *wire.MsgTx

	// InputIndex is the index of the input to be signed.
	InputIndex int

	// Output is the previous output that is being spent.
	Output *wire.TxOut

	// SigHashes is the sighash cache for the transaction.
	SigHashes *txscript.TxSigHashes

	// HashType is the signature hash type to use.
	HashType txscript.SigHashType

	// Tweaker is an optional function that can be used to tweak the
	// private key before signing.
	Tweaker PrivKeyTweaker
}

// RawSigParams provides all the necessary parameters to generate a raw
// signature for a transaction input.
type RawSigParams struct {
	// Tx is the transaction containing the input to be signed.
	Tx *wire.MsgTx

	// InputIndex is the index of the input to be signed.
	InputIndex int

	// Output is the previous output that is being spent.
	Output *wire.TxOut

	// SigHashes is the sighash cache for the transaction.
	SigHashes *txscript.TxSigHashes

	// HashType is the signature hash type to use.
	HashType txscript.SigHashType

	// Path is the BIP-32 derivation path of the key to be used for
	// signing.
	Path BIP32Path

	// Tweaker is an optional function that can be used to tweak the
	// private key before signing.
	Tweaker PrivKeyTweaker

	// Details specifies the version-specific information for signing.
	// This field MUST be set to either LegacySpendDetails,
	// SegwitV0SpendDetails or TaprootSpendDetails.
	Details SpendDetails
}

// RawSignature is a raw signature.
type RawSignature []byte

// TaprootSpendPath is an enum that specifies the spending path to be used for a
// Taproot input.
type TaprootSpendPath uint8

const (
	// KeyPathSpend indicates that the output should be spent using the key
	// path.
	KeyPathSpend TaprootSpendPath = iota

	// ScriptPathSpend indicates that the output should be spent using the
	// script path.
	ScriptPathSpend
)

// SpendDetails is a sealed interface that provides the version-specific
// details required to generate a raw signature.
type SpendDetails interface {
	// isSpendDetails is a marker method to ensure that only the types
	// defined in this package can implement this interface.
	isSpendDetails()

	// Sign performs the version-specific signing operation.
	Sign(params *RawSigParams, privKey *btcec.PrivateKey) (
		RawSignature, error)
}

// LegacySpendDetails provides the details for signing a legacy P2PKH input.
type LegacySpendDetails struct {
	// RedeemScript is the redeem script for P2SH spends.
	RedeemScript []byte
}

// Sign performs the version-specific signing operation for a legacy input.
func (l LegacySpendDetails) Sign(params *RawSigParams,
	privKey *btcec.PrivateKey) (RawSignature, error) {

	// For P2SH, the redeem script must be provided. For P2PKH, the pkscript
	// of the output is used.
	script := l.RedeemScript
	if script == nil {
		script = params.Output.PkScript
	}

	rawSig, err := txscript.RawTxInSignature(
		params.Tx, params.InputIndex, script,
		params.HashType, privKey,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot create raw signature: %w", err)
	}

	return rawSig, nil
}

// isSpendDetails implements the sealed interface.
func (l LegacySpendDetails) isSpendDetails() {}

// SegwitV0SpendDetails provides the details for signing a SegWit v0 input.
type SegwitV0SpendDetails struct {
	// WitnessScript is the witness script for P2WSH spends. For P2WKH,
	// this should be the P2PKH script of the key.
	WitnessScript []byte
}

// Sign performs the version-specific signing operation for a SegWit v0 input.
func (s SegwitV0SpendDetails) Sign(params *RawSigParams,
	privKey *btcec.PrivateKey) (RawSignature, error) {

	sig, err := txscript.RawTxInWitnessSignature(
		params.Tx, params.SigHashes, params.InputIndex,
		params.Output.Value, s.WitnessScript,
		params.HashType, privKey,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot create witness sig: %w", err)
	}

	return sig[:len(sig)-1], nil
}

// isSpendDetails implements the sealed interface.
func (s SegwitV0SpendDetails) isSpendDetails() {}

// TaprootSpendDetails provides the details for signing a Taproot input.
type TaprootSpendDetails struct {
	// SpendPath specifies which spending path to use.
	SpendPath TaprootSpendPath

	// Tweak is the tweak to apply to the internal key. For a key-path
	// spend, this is typically the merkle root of the script tree.
	Tweak []byte

	// WitnessScript is the specific script leaf being spent. This is
	// only used for ScriptPathSpend.
	WitnessScript []byte
}

// Sign performs the version-specific signing operation for a Taproot input.
func (t TaprootSpendDetails) Sign(params *RawSigParams,
	privKey *btcec.PrivateKey) (RawSignature, error) {

	var (
		rawSig []byte
		err    error
	)
	switch t.SpendPath {
	case KeyPathSpend:
		rawSig, err = txscript.RawTxInTaprootSignature(
			params.Tx, params.SigHashes,
			params.InputIndex, params.Output.Value,
			params.Output.PkScript, t.Tweak,
			params.HashType, privKey,
		)
		if err != nil {
			return nil, fmt.Errorf("taproot sig error: %w", err)
		}
	case ScriptPathSpend:
		leaf := txscript.TapLeaf{
			LeafVersion: txscript.BaseLeafVersion,
			Script:      t.WitnessScript,
		}

		rawSig, err = txscript.RawTxInTapscriptSignature(
			params.Tx, params.SigHashes,
			params.InputIndex, params.Output.Value,
			params.Output.PkScript, leaf,
			params.HashType, privKey,
		)
		if err != nil {
			return nil, fmt.Errorf("tapscript sig error: %w", err)
		}
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownSignMethod,
			t.SpendPath)
	}

	return rawSig, nil
}
