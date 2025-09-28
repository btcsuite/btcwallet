package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// ErrUnknownSignMethod is returned when a transaction is signed with an
	// unknown sign method.
	ErrUnknownSignMethod = errors.New("unknown sign method")

	// ErrUnsupportedAddressType is returned when a transaction is signed
	// for an unsupported address type.
	ErrUnsupportedAddressType = errors.New("unsupported address type")
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

	// DerivePrivKey derives a private key from a full BIP-32 derivation
	// path.
	//
	// DANGER: This method exports sensitive key material.
	DerivePrivKey(ctx context.Context, path BIP32Path) (
		*btcec.PrivateKey, error)

	// GetPrivKeyForAddress returns the private key for a given address.
	//
	// DANGER: This method exports sensitive key material.
	GetPrivKeyForAddress(ctx context.Context, a btcutil.Address) (
		*btcec.PrivateKey, error)
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

// isSpendDetails implements the sealed interface.
func (t TaprootSpendDetails) isSpendDetails() {}

// A compile-time assertion to ensure that all SpendDetails implementations
// adhere to the interface.
var _ SpendDetails = (*LegacySpendDetails)(nil)
var _ SpendDetails = (*SegwitV0SpendDetails)(nil)
var _ SpendDetails = (*TaprootSpendDetails)(nil)

// DerivePubKey derives a public key from a full BIP-32 derivation path.
func (w *Wallet) DerivePubKey(_ context.Context, path BIP32Path) (
	*btcec.PublicKey, error) {

	managedPubKeyAddr, err := w.fetchManagedPubKeyAddress(path)
	if err != nil {
		return nil, err
	}

	return managedPubKeyAddr.PubKey(), nil
}

// fetchManagedPubKeyAddress is a helper function that encapsulates the common
// logic of fetching a scoped key manager, deriving a managed address from a
// BIP32 path, and ensuring it is a public key address.
//
// Time Complexity:
//   - Average Case: O(1) - This is the common case where the account
//     information is already cached in memory. The function performs a few
//     map lookups and constant-time cryptographic operations.
//   - Worst Case: O(log N) - This occurs on a cache miss (e.g., the first
//     time an account is used). The function must perform a single, indexed
//     database lookup to fetch the account's master key. N is the number of
//     accounts in the wallet.
//
// Database Actions:
//   - This method performs a single read-only database transaction
//     (`walletdb.View`).
//   - The transaction's only purpose is to call `DeriveFromKeyPath`, which
//     performs at most one indexed database lookup for account information if
//     that information is not already in the in-memory cache.
func (w *Wallet) fetchManagedPubKeyAddress(path BIP32Path) (
	waddrmgr.ManagedPubKeyAddress, error) {

	// Fetch the scoped key manager for the given key scope. This can be
	// done outside of the database transaction as it only deals with
	// in-memory state.
	manager, err := w.addrStore.FetchScopedKeyManager(path.KeyScope)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch scoped key manager: %w",
			err)
	}

	// The derivation of the address is the only part that requires a
	// database transaction.
	var addr waddrmgr.ManagedAddress

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		// Derive the managed address from the derivation path.
		derivedAddr, err := manager.DeriveFromKeyPath(
			addrmgrNs, path.DerivationPath,
		)
		if err != nil {
			return fmt.Errorf("cannot derive from key path: %w",
				err)
		}

		addr = derivedAddr

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cannot view wallet database: %w", err)
	}

	// The post-processing of the address can be done outside of the
	// database transaction as it only deals with the in-memory struct.
	managedPubKeyAddr, ok := addr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, fmt.Errorf("%w: addr %s", ErrNotPubKeyAddress,
			addr.Address())
	}

	return managedPubKeyAddr, nil
}

// ECDH performs a scalar multiplication (ECDH-like operation) between a key
// from the wallet and a remote public key. The output returned will be the
// sha256 of the resulting shared point serialized in compressed format.
func (w *Wallet) ECDH(_ context.Context, path BIP32Path,
	pub *btcec.PublicKey) ([32]byte, error) {

	managedPubKeyAddr, err := w.fetchManagedPubKeyAddress(path)
	if err != nil {
		return [32]byte{}, err
	}

	// Get the private key for the derived address.
	privKey, err := managedPubKeyAddr.PrivKey()
	if err != nil {
		return [32]byte{}, fmt.Errorf("cannot get private key: %w",
			err)
	}
	defer privKey.Zero()

	// Perform the scalar multiplication and hash the result.
	secret := btcec.GenerateSharedSecret(privKey, pub)

	var sharedSecret [32]byte
	copy(sharedSecret[:], secret)

	return sharedSecret, nil
}

// SignMessage signs a message based on the provided intent.
func (w *Wallet) SignMessage(_ context.Context, path BIP32Path,
	intent *SignMessageIntent) (Signature, error) {

	managedPubKeyAddr, err := w.fetchManagedPubKeyAddress(path)
	if err != nil {
		return nil, err
	}

	// Get the private key for the derived address.
	privKey, err := managedPubKeyAddr.PrivKey()
	if err != nil {
		return nil, fmt.Errorf("cannot get private key: %w", err)
	}
	defer privKey.Zero()

	// Now, sign the message using the derived private key. This is all
	// pure computation, so it can be done outside the DB transaction.
	return signMessageWithPrivKey(privKey, intent)
}

// signMessageWithPrivKey performs the actual signing of a message with a given
// private key, based on the options specified in the SignMessageIntent. It
// acts as a dispatcher to the appropriate signing algorithm.
func signMessageWithPrivKey(privKey *btcec.PrivateKey,
	intent *SignMessageIntent) (Signature, error) {

	// If Schnorr options are provided, we'll generate a Schnorr signature.
	if intent.Schnorr != nil {
		return signMessageSchnorr(privKey, intent)
	}

	// Otherwise, we'll generate an ECDSA signature.
	return signMessageECDSA(privKey, intent)
}

// signMessageSchnorr performs the actual signing of a message with a given
// private key, using the Schnorr signature algorithm.
func signMessageSchnorr(privKey *btcec.PrivateKey,
	intent *SignMessageIntent) (Signature, error) {

	if intent.Schnorr.Tweak != nil {
		privKey = txscript.TweakTaprootPrivKey(
			*privKey, intent.Schnorr.Tweak,
		)
	}

	var digest []byte
	if intent.Schnorr.Tag != nil {
		taggedHash := chainhash.TaggedHash(
			intent.Schnorr.Tag, intent.Msg,
		)
		digest = taggedHash[:]
	} else {
		digest = btcutil.Hash160(intent.Msg)
	}

	sig, err := schnorr.Sign(privKey, digest)
	if err != nil {
		return nil, fmt.Errorf("cannot create schnorr sig: %w", err)
	}

	return SchnorrSignature{sig}, nil
}

// signMessageECDSA performs the actual signing of a message with a given
// private key, using the ECDSA signature algorithm.
func signMessageECDSA(privKey *btcec.PrivateKey,
	intent *SignMessageIntent) (Signature, error) {

	var digest []byte
	if intent.DoubleHash {
		digest = chainhash.DoubleHashB(intent.Msg)
	} else {
		digest = btcutil.Hash160(intent.Msg)
	}

	if intent.CompactSig {
		sig := ecdsa.SignCompact(privKey, digest, true)
		return CompactSignature(sig), nil
	}

	sig := ecdsa.Sign(privKey, digest)

	return ECDSASignature{sig}, nil
}

// ComputeUnlockingScript generates the full sigScript and witness required to
// spend a UTXO.
func (w *Wallet) ComputeUnlockingScript(ctx context.Context,
	params *UnlockingScriptParams) (*UnlockingScript, error) {

	// First, we'll fetch the managed address that corresponds to the
	// output being spent. This will be used to look up the private key
	// required for signing.
	scriptInfo, err := w.ScriptForOutput(ctx, *params.Output)
	if err != nil {
		return nil, err
	}

	// The address must be a public key address.
	pubKeyAddr, ok := scriptInfo.Addr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, fmt.Errorf("%w: addr %s",
			ErrNotPubKeyAddress, scriptInfo.Addr.Address())
	}

	// Get the private key for the derived address.
	privKey, err := pubKeyAddr.PrivKey()
	if err != nil {
		return nil, fmt.Errorf("cannot get private key: %w", err)
	}
	defer privKey.Zero()

	// If a tweaker is provided, we'll use it to tweak the private key.
	if params.Tweaker != nil {
		privKey, err = params.Tweaker(privKey)
		if err != nil {
			return nil, fmt.Errorf("error tweaking private key: %w",
				err)
		}
	}

	// With the private key retrieved and tweaked, we can now generate the
	// unlocking script.
	return signAndAssembleScript(params, privKey, &scriptInfo)
}

// signAndAssembleScript is a helper function that performs the final signing
// and script assembly for a given set of parameters and a private key.
func signAndAssembleScript(params *UnlockingScriptParams,
	privKey *btcec.PrivateKey,
	scriptInfo *Script) (*UnlockingScript, error) {

	// Dispatch to the correct signing logic based on the address type of
	// the output.
	switch scriptInfo.Addr.AddrType() {
	// For Taproot key-path spends, we produce a Schnorr signature.
	case waddrmgr.TaprootPubKey:
		witness, err := txscript.TaprootWitnessSignature(
			params.Tx, params.SigHashes, params.InputIndex,
			params.Output.Value, params.Output.PkScript,
			params.HashType, privKey,
		)
		if err != nil {
			return nil, fmt.Errorf("taproot witness error: %w", err)
		}

		return &UnlockingScript{
			Witness: witness,
		}, nil

	// For SegWit v0 outputs, we'll generate a standard ECDSA signature.
	case waddrmgr.WitnessPubKey, waddrmgr.NestedWitnessPubKey:
		witness, err := txscript.WitnessSignature(
			params.Tx, params.SigHashes, params.InputIndex,
			params.Output.Value, scriptInfo.WitnessProgram,
			params.HashType, privKey, true,
		)
		if err != nil {
			return nil, fmt.Errorf("witness sig error: %w", err)
		}

		return &UnlockingScript{
			Witness:   witness,
			SigScript: scriptInfo.RedeemScript,
		}, nil

	// For legacy P2PKH outputs, we'll generate a signature script.
	case waddrmgr.PubKeyHash:
		sigScript, err := txscript.SignatureScript(
			params.Tx, params.InputIndex, params.Output.PkScript,
			params.HashType, privKey, true,
		)
		if err != nil {
			return nil, fmt.Errorf("sig script error: %w", err)
		}

		return &UnlockingScript{
			SigScript: sigScript,
		}, nil

	// The following address types are not supported by this function.
	case waddrmgr.Script, waddrmgr.RawPubKey, waddrmgr.WitnessScript,
		waddrmgr.TaprootScript:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAddressType,
			scriptInfo.Addr.AddrType())

	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAddressType,
			scriptInfo.Addr.AddrType())
	}
}
