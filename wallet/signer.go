package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// ErrUnknownSignMethod is returned when a transaction is signed with an
	// unknown sign method.
	ErrUnknownSignMethod = errors.New("unknown sign method")

	// ErrUnsupportedAddressType is returned when a transaction is signed
	// for an unsupported address type.
	ErrUnsupportedAddressType = errors.New("unsupported address type")

	// ErrInvalidDigestSize is returned when a signature digest is not 32
	// bytes.
	ErrInvalidDigestSize = errors.New("digest must be 32 bytes")

	// ErrInvalidSignParam is returned when the parameters for the signing
	// operation are invalid.
	ErrInvalidSignParam = errors.New("invalid signing parameters")

	// ErrWatchOnlyAccount is returned when account metadata exists but has no
	// private key material available for signing.
	ErrWatchOnlyAccount = errors.New("account is watch-only")

	// ErrAccountNotInStore is returned when neither legacy waddrmgr nor the
	// durable store can resolve the signing account.
	ErrAccountNotInStore = errors.New("account not in store")
)

// Signer provides an interface for common, safe cryptographic operations,
// including signing and key derivation.
type Signer interface {
	// DerivePubKey derives a public key from a full BIP-32 derivation
	// path.
	DerivePubKey(ctx context.Context, path BIP32Path) (
		*btcec.PublicKey, error)

	// ECDH performs a scalar multiplication (ECDH-like operation) between
	// a key from the wallet and a remote public key. The output returned
	// will be the raw 32-byte shared secret (the X-coordinate of the
	// result point).
	ECDH(ctx context.Context, path BIP32Path, pub *btcec.PublicKey) (
		[32]byte, error)

	// SignDigest signs a message digest based on the provided intent. The
	// returned Signature is a marker interface that can be asserted to the
	// concrete signature types, ECDSASignature or SchnorrSignature.
	SignDigest(ctx context.Context, path BIP32Path,
		intent *SignDigestIntent) (Signature, error)

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

// A compile-time check to ensure that Wallet implements the Signer and
// UnsafeSigner interfaces.
var _ Signer = (*Wallet)(nil)
var _ UnsafeSigner = (*Wallet)(nil)

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

// SignatureType represents the type of signature to produce.
type SignatureType uint8

const (
	// SigTypeECDSA represents an ECDSA signature.
	SigTypeECDSA SignatureType = iota

	// SigTypeSchnorr represents a Schnorr signature.
	SigTypeSchnorr
)

// SignDigestIntent represents the user's intent to sign a message digest. It
// serves as a blueprint for the Signer, bundling all the parameters
// required to produce a signature into a single, coherent structure.
//
// # Usage Examples
//
// ## Standard ECDSA Signature (DER Encoded)
// To produce a standard ECDSA signature, set SigType to SigTypeECDSA.
//
//	intent := &wallet.SignDigestIntent{
//	    Digest:     chainhash.HashB([]byte("a message")),
//	    SigType:    wallet.SigTypeECDSA,
//	}
//	rawSig, err := signer.SignDigest(ctx, path, intent)
//	// Type-assert the result to ECDSASignature.
//	ecdsaSig := rawSig.(wallet.ECDSASignature)
//
// ## Compact, Recoverable ECDSA Signature
// To produce a compact, recoverable signature, set CompactSig to true.
//
//	intent := &wallet.SignDigestIntent{
//	    Digest:     chainhash.DoubleHashB([]byte("a message")),
//	    SigType:    wallet.SigTypeECDSA,
//	    CompactSig: true,
//	}
//	rawSig, err := signer.SignDigest(ctx, path, intent)
//	// Type-assert the result to CompactSignature.
//	compactSig := rawSig.(wallet.CompactSignature)
//
// ## Schnorr Signature
// To produce a Schnorr signature, set SigType to SigTypeSchnorr.
//
//	intent := &wallet.SignDigestIntent{
//	    Digest: chainhash.TaggedHash(
//	        []byte("my_protocol_tag"), []byte("a message"),
//	    ),
//	    SigType: wallet.SigTypeSchnorr,
//	}
//	rawSig, err := signer.SignDigest(ctx, path, intent)
//	// Type-assert the result to SchnorrSignature.
//	schnorrSig := rawSig.(wallet.SchnorrSignature)
type SignDigestIntent struct {
	// Digest is the 32-byte hash digest to be signed.
	Digest []byte

	// SigType specifies the type of signature to generate.
	SigType SignatureType

	// CompactSig specifies whether the signature should be returned in the
	// compact, recoverable format. This is only valid for ECDSA signatures.
	CompactSig bool

	// TaprootTweak is an optional private key tweak to be applied before
	// signing. This is only valid for Schnorr signatures.
	TaprootTweak []byte
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

	// Validate the signature by parsing it. This serves as a sanity check
	// to ensure the generated signature is valid.
	_, err = ecdsa.ParseDERSignature(sig[:len(sig)-1])
	if err != nil {
		return nil, fmt.Errorf("generated invalid witness sig: %w", err)
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

	// Validate the signature by parsing it. This serves as a sanity check
	// to ensure the generated signature is valid.
	_, err = schnorr.ParseSignature(rawSig[:schnorr.SignatureSize])
	if err != nil {
		return nil, fmt.Errorf("generated invalid taproot sig: %w", err)
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

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

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

	err = walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
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

// derivePathPrivKey resolves the signing private key for a full BIP-32 path.
//
// It first walks the legacy waddrmgr-backed managed-address lookup, which is
// the fast path for accounts mirrored into waddrmgr. When that lookup misses
// because the account or its scope only lives in the SQL store, it falls back
// to the account-level encrypted secret resolved through keyVault. The
// fallback is gated on a waddrmgr account/scope miss so legacy-backed accounts
// keep their existing behavior and only genuine store-only accounts take the
// slower path.
//
// The returned private key is owned by the caller, who is responsible for
// zeroing it once signing completes.
func (w *Wallet) derivePathPrivKey(ctx context.Context, path BIP32Path) (
	*btcec.PrivateKey, error) {

	managedPubKeyAddr, err := w.fetchManagedPubKeyAddress(path)
	switch {
	case err == nil:
		privKey, err := managedPubKeyAddr.PrivKey()
		if err != nil {
			return nil, fmt.Errorf("cannot get private key: %w",
				err)
		}

		return privKey, nil

	// A scope or account miss means the account is not mirrored into the
	// legacy waddrmgr; resolve it from the store-backed account secret
	// instead. Any other error is a real failure and must surface.
	case isWaddrmgrAccountClassError(
		err, waddrmgr.ErrScopeNotFound, waddrmgr.ErrAccountNotFound,
	):

		privKey, storeErr := w.resolveDerivedPrivKeyFromStore(
			ctx, path.KeyScope, path.DerivationPath,
		)
		if storeErr != nil {
			return nil, fmt.Errorf("store account fallback after "+
				"legacy address miss: %w: %w", err, storeErr)
		}

		return privKey, nil

	default:
		return nil, err
	}
}

// ECDH performs a scalar multiplication (ECDH-like operation) between a key
// from the wallet and a remote public key. The output returned will be the
// sha256 of the resulting shared point serialized in compressed format.
func (w *Wallet) ECDH(ctx context.Context, path BIP32Path,
	pub *btcec.PublicKey) ([32]byte, error) {

	err := w.state.canSign()
	if err != nil {
		return [32]byte{}, err
	}

	// Resolve the private key for the derived path, falling back to the
	// store-backed account secret for SQL-only accounts.
	privKey, err := w.derivePathPrivKey(ctx, path)
	if err != nil {
		return [32]byte{}, err
	}
	defer privKey.Zero()

	// Perform the scalar multiplication and hash the result.
	secret := btcec.GenerateSharedSecret(privKey, pub)

	var sharedSecret [32]byte
	copy(sharedSecret[:], secret)

	return sharedSecret, nil
}

// validateSignDigestIntent validates the parameters of a SignDigestIntent.
func validateSignDigestIntent(intent *SignDigestIntent) error {
	// The digest must be exactly 32 bytes.
	if len(intent.Digest) != chainhash.HashSize {
		return ErrInvalidDigestSize
	}

	// Validate parameters based on signature type.
	switch intent.SigType {
	case SigTypeECDSA:
		if intent.TaprootTweak != nil {
			return fmt.Errorf("%w: taproot tweak cannot be used "+
				"with ECDSA", ErrInvalidSignParam)
		}

	case SigTypeSchnorr:
		if intent.CompactSig {
			return fmt.Errorf("%w: compact signature cannot be "+
				"used with Schnorr", ErrInvalidSignParam)
		}
	}

	return nil
}

// SignDigest signs a message digest based on the provided intent.
func (w *Wallet) SignDigest(ctx context.Context, path BIP32Path,
	intent *SignDigestIntent) (Signature, error) {

	err := w.state.canSign()
	if err != nil {
		return nil, err
	}

	err = validateSignDigestIntent(intent)
	if err != nil {
		return nil, err
	}

	// Resolve the private key for the derived path, falling back to the
	// store-backed account secret for SQL-only accounts.
	privKey, err := w.derivePathPrivKey(ctx, path)
	if err != nil {
		return nil, err
	}
	defer privKey.Zero()

	// Now, sign the message using the derived private key. This is all
	// pure computation, so it can be done outside the DB transaction.
	return signDigestWithPrivKey(privKey, intent)
}

// signDigestWithPrivKey performs the actual signing of a digest with a given
// private key, based on the options specified in the SignDigestIntent. It
// acts as a dispatcher to the appropriate signing algorithm.
func signDigestWithPrivKey(privKey *btcec.PrivateKey,
	intent *SignDigestIntent) (Signature, error) {

	// If Schnorr is specified, we'll generate a Schnorr signature.
	if intent.SigType == SigTypeSchnorr {
		return signDigestSchnorr(privKey, intent)
	}

	// Otherwise, we'll generate an ECDSA signature.
	return signDigestECDSA(privKey, intent)
}

// signDigestSchnorr performs the actual signing of a digest with a given
// private key, using the Schnorr signature algorithm.
func signDigestSchnorr(privKey *btcec.PrivateKey,
	intent *SignDigestIntent) (Signature, error) {

	if intent.TaprootTweak != nil {
		privKey = txscript.TweakTaprootPrivKey(
			*privKey, intent.TaprootTweak,
		)
	}

	sig, err := schnorr.Sign(privKey, intent.Digest)
	if err != nil {
		return nil, fmt.Errorf("cannot create schnorr sig: %w", err)
	}

	return SchnorrSignature{sig}, nil
}

// signDigestECDSA performs the actual signing of a digest with a given
// private key, using the ECDSA signature algorithm.
func signDigestECDSA(privKey *btcec.PrivateKey,
	intent *SignDigestIntent) (Signature, error) {

	if intent.CompactSig {
		sig := ecdsa.SignCompact(privKey, intent.Digest, true)
		return CompactSignature(sig), nil
	}

	sig := ecdsa.Sign(privKey, intent.Digest)

	return ECDSASignature{sig}, nil
}

// ComputeUnlockingScript generates the full sigScript and witness required to
// spend a UTXO.
func (w *Wallet) ComputeUnlockingScript(ctx context.Context,
	params *UnlockingScriptParams) (*UnlockingScript, error) {

	err := w.state.canSign()
	if err != nil {
		return nil, err
	}

	// First, we'll fetch the managed address that corresponds to the
	// output being spent. This will be used to look up the private key
	// required for signing.
	scriptInfo, err := w.ScriptForOutput(ctx, *params.Output)
	if err != nil {
		return nil, err
	}

	privKey, err := w.privKeyForOutput(ctx, scriptInfo)
	if err != nil {
		return nil, err
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

// privKeyForOutput returns the private key needed to sign for the given
// wallet-controlled output.
func (w *Wallet) privKeyForOutput(ctx context.Context,
	scriptInfo OutputScriptInfo) (
	*btcec.PrivateKey, error) {

	if canUseAddressInfoDerivation(scriptInfo.AddressInfo) {
		return w.privKeyForAddressInfo(ctx, scriptInfo.AddressInfo)
	}

	pubKeyAddr, err := w.loadManagedPubKeyAddr(scriptInfo.Addr)
	if err != nil {
		return nil, err
	}

	return w.resolvePrivKey(ctx, pubKeyAddr)
}

// canUseAddressInfoDerivation reports whether address metadata contains enough
// derivation information to derive a private key without a legacy address row.
func canUseAddressInfoDerivation(addressInfo AddressInfo) bool {
	if addressInfo.Imported || addressInfo.Derivation == nil {
		return false
	}

	return addressInfo.Derivation.KeyScope != (waddrmgr.KeyScope{})
}

// privKeyForAddressInfo derives the private key described by store-backed
// address metadata.
func (w *Wallet) privKeyForAddressInfo(ctx context.Context,
	addressInfo AddressInfo) (
	*btcec.PrivateKey, error) {

	derivation := addressInfo.Derivation
	if derivation == nil {
		return nil, fmt.Errorf("%w: derivation info not found for %v",
			ErrDerivationPathNotFound, addressInfo.Addr)
	}

	derivationPath := waddrmgr.DerivationPath{
		InternalAccount:      derivation.Account,
		Account:              derivation.Account + hdkeychain.HardenedKeyStart,
		Branch:               derivation.Branch,
		Index:                derivation.Index,
		MasterKeyFingerprint: derivation.MasterKeyFingerprint,
	}

	return w.resolveDerivedPathPrivKey(
		ctx, derivation.KeyScope, derivationPath,
	)
}

// loadManagedPubKeyAddr loads a managed pubkey address for signer-private key
// access.
func (w *Wallet) loadManagedPubKeyAddr(addr btcutil.Address) (
	waddrmgr.ManagedPubKeyAddress, error) {

	var pubKeyAddr waddrmgr.ManagedPubKeyAddress

	err := walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		managedAddr, err := w.addrStore.Address(addrmgrNs, addr)
		if err != nil {
			return fmt.Errorf("fetch address: %w", err)
		}

		var ok bool

		pubKeyAddr, ok = managedAddr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return fmt.Errorf("%w: addr %s", ErrNotPubKeyAddress,
				managedAddr.Address())
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("view signer address: %w", err)
	}

	return pubKeyAddr, nil
}

// resolvePrivKey resolves the private key for a managed pubkey address without
// using output-script inspection as the private-key lookup seam.
func (w *Wallet) resolvePrivKey(ctx context.Context,
	pubKeyAddr waddrmgr.ManagedPubKeyAddress) (
	*btcec.PrivateKey, error) {

	// Imported spendable keys have no derivation path, so we fall back to the
	// dedicated private-key lookup exposed by the managed pubkey address.
	if pubKeyAddr.Imported() {
		privKey, err := pubKeyAddr.PrivKey()
		if err != nil {
			return nil, fmt.Errorf("fetch imported private key: %w", err)
		}

		return privKey, nil
	}

	keyScope, derivationPath, ok := pubKeyAddr.DerivationInfo()
	if !ok {
		return nil, fmt.Errorf("%w: addr=%v", ErrDerivationPathNotFound,
			pubKeyAddr.Address())
	}

	return w.resolveDerivedPathPrivKey(ctx, keyScope, derivationPath)
}

// resolveDerivedPathPrivKey resolves one derived private key through the scoped
// manager cache or the database-backed fallback.
func (w *Wallet) resolveDerivedPathPrivKey(ctx context.Context,
	keyScope waddrmgr.KeyScope,
	derivationPath waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	// SQL-only accounts (created via Store.CreateDerivedAccount without a
	// mirrored legacy waddrmgr account) miss both DeriveFromKeyPathCache
	// and the DB-backed DeriveFromKeyPath fallback below because the legacy
	// waddrmgr has no row for them. Each of those misses therefore falls
	// through to resolveDerivedPrivKeyFromStore, which fetches
	// account_secrets.encrypted_priv_key, decrypts it via w.keyVault, and
	// derives at branch/index locally — symmetric to deriveAddressData's
	// AccountPubKey plumbing on the public-key side.
	accountManager, err := w.addrStore.FetchScopedKeyManager(keyScope)
	if err != nil {
		if isWaddrmgrAccountClassError(
			err, waddrmgr.ErrScopeNotFound,
			waddrmgr.ErrAccountNotFound,
		) {

			privKey, storeErr := w.resolveDerivedPrivKeyFromStore(
				ctx, keyScope, derivationPath,
			)
			if storeErr != nil {
				return nil, fmt.Errorf("store account fallback after "+
					"legacy scope miss: %w: %w", err, storeErr)
			}

			return privKey, nil
		}

		return nil, fmt.Errorf("fetch scoped key manager: %w", err)
	}

	privKey, err := accountManager.DeriveFromKeyPathCache(derivationPath)
	if err == nil {
		return privKey, nil
	}

	// Only a cold account cache warrants the slower DB-backed fallback. Other
	// derivation errors are real failures that re-running through the database
	// will not repair.
	if !isWaddrmgrAccountClassError(err, waddrmgr.ErrAccountNotCached) {
		return nil, fmt.Errorf("derive private key from cache: %w", err)
	}

	privKey, err = w.resolveDerivedPrivKey(accountManager, derivationPath)
	if err == nil {
		return privKey, nil
	}

	if !isWaddrmgrAccountClassError(err, waddrmgr.ErrAccountNotFound) {
		return nil, err
	}

	privKey, storeErr := w.resolveDerivedPrivKeyFromStore(
		ctx, keyScope, derivationPath,
	)
	if storeErr != nil {
		return nil, fmt.Errorf("store account fallback after legacy "+
			"account miss: %w: %w", err, storeErr)
	}

	return privKey, nil
}

// resolveDerivedPrivKey resolves one derived private key through the normal
// database-backed derivation path after a cache miss.
func (w *Wallet) resolveDerivedPrivKey(accountManager waddrmgr.AccountStore,
	derivationPath waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	var privKey *btcec.PrivateKey

	err := walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		managedAddr, err := accountManager.DeriveFromKeyPath(
			addrmgrNs, derivationPath,
		)
		if err != nil {
			return fmt.Errorf("derive private key from db: %w", err)
		}

		pubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return fmt.Errorf("%w: addr %s", ErrNotPubKeyAddress,
				managedAddr.Address())
		}

		privKey, err = pubKeyAddr.PrivKey()
		if err != nil {
			return fmt.Errorf("fetch derived private key: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("view signer derivation: %w", err)
	}

	return privKey, nil
}

// resolveDerivedPrivKeyFromStore resolves one derived private key from the
// account-level encrypted secret stored behind the wallet store.
func (w *Wallet) resolveDerivedPrivKeyFromStore(ctx context.Context,
	keyScope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	if w.cache == nil {
		return nil, fmt.Errorf("%w: cache", ErrMissingParam)
	}

	secret, err := w.cache.GetAccountSecret(ctx, db.GetAccountSecretQuery{
		WalletID:      w.id,
		Scope:         db.KeyScope(keyScope),
		AccountNumber: &path.InternalAccount,
	})
	switch {
	case errors.Is(err, db.ErrAccountSecretUnavailable),
		errors.Is(err, db.ErrAccountNotFound):

		return nil, ErrAccountNotInStore

	case err != nil:
		return nil, fmt.Errorf("fetch account secret: %w", err)
	}

	if len(secret.EncryptedPrivateKey) == 0 {
		return nil, ErrWatchOnlyAccount
	}

	if w.keyVault == nil {
		return nil, fmt.Errorf("%w: keyVault", ErrMissingParam)
	}

	return deriveStoredAccountChildKey(
		w.keyVault, secret.EncryptedPrivateKey, path,
	)
}

// deriveStoredAccountChildKey decrypts an account's encrypted private
// key with the wallet's keyVault and walks the branch + index
// derivation to produce the leaf private key. The decrypted byte slice
// and the intermediate hd keys are zeroed before the call returns.
// Note that hdkeychain/base58 parsing allocates a transient immutable
// string copy (string(plaintext)) of the decrypted bytes that cannot be
// wiped and is left to the garbage collector.
func deriveStoredAccountChildKey(vault keyvault.Vault,
	encryptedAccountPriv []byte,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	plaintext, err := vault.Decrypt(
		waddrmgr.CKTPrivate, encryptedAccountPriv,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt account priv: %w", err)
	}

	// Zero the decrypted byte slice as soon as it has been parsed (on
	// both the error and success paths) so it does not stay alive
	// through the branch and index derivation below.
	acctPriv, err := hdkeychain.NewKeyFromString(string(plaintext))
	if err != nil {
		zero.Bytes(plaintext)
		return nil, fmt.Errorf("parse account priv: %w", err)
	}

	zero.Bytes(plaintext)

	defer acctPriv.Zero()

	branchKey, err := deriveChildKey(acctPriv, path.Branch)
	if err != nil {
		return nil, fmt.Errorf("derive branch: %w", err)
	}
	defer branchKey.Zero()

	addrKey, err := deriveChildKey(branchKey, path.Index)
	if err != nil {
		return nil, fmt.Errorf("derive index: %w", err)
	}
	defer addrKey.Zero()

	privKey, err := addrKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("derive private key: %w", err)
	}

	return privKey, nil
}

// isWaddrmgrAccountClassError reports whether err wraps a waddrmgr
// ManagerError whose code belongs to the supplied set.
func isWaddrmgrAccountClassError(err error,
	codes ...waddrmgr.ErrorCode) bool {

	var mErr waddrmgr.ManagerError
	if !errors.As(err, &mErr) {
		return false
	}

	for _, code := range codes {
		if mErr.ErrorCode == code {
			return true
		}
	}

	return false
}

// signAndAssembleScript is a helper function that performs the final signing
// and script assembly for a given set of parameters and a private key.
func signAndAssembleScript(params *UnlockingScriptParams,
	privKey *btcec.PrivateKey,
	scriptInfo *OutputScriptInfo) (*UnlockingScript, error) {

	// Dispatch to the correct signing logic based on the address type signing
	// method.
	signingMethod, err := scriptInfo.AddrType.SigningMethod()
	if err != nil {
		return nil, fmt.Errorf("determine signing method: %w", err)
	}

	switch signingMethod {
	case waddrmgr.SigningMethodTaprootKeySpend:
		witness, err := txscript.TaprootWitnessSignature(
			params.Tx, params.SigHashes, params.InputIndex,
			params.Output.Value, params.Output.PkScript,
			params.HashType, privKey,
		)
		if err != nil {
			return nil, fmt.Errorf("taproot witness error: %w", err)
		}

		return &UnlockingScript{Witness: witness}, nil

	case waddrmgr.SigningMethodWitnessV0:
		witness, err := txscript.WitnessSignature(
			params.Tx, params.SigHashes, params.InputIndex,
			params.Output.Value, scriptInfo.WitnessProgram,
			params.HashType, privKey, true,
		)
		if err != nil {
			return nil, fmt.Errorf("witness sig error: %w", err)
		}

		sigScript, err := redeemSigScript(scriptInfo.RedeemScript)
		if err != nil {
			return nil, err
		}

		return &UnlockingScript{
			Witness:   witness,
			SigScript: sigScript,
		}, nil

	case waddrmgr.SigningMethodLegacy:
		sigScript, err := txscript.SignatureScript(
			params.Tx, params.InputIndex, params.Output.PkScript,
			params.HashType, privKey, true,
		)
		if err != nil {
			return nil, fmt.Errorf("sig script error: %w", err)
		}

		return &UnlockingScript{SigScript: sigScript}, nil

	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAddressType,
			scriptInfo.AddrType)
	}
}

// redeemSigScript wraps a redeem script into the final scriptSig push required
// for nested witness spends.
func redeemSigScript(redeemScript []byte) ([]byte, error) {
	if len(redeemScript) == 0 {
		return nil, nil
	}

	builder := txscript.NewScriptBuilder()
	builder.AddData(redeemScript)

	sigScript, err := builder.Script()
	if err != nil {
		return nil, fmt.Errorf("build sig script: %w", err)
	}

	return sigScript, nil
}

// ComputeRawSig generates a raw signature for a single transaction input. The
// caller is responsible for assembling the final witness.
func (w *Wallet) ComputeRawSig(ctx context.Context, params *RawSigParams) (
	RawSignature, error) {

	err := w.state.canSign()
	if err != nil {
		return nil, err
	}

	// Resolve the private key for the specified derivation path, falling
	// back to the store-backed account secret for SQL-only accounts.
	privKey, err := w.derivePathPrivKey(ctx, params.Path)
	if err != nil {
		return nil, err
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

	// With the private key retrieved and tweaked, we can now delegate the
	// actual signing to the version-specific details object.
	rawSig, err := params.Details.Sign(params, privKey)
	if err != nil {
		return nil, fmt.Errorf("cannot sign transaction: %w", err)
	}

	return rawSig, nil
}

// DerivePrivKey derives a private key from a full BIP-32 derivation
// path.
//
// DANGER: This method exports sensitive key material.
func (w *Wallet) DerivePrivKey(ctx context.Context, path BIP32Path) (
	*btcec.PrivateKey, error) {

	err := w.state.canSign()
	if err != nil {
		return nil, err
	}

	// Resolve the private key for the derived path, falling back to the
	// store-backed account secret for SQL-only accounts.
	return w.derivePathPrivKey(ctx, path)
}

// GetPrivKeyForAddress returns the private key for a given address.
//
// DANGER: This method exports sensitive key material.
func (w *Wallet) GetPrivKeyForAddress(ctx context.Context, a btcutil.Address) (
	*btcec.PrivateKey, error) {

	err := w.state.canSign()
	if err != nil {
		return nil, err
	}

	// Try the store-routed lookup so SQL-derived addresses (persisted
	// only in the store) can be signed for. Fall back to the legacy
	// waddrmgr lookup ONLY when the address is genuinely not in the
	// store, or when the store record lacks usable derivation metadata
	// (imported / kvdb cases). Unexpected store errors must surface — do
	// not mask them.
	info, err := w.GetAddressInfo(ctx, a)
	switch {
	case err == nil && canUseAddressInfoDerivation(info):
		return w.privKeyForAddressInfo(ctx, info)

	case err == nil:
		// Store record exists but no usable derivation info
		// (imported case).
		return w.PrivKeyForAddress(a)

	case errors.Is(err, db.ErrAddressNotFound):
		// Address not in the store — fall through to the legacy
		// lookup (kvdb path or pre-store legacy address).
		return w.PrivKeyForAddress(a)

	default:
		// Unexpected store error: surface, don't mask.
		return nil, fmt.Errorf("GetPrivKeyForAddress: %w", err)
	}
}

// PrivKeyForAddress looks up the associated private key for a P2PKH or P2PK
// address.
func (w *Wallet) PrivKeyForAddress(a btcutil.Address) (
	*btcec.PrivateKey, error) {

	err := w.state.canSign()
	if err != nil {
		return nil, err
	}

	var privKey *btcec.PrivateKey

	err = walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		addr, err := w.addrStore.Address(addrmgrNs, a)
		if err != nil {
			return fmt.Errorf("failed to get address: %w", err)
		}

		managedPubKeyAddr, ok := addr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return ErrNoAssocPrivateKey
		}

		privKey, err = managedPubKeyAddr.PrivKey()
		if err != nil {
			return fmt.Errorf("failed to get private key: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to view database: %w", err)
	}

	return privKey, nil
}
