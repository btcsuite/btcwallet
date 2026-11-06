package wallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
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

	// ErrWatchOnlyAccount is returned when account metadata exists but has
	// no private key material available for signing.
	ErrWatchOnlyAccount = errors.New("account is watch-only")

	// ErrAccountNotInStore is returned when neither legacy waddrmgr nor the
	// durable store can resolve the signing account.
	ErrAccountNotInStore = errors.New("account not in store")
)

// DerivePubKeyParams identifies an account and the unhardened child key to
// derive from its extended public key.
type DerivePubKeyParams struct {
	// Account identifies the account by portable wallet semantics.
	Account AccountSelector

	// Branch is the account child branch to derive.
	Branch uint32

	// Index is the child index within Branch to derive.
	Index uint32
}

// Signer provides an interface for common, safe cryptographic operations,
// including signing and key derivation.
type Signer interface {
	// DerivePubKey derives a public child key from the selected account's
	// extended public key. The account may be selected by name when it has
	// no BIP44 account number, such as an imported XPub account.
	DerivePubKey(ctx context.Context, params DerivePubKeyParams) (
		*btcec.PublicKey, error)

	// ECDH performs a scalar multiplication (ECDH-like operation) between
	// a key from the wallet and a remote public key. The output returned
	// is the SHA-256 of the resulting shared point serialized in its
	// 33-byte compressed form. This is libsecp256k1's default ECDH output
	// and the shared secret lnd's keychain.ECDHRing and BOLT 8 expect. It
	// is not the hash of the X coordinate alone: the compressed form also
	// commits to the point's Y parity.
	//
	// A nil remote key returns ErrNilArguments, and one that is not a curve
	// point returns ErrInvalidSignParam; neither derives a wallet key.
	ECDH(ctx context.Context, path BIP32Path, pub *btcec.PublicKey) (
		[32]byte, error)

	// SignDigest signs a message digest based on the provided intent. The
	// returned Signature is a marker interface that can be asserted to the
	// concrete signature types, ECDSASignature or SchnorrSignature.
	//
	// A nil intent returns ErrNilArguments.
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
	//
	// Nil params, or params with no Output, return ErrNilArguments.
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
	//
	// Nil params, missing Details, or a missing Output required by the spend
	// details return ErrNilArguments.
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
	GetPrivKeyForAddress(ctx context.Context, a address.Address) (
		*btcec.PrivateKey, error)
}

// Compile-time checks ensure that Wallet implements the signer interfaces.
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
	// Wallet interprets InternalAccount as the unhardened BIP44 account
	// number, not a backend account ID. Account is the hardened BIP32 child;
	// Branch and Index select the key within that account.
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

// KeyTweak derives a signing key from the wallet's base key d as mul*d + add
// modulo the curve order. Its zero value leaves the key unchanged. Build one
// with NewAddTweak or NewMulAddTweak.
type KeyTweak struct {
	mul btcec.ModNScalar
	add btcec.ModNScalar
}

// NewAddTweak returns the tweak d + add, such as lnd's single tweak. add is a
// big-endian scalar below the curve order.
func NewAddTweak(add [32]byte) (KeyTweak, error) {
	return NewMulAddTweak([32]byte{31: 1}, add)
}

// NewMulAddTweak returns the tweak mul*d + add, such as lnd's revocation
// derivation. Both are big-endian scalars below the curve order, and mul must
// not be zero, which would leave nothing of the wallet's key. The identity,
// mul 1 and add 0, is returned as the zero value.
func NewMulAddTweak(mul, add [32]byte) (KeyTweak, error) {
	var t KeyTweak
	if t.mul.SetBytes(&mul) != 0 || t.add.SetBytes(&add) != 0 {
		return KeyTweak{}, fmt.Errorf("%w: tweak exceeds the curve "+
			"order", ErrInvalidSignParam)
	}

	if t.mul.IsZero() {
		return KeyTweak{}, fmt.Errorf("%w: zero tweak multiplier",
			ErrInvalidSignParam)
	}

	// The zero value keeps the derivation record's own key bytes, so the
	// identity must be it.
	one := new(btcec.ModNScalar).SetInt(1)
	if t.mul.Equals(one) && t.add.IsZero() {
		return KeyTweak{}, nil
	}

	return t, nil
}

// apply tweaks a key the caller owns. A tweak that cancels the key is
// refused.
func (t KeyTweak) apply(key *btcec.PrivateKey) error {
	if t == (KeyTweak{}) {
		return nil
	}

	key.Key.Mul(&t.mul).Add(&t.add)

	if key.Key.IsZero() {
		return fmt.Errorf("%w: tweak cancels the key",
			ErrInvalidSignParam)
	}

	return nil
}

// pubKey returns the public key apply produces from base's private key:
// mul*base + add*G.
func (t KeyTweak) pubKey(base *btcec.PublicKey) (*btcec.PublicKey, error) {
	if t == (KeyTweak{}) {
		return base, nil
	}

	var point, mulPoint, addPoint, result btcec.JacobianPoint
	base.AsJacobian(&point)
	btcec.ScalarMultNonConst(&t.mul, &point, &mulPoint)
	btcec.ScalarBaseMultNonConst(&t.add, &addPoint)
	btcec.AddNonConst(&mulPoint, &addPoint, &result)

	if (result.X.IsZero() && result.Y.IsZero()) || result.Z.IsZero() {
		return nil, fmt.Errorf("%w: tweak cancels the key",
			ErrInvalidSignParam)
	}

	result.ToAffine()

	return btcec.NewPublicKey(&result.X, &result.Y), nil
}

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
}

// RawSigParams provides all the necessary parameters to generate a raw
// signature for a transaction input.
type RawSigParams struct {
	// Tx is the transaction containing the input to be signed.
	Tx *wire.MsgTx

	// InputIndex is the index of the input to be signed.
	InputIndex int

	// Output is the previous output that is being spent. It is required
	// except for legacy signing with an explicit RedeemScript.
	Output *wire.TxOut

	// SigHashes is the sighash cache for the transaction.
	SigHashes *txscript.TxSigHashes

	// HashType is the signature hash type to use.
	HashType txscript.SigHashType

	// Path is the BIP-32 derivation path of the key to be used for
	// signing.
	Path BIP32Path

	// Tweak is applied to the derived key before it signs. The zero value
	// signs with the derived key.
	Tweak KeyTweak

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
//
// SpendDetails only describes what an input signature commits to. The wallet
// computes the signature hash from it, and the key that signs that hash stays
// with the wallet's key vault.
type SpendDetails interface {
	// isSpendDetails is a marker method to ensure that only the types
	// defined in this package can implement this interface.
	isSpendDetails()

	// inputSigHash returns the digest one input signature signs, and how
	// the signature is made and serialized. It needs no private key.
	inputSigHash(params *RawSigParams) (*inputSigHash, error)
}

// inputSigHash is the signing request for one transaction input: the digest,
// the signature algorithm, any BIP-341 output key tweak, and the sighash byte
// the serialized signature carries.
type inputSigHash struct {
	// digest is the signature hash of the input.
	digest [32]byte

	// schnorr selects BIP-340 signing; otherwise the input is signed with
	// ECDSA.
	schnorr bool

	// keyPath reports a Taproot key-path spend. Its key is the BIP-341
	// output key for scriptRoot, not the derived key itself.
	keyPath bool

	// scriptRoot is the script tree root of a key-path spend. Empty commits
	// to no scripts, as BIP-86 does.
	scriptRoot []byte

	// hashType is appended to the signature when appendHashType is set.
	hashType txscript.SigHashType

	// appendHashType reports whether the serialized signature ends in its
	// sighash byte.
	appendHashType bool
}

// serialize returns the raw signature for sig, with the sighash byte when the
// input format carries one.
func (h *inputSigHash) serialize(sig []byte) RawSignature {
	if h.appendHashType {
		return append(sig, byte(h.hashType))
	}

	return sig
}

// LegacySpendDetails provides the details for signing a legacy P2PKH input.
type LegacySpendDetails struct {
	// RedeemScript is the redeem script for P2SH spends.
	RedeemScript []byte
}

// inputSigHash returns the legacy signature hash. The signature carries its
// sighash byte.
func (l LegacySpendDetails) inputSigHash(params *RawSigParams) (*inputSigHash,
	error) {

	// For P2SH, the redeem script must be provided. For P2PKH, the pkscript
	// of the output is used.
	script := l.RedeemScript
	if script == nil {
		// P2PKH needs the output script; an explicit redeem script already
		// supplies the legacy signing preimage without an output.
		if params.Output == nil {
			return nil, fmt.Errorf("%w: missing legacy output",
				ErrNilArguments)
		}

		script = params.Output.PkScript
	}

	hash, err := txscript.CalcSignatureHash(
		script, params.HashType, params.Tx, params.InputIndex,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot create raw signature: %w", err)
	}

	sigHash := &inputSigHash{
		hashType:       params.HashType,
		appendHashType: true,
	}
	copy(sigHash.digest[:], hash)

	return sigHash, nil
}

// isSpendDetails implements the sealed interface.
func (l LegacySpendDetails) isSpendDetails() {}

// SegwitV0SpendDetails provides the details for signing a SegWit v0 input.
type SegwitV0SpendDetails struct {
	// WitnessScript is the witness script for P2WSH spends. For P2WKH,
	// this should be the P2PKH script of the key.
	WitnessScript []byte
}

// inputSigHash returns the BIP-143 signature hash. The raw signature does not
// carry its sighash byte.
func (s SegwitV0SpendDetails) inputSigHash(params *RawSigParams) (
	*inputSigHash, error) {

	// Segwit commits to the previous output value, even when the caller
	// supplies a witness script. Reject its absence before dereferencing it.
	if params.Output == nil {
		return nil, fmt.Errorf("%w: missing segwit output", ErrNilArguments)
	}

	hash, err := txscript.CalcWitnessSigHash(
		s.WitnessScript, params.SigHashes, params.HashType, params.Tx,
		params.InputIndex, params.Output.Value,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot create witness sig: %w", err)
	}

	sigHash := &inputSigHash{hashType: params.HashType}
	copy(sigHash.digest[:], hash)

	return sigHash, nil
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

// inputSigHash returns the BIP-341 signature hash of the key or script path.
// The signature carries its sighash byte unless the type is SigHashDefault.
func (t TaprootSpendDetails) inputSigHash(params *RawSigParams) (
	*inputSigHash, error) {

	// Both supported Taproot paths commit to the previous output. Keep
	// unknown-path rejection with the existing dispatch below.
	if params.Output == nil &&
		(t.SpendPath == KeyPathSpend || t.SpendPath == ScriptPathSpend) {

		return nil, fmt.Errorf("%w: missing taproot output", ErrNilArguments)
	}

	sigHash := &inputSigHash{
		schnorr:        true,
		hashType:       params.HashType,
		appendHashType: params.HashType != txscript.SigHashDefault,
	}

	var (
		hash []byte
		err  error
	)

	switch t.SpendPath {
	case KeyPathSpend:
		hash, err = txscript.CalcTaprootSignatureHash(
			params.SigHashes, params.HashType, params.Tx,
			params.InputIndex, txscript.NewCannedPrevOutputFetcher(
				params.Output.PkScript, params.Output.Value,
			),
		)
		if err != nil {
			return nil, fmt.Errorf("taproot sig error: %w", err)
		}

		sigHash.keyPath = true
		sigHash.scriptRoot = t.Tweak

	case ScriptPathSpend:
		leaf := txscript.TapLeaf{
			LeafVersion: txscript.BaseLeafVersion,
			Script:      t.WitnessScript,
		}

		hash, err = txscript.CalcTapscriptSignaturehash(
			params.SigHashes, params.HashType, params.Tx,
			params.InputIndex, txscript.NewCannedPrevOutputFetcher(
				params.Output.PkScript, params.Output.Value,
			), leaf,
		)
		if err != nil {
			return nil, fmt.Errorf("tapscript sig error: %w", err)
		}

	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownSignMethod,
			t.SpendPath)
	}

	copy(sigHash.digest[:], hash)

	return sigHash, nil
}

// isSpendDetails implements the sealed interface.
func (t TaprootSpendDetails) isSpendDetails() {}

// A compile-time assertion to ensure that all SpendDetails implementations
// adhere to the interface.
var _ SpendDetails = (*LegacySpendDetails)(nil)
var _ SpendDetails = (*SegwitV0SpendDetails)(nil)
var _ SpendDetails = (*TaprootSpendDetails)(nil)

// signInputSigHash signs an input signature hash with a key the wallet already
// holds. Only the legacy kvdb key path uses it; SQL wallets sign in the vault.
// A key-path spend signs with the BIP-341 output key, which is cleared before
// return.
func signInputSigHash(privKey *btcec.PrivateKey,
	sigHash *inputSigHash) (RawSignature, error) {

	key := privKey
	if sigHash.keyPath {
		key = txscript.TweakTaprootPrivKey(*privKey, sigHash.scriptRoot)
		defer key.Zero()
	}

	if !sigHash.schnorr {
		sig := ecdsa.Sign(key, sigHash.digest[:])

		return sigHash.serialize(sig.Serialize()), nil
	}

	sig, err := schnorr.Sign(key, sigHash.digest[:])
	if err != nil {
		return nil, fmt.Errorf("taproot sig error: %w", err)
	}

	return sigHash.serialize(sig.Serialize()), nil
}

// derivePubKeyReq retains account selection until accepted derivation ends.
type derivePubKeyReq struct {
	reqCtx

	params   DerivePubKeyParams
	respChan chan pubKeyResp
}

// pubKeyResp returns the derived public key after the accepted lookup ends.
type pubKeyResp struct {
	key *btcec.PublicKey
	err error
}

// ecdhReq borrows the remote key until accepted secret computation ends.
type ecdhReq struct {
	reqCtx

	path     BIP32Path
	pub      *btcec.PublicKey
	respChan chan ecdhResp
}

// ecdhResp returns the shared secret after temporary key cleanup.
type ecdhResp struct {
	secret [32]byte
	err    error
}

// signDigestReq borrows digest and tweak bytes through vault-backed signing.
type signDigestReq struct {
	reqCtx

	path     BIP32Path
	intent   *SignDigestIntent
	respChan chan signatureResp
}

// signatureResp delivers the completed signature without retaining its key.
type signatureResp struct {
	signature Signature
	err       error
}

// unlockingScriptReq borrows transaction data until assembly completes.
type unlockingScriptReq struct {
	reqCtx

	params   *UnlockingScriptParams
	respChan chan unlockingScriptResp
}

// unlockingScriptResp retains completed unlocking data for its caller.
type unlockingScriptResp struct {
	script *UnlockingScript
	err    error
}

// rawSigReq borrows signing inputs until its accepted vault operation ends.
type rawSigReq struct {
	reqCtx

	params   *RawSigParams
	respChan chan rawSigResp
}

// rawSigResp returns the signature after signing and key cleanup complete.
type rawSigResp struct {
	signature RawSignature
	err       error
}

// derivePrivKeyReq keeps an exported key joined until it can be delivered.
type derivePrivKeyReq struct {
	reqCtx

	path     BIP32Path
	respChan chan privKeyResp
}

// privKeyForAddressReq borrows the destination through exported-key lookup.
type privKeyForAddressReq struct {
	reqCtx

	addr     address.Address
	respChan chan privKeyResp
}

// privKeyResp delivers exported key ownership to its noncanceling waiter.
type privKeyResp struct {
	key *btcec.PrivateKey
	err error
}

// DerivePubKey derives a public child key from a semantically selected
// account. The account XPub is read from the durable store, then the branch and
// child index are derived in memory. Public derivation requires a started
// wallet but remains available while the wallet is locked.
func (w *Wallet) DerivePubKey(ctx context.Context,
	params DerivePubKeyParams) (
	*btcec.PublicKey, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	err = params.Account.validate()
	if err != nil {
		return nil, err
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := derivePubKeyReq{
		reqCtx:   reqCtx{ctx: ctx},
		params:   params,
		respChan: make(chan pubKeyResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return nil, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.key, result.err
}

// handleDerivePrivKey delivers the result of an accepted component request.
func (w *Wallet) handleDerivePrivKey(r derivePrivKeyReq) {
	// Transfer the exported key to its waiting caller, which owns zeroing it.
	key, err := w.derivePathPrivKey(r.ctx, r.path)
	r.respChan <- privKeyResp{key: key, err: err}
}

// derivePathPrivKey resolves the signing private key for a full BIP-32 path.
//
// The private key is resolved entirely through the durable store: the
// account-level extended private key is fetched by the path's BIP44 account
// number, decrypted through unsafeVault, and the branch and index derived
// locally. This single path covers both SQL-backed and kvdb-backed wallets
// because the kvdb store adapter exports the legacy address manager's
// encrypted account material through the same account-secret contract.
//
// This resolver is used by the path-driven signer entry points (SignDigest,
// ECDH, DerivePrivKey and ComputeRawSig/PSBT), which have only a derivation
// path. Address-driven paths reach the same resolver through
// privKeyForAddressInfo once the store has resolved the address to its
// derivation info, so both address the account by number.
//
// The returned private key is owned by the caller, who is responsible for
// zeroing it once signing completes.
func (w *Wallet) derivePathPrivKey(ctx context.Context, path BIP32Path) (
	*btcec.PrivateKey, error) {

	return w.resolveDerivedPrivKeyFromStore(
		ctx, path.KeyScope, path.DerivationPath,
	)
}

// derivePathPubKey derives the public key at a BIP-32 path from its account's
// extended public key, without the account's private key.
func (w *Wallet) derivePathPubKey(ctx context.Context, path BIP32Path) (
	*btcec.PublicKey, error) {

	derivation := path.DerivationPath

	return w.resolveDerivedPubKeyFromStore(ctx, DerivePubKeyParams{
		Account: NewAccountSelectorByNumber(
			path.KeyScope, AccountNumber(derivation.InternalAccount),
		),
		Branch: derivation.Branch,
		Index:  derivation.Index,
	})
}

// ECDH performs a scalar multiplication (ECDH-like operation) between a key
// from the wallet and a remote public key. The output returned will be the
// sha256 of the resulting shared point serialized in compressed format. The
// wallet's private key and the shared point never leave the wallet.
func (w *Wallet) ECDH(ctx context.Context, path BIP32Path,
	pub *btcec.PublicKey) ([32]byte, error) {

	err := w.state.canSign()
	if err != nil {
		return [32]byte{}, err
	}

	// Reject the remote key before admission. The computation runs on its own
	// goroutine, where a nil key would fault with no caller to recover it, and
	// it would do so only after the leaf private key had been derived.
	if pub == nil {
		return [32]byte{}, fmt.Errorf(
			"%w: remote public key is nil", ErrNilArguments,
		)
	}

	// A key that is not a curve point multiplies to the point at infinity,
	// whose coordinates are zero. Hashing it yields a fixed, valid-looking
	// 32-byte secret both sides could agree on without either holding a
	// private key, so it has to be an error rather than a result.
	if !pub.IsOnCurve() {
		return [32]byte{}, fmt.Errorf(
			"%w: remote public key is not a curve point",
			ErrInvalidSignParam,
		)
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := ecdhReq{
		reqCtx:   reqCtx{ctx: ctx},
		path:     path,
		pub:      pub,
		respChan: make(chan ecdhResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return [32]byte{}, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.secret, result.err
}

// handleECDH delivers the result of an accepted component request.
func (w *Wallet) handleECDH(r ecdhReq) {
	// The operation zeroes its derived private key before delivery.
	secret, err := w.ecdh(r.ctx, r.path, r.pub)
	r.respChan <- ecdhResp{secret: secret, err: err}
}

// ecdh computes the shared secret within an accepted vault operation.
func (w *Wallet) ecdh(ctx context.Context, path BIP32Path,
	pub *btcec.PublicKey) ([32]byte, error) {

	// A SQL vault computes the digest itself, so the key stays inside it.
	signingVault, ok := w.keyVault.(keyvault.SigningVault)
	if ok {
		secret, err := signingVault.ECDH(ctx, pathKeySelector(path), pub)
		if err != nil {
			return [32]byte{}, mapDerivedKeyErr(err)
		}

		return secret, nil
	}

	privKey, err := w.derivePathPrivKey(ctx, path)
	if err != nil {
		return [32]byte{}, err
	}
	defer privKey.Zero()

	// Perform the scalar multiplication and hash all 33 bytes of the
	// compressed result. The leading byte carries the Y parity, so this
	// differs from hashing the X coordinate alone.
	point := compressedSharedPoint(privKey, pub)
	defer zero.Bytes(point)

	return sha256.Sum256(point), nil
}

// compressedSharedPoint multiplies pub by privKey and returns the 33-byte
// compressed encoding of the product. The caller must supply an on-curve
// pub and a nonzero privKey, so the product is never the point at infinity,
// and must zero the returned point once it has derived its result.
func compressedSharedPoint(privKey *btcec.PrivateKey,
	pub *btcec.PublicKey) []byte {

	var remote, shared btcec.JacobianPoint
	pub.AsJacobian(&remote)
	btcec.ScalarMultNonConst(&privKey.Key, &remote, &shared)
	shared.ToAffine()

	return btcec.NewPublicKey(&shared.X, &shared.Y).SerializeCompressed()
}

// validateSignDigestIntent validates the parameters of a SignDigestIntent.
func validateSignDigestIntent(intent *SignDigestIntent) error {
	// Every field below is read through the intent, so its absence has to be
	// answered before any of them are.
	if intent == nil {
		return fmt.Errorf("%w: intent is nil", ErrNilArguments)
	}

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

	// Admission keeps dependency access joined through concurrent Stop.
	r := signDigestReq{
		reqCtx:   reqCtx{ctx: ctx},
		path:     path,
		intent:   intent,
		respChan: make(chan signatureResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return nil, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.signature, result.err
}

// handleSignDigest delivers the result of an accepted component request.
func (w *Wallet) handleSignDigest(r signDigestReq) {
	// The operation zeroes its derived private key before delivery.
	signature, err := w.signDigest(r.ctx, r.path, r.intent)
	r.respChan <- signatureResp{signature: signature, err: err}
}

// signDigest signs the requested digest and zeroes its key before completion.
func (w *Wallet) signDigest(ctx context.Context, path BIP32Path,
	intent *SignDigestIntent) (Signature, error) {

	signingVault, ok := w.keyVault.(keyvault.SigningVault)
	if ok {
		return w.signDigestInVault(ctx, signingVault, path, intent)
	}

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
// spend a UTXO. Accepted signing finishes before return even if the caller
// cancels after admission.
func (w *Wallet) ComputeUnlockingScript(ctx context.Context,
	params *UnlockingScriptParams) (*UnlockingScript, error) {

	err := w.state.canSign()
	if err != nil {
		return nil, err
	}

	// The handler dereferences these params on its own goroutine, where a nil
	// would fault with no caller to recover it.
	if params == nil {
		return nil, fmt.Errorf(
			"%w: unlocking script params are nil", ErrNilArguments,
		)
	}

	// Output is dereferenced unconditionally by the handler and is documented
	// as required, so its absence is the same fault as a nil params.
	if params.Output == nil {
		return nil, fmt.Errorf(
			"%w: unlocking script output is nil", ErrNilArguments,
		)
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := unlockingScriptReq{
		reqCtx:   reqCtx{ctx: ctx},
		params:   params,
		respChan: make(chan unlockingScriptResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return nil, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.script, result.err
}

// handleComputeUnlockingScript delivers the result of an accepted component
// request.
func (w *Wallet) handleComputeUnlockingScript(r unlockingScriptReq) {
	// Reuse the signing operation also called from admitted PSBT finalization.
	script, err := w.computeUnlockingScript(r.ctx, r.params)
	r.respChan <- unlockingScriptResp{script: script, err: err}
}

// computeUnlockingScript assembles spending data inside its accepted request.
func (w *Wallet) computeUnlockingScript(ctx context.Context,
	params *UnlockingScriptParams) (*UnlockingScript, error) {

	// First, we'll fetch the managed address that corresponds to the
	// output being spent. This will be used to look up the private key
	// required for signing.
	scriptInfo, err := w.scriptForOutput(ctx, *params.Output)
	if err != nil {
		return nil, err
	}

	// A SQL vault signs and the wallet assembles the witness from public
	// data, so no private key reaches Wallet code.
	signingVault, ok := w.keyVault.(keyvault.SigningVault)
	if ok {
		return unlockingScriptInVault(
			ctx, signingVault, params, &scriptInfo,
		)
	}

	privKey, err := w.privKeyForOutput(ctx, scriptInfo)
	if err != nil {
		return nil, err
	}
	defer privKey.Zero()

	// With the private key retrieved, we can now generate the unlocking
	// script.
	return signAndAssembleScript(params, privKey, &scriptInfo)
}

// privKeyForOutput returns the private key needed to sign for the given
// wallet-controlled output.
//
// Derived addresses resolve through the account-level secret. A derived child
// without wallet-seed derivation metadata, such as an imported-XPub child,
// cannot sign. Only raw imported addresses resolve through their own encrypted
// private key material in the store.
func (w *Wallet) privKeyForOutput(ctx context.Context,
	scriptInfo OutputScriptInfo) (
	*btcec.PrivateKey, error) {

	if canUseAddressInfoDerivation(scriptInfo.AddressInfo) {
		return w.privKeyForAddressInfo(ctx, scriptInfo.AddressInfo)
	}

	if !scriptInfo.Imported {
		return nil, ErrNoAssocPrivateKey
	}

	return w.resolveImportedAddrPrivKey(ctx, scriptInfo.scriptPubKey())
}

// scriptPubKey returns the output pkScript associated with the address
// metadata. It re-derives the script from the address so callers that only
// hold OutputScriptInfo need not thread the raw pkScript separately.
func (info OutputScriptInfo) scriptPubKey() []byte {
	// The script is only used to key the store lookup. A derivation error
	// returns nil, so the subsequent query fails address-query validation.
	script, err := txscript.PayToAddrScript(info.Addr)
	if err != nil {
		return nil
	}

	return script
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
// address metadata. It resolves the owning account's encrypted extended
// private key through the store, decrypts it through unsafeVault, and derives
// the leaf key at the address's branch and index.
func (w *Wallet) privKeyForAddressInfo(ctx context.Context,
	addressInfo AddressInfo) (
	*btcec.PrivateKey, error) {

	// Raw imports and numberless imported-XPub children have no derivation.
	// Refuse before lookup so a missing number cannot select account zero.
	// Numbered imported children reach the account's empty-secret check below.
	derivation := addressInfo.Derivation
	if derivation == nil {
		return nil, ErrNoAssocPrivateKey
	}

	internalAccount := derivation.Account
	hardenedAccount := internalAccount + hdkeychain.HardenedKeyStart

	derivationPath := waddrmgr.DerivationPath{
		InternalAccount:      internalAccount,
		Account:              hardenedAccount,
		Branch:               derivation.Branch,
		Index:                derivation.Index,
		MasterKeyFingerprint: derivation.MasterKeyFingerprint,
	}

	return w.resolveDerivedPrivKeyFromStore(
		ctx, derivation.KeyScope, derivationPath,
	)
}

// resolveImportedAddrPrivKey resolves the private key for an imported address
// from its encrypted private-key material in the store. Imported addresses
// have no derivation path, so the key is stored per-address rather than
// derived from an account. An address that exists but holds no private-key
// material (watch-only import) yields ErrNoAssocPrivateKey.
func (w *Wallet) resolveImportedAddrPrivKey(ctx context.Context,
	scriptPubKey []byte) (*btcec.PrivateKey, error) {

	secret, err := w.cache.GetAddressSecret(ctx, db.GetAddressSecretQuery{
		WalletID:     w.id,
		ScriptPubKey: scriptPubKey,
	})
	switch {
	// A resolved address that carries no secret, and (for kvdb) an address
	// that does not resolve at all, both surface as ErrSecretNotFound.
	// Either way the wallet holds no spendable key for this address.
	case errors.Is(err, db.ErrSecretNotFound),
		errors.Is(err, db.ErrAddressNotFound):

		return nil, ErrNoAssocPrivateKey

	case err != nil:
		return nil, fmt.Errorf("fetch address secret: %w", err)
	}

	if len(secret.EncryptedPrivKey) == 0 {
		return nil, ErrNoAssocPrivateKey
	}

	plaintext, err := w.unsafeVault.Decrypt(
		waddrmgr.CKTPrivate, secret.EncryptedPrivKey,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt imported priv: %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(plaintext)
	zero.Bytes(plaintext)

	return privKey, nil
}

// isScriptSpendAddress reports whether an address is spent through a redeem or
// witness script rather than a single public key. These are the P2SH, P2WSH
// and taproot script-path families, whose spending script is stored encrypted
// per address rather than derived from a public key.
func isScriptSpendAddress(addressInfo AddressInfo) bool {
	spendType := addressInfo.AddrType.SpendType()

	return spendType == waddrmgr.SpendTypeScriptHash ||
		spendType == waddrmgr.SpendTypeWitnessScript ||
		spendType == waddrmgr.SpendTypeTaprootScriptPath
}

// storedScriptForOutput resolves the plaintext redeem, witness, or Taproot leaf
// script for a script-based output.
//
// On SQL wallets the vault loads and decrypts the stored script itself, so the
// Wallet never sees the encrypted secret. kvdb wallets keep the
// Store-and-Decrypt path in scriptForAddressInfo.
func (w *Wallet) storedScriptForOutput(ctx context.Context,
	addressInfo AddressInfo, scriptPubKey []byte) ([]byte, error) {

	// kvdb wallets fall back to the legacy Store-and-Decrypt flow.
	if w.addrStore != nil {
		return w.scriptForAddressInfo(ctx, addressInfo, scriptPubKey)
	}

	stored, err := w.keyVault.DecryptScript(ctx, scriptPubKey)
	switch {
	// The wallet cannot reconstruct the script of an unknown output, or of
	// an address without an encrypted script.
	case errors.Is(err, keyvault.ErrScriptNotFound):
		return nil, ErrNoAssocPrivateKey

	case err != nil:
		return nil, fmt.Errorf("decrypt script: %w", err)
	}

	return spendingScriptFromStored(
		addressInfo, stored, waddrmgr.DecodeTaprootScript,
	)
}

// tapscriptDecoder decodes an encoded Tapscript. It borrows its input and must
// not retain it.
type tapscriptDecoder func([]byte) (*waddrmgr.Tapscript, error)

// spendingScriptFromStored returns the spending script held in the decrypted
// stored script of a script-based output. It takes ownership of stored.
//
// P2SH and P2WSH store the redeem or witness script itself, so stored is
// returned to the caller. Taproot script-path imports store an encoded
// Tapscript; its single revealed leaf is returned as a new copy, and stored
// and the decoded Tapscript are cleared on success, error, and panic.
//
// Production callers pass waddrmgr.DecodeTaprootScript as decode; tests pass a
// failing decoder to prove the cleanup on panic.
func spendingScriptFromStored(addressInfo AddressInfo, stored []byte,
	decode tapscriptDecoder) ([]byte, error) {

	if addressInfo.AddrType.SpendType() !=
		waddrmgr.SpendTypeTaprootScriptPath {

		return stored, nil
	}

	defer clear(stored)

	tapscript, err := decode(stored)
	defer clearTapscript(tapscript)

	if err != nil {
		return nil, fmt.Errorf("decode tapscript: %w", err)
	}

	leaf, err := revealedTapscriptLeaf(tapscript)
	if err != nil {
		return nil, fmt.Errorf("%w: addr %v", err, addressInfo.Addr)
	}

	return bytes.Clone(leaf), nil
}

// clearTapscript clears the script bytes of a decoded Tapscript. Its public
// keys are not secret and stay as they are.
func clearTapscript(tapscript *waddrmgr.Tapscript) {
	if tapscript == nil {
		return
	}

	clear(tapscript.RevealedScript)

	for i := range tapscript.Leaves {
		clear(tapscript.Leaves[i].Script)
	}

	if tapscript.ControlBlock != nil {
		clear(tapscript.ControlBlock.InclusionProof)
	}
}

// scriptForAddressInfo resolves the plaintext redeem or witness script for a
// script-based output from its encrypted material in the store. It serves kvdb
// wallets, whose vault does not implement Vault.DecryptScript. Stored scripts
// are decrypted with their legacy key class, then interpreted and cleared by
// the same helper as SQL scripts.
//
// An address that exists but carries no encrypted script (a watch-only import)
// yields ErrNoAssocPrivateKey, matching the private-key surface: the wallet
// cannot spend it.
func (w *Wallet) scriptForAddressInfo(ctx context.Context,
	addressInfo AddressInfo, scriptPubKey []byte) ([]byte, error) {

	secret, err := w.cache.GetAddressSecret(ctx, db.GetAddressSecretQuery{
		WalletID:     w.id,
		ScriptPubKey: scriptPubKey,
	})
	switch {
	case errors.Is(err, db.ErrSecretNotFound),
		errors.Is(err, db.ErrAddressNotFound):

		return nil, ErrNoAssocPrivateKey

	case err != nil:
		return nil, fmt.Errorf("fetch address secret: %w", err)
	}

	if len(secret.EncryptedScript) == 0 {
		return nil, ErrNoAssocPrivateKey
	}

	// Decrypt the script under the key the store reports it was written
	// with. waddrmgr records that per address: a non-secret witness or
	// taproot row is sealed under the public key and stays readable while
	// locked, everything else under the script key.
	scriptKey := waddrmgr.CKTPublic
	if secret.ScriptIsSecret {
		scriptKey = waddrmgr.CKTScript
	}

	plaintext, err := w.unsafeVault.Decrypt(scriptKey, secret.EncryptedScript)
	if err != nil {
		return nil, fmt.Errorf("decrypt script: %w", err)
	}

	return spendingScriptFromStored(
		addressInfo, plaintext, waddrmgr.DecodeTaprootScript,
	)
}

// revealedTapscriptLeaf returns the single leaf script a taproot script-path
// spend commits to. It supports the partial-reveal form (one revealed script)
// and the full-tree form when the tree holds exactly one leaf; other shapes do
// not carry a unique spending script and are rejected.
func revealedTapscriptLeaf(tapscript *waddrmgr.Tapscript) ([]byte, error) {
	switch {
	case len(tapscript.RevealedScript) > 0:
		return tapscript.RevealedScript, nil

	case len(tapscript.Leaves) == 1:
		return tapscript.Leaves[0].Script, nil

	default:
		return nil, ErrDerivationPathNotFound
	}
}

// resolveDerivedPrivKeyFromStore resolves one derived private key from the
// account-level encrypted secret stored behind the wallet store, addressed by
// the derivation path's BIP44 account number.
//
// Numbered imported-XPub children also reach this lookup, but their accounts
// have no encrypted private key and return ErrWatchOnlyAccount. Numberless
// imported children are refused before lookup, so an unknown number cannot
// fall back to the wallet's default account zero.
//
// A watch-only account (no encrypted private material) yields
// ErrWatchOnlyAccount, and an account that is not in the store yields
// ErrAccountNotInStore. The returned private key is owned by the caller, who
// is responsible for zeroing it once signing completes.
func (w *Wallet) resolveDerivedPrivKeyFromStore(ctx context.Context,
	keyScope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	query := db.GetAccountSecretQuery{
		WalletID:      w.id,
		Scope:         db.KeyScope(keyScope),
		AccountNumber: path.InternalAccount,
	}

	secret, err := w.cache.GetAccountSecret(ctx, query)
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

	return deriveStoredAccountChildKey(
		w.unsafeVault, secret.EncryptedPrivateKey, path,
	)
}

// deriveStoredAccountChildKey decrypts an account's encrypted private key with
// the wallet's unsafeVault and walks the branch and index derivation to produce
// the leaf private key. The decrypted byte slice and intermediate HD keys are
// zeroed before the call returns. Note that hdkeychain/base58 parsing allocates
// a transient immutable string copy of the decrypted bytes that cannot be
// wiped and is left to the garbage collector.
func deriveStoredAccountChildKey(vault keyvault.UnsafeVault,
	encryptedAccountPriv []byte,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	plaintext, err := vault.Decrypt(
		waddrmgr.CKTPrivate, encryptedAccountPriv,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt account priv: %w", err)
	}

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

// handleDerivePubKey delivers the result of an accepted component request.
func (w *Wallet) handleDerivePubKey(r derivePubKeyReq) {
	// Keep the existing Store-backed key resolver inside accepted work.
	key, err := w.resolveDerivedPubKeyFromStore(r.ctx, r.params)
	r.respChan <- pubKeyResp{key: key, err: err}
}

// resolveDerivedPubKeyFromStore resolves one derived public key from the
// account-level extended public key stored behind the wallet store. It is the
// public-key counterpart of resolveDerivedPrivKeyFromStore and, since the
// account xpub is stored in plaintext, it also serves watch-only accounts that
// hold no encrypted private material.
func (w *Wallet) resolveDerivedPubKeyFromStore(ctx context.Context,
	params DerivePubKeyParams) (*btcec.PublicKey, error) {

	query := db.GetAccountQuery{
		WalletID:    w.id,
		Scope:       db.KeyScope(params.Account.keyScope),
		SkipBalance: true,
	}

	if params.Account.accountName != nil {
		query.Name = params.Account.accountName
	} else {
		accountNumber := uint32(*params.Account.accountNumber)
		query.AccountNumber = &accountNumber
	}

	// The account xpub is public metadata, so it comes from the account read
	// rather than the secret read: AccountSecret carries encrypted private
	// material only. SkipBalance keeps this to one backend query, and the
	// public path works while the wallet is locked.
	account, err := w.cache.GetAccount(ctx, query)
	switch {
	case errors.Is(err, db.ErrAccountNotFound):
		return nil, ErrAccountNotInStore

	case err != nil:
		return nil, fmt.Errorf("fetch account: %w", err)
	}

	if len(account.PublicKey) == 0 {
		return nil, fmt.Errorf(
			"%w: account public key", ErrMissingParam,
		)
	}

	return deriveStoredAccountChildPubKey(account.PublicKey,
		waddrmgr.DerivationPath{
			Branch: params.Branch,
			Index:  params.Index,
		})
}

// deriveStoredAccountChildPubKey parses an account-level extended public key
// and walks the branch and index derivation to produce the leaf public key.
// The intermediate HD keys are zeroed before the call returns.
func deriveStoredAccountChildPubKey(accountPubKey []byte,
	path waddrmgr.DerivationPath) (*btcec.PublicKey, error) {

	acctPub, err := hdkeychain.NewKeyFromString(string(accountPubKey))
	if err != nil {
		return nil, fmt.Errorf("parse account pub: %w", err)
	}
	defer acctPub.Zero()

	branchKey, err := deriveChildKey(acctPub, path.Branch)
	if err != nil {
		return nil, fmt.Errorf("derive branch: %w", err)
	}
	defer branchKey.Zero()

	addrKey, err := deriveChildKey(branchKey, path.Index)
	if err != nil {
		return nil, fmt.Errorf("derive index: %w", err)
	}
	defer addrKey.Zero()

	pubKey, err := addrKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	return pubKey, nil
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
// caller is responsible for assembling the final witness. Accepted signing
// finishes before return even if the caller cancels after admission.
func (w *Wallet) ComputeRawSig(ctx context.Context, params *RawSigParams) (
	RawSignature, error) {

	err := w.state.canSign()
	if err != nil {
		return nil, err
	}

	// The handler dereferences these params on its own goroutine, where a nil
	// would fault with no caller to recover it.
	if params == nil {
		return nil, fmt.Errorf(
			"%w: raw signature params are nil", ErrNilArguments,
		)
	}

	// Details carries the version-specific signing behavior and its own
	// documentation requires it to be set. The handler calls through it
	// unconditionally, so an unset interface faults there.
	if params.Details == nil {
		return nil, fmt.Errorf(
			"%w: raw signature details are nil", ErrNilArguments,
		)
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := rawSigReq{
		reqCtx:   reqCtx{ctx: ctx},
		params:   params,
		respChan: make(chan rawSigResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return nil, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.signature, result.err
}

// handleComputeRawSig delivers the result of an accepted component request.
func (w *Wallet) handleComputeRawSig(r rawSigReq) {
	// Reuse raw signing shared with PSBTs and finish key cleanup before
	// delivery.
	signature, err := w.computeRawSig(r.ctx, r.params, nil)
	r.respChan <- rawSigResp{signature: signature, err: err}
}

// computeRawSig signs and zeroes its key inside the accepted request. With
// signer set, the tweaked key must be signer, as PSBT records name keys, before
// it signs.
func (w *Wallet) computeRawSig(ctx context.Context, params *RawSigParams,
	signer []byte) (RawSignature, error) {

	// A SQL vault signs without giving the key to Wallet code. PSBT
	// signing, which names the signer, keeps the legacy path for now.
	signingVault, ok := w.keyVault.(keyvault.SigningVault)
	if ok && signer == nil {
		return w.computeRawSigInVault(ctx, signingVault, params)
	}

	privKey, err := w.derivePathPrivKey(ctx, params.Path)
	if err != nil {
		return nil, err
	}
	defer privKey.Zero()

	err = params.Tweak.apply(privKey)
	if err != nil {
		return nil, err
	}

	if signer != nil && !recordKeyIs(signer, privKey.PubKey()) {
		return nil, fmt.Errorf("%w: derived key differs",
			ErrSigningKeyMismatch)
	}

	// With the private key retrieved and tweaked, we can now delegate the
	// actual signing to the version-specific details object.
	sigHash, err := params.Details.inputSigHash(params)
	if err != nil {
		return nil, fmt.Errorf("cannot sign transaction: %w", err)
	}

	rawSig, err := signInputSigHash(privKey, sigHash)
	if err != nil {
		return nil, fmt.Errorf("cannot sign transaction: %w", err)
	}

	return rawSig, nil
}

// DerivePrivKey derives a private key from a full BIP-32 derivation
// path.
//
// DANGER: This method exports sensitive key material. Once admitted, the call
// waits for key delivery despite cancellation. The caller must zero the key.
func (w *Wallet) DerivePrivKey(ctx context.Context, path BIP32Path) (
	*btcec.PrivateKey, error) {

	err := w.state.canSign()
	if err != nil {
		return nil, err
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := derivePrivKeyReq{
		reqCtx:   reqCtx{ctx: ctx},
		path:     path,
		respChan: make(chan privKeyResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return nil, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.key, result.err
}

// GetPrivKeyForAddress returns the private key for a given address.
//
// DANGER: This method exports sensitive key material. Once admitted, the call
// waits for key delivery despite cancellation. The caller must zero the key.
func (w *Wallet) GetPrivKeyForAddress(ctx context.Context, a address.Address) (
	*btcec.PrivateKey, error) {

	err := w.state.canSign()
	if err != nil {
		return nil, err
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := privKeyForAddressReq{
		reqCtx:   reqCtx{ctx: ctx},
		addr:     a,
		respChan: make(chan privKeyResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return nil, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.key, result.err
}

// PrivKeyForAddress looks up the associated private key for a wallet address.
//
// It is the context-free compatibility wrapper over privKeyForAddress used by
// callers on the legacy Signer interface. It performs no walletdb transaction
// of its own; the private key is resolved entirely through the store and
// unsafeVault.
//
// DANGER: This method exports sensitive key material.
func (w *Wallet) PrivKeyForAddress(a address.Address) (
	*btcec.PrivateKey, error) {

	err := w.state.canSign()
	if err != nil {
		return nil, err
	}

	return w.privKeyForAddress(context.Background(), a)
}

// handleGetPrivKeyForAddress delivers the result of an accepted component
// request.
func (w *Wallet) handleGetPrivKeyForAddress(r privKeyForAddressReq) {
	// Reuse address-key lookup and transfer the exported key to its caller.
	key, err := w.privKeyForAddress(r.ctx, r.addr)
	r.respChan <- privKeyResp{key: key, err: err}
}

// privKeyForAddress resolves the private key for a wallet address through the
// store. Derived addresses resolve through the owning account's encrypted
// extended private key; imported addresses resolve through their own encrypted
// private key material. An address that is not owned by the wallet, or that
// holds no spendable key, yields ErrNoAssocPrivateKey.
func (w *Wallet) privKeyForAddress(ctx context.Context,
	a address.Address) (*btcec.PrivateKey, error) {

	info, err := w.getAddressInfo(ctx, a)
	switch {
	case err == nil && canUseAddressInfoDerivation(info):
		return w.privKeyForAddressInfo(ctx, info)

	case err == nil && !info.Imported:
		// The address is owned and HD-shaped but carries no derivation:
		// it is an imported-xpub child. Its account was created from an
		// extended *public* key, so no signing material exists for it
		// anywhere — refuse before querying a secret rather than after
		// the backend misses.
		return nil, ErrNoAssocPrivateKey

	case err == nil:
		// A raw import: its private key, if any, lives in its own
		// encrypted secret.
		scriptPubKey, err := txscript.PayToAddrScript(a)
		if err != nil {
			return nil, fmt.Errorf("pay to addr script: %w", err)
		}

		return w.resolveImportedAddrPrivKey(ctx, scriptPubKey)

	case errors.Is(err, ErrAddressNotFound):
		// The address is not owned by the wallet, so the wallet holds
		// no private key for it.
		return nil, ErrNoAssocPrivateKey

	default:
		// Unexpected store error: surface, don't mask.
		return nil, fmt.Errorf("priv key for address: %w", err)
	}
}
