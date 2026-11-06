package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
)

// pathKeySelector converts a signer path into the vault selector for the same
// key. The vault reads the account by its BIP44 number, so only
// InternalAccount, Branch and Index are used, as in the legacy key path.
func pathKeySelector(path BIP32Path) keyvault.KeySelector {
	return keyvault.DerivedKey(
		path.KeyScope, path.DerivationPath.InternalAccount,
		path.DerivationPath.Branch, path.DerivationPath.Index,
	)
}

// mapDerivedKeyErr maps vault errors for an account-derived key to the errors
// the legacy Store path returns, so callers see the same sentinels on every
// backend. Other errors are returned unchanged.
func mapDerivedKeyErr(err error) error {
	switch {
	case errors.Is(err, keyvault.ErrKeyNotFound):
		return ErrAccountNotInStore

	case errors.Is(err, keyvault.ErrNoPrivateKey):
		return ErrWatchOnlyAccount

	default:
		return mapVaultSignErr(err)
	}
}

// mapImportedKeyErr maps vault errors for a raw imported key to the errors the
// legacy Store path returns. An unknown import and a watch-only import both
// mean the wallet holds no key for the output.
func mapImportedKeyErr(err error) error {
	switch {
	case errors.Is(err, keyvault.ErrKeyNotFound),
		errors.Is(err, keyvault.ErrNoPrivateKey):

		return ErrNoAssocPrivateKey

	default:
		return mapVaultSignErr(err)
	}
}

// mapVaultSignErr maps vault tweak and effective-key errors to the wallet's
// signing sentinels. Other errors are returned unchanged.
func mapVaultSignErr(err error) error {
	switch {
	case errors.Is(err, keyvault.ErrInvalidKeyTweak):
		return fmt.Errorf("%w: %w", ErrInvalidSignParam, err)

	case errors.Is(err, keyvault.ErrEffectiveKeyMismatch):
		return fmt.Errorf("%w: derived key differs", ErrSigningKeyMismatch)

	default:
		return err
	}
}

// signDigestInVault signs a validated intent through the vault. The wallet
// computes any Taproot tweak from public data, and the vault applies it to the
// key it derives.
func (w *Wallet) signDigestInVault(ctx context.Context,
	signingVault keyvault.SigningVault, path BIP32Path,
	intent *SignDigestIntent) (Signature, error) {

	req := keyvault.SignDigestRequest{
		Key:  pathKeySelector(path),
		Mode: vaultSignMode(intent),
	}
	copy(req.Digest[:], intent.Digest)

	if intent.SigType == SigTypeSchnorr && intent.TaprootTweak != nil {
		base, err := w.derivePathPubKey(ctx, path)
		if err != nil {
			return nil, err
		}

		tweak, outputKey, err := foldKeyTweak(
			base, KeyTweak{}, true, intent.TaprootTweak,
		)
		if err != nil {
			return nil, err
		}
		defer tweak.Zero()

		req.Tweak = tweak
		req.EffectiveKey = outputKey
	}

	sig, err := signingVault.SignDigest(ctx, req)
	if err != nil {
		return nil, mapDerivedKeyErr(err)
	}

	return walletSignature(req.Mode, sig)
}

// vaultSignMode returns the vault signing mode for a validated intent.
func vaultSignMode(intent *SignDigestIntent) keyvault.SignMode {
	switch {
	case intent.SigType == SigTypeSchnorr:
		return keyvault.SignModeSchnorr

	case intent.CompactSig:
		return keyvault.SignModeCompactECDSA

	default:
		return keyvault.SignModeECDSA
	}
}

// walletSignature wraps a vault signature in the public Signature type for
// mode.
func walletSignature(mode keyvault.SignMode,
	sig keyvault.DigestSignature) (Signature, error) {

	switch mode {
	case keyvault.SignModeSchnorr:
		return SchnorrSignature{sig.Schnorr}, nil

	case keyvault.SignModeCompactECDSA:
		return CompactSignature(sig.Compact), nil

	case keyvault.SignModeECDSA:
		return ECDSASignature{sig.ECDSA}, nil

	default:
		return nil, fmt.Errorf("%w: sign mode %d", ErrUnknownSignMethod,
			mode)
	}
}

// foldKeyTweak returns one vault scalar pair for tweak followed, when
// outputTweak is set, by the BIP-341 output tweak for scriptRoot. It returns a
// nil pair for the identity.
//
// With an output tweak, it also returns the output key, which the vault checks
// before it signs. The effective internal key is tweak applied to base; lift_x
// of that key is s times it, with s = -1 for an odd Y coordinate; and the
// output key adds t*G for the BIP-341 tweak hash t. The private key of the
// output key is thus (s*mul)*d + (s*add + t). base is required only with an
// output tweak, and the result equals txscript.TweakTaprootPrivKey applied to
// the tweaked key.
func foldKeyTweak(base *btcec.PublicKey, tweak KeyTweak, outputTweak bool,
	scriptRoot []byte) (*keyvault.KeyTweak, *btcec.PublicKey, error) {

	identity := tweak == (KeyTweak{})

	var mul, add btcec.ModNScalar
	defer mul.Zero()
	defer add.Zero()

	mul.SetInt(1)

	if !identity {
		mul.Set(&tweak.mul)
		add.Set(&tweak.add)
	}

	if !outputTweak {
		if identity {
			return nil, nil, nil
		}

		pair, err := keyvault.NewKeyTweak(&mul, &add)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrInvalidSignParam,
				err)
		}

		return pair, nil, nil
	}

	if base == nil {
		return nil, nil, fmt.Errorf("%w: missing taproot base key",
			ErrInvalidSignParam)
	}

	internalKey, err := tweak.pubKey(base)
	if err != nil {
		return nil, nil, err
	}

	if internalKey.Y().Bit(0) == 1 {
		mul.Negate()
		add.Negate()
	}

	tweakHash := chainhash.TaggedHash(
		chainhash.TagTapTweak, schnorr.SerializePubKey(internalKey),
		scriptRoot,
	)

	// BIP-341 fails a tweak at or above the curve order instead of reducing
	// it.
	var outputAdd btcec.ModNScalar
	if outputAdd.SetByteSlice(tweakHash[:]) {
		return nil, nil, fmt.Errorf("%w: taproot tweak out of range",
			ErrInvalidSignParam)
	}

	add.Add(&outputAdd)

	pair, err := keyvault.NewKeyTweak(&mul, &add)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidSignParam, err)
	}

	outputKey := txscript.ComputeTaprootOutputKey(internalKey, scriptRoot)

	return pair, outputKey, nil
}

// signInputInVault signs one input signature hash with the selected key under
// tweak. base is the selected key's public key; it is required for a Taproot
// key-path spend. effective, when set, is the key the tweaked key must be.
// Vault errors are returned unmapped.
func signInputInVault(ctx context.Context, signingVault keyvault.SigningVault,
	key keyvault.KeySelector, base *btcec.PublicKey, tweak KeyTweak,
	sigHash *inputSigHash, effective *btcec.PublicKey) (RawSignature,
	error) {

	pair, outputKey, err := foldKeyTweak(
		base, tweak, sigHash.keyPath, sigHash.scriptRoot,
	)
	if err != nil {
		return nil, err
	}
	defer pair.Zero()

	req := keyvault.SignDigestRequest{
		Key:          key,
		Digest:       sigHash.digest,
		Mode:         keyvault.SignModeECDSA,
		Tweak:        pair,
		EffectiveKey: effective,
	}

	if sigHash.schnorr {
		req.Mode = keyvault.SignModeSchnorr
	}

	if outputKey != nil {
		req.EffectiveKey = outputKey
	}

	sig, err := signingVault.SignDigest(ctx, req)
	if err != nil {
		return nil, err //nolint:wrapcheck
	}

	if sigHash.schnorr {
		return sigHash.serialize(sig.Schnorr.Serialize()), nil
	}

	return sigHash.serialize(sig.ECDSA.Serialize()), nil
}

// computeRawSigInVault signs a raw input signature through the vault. The
// signature hash is computed before any key lookup, so a malformed request
// fails without touching a secret.
func (w *Wallet) computeRawSigInVault(ctx context.Context,
	signingVault keyvault.SigningVault,
	params *RawSigParams) (RawSignature, error) {

	sigHash, err := params.Details.inputSigHash(params)
	if err != nil {
		return nil, fmt.Errorf("cannot sign transaction: %w", err)
	}

	// The output tweak needs the parity of the tweaked key, which the
	// account XPub gives without the private key.
	var base *btcec.PublicKey
	if sigHash.keyPath {
		base, err = w.derivePathPubKey(ctx, params.Path)
		if err != nil {
			return nil, err
		}
	}

	rawSig, err := signInputInVault(
		ctx, signingVault, pathKeySelector(params.Path), base,
		params.Tweak, sigHash, nil,
	)
	if err != nil {
		return nil, mapDerivedKeyErr(err)
	}

	return rawSig, nil
}

// outputKeySelector returns the vault selector for the single key that spends
// a wallet output, as privKeyForOutput resolves it on the legacy path. It
// reports whether the key is a raw import.
func outputKeySelector(scriptInfo *OutputScriptInfo) (keyvault.KeySelector,
	bool, error) {

	if canUseAddressInfoDerivation(scriptInfo.AddressInfo) {
		derivation := scriptInfo.Derivation

		return keyvault.DerivedKey(
			derivation.KeyScope, derivation.Account,
			derivation.Branch, derivation.Index,
		), false, nil
	}

	// Raw imports and numberless imported-XPub children have no
	// derivation. Only a raw import holds its own key.
	if !scriptInfo.Imported {
		return keyvault.KeySelector{}, false, ErrNoAssocPrivateKey
	}

	return keyvault.ImportedKey(scriptInfo.scriptPubKey()), true, nil
}

// outputSigner signs the input signature hashes of one wallet output through
// the vault. The vault checks that the key it signs with is the output's
// public key, or for Taproot its BIP-86 output key.
type outputSigner struct {
	signingVault keyvault.SigningVault
	key          keyvault.KeySelector
	imported     bool
	pubKey       *btcec.PublicKey
}

// sign signs sigHash and maps vault errors to the legacy sentinels for the
// key kind.
func (s *outputSigner) sign(ctx context.Context,
	sigHash *inputSigHash) (RawSignature, error) {

	sig, err := signInputInVault(
		ctx, s.signingVault, s.key, s.pubKey, KeyTweak{}, sigHash,
		s.pubKey,
	)

	switch {
	case err == nil:
		return sig, nil

	case s.imported:
		return nil, mapImportedKeyErr(err)

	default:
		return nil, mapDerivedKeyErr(err)
	}
}

// unlockingScriptInVault signs a single-key output through the vault and
// assembles its witness or sigScript from public data.
func unlockingScriptInVault(ctx context.Context,
	signingVault keyvault.SigningVault, params *UnlockingScriptParams,
	scriptInfo *OutputScriptInfo) (*UnlockingScript, error) {

	key, imported, err := outputKeySelector(scriptInfo)
	if err != nil {
		return nil, err
	}

	signingMethod, err := scriptInfo.AddrType.SigningMethod()
	if err != nil {
		return nil, fmt.Errorf("determine signing method: %w", err)
	}

	// Single-key outputs always carry their public key; see
	// buildScriptsForAddressInfo.
	signer := &outputSigner{
		signingVault: signingVault,
		key:          key,
		imported:     imported,
		pubKey:       scriptInfo.PubKey,
	}

	rawParams := &RawSigParams{
		Tx:         params.Tx,
		InputIndex: params.InputIndex,
		Output:     params.Output,
		SigHashes:  params.SigHashes,
		HashType:   params.HashType,
	}

	switch signingMethod {
	case waddrmgr.SigningMethodTaprootKeySpend:
		return taprootUnlockingScript(ctx, rawParams, signer)

	case waddrmgr.SigningMethodWitnessV0:
		return witnessV0UnlockingScript(
			ctx, rawParams, scriptInfo, signer,
		)

	case waddrmgr.SigningMethodLegacy:
		return legacyUnlockingScript(ctx, rawParams, signer)

	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAddressType,
			scriptInfo.AddrType)
	}
}

// taprootUnlockingScript signs a BIP-86 key-path spend. Its witness is the
// signature alone.
func taprootUnlockingScript(ctx context.Context, params *RawSigParams,
	signer *outputSigner) (*UnlockingScript, error) {

	// A wallet Taproot key commits to no scripts, as BIP-86 does.
	sigHash, err := TaprootSpendDetails{
		SpendPath: KeyPathSpend,
		Tweak:     []byte{},
	}.inputSigHash(params)
	if err != nil {
		return nil, fmt.Errorf("taproot witness error: %w", err)
	}

	sig, err := signer.sign(ctx, sigHash)
	if err != nil {
		return nil, err
	}

	return &UnlockingScript{Witness: wire.TxWitness{sig}}, nil
}

// legacyUnlockingScript signs a P2PKH spend and pushes the signature and the
// compressed public key into its sigScript.
func legacyUnlockingScript(ctx context.Context, params *RawSigParams,
	signer *outputSigner) (*UnlockingScript, error) {

	sigHash, err := LegacySpendDetails{}.inputSigHash(params)
	if err != nil {
		return nil, fmt.Errorf("sig script error: %w", err)
	}

	sig, err := signer.sign(ctx, sigHash)
	if err != nil {
		return nil, err
	}

	sigScript, err := txscript.NewScriptBuilder().
		AddData(sig).
		AddData(signer.pubKey.SerializeCompressed()).
		Script()
	if err != nil {
		return nil, fmt.Errorf("sig script error: %w", err)
	}

	return &UnlockingScript{SigScript: sigScript}, nil
}

// witnessV0UnlockingScript signs a P2WKH or nested P2WKH output and assembles
// its witness, plus the redeem script push for a nested output. The witness
// signature carries its sighash byte.
func witnessV0UnlockingScript(ctx context.Context, params *RawSigParams,
	scriptInfo *OutputScriptInfo, signer *outputSigner) (*UnlockingScript,
	error) {

	sigHash, err := SegwitV0SpendDetails{
		WitnessScript: scriptInfo.WitnessProgram,
	}.inputSigHash(params)
	if err != nil {
		return nil, fmt.Errorf("witness sig error: %w", err)
	}

	// A witness signature carries its sighash byte, unlike the raw
	// signature ComputeRawSig returns.
	sigHash.appendHashType = true

	sig, err := signer.sign(ctx, sigHash)
	if err != nil {
		return nil, err
	}

	sigScript, err := redeemSigScript(scriptInfo.RedeemScript)
	if err != nil {
		return nil, err
	}

	return &UnlockingScript{
		Witness: wire.TxWitness{
			sig, signer.pubKey.SerializeCompressed(),
		},
		SigScript: sigScript,
	}, nil
}
