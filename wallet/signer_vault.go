package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
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

// mapDerivedKeyErr maps vault lookup errors for an account-derived key to the
// errors the legacy Store path returns, so callers see the same sentinels on
// every backend. Other errors are returned unchanged.
func mapDerivedKeyErr(err error) error {
	switch {
	case errors.Is(err, keyvault.ErrKeyNotFound):
		return ErrAccountNotInStore

	case errors.Is(err, keyvault.ErrNoPrivateKey):
		return ErrWatchOnlyAccount

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
		tweak, effective, err := w.taprootDigestTweak(
			ctx, path, intent.TaprootTweak,
		)
		if err != nil {
			return nil, err
		}
		defer tweak.Zero()

		req.Tweak = tweak
		req.EffectiveKey = effective
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

// taprootDigestTweak returns the scalar pair and output key that turn the key
// at path into its BIP-341 output key for scriptRoot.
//
// It reads the base public key from the account XPub, so it needs no private
// key. The output key is lift_x(P) + t*G, where t is the BIP-341 tweak hash.
// For a private key d with public key P, the matching key is s*d + t, with s
// set to -1 when P has an odd Y coordinate. This equals
// txscript.TweakTaprootPrivKey(d, scriptRoot).
func (w *Wallet) taprootDigestTweak(ctx context.Context, path BIP32Path,
	scriptRoot []byte) (*keyvault.KeyTweak, *btcec.PublicKey, error) {

	base, err := w.resolveDerivedPubKeyFromStore(ctx, DerivePubKeyParams{
		Account: NewAccountSelectorByNumber(
			path.KeyScope,
			AccountNumber(path.DerivationPath.InternalAccount),
		),
		Branch: path.DerivationPath.Branch,
		Index:  path.DerivationPath.Index,
	})
	if err != nil {
		return nil, nil, err
	}

	return taprootOutputTweak(base, scriptRoot)
}

// taprootOutputTweak returns the scalar pair that turns the private key of
// base into the private key of its BIP-341 output key for scriptRoot, and that
// output key.
func taprootOutputTweak(base *btcec.PublicKey,
	scriptRoot []byte) (*keyvault.KeyTweak, *btcec.PublicKey, error) {

	var mul, add btcec.ModNScalar
	defer mul.Zero()
	defer add.Zero()

	// lift_x(P) is P or -P, whichever has an even Y coordinate.
	mul.SetInt(1)

	if base.Y().Bit(0) == 1 {
		mul.Negate()
	}

	tweakHash := chainhash.TaggedHash(
		chainhash.TagTapTweak, schnorr.SerializePubKey(base), scriptRoot,
	)

	// BIP-341 fails a tweak at or above the curve order instead of reducing
	// it.
	overflow := add.SetByteSlice(tweakHash[:])
	if overflow {
		return nil, nil, fmt.Errorf("%w: taproot tweak out of range",
			ErrInvalidSignParam)
	}

	tweak, err := keyvault.NewKeyTweak(&mul, &add)
	if err != nil {
		return nil, nil, fmt.Errorf("taproot tweak: %w", err)
	}

	return tweak, txscript.ComputeTaprootOutputKey(base, scriptRoot), nil
}
