package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/signing"
)

// mapDerivedSignErr maps vault signing errors for an account-derived key to
// the public signer errors. A tweak the vault refuses with ErrInvalidKeyTweak
// becomes ErrInvalidSignParam, keeping ErrInvalidKeyTweak in the chain; any
// other error goes through mapAccountSecretErr, so a lookup error becomes the
// sentinel the legacy Store path returns and the rest are unchanged.
func mapDerivedSignErr(err error) error {
	if errors.Is(err, signing.ErrInvalidKeyTweak) {
		return fmt.Errorf("%w: %w", ErrInvalidSignParam, err)
	}

	return mapAccountSecretErr(err)
}

// signingPubKey returns the public key at path. The vault derives it through
// the private key, so it serves hardened children, which an account XPub
// cannot derive, and reports a missing or watch-only account like signing.
func (w *Wallet) signingPubKey(ctx context.Context,
	path BIP32Path) (*btcec.PublicKey, error) {

	pub, err := w.keyVault.PubKey(ctx, signing.DerivedKey(path))
	if err != nil {
		return nil, mapAccountSecretErr(err)
	}

	return pub, nil
}

// signDigest signs a validated intent with the key at path through the vault.
//
// For a Taproot tweak, Wallet folds the BIP-341 output tweak into the vault's
// scalar pair from the key's public key, so the vault applies no Taproot
// rules. The signature must then verify under the output key, or the call
// returns ErrSigningKeyMismatch.
func (w *Wallet) signDigest(ctx context.Context, path BIP32Path,
	intent *SignDigestIntent) (Signature, error) {

	req := intent.digestRequest(path)

	if intent.SigType != SigTypeSchnorr || intent.TaprootTweak == nil {
		sig, err := w.keyVault.SignDigest(ctx, req)
		if err != nil {
			return nil, mapDerivedSignErr(err)
		}

		return sig, nil
	}

	base, err := w.signingPubKey(ctx, path)
	if err != nil {
		return nil, err
	}

	req.Tweak, err = taprootOutputTweak(base, intent.TaprootTweak)
	if err != nil {
		return nil, err
	}

	sig, err := w.keyVault.SignDigest(ctx, req)
	if err != nil {
		return nil, mapDerivedSignErr(err)
	}

	// txscript computes the expected output key independently of the tweak
	// above, so a wrong tweak cannot verify against its own result.
	outputKey := txscript.ComputeTaprootOutputKey(base, intent.TaprootTweak)

	err = verifySignature(sig, req.Digest[:], outputKey)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// verifySignature checks that the vault's Taproot signature sig signs digest
// under key. The vault signs with the key it derives; this catches a tweak
// that Wallet computed from a different public key. A mismatch returns
// ErrSigningKeyMismatch, and any signature other than a Schnorr one returns
// ErrUnknownSignMethod.
func verifySignature(sig Signature, digest []byte,
	key *btcec.PublicKey) error {

	schnorrSig, ok := sig.(SchnorrSignature)
	if !ok {
		return fmt.Errorf("%w: %T", ErrUnknownSignMethod, sig)
	}

	if !schnorrSig.Verify(digest, key) {
		return fmt.Errorf("%w: signature does not verify under the "+
			"expected key", ErrSigningKeyMismatch)
	}

	return nil
}

// digestRequest returns the vault request that signs a validated intent with
// the key at path. It carries no tweak: Wallet folds any Taproot tweak into
// the request after it has the key's public key.
func (intent *SignDigestIntent) digestRequest(
	path BIP32Path) signing.DigestRequest {

	req := signing.DigestRequest{
		Key:  signing.DerivedKey(path),
		Mode: signing.ModeECDSA,
	}
	copy(req.Digest[:], intent.Digest)

	switch {
	case intent.SigType == SigTypeSchnorr:
		req.Mode = signing.ModeSchnorr

	case intent.CompactSig:
		req.Mode = signing.ModeCompactECDSA
	}

	return req
}

// taprootOutputTweak returns the scalar pair that turns the private key d of
// internal into its BIP-341 tweaked private key for scriptRoot: s*d + t, where
// t is the BIP-341 tweak hash and s is -1 when internal has an odd Y
// coordinate and 1 otherwise. This equals txscript.TweakTaprootPrivKey(d,
// scriptRoot).
func taprootOutputTweak(internal *btcec.PublicKey,
	scriptRoot []byte) (signing.KeyTweak, error) {

	var mul btcec.ModNScalar
	mul.SetInt(1)

	if internal.Y().Bit(0) == 1 {
		mul.Negate()
	}

	tweakHash := chainhash.TaggedHash(
		chainhash.TagTapTweak, schnorr.SerializePubKey(internal),
		scriptRoot,
	)

	// BIP-341 fails a tweak at or above the curve order instead of
	// reducing it, as NewKeyTweak does.
	tweak, err := signing.NewKeyTweak(mul.Bytes(), *tweakHash)
	if err != nil {
		return signing.KeyTweak{}, fmt.Errorf("%w: taproot tweak: %w",
			ErrInvalidSignParam, err)
	}

	return tweak, nil
}
