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

	var outputKey *btcec.PublicKey

	req.Tweak, outputKey, err = keyPathTweak(
		KeyTweak{}, base, intent.TaprootTweak,
	)
	if err != nil {
		return nil, err
	}

	sig, err := w.keyVault.SignDigest(ctx, req)
	if err != nil {
		return nil, mapDerivedSignErr(err)
	}

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

// vaultInputSigner signs the signature hashes of transaction inputs with one
// key the vault holds.
type vaultInputSigner struct {
	// vault signs with the selected key.
	vault keyvault.Vault

	// key selects the vault key that signs.
	key signing.KeySelector

	// pubKey is the selected key's public key. It must be set for a
	// Taproot key path, whose BIP-341 output tweak depends on it. When it
	// is set, every signature must verify under the key it was made with.
	pubKey *btcec.PublicKey

	// mapErr maps the vault's errors to the public signer errors for the
	// kind of key that key selects.
	mapErr func(error) error
}

// sign signs sigHash in the vault with the selected key under tweak.
//
// For a Taproot key path, Wallet folds the BIP-341 output tweak of the tweaked
// internal key into the vault's scalar pair, so the vault applies no Taproot
// rules, and checks the signature under the output key. The vault must return
// the signature kind the input takes. Errors from the vault go through mapErr;
// a tweak Wallet refuses itself returns ErrInvalidSignParam.
func (s *vaultInputSigner) sign(ctx context.Context, tweak KeyTweak,
	sigHash *inputSigHash) (RawSignature, error) {

	// The caller's tweak can be secret, such as a revocation add term.
	// Clear this copy and the request's, which may hold it composed with
	// the output tweak, once the vault has signed.
	defer tweak.Zero()

	req := signing.DigestRequest{
		Key:    s.key,
		Digest: sigHash.digest,
		Mode:   signing.ModeECDSA,
		Tweak:  tweak,
	}
	defer req.Tweak.Zero()

	if sigHash.schnorr {
		req.Mode = signing.ModeSchnorr
	}

	// want is the key the signature must verify under, if any.
	var (
		want *btcec.PublicKey
		err  error
	)

	switch {
	case sigHash.taprootKeyPath:
		req.Tweak, want, err = keyPathTweak(
			tweak, s.pubKey, sigHash.taprootScriptRoot,
		)

	case s.pubKey != nil:
		want, err = tweakedPubKey(&tweak, s.pubKey)
	}

	if err != nil {
		return nil, err
	}

	sig, err := s.vault.SignDigest(ctx, req)
	if err != nil {
		return nil, s.mapErr(err)
	}

	return inputSignature(sig, sigHash, want)
}

// inputSignature checks the vault's signature for one input and serializes
// it. A Taproot input takes a Schnorr signature and any other input an ECDSA
// one, or ErrUnknownSignMethod is returned. When want is set, the signature
// must verify under it, or ErrSigningKeyMismatch is returned.
func inputSignature(sig Signature, sigHash *inputSigHash,
	want *btcec.PublicKey) (RawSignature, error) {

	var (
		raw   []byte
		valid bool
	)

	switch sig := sig.(type) {
	case SchnorrSignature:
		if !sigHash.schnorr {
			return nil, fmt.Errorf("%w: %T for an ECDSA input",
				ErrUnknownSignMethod, sig)
		}

		raw = sig.Serialize()
		valid = want == nil || sig.Verify(sigHash.digest[:], want)

	case ECDSASignature:
		if sigHash.schnorr {
			return nil, fmt.Errorf("%w: %T for a Taproot input",
				ErrUnknownSignMethod, sig)
		}

		raw = sig.Serialize()
		valid = want == nil || sig.Verify(sigHash.digest[:], want)

	default:
		return nil, fmt.Errorf("%w: %T", ErrUnknownSignMethod, sig)
	}

	if !valid {
		return nil, fmt.Errorf("%w: signature does not verify under "+
			"the expected key", ErrSigningKeyMismatch)
	}

	return sigHash.serialize(raw), nil
}

// keyPathTweak returns the vault scalar pair for a Taproot key-path spend:
// tweak followed by the BIP-341 output tweak of the tweaked internal key. It
// also returns the output key the signature must verify under, which txscript
// computes from the internal key independently of the scalar pair. base is the
// selected key's public key. Its copy of tweak is zeroed before it returns.
func keyPathTweak(tweak KeyTweak, base *btcec.PublicKey,
	scriptRoot []byte) (KeyTweak, *btcec.PublicKey, error) {

	defer tweak.Zero()

	internal, err := tweakedPubKey(&tweak, base)
	if err != nil {
		return KeyTweak{}, nil, err
	}

	outputTweak, err := taprootOutputTweak(internal, scriptRoot)
	if err != nil {
		return KeyTweak{}, nil, err
	}

	outputKey := txscript.ComputeTaprootOutputKey(internal, scriptRoot)

	return tweak.Then(outputTweak), outputKey, nil
}

// computeRawSigInVault signs a raw input signature through the vault. The
// signature hash is computed before any key lookup, so a malformed request
// fails without touching a secret. Only a Taproot key path reads the key's
// public key, which its output tweak needs; other raw signatures are returned
// without a key check, as before.
func (w *Wallet) computeRawSigInVault(ctx context.Context,
	params *RawSigParams) (RawSignature, error) {

	sigHash, err := params.Details.inputSigHash(params)
	if err != nil {
		return nil, fmt.Errorf("cannot sign transaction: %w", err)
	}

	signer := &vaultInputSigner{
		vault:  w.keyVault,
		key:    signing.DerivedKey(params.Path),
		mapErr: mapDerivedSignErr,
	}

	if sigHash.taprootKeyPath {
		signer.pubKey, err = w.signingPubKey(ctx, params.Path)
		if err != nil {
			return nil, err
		}
	}

	return signer.sign(ctx, params.Tweak, sigHash)
}
