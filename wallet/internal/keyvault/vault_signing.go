package keyvault

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcwallet/wallet/internal/signing"
)

// SignDigest signs a wallet-computed digest with the selected key. See Vault
// for the lock and cleanup contract.
func (v *WalletVault) SignDigest(ctx context.Context,
	req signing.DigestRequest) (signing.Signature, error) {

	// The callback clears the tweak, which can be secret, under the guard;
	// this covers the exits before it runs.
	defer req.Tweak.Zero()

	err := req.Validate()
	if err != nil {
		return nil, fmt.Errorf("wallet %d vault SignDigest: %w",
			v.walletID, err)
	}

	var sig signing.Signature

	err = v.useKey(ctx, req.Key, func(key *btcec.PrivateKey) error {
		defer req.Tweak.Zero()

		sig, err = SignDigestWithKey(key, &req)

		return err
	})
	if err != nil {
		return nil, fmt.Errorf("wallet %d vault SignDigest: %w",
			v.walletID, err)
	}

	return sig, nil
}

// SignDigestWithKey applies req.Tweak to key in place and signs req.Digest in
// req.Mode. The caller validates req, owns key and zeroes it. It is for vault
// implementations only; key must never come from or return to Wallet code.
func SignDigestWithKey(key *btcec.PrivateKey,
	req *signing.DigestRequest) (signing.Signature, error) {

	err := req.Tweak.Apply(key)
	if err != nil {
		return nil, err
	}

	return signDigest(key, req.Mode, req.Digest[:])
}

// signDigest returns the signature of digest for mode.
func signDigest(key *btcec.PrivateKey, mode signing.Mode,
	digest []byte) (signing.Signature, error) {

	switch mode {
	case signing.ModeECDSA:
		return signing.ECDSASignature{
			Signature: ecdsa.Sign(key, digest),
		}, nil

	case signing.ModeCompactECDSA:
		return signing.CompactSignature(
			ecdsa.SignCompact(key, digest, true),
		), nil

	case signing.ModeSchnorr:
		sig, err := schnorr.Sign(key, digest)
		if err != nil {
			return nil, fmt.Errorf("schnorr sign: %w", err)
		}

		return signing.SchnorrSignature{Signature: sig}, nil

	default:
		return nil, fmt.Errorf("%w: %d", signing.ErrInvalidMode, mode)
	}
}
