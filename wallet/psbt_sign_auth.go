// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// ErrInvalidSignatureRecord is returned when a packet carries an existing
// signature record that does not verify for the input it sits on.
var ErrInvalidSignatureRecord = errors.New("invalid psbt signature record")

// authorizeSignRecords checks the existing signature records in a packet
// against the input each sits on. It uses no wallet state.
func authorizeSignRecords(packet *psbt.Packet, sigHashes *txscript.TxSigHashes,
	prevOuts txscript.PrevOutputFetcher) error {

	for i := range packet.Inputs {
		pIn := &packet.Inputs[i]

		if pIn.TaprootKeySpendSig == nil {
			continue
		}

		utxo, err := fetchPsbtUtxo(packet, i)
		if err != nil {
			return err
		}

		err = authorizeTaprootKeySpendSig(
			packet, i, utxo, sigHashes, prevOuts,
		)
		if err != nil {
			return fmt.Errorf("%w: input %d: %w",
				ErrInvalidSignatureRecord, i, err)
		}
	}

	return nil
}

// authorizeTaprootKeySpendSig checks an input's Taproot key-path record
// against the output key.
func authorizeTaprootKeySpendSig(packet *psbt.Packet, idx int,
	utxo *wire.TxOut, sigHashes *txscript.TxSigHashes,
	prevOuts txscript.PrevOutputFetcher) error {

	pIn := &packet.Inputs[idx]

	sig := pIn.TaprootKeySpendSig
	if sig == nil {
		return nil
	}

	if txscript.GetScriptClass(utxo.PkScript) !=
		txscript.WitnessV1TaprootTy {

		return errors.New("key spend signature on a non-taproot output")
	}

	// A default sighash is encoded by omitting the byte, so an explicit
	// zero byte is invalid. Other lengths fail to parse below.
	hashType := txscript.SigHashDefault
	if len(sig) == schnorr.SignatureSize+1 {
		hashType = txscript.SigHashType(sig[schnorr.SignatureSize])
		if hashType == txscript.SigHashDefault {
			return errors.New("key spend signature encodes the " +
				"default sighash explicitly")
		}

		sig = sig[:schnorr.SignatureSize]
	}

	if !taprootSigHashAllowed(hashType, pIn.SighashType) {
		return fmt.Errorf("key spend signature sighash %#x, input "+
			"requests %#x", uint32(hashType),
			uint32(pIn.SighashType))
	}

	digest, err := txscript.CalcTaprootSignatureHash(
		sigHashes, hashType, packet.UnsignedTx, idx, prevOuts,
	)
	if err != nil {
		return fmt.Errorf("key spend digest: %w", err)
	}

	err = verifySchnorr(sig, digest, utxo.PkScript[2:34])
	if err != nil {
		return fmt.Errorf("key spend signature: %w", err)
	}

	return nil
}

// taprootSigHashAllowed reports whether a Taproot signature's sighash is one
// its input allows. An input that sets a sighash type allows only that type.
// One that sets none allows SIGHASH_DEFAULT, the BIP 371 default, and an
// explicit SIGHASH_ALL, which commits to the same transaction data.
func taprootSigHashAllowed(sigHash, inputSigHash txscript.SigHashType) bool {
	if inputSigHash != txscript.SigHashDefault {
		return sigHash == inputSigHash
	}

	return sigHash == txscript.SigHashDefault ||
		sigHash == txscript.SigHashAll
}

// verifySchnorr checks a bare 64-byte Schnorr signature over a digest.
func verifySchnorr(sig, digest, xOnlyKey []byte) error {
	key, err := schnorr.ParsePubKey(xOnlyKey)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}

	parsed, err := schnorr.ParseSignature(sig)
	if err != nil {
		return err
	}

	if !parsed.Verify(digest, key) {
		return errors.New("does not verify")
	}

	return nil
}
