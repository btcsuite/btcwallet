package signing

import (
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Signature describes one supported primitive signing result.
type Signature interface {
	// Serialize returns the raw signature bytes without any appended sighash
	// byte; the wallet layer owns sighash semantics.
	Serialize() []byte

	// isSignature seals Signature to variants defined in this package.
	isSignature()
}

// ECDSASignature wraps a normal ECDSA signature result.
type ECDSASignature struct {
	// Signature is the generated ECDSA signature.
	Signature ecdsa.Signature
}

// isSignature implements the sealed Signature interface.
func (ECDSASignature) isSignature() {}

// Serialize returns the DER-encoded ECDSA signature bytes.
func (s ECDSASignature) Serialize() []byte {
	return s.Signature.Serialize()
}

// CompactECDSASignature wraps a compact recoverable ECDSA signature result.
type CompactECDSASignature struct {
	// Signature is the compact recoverable ECDSA signature bytes.
	Signature []byte
}

// isSignature implements the sealed Signature interface.
func (CompactECDSASignature) isSignature() {}

// Serialize returns a copy of the compact recoverable ECDSA signature bytes.
func (s CompactECDSASignature) Serialize() []byte {
	return append([]byte(nil), s.Signature...)
}

// SchnorrSignature wraps a BIP340 Schnorr signature result.
type SchnorrSignature struct {
	// Signature is the generated Schnorr signature.
	Signature schnorr.Signature
}

// isSignature implements the sealed Signature interface.
func (SchnorrSignature) isSignature() {}

// Serialize returns the BIP340 Schnorr signature bytes.
func (s SchnorrSignature) Serialize() []byte {
	return s.Signature.Serialize()
}

// Ensure the signature variants implement Signature.
var _ Signature = ECDSASignature{}
var _ Signature = CompactECDSASignature{}
var _ Signature = SchnorrSignature{}
