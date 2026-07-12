package signing

import (
	"github.com/btcsuite/btcd/btcec/v2"
)

// Request identifies a signing operation using one of the supported request
// variants.
type Request interface {
	// isRequest seals Request to variants defined in this package.
	isRequest()
}

// ECDSARequest requests a normal ECDSA signature over a digest.
type ECDSARequest struct {
	// KeyLocator identifies the key used to sign Digest.
	KeyLocator KeyLocator

	// Digest is the 32-byte hash to sign.
	Digest [32]byte
}

// isRequest implements the sealed Request interface.
func (ECDSARequest) isRequest() {}

// CompactKeyFormat describes the public-key header semantics for compact ECDSA
// signatures. Implementations must reject CompactKeyFormatUnknown.
type CompactKeyFormat uint8

const (
	// CompactKeyFormatUnknown represents an omitted compact key format.
	// Implementations must reject this value.
	CompactKeyFormatUnknown CompactKeyFormat = iota

	// CompactKeyUncompressed requests compact signature header semantics for an
	// uncompressed public key.
	CompactKeyUncompressed

	// CompactKeyCompressed requests compact signature header semantics for a
	// compressed public key.
	CompactKeyCompressed
)

// CompactECDSARequest requests a compact recoverable ECDSA signature over a
// digest.
type CompactECDSARequest struct {
	// KeyLocator identifies the key used to sign Digest.
	KeyLocator KeyLocator

	// Digest is the 32-byte hash to sign.
	Digest [32]byte

	// KeyFormat selects the compact signature header semantics.
	KeyFormat CompactKeyFormat
}

// isRequest implements the sealed Request interface.
func (CompactECDSARequest) isRequest() {}

// SchnorrRequest requests a BIP340 Schnorr signature over a digest.
type SchnorrRequest struct {
	// KeyLocator identifies the key used to sign Digest.
	KeyLocator KeyLocator

	// Digest is the 32-byte hash to sign.
	Digest [32]byte
}

// isRequest implements the sealed Request interface.
func (SchnorrRequest) isRequest() {}

// SchnorrKeyTweak describes an additive secp256k1 tweak for Schnorr signing.
type SchnorrKeyTweak struct {
	// Scalar is the already-computed additive secp256k1 scalar. It is not a
	// Taproot script root, merkle root, or BIP341 tweak input byte string.
	Scalar btcec.ModNScalar

	// NormalizeEvenY reports whether the key should be normalized to the BIP340
	// even-Y representative before the tweak is applied.
	NormalizeEvenY bool
}

// TweakedSchnorrRequest requests a BIP340 Schnorr signature over a digest after
// applying an additive key tweak.
type TweakedSchnorrRequest struct {
	// KeyLocator identifies the key used to sign Digest.
	KeyLocator KeyLocator

	// Digest is the 32-byte hash to sign.
	Digest [32]byte

	// Tweak is the additive secp256k1 scalar applied before signing.
	Tweak SchnorrKeyTweak
}

// isRequest implements the sealed Request interface.
func (TweakedSchnorrRequest) isRequest() {}

// Ensure the request variants implement Request.
var _ Request = ECDSARequest{}
var _ Request = CompactECDSARequest{}
var _ Request = SchnorrRequest{}
var _ Request = TweakedSchnorrRequest{}
