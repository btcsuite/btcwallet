package keyvault

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ECDHSecret returns SHA256(compressed(privKey*remote)), the shared secret
// format of BOLT 8 and lnd's keychain.ECDHRing. remote must be on-curve and
// privKey nonzero, so the product is never the point at infinity. The shared
// point is cleared before returning.
//
// It is exported only so ECDH that still runs outside the SQL vault computes
// the same secret without its own copy.
//
// TODO(gus): unexport once kvdb support is removed.
func ECDHSecret(privKey *btcec.PrivateKey, remote *btcec.PublicKey) [32]byte {
	var peer, shared btcec.JacobianPoint
	defer func() {
		shared.X.Zero()
		shared.Y.Zero()
		shared.Z.Zero()
	}()

	remote.AsJacobian(&peer)
	btcec.ScalarMultNonConst(&privKey.Key, &peer, &shared)
	shared.ToAffine()

	// Encode without creating an additional PublicKey copy of the point.
	var point [btcec.PubKeyBytesLenCompressed]byte
	defer clear(point[:])

	point[0] = secp256k1.PubKeyFormatCompressedEven |
		byte(shared.Y.IsOddBit())
	shared.X.PutBytesUnchecked(point[1:])

	return sha256.Sum256(point[:])
}
