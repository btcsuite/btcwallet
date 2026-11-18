package keyvault

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ErrInvalidRemoteKey reports a missing or off-curve ECDH peer key.
var ErrInvalidRemoteKey = errors.New("invalid ECDH remote key")

// ECDH resolves an account before taking the guard, then decrypts, derives,
// computes and clears all owned secret work under the guard.
func (v *WalletVault) ECDH(ctx context.Context, scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath, remote *btcec.PublicKey) ([32]byte, error) {

	if remote == nil || !remote.IsOnCurve() {
		return [32]byte{}, ErrInvalidRemoteKey
	}

	secret, err := v.store.GetAccountSecret(ctx, db.GetAccountSecretQuery{
		WalletID:      v.walletID,
		Scope:         db.KeyScope(scope),
		AccountNumber: path.InternalAccount,
	})
	if secret != nil {
		defer clear(secret.EncryptedPrivateKey)
	}

	if err != nil {
		return [32]byte{}, fmt.Errorf("fetch account secret: %w", err)
	}

	if len(secret.EncryptedPrivateKey) == 0 {
		return [32]byte{}, ErrNoPrivateKey
	}

	return v.ecdh(
		path, remote, secret.EncryptedPrivateKey, (*snacl.CryptoKey).Decrypt,
	)
}

// accountDecryptor opens account ciphertext. Production uses CryptoKey.Decrypt;
// tests retain its plaintext result to observe cleanup, or pause/panic to
// check the guard. It is vault-owned code, never supplied by Wallet callers.
type accountDecryptor func(*snacl.CryptoKey, []byte) ([]byte, error)

// ecdh owns the guarded secret phase after lookup. No Store access or public
// vault calls are permitted here. remote must be on-curve, and decrypt must
// not retain the crypto key.
func (v *WalletVault) ecdh(path waddrmgr.DerivationPath,
	remote *btcec.PublicKey, encAccountPriv []byte,
	decrypt accountDecryptor) ([32]byte, error) {

	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.unlockedState == nil {
		return [32]byte{}, ErrVaultLocked
	}

	cryptoKey, err := v.selectUnlockedCryptoKey(waddrmgr.CKTPrivate)
	if err != nil {
		return [32]byte{}, err
	}

	accountPriv, err := decrypt(cryptoKey, encAccountPriv)
	defer clear(accountPriv)

	if err != nil {
		return [32]byte{}, fmt.Errorf("decrypt account priv: %w", err)
	}

	privKey, err := DeriveAccountChildKey(accountPriv, path)
	if err != nil {
		return [32]byte{}, err
	}
	defer privKey.Zero()

	return ECDHSecret(privKey, remote), nil
}

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
