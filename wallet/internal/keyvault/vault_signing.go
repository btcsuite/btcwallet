package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	// ErrKeyNotFound reports that the wallet has no account or address for
	// the selected key.
	ErrKeyNotFound = errors.New("signing key not found")

	// ErrNoPrivateKey reports that the selected account or address exists
	// but holds no private key material, such as a watch-only account, an
	// imported XPub account or a watch-only import.
	ErrNoPrivateKey = errors.New("key has no private material")

	// ErrInvalidKeySelector reports a selector that names no key.
	ErrInvalidKeySelector = errors.New("invalid key selector")

	// ErrInvalidKeyTweak reports a key tweak with a zero multiplier, or a
	// tweak that turns the selected key into zero.
	ErrInvalidKeyTweak = errors.New("invalid key tweak")

	// ErrEffectiveKeyMismatch reports that the tweaked key does not have
	// the public key the caller planned to sign with.
	ErrEffectiveKeyMismatch = errors.New("effective key mismatch")

	// ErrInvalidRemoteKey reports an ECDH remote key that is missing or is
	// not a curve point.
	ErrInvalidRemoteKey = errors.New("invalid remote public key")

	// ErrInvalidSignMode reports a digest signing request with an unknown
	// signature mode.
	ErrInvalidSignMode = errors.New("invalid sign mode")
)

// SigningVault is the vault operation set that uses a wallet private key
// without returning it: digest signing and ECDH.
//
// It is separate from Vault because only the SQL WalletVault serves it. The
// legacy kvdb vault keeps the wallet's existing key path.
//
// Every operation resolves its selector through the Store before it takes the
// vault guard, so a missing or watch-only key is reported even while the vault
// is locked. Otherwise a locked vault returns ErrVaultLocked. The private key
// and every intermediate secret are cleared before the operation returns or
// panics, and Lock waits for an operation in progress.
type SigningVault interface {
	// SignDigest signs req.Digest with the selected key under req.Tweak.
	SignDigest(ctx context.Context, req SignDigestRequest) (
		DigestSignature, error)

	// ECDH multiplies remote by the selected private key and returns the
	// SHA-256 digest of the 33-byte compressed shared point. The shared
	// point does not leave the vault.
	ECDH(ctx context.Context, key KeySelector,
		remote *btcec.PublicKey) ([32]byte, error)
}

// Ensure WalletVault serves the signing operations.
var _ SigningVault = (*WalletVault)(nil)

// keySelectorKind tells which of the KeySelector forms is set.
type keySelectorKind uint8

const (
	// keySelectorNone is the zero value, which names no key.
	keySelectorNone keySelectorKind = iota

	// keySelectorDerived names a child of a wallet-derived account.
	keySelectorDerived

	// keySelectorImported names a raw imported key by its script pubkey.
	keySelectorImported
)

// KeySelector names one private key in the vault's wallet. Build it with
// DerivedKey or ImportedKey. A selector holds no Store row ID and no wallet
// ID; the vault resolves it within its own wallet.
type KeySelector struct {
	kind keySelectorKind

	scope   waddrmgr.KeyScope
	account uint32
	branch  uint32
	index   uint32

	scriptPubKey []byte
}

// DerivedKey selects the child key at branch/index of the account with the
// given BIP44 account number in scope. The account number is the unhardened
// number; the vault uses the account's stored extended private key, so the
// hardened account step is not repeated.
func DerivedKey(scope waddrmgr.KeyScope, account, branch,
	index uint32) KeySelector {

	return KeySelector{
		kind:    keySelectorDerived,
		scope:   scope,
		account: account,
		branch:  branch,
		index:   index,
	}
}

// ImportedKey selects the raw imported private key stored for scriptPubKey.
// The selector keeps its own copy of the script.
func ImportedKey(scriptPubKey []byte) KeySelector {
	return KeySelector{
		kind:         keySelectorImported,
		scriptPubKey: bytes.Clone(scriptPubKey),
	}
}

// validate checks that the selector names a key.
func (s KeySelector) validate() error {
	switch s.kind {
	case keySelectorDerived:
		return nil

	case keySelectorImported:
		if len(s.scriptPubKey) == 0 {
			return fmt.Errorf("%w: empty script pubkey",
				ErrInvalidKeySelector)
		}

		return nil

	case keySelectorNone:
		return ErrInvalidKeySelector

	default:
		return ErrInvalidKeySelector
	}
}

// KeyTweak is the scalar pair (mul, add) that turns a wallet private key d
// into the effective signing key mul*d + add.
//
// The pair can be secret: a Lightning revocation add term reveals the
// revocation key. KeyTweak never logs or formats its scalars. The owner of a
// KeyTweak calls Zero when it is done with it.
type KeyTweak struct {
	mul btcec.ModNScalar
	add btcec.ModNScalar
}

// NewKeyTweak returns a tweak with copies of mul and add. A zero multiplier
// returns ErrInvalidKeyTweak, because it discards the wallet key. The caller
// keeps ownership of its inputs.
func NewKeyTweak(mul, add *btcec.ModNScalar) (*KeyTweak, error) {
	if mul == nil || add == nil {
		return nil, fmt.Errorf("%w: missing scalar", ErrInvalidKeyTweak)
	}

	if mul.IsZero() {
		return nil, fmt.Errorf("%w: zero multiplier", ErrInvalidKeyTweak)
	}

	tweak := &KeyTweak{}
	tweak.mul.Set(mul)
	tweak.add.Set(add)

	return tweak, nil
}

// Zero clears both scalars. A cleared tweak has a zero multiplier, so a later
// use returns ErrInvalidKeyTweak instead of signing with a different key.
func (t *KeyTweak) Zero() {
	if t == nil {
		return
	}

	t.mul.Zero()
	t.add.Zero()
}

// SignMode selects the signature algorithm and encoding of SignDigest.
type SignMode uint8

const (
	// SignModeECDSA produces an ECDSA signature.
	SignModeECDSA SignMode = iota + 1

	// SignModeCompactECDSA produces a 65-byte recoverable ECDSA signature
	// for the compressed public key.
	SignModeCompactECDSA

	// SignModeSchnorr produces a BIP-340 Schnorr signature.
	SignModeSchnorr
)

// SignDigestRequest describes one digest signature.
type SignDigestRequest struct {
	// Key selects the wallet key to sign with.
	Key KeySelector

	// Digest is the 32-byte message digest. The wallet computes it; the
	// vault does not interpret it.
	Digest [32]byte

	// Mode selects the signature algorithm.
	Mode SignMode

	// Tweak is an optional scalar pair applied to the selected key before
	// signing. Nil signs with the selected key itself. The vault reads it
	// but does not keep it; the caller owns and clears it.
	Tweak *KeyTweak

	// EffectiveKey is the optional public key that the tweaked key must
	// have. The vault checks it before it signs and returns
	// ErrEffectiveKeyMismatch when the keys differ.
	EffectiveKey *btcec.PublicKey
}

// validate checks the request fields that need no Store lookup.
func (r *SignDigestRequest) validate() error {
	err := r.Key.validate()
	if err != nil {
		return err
	}

	switch r.Mode {
	case SignModeECDSA, SignModeCompactECDSA, SignModeSchnorr:
	default:
		return fmt.Errorf("%w: %d", ErrInvalidSignMode, r.Mode)
	}

	if r.Tweak != nil && r.Tweak.mul.IsZero() {
		return fmt.Errorf("%w: zero multiplier", ErrInvalidKeyTweak)
	}

	return nil
}

// DigestSignature holds the signature of one SignDigest call. Exactly the
// field that matches the request mode is set.
type DigestSignature struct {
	// ECDSA is set for SignModeECDSA.
	ECDSA *ecdsa.Signature

	// Compact is set for SignModeCompactECDSA.
	Compact []byte

	// Schnorr is set for SignModeSchnorr.
	Schnorr *schnorr.Signature
}

// decryptPrivateSecret decrypts a stored private key secret. Tests replace it
// to observe the plaintext work buffer; production code must not change it.
var decryptPrivateSecret = func(key *snacl.CryptoKey,
	ciphertext []byte) ([]byte, error) {

	return key.Decrypt(ciphertext)
}

// privateKeyReadyHook runs under the guard once the effective key is ready.
// Tests set it to hold or fail an operation; it is nil in production.
var privateKeyReadyHook func()

// SignDigest signs a wallet-computed digest with the selected key. See
// SigningVault for the lock and cleanup contract.
func (v *WalletVault) SignDigest(ctx context.Context,
	req SignDigestRequest) (DigestSignature, error) {

	err := req.validate()
	if err != nil {
		return DigestSignature{}, fmt.Errorf("wallet %d vault "+
			"SignDigest: %w", v.walletID, err)
	}

	var sig DigestSignature

	err = v.useKey(
		ctx, req.Key, req.Tweak, req.EffectiveKey,
		func(key *btcec.PrivateKey) error {
			return signDigest(key, req.Mode, req.Digest[:], &sig)
		},
	)
	if err != nil {
		return DigestSignature{}, fmt.Errorf("wallet %d vault "+
			"SignDigest: %w", v.walletID, err)
	}

	return sig, nil
}

// signDigest writes the signature for mode into sig.
func signDigest(key *btcec.PrivateKey, mode SignMode, digest []byte,
	sig *DigestSignature) error {

	switch mode {
	case SignModeECDSA:
		sig.ECDSA = ecdsa.Sign(key, digest)

	case SignModeCompactECDSA:
		sig.Compact = ecdsa.SignCompact(key, digest, true)

	case SignModeSchnorr:
		schnorrSig, err := schnorr.Sign(key, digest)
		if err != nil {
			return fmt.Errorf("schnorr sign: %w", err)
		}

		sig.Schnorr = schnorrSig

	default:
		return fmt.Errorf("%w: %d", ErrInvalidSignMode, mode)
	}

	return nil
}

// ECDH returns SHA-256 of the compressed point key*remote. See SigningVault
// for the lock and cleanup contract.
func (v *WalletVault) ECDH(ctx context.Context, key KeySelector,
	remote *btcec.PublicKey) ([32]byte, error) {

	// A point that is not on the curve multiplies to a result that both
	// sides could agree on without a private key, so refuse it before any
	// lookup.
	if remote == nil || !remote.IsOnCurve() {
		return [32]byte{}, fmt.Errorf("wallet %d vault ECDH: %w",
			v.walletID, ErrInvalidRemoteKey)
	}

	err := key.validate()
	if err != nil {
		return [32]byte{}, fmt.Errorf("wallet %d vault ECDH: %w",
			v.walletID, err)
	}

	var digest [32]byte

	err = v.useKey(ctx, key, nil, nil, func(priv *btcec.PrivateKey) error {
		digest = hashedSharedPoint(priv, remote)

		return nil
	})
	if err != nil {
		return [32]byte{}, fmt.Errorf("wallet %d vault ECDH: %w",
			v.walletID, err)
	}

	return digest, nil
}

// hashedSharedPoint returns SHA-256 of the 33-byte compressed encoding of
// priv*remote. It clears the shared point and its encoding before it returns.
func hashedSharedPoint(priv *btcec.PrivateKey,
	remote *btcec.PublicKey) [32]byte {

	var remotePoint, shared btcec.JacobianPoint
	defer func() {
		shared.X.Zero()
		shared.Y.Zero()
		shared.Z.Zero()
	}()

	remote.AsJacobian(&remotePoint)
	btcec.ScalarMultNonConst(&priv.Key, &remotePoint, &shared)
	shared.ToAffine()

	// Encode the point like PublicKey.SerializeCompressed, without the
	// PublicKey copy that could not be cleared.
	var point [btcec.PubKeyBytesLenCompressed]byte
	defer clear(point[:])

	point[0] = secp256k1.PubKeyFormatCompressedEven |
		byte(shared.Y.IsOddBit())
	shared.X.PutBytesUnchecked(point[1:])

	return sha256.Sum256(point[:])
}

// useKey resolves the selected private key, applies tweak, checks the result
// against effective, and runs use with the result under the vault guard.
//
// The Store lookup runs before the guard is taken. use is vault code, not
// caller code: it must not keep the key, call the Store or call another vault
// method. Every secret is cleared before useKey returns or panics.
func (v *WalletVault) useKey(ctx context.Context, sel KeySelector,
	tweak *KeyTweak, effective *btcec.PublicKey,
	use func(*btcec.PrivateKey) error) error {

	encrypted, err := v.loadPrivateSecret(ctx, sel)

	// The vault owns the encrypted copy from the Store, so clear it on
	// every path.
	defer clear(encrypted)

	if err != nil {
		return err
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.unlockedState == nil {
		return ErrVaultLocked
	}

	cryptoKey, err := v.selectUnlockedCryptoKey(waddrmgr.CKTPrivate)
	if err != nil {
		return err
	}

	plaintext, err := decryptPrivateSecret(cryptoKey, encrypted)
	defer clear(plaintext)

	if err != nil {
		return fmt.Errorf("decrypt private key: %w", err)
	}

	key, err := parsePrivateSecret(sel, plaintext)
	if err != nil {
		return err
	}
	defer key.Zero()

	err = applyKeyTweak(key, tweak)
	if err != nil {
		return err
	}

	if effective != nil && !key.PubKey().IsEqual(effective) {
		return ErrEffectiveKeyMismatch
	}

	if privateKeyReadyHook != nil {
		privateKeyReadyHook()
	}

	return use(key)
}

// loadPrivateSecret reads the encrypted private material for sel from the
// Store. The caller owns and clears the returned ciphertext. It must be called
// without the vault guard.
func (v *WalletVault) loadPrivateSecret(ctx context.Context,
	sel KeySelector) ([]byte, error) {

	switch sel.kind {
	case keySelectorDerived:
		return v.loadAccountSecret(ctx, sel)

	case keySelectorImported:
		return v.loadImportedSecret(ctx, sel)

	case keySelectorNone:
		return nil, ErrInvalidKeySelector

	default:
		return nil, ErrInvalidKeySelector
	}
}

// loadAccountSecret reads the encrypted extended private key of the account
// that sel names.
func (v *WalletVault) loadAccountSecret(ctx context.Context,
	sel KeySelector) ([]byte, error) {

	secret, err := v.store.GetAccountSecret(ctx, db.GetAccountSecretQuery{
		WalletID:      v.walletID,
		Scope:         db.KeyScope(sel.scope),
		AccountNumber: sel.account,
	})

	switch {
	case errors.Is(err, db.ErrAccountSecretUnavailable),
		errors.Is(err, db.ErrAccountNotFound):

		return nil, ErrKeyNotFound

	case err != nil:
		return nil, fmt.Errorf("get account secret: %w", err)
	}

	if secret == nil || len(secret.EncryptedPrivateKey) == 0 {
		return nil, ErrNoPrivateKey
	}

	return secret.EncryptedPrivateKey, nil
}

// loadImportedSecret reads the encrypted raw private key stored for the
// script pubkey that sel names.
func (v *WalletVault) loadImportedSecret(ctx context.Context,
	sel KeySelector) ([]byte, error) {

	secret, err := v.store.GetAddressSecret(ctx, db.GetAddressSecretQuery{
		WalletID:     v.walletID,
		ScriptPubKey: sel.scriptPubKey,
	})

	switch {
	case errors.Is(err, db.ErrSecretNotFound),
		errors.Is(err, db.ErrAddressNotFound):

		return nil, ErrKeyNotFound

	case err != nil:
		return nil, fmt.Errorf("get address secret: %w", err)
	}

	if secret == nil {
		return nil, ErrNoPrivateKey
	}

	// Only the private key is used. Clear the script copy here, since the
	// caller clears just the returned ciphertext.
	clear(secret.EncryptedScript)

	if len(secret.EncryptedPrivKey) == 0 {
		return nil, ErrNoPrivateKey
	}

	return secret.EncryptedPrivKey, nil
}

// parsePrivateSecret turns decrypted private material into the selected
// private key. The caller owns the returned key and must zero it. Every
// intermediate key is zeroed before return.
func parsePrivateSecret(sel KeySelector,
	plaintext []byte) (*btcec.PrivateKey, error) {

	if sel.kind == keySelectorImported {
		if len(plaintext) != btcec.PrivKeyBytesLen {
			return nil, fmt.Errorf("imported private key has %d "+
				"bytes: %w", len(plaintext), errUnexpectedState)
		}

		key, _ := btcec.PrivKeyFromBytes(plaintext)
		if key.Key.IsZero() {
			return nil, fmt.Errorf("imported private key is zero: %w",
				errUnexpectedState)
		}

		return key, nil
	}

	// hdkeychain parses only strings. The string is not kept, and Go
	// cannot clear it; see ADR 0010 section 3.8.
	account, err := hdkeychain.NewKeyFromString(string(plaintext))
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w: %w",
			errUnexpectedState, err)
	}
	defer account.Zero()

	if !account.IsPrivate() {
		return nil, ErrNoPrivateKey
	}

	branch, err := deriveChild(account, sel.branch)
	if err != nil {
		return nil, fmt.Errorf("derive branch: %w", err)
	}
	defer branch.Zero()

	leaf, err := deriveChild(branch, sel.index)
	if err != nil {
		return nil, fmt.Errorf("derive index: %w", err)
	}
	defer leaf.Zero()

	key, err := leaf.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("derive private key: %w", err)
	}

	return key, nil
}

// deriveChild derives child i of parent. It keeps the non-standard
// derivation for keys affected by btcutil issue 172, as the wallet's address
// derivation does, so both sides derive the same key.
func deriveChild(parent *hdkeychain.ExtendedKey,
	i uint32) (*hdkeychain.ExtendedKey, error) {

	if parent.IsAffectedByIssue172() {
		//nolint:wrapcheck,staticcheck
		return parent.DeriveNonStandard(i)
	}

	return parent.Derive(i) //nolint:wrapcheck
}

// applyKeyTweak replaces key with tweak.mul*key + tweak.add. A nil tweak
// leaves key unchanged. A zero multiplier or a zero result returns
// ErrInvalidKeyTweak; key is then left for the caller to zero.
func applyKeyTweak(key *btcec.PrivateKey, tweak *KeyTweak) error {
	if tweak == nil {
		return nil
	}

	if tweak.mul.IsZero() {
		return fmt.Errorf("%w: zero multiplier", ErrInvalidKeyTweak)
	}

	key.Key.Mul(&tweak.mul).Add(&tweak.add)

	if key.Key.IsZero() {
		return fmt.Errorf("%w: zero effective key", ErrInvalidKeyTweak)
	}

	return nil
}
