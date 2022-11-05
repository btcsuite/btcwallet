// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// ErrPubKeyMismatch is returned when address validation fails as the
	// derived public key doesn't match the key held within the address
	// struct.
	ErrPubKeyMismatch = fmt.Errorf("derived pubkey doesn't match original")

	// ErrAddrMismatch is returned when addr validation fails due to a
	// re-derived address not matching the address
	ErrAddrMismatch = fmt.Errorf("derived addr doesn't match original")

	// ErrInvalidSignature is returned when we go to generate a signature
	// to verify against the public key and that signature comes back as
	// invalid.
	ErrInvalidSignature = fmt.Errorf("private key sig doesn't validate " +
		"against pubkey")
)

// AddressType represents the various address types waddrmgr is currently able
// to generate, and maintain.
//
// NOTE: These MUST be stable as they're used for scope address schema
// recognition within the database.
type AddressType uint8

const (
	// PubKeyHash is a regular p2pkh address.
	PubKeyHash AddressType = iota

	// Script reprints a raw script address.
	Script

	// RawPubKey is just raw public key to be used within scripts, This
	// type indicates that a scoped manager with this address type
	// shouldn't be consulted during historical rescans.
	RawPubKey

	// NestedWitnessPubKey represents a p2wkh output nested within a p2sh
	// output. Using this address type, the wallet can receive funds from
	// other wallet's which don't yet recognize the new segwit standard
	// output types. Receiving funds to this address maintains the
	// scalability, and malleability fixes due to segwit in a backwards
	// compatible manner.
	NestedWitnessPubKey

	// WitnessPubKey represents a p2wkh (pay-to-witness-key-hash) address
	// type.
	WitnessPubKey

	// WitnessScript represents a p2wsh (pay-to-witness-script-hash) address
	// type.
	WitnessScript

	// TaprootPubKey represents a p2tr (pay-to-taproot) address type that
	// uses BIP-0086 (for the derivation path and for calculating the tap
	// root hash/tweak).
	TaprootPubKey

	// TaprootScript represents a p2tr (pay-to-taproot) address type that
	// commits to a script and not just a single key.
	TaprootScript
)

const (
	// witnessVersionV0 is the SegWit v0 witness version used for p2wpkh and
	// p2wsh outputs and addresses.
	witnessVersionV0 byte = 0x00

	// witnessVersionV1 is the SegWit v1 witness version used for p2tr
	// outputs and addresses.
	witnessVersionV1 byte = 0x01
)

// ManagedAddress is an interface that provides acces to information regarding
// an address managed by an address manager. Concrete implementations of this
// type may provide further fields to provide information specific to that type
// of address.
type ManagedAddress interface {
	// InternalAccount returns the internal account the address is
	// associated with.
	InternalAccount() uint32

	// Address returns a btcutil.Address for the backing address.
	Address() btcutil.Address

	// AddrHash returns the key or script hash related to the address
	AddrHash() []byte

	// Imported returns true if the backing address was imported instead
	// of being part of an address chain.
	Imported() bool

	// Internal returns true if the backing address was created for internal
	// use such as a change output of a transaction.
	Internal() bool

	// Compressed returns true if the backing address is compressed.
	Compressed() bool

	// Used returns true if the backing address has been used in a transaction.
	Used(ns walletdb.ReadBucket) bool

	// AddrType returns the address type of the managed address. This can
	// be used to quickly discern the address type without further
	// processing
	AddrType() AddressType
}

// ManagedPubKeyAddress extends ManagedAddress and additionally provides the
// public and private keys for pubkey-based addresses.
type ManagedPubKeyAddress interface {
	ManagedAddress

	// PubKey returns the public key associated with the address.
	PubKey() *btcec.PublicKey

	// ExportPubKey returns the public key associated with the address
	// serialized as a hex encoded string.
	ExportPubKey() string

	// PrivKey returns the private key for the address.  It can fail if the
	// address manager is watching-only or locked, or the address does not
	// have any keys.
	PrivKey() (*btcec.PrivateKey, error)

	// ExportPrivKey returns the private key associated with the address
	// serialized as Wallet Import Format (WIF).
	ExportPrivKey() (*btcutil.WIF, error)

	// DerivationInfo contains the information required to derive the key
	// that backs the address via traditional methods from the HD root. For
	// imported keys, the first value will be set to false to indicate that
	// we don't know exactly how the key was derived.
	DerivationInfo() (KeyScope, DerivationPath, bool)
}

// ValidatableManagedAddress is a type of managed pubkey address that can
// perform external validation to catch unintended mutations between the
// derivation process and the ultimate address being created. This may help to
// catch things like hardware issue, or cosmic ray bit flips.
type ValidatableManagedAddress interface {
	ManagedPubKeyAddress

	// Validate takes a random message and a private key and ensures that:
	//  1. The private key properly maps back to the target address.
	//
	//  2. The public key generated by the private key matches the public
	//  key of the address.
	//
	//  3. We're able to generate a valid ECDSA/Schnorr signature based on
	//  the passed private key validated against the internal public key.
	Validate(msg [32]byte, priv *btcec.PrivateKey) error
}

// ManagedScriptAddress extends ManagedAddress and represents a pay-to-script-hash
// style of bitcoin addresses.  It additionally provides information about the
// script.
type ManagedScriptAddress interface {
	ManagedAddress

	// Script returns the script associated with the address.
	Script() ([]byte, error)
}

// ManagedTaprootScriptAddress extends ManagedScriptAddress and represents a
// pay-to-taproot script address. It additionally provides information about the
// script.
type ManagedTaprootScriptAddress interface {
	ManagedScriptAddress

	// TaprootScript returns all the information needed to derive the script
	// tree root hash needed to arrive at the tweaked taproot key.
	TaprootScript() (*Tapscript, error)
}

// managedAddress represents a public key address.  It also may or may not have
// the private key associated with the public key.
type managedAddress struct {
	manager          *ScopedKeyManager
	derivationPath   DerivationPath
	address          btcutil.Address
	imported         bool
	internal         bool
	compressed       bool
	addrType         AddressType
	pubKey           *btcec.PublicKey
	privKeyEncrypted []byte // nil if part of watch-only account
	privKeyCT        []byte // non-nil if unlocked
	privKeyMutex     sync.Mutex
}

// Enforce managedAddress satisfies the ManagedPubKeyAddress interface.
var _ ManagedPubKeyAddress = (*managedAddress)(nil)

// unlock decrypts and stores a pointer to the associated private key.  It will
// fail if the key is invalid or the encrypted private key is not available.
// The returned clear text private key will always be a copy that may be safely
// used by the caller without worrying about it being zeroed during an address
// lock.
func (a *managedAddress) unlock(key EncryptorDecryptor) ([]byte, error) {
	// Protect concurrent access to clear text private key.
	a.privKeyMutex.Lock()
	defer a.privKeyMutex.Unlock()

	// If the address belongs to a watch-only account, the encrypted private
	// key won't be present, so we'll return an error.
	if len(a.privKeyEncrypted) == 0 {
		return nil, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	if len(a.privKeyCT) == 0 {
		privKey, err := key.Decrypt(a.privKeyEncrypted)
		if err != nil {
			str := fmt.Sprintf("failed to decrypt private key for "+
				"%s", a.address)
			return nil, managerError(ErrCrypto, str, err)
		}

		a.privKeyCT = privKey
	}

	privKeyCopy := make([]byte, len(a.privKeyCT))
	copy(privKeyCopy, a.privKeyCT)
	return privKeyCopy, nil
}

// lock zeroes the associated clear text private key.
func (a *managedAddress) lock() {
	// Zero and nil the clear text private key associated with this
	// address.
	a.privKeyMutex.Lock()
	zero.Bytes(a.privKeyCT)
	a.privKeyCT = nil
	a.privKeyMutex.Unlock()
}

// InternalAccount returns the internal account number the address is associated
// with.
//
// This is part of the ManagedAddress interface implementation.
func (a *managedAddress) InternalAccount() uint32 {
	return a.derivationPath.InternalAccount
}

// AddrType returns the address type of the managed address. This can be used
// to quickly discern the address type without further processing
//
// This is part of the ManagedAddress interface implementation.
func (a *managedAddress) AddrType() AddressType {
	return a.addrType
}

// Address returns the btcutil.Address which represents the managed address.
// This will be a pay-to-pubkey-hash address.
//
// This is part of the ManagedAddress interface implementation.
func (a *managedAddress) Address() btcutil.Address {
	return a.address
}

// AddrHash returns the public key hash for the address.
//
// This is part of the ManagedAddress interface implementation.
func (a *managedAddress) AddrHash() []byte {
	var hash []byte

	switch n := a.address.(type) {
	case *btcutil.AddressPubKeyHash:
		hash = n.Hash160()[:]
	case *btcutil.AddressScriptHash:
		hash = n.Hash160()[:]
	case *btcutil.AddressWitnessPubKeyHash:
		hash = n.Hash160()[:]
	case *btcutil.AddressTaproot:
		hash = n.WitnessProgram()
	}

	return hash
}

// Imported returns true if the address was imported instead of being part of an
// address chain.
//
// This is part of the ManagedAddress interface implementation.
func (a *managedAddress) Imported() bool {
	return a.imported
}

// Internal returns true if the address was created for internal use such as a
// change output of a transaction.
//
// This is part of the ManagedAddress interface implementation.
func (a *managedAddress) Internal() bool {
	return a.internal
}

// Compressed returns true if the address is compressed.
//
// This is part of the ManagedAddress interface implementation.
func (a *managedAddress) Compressed() bool {
	return a.compressed
}

// Used returns true if the address has been used in a transaction.
//
// This is part of the ManagedAddress interface implementation.
func (a *managedAddress) Used(ns walletdb.ReadBucket) bool {
	return a.manager.fetchUsed(ns, a.AddrHash())
}

// PubKey returns the public key associated with the address.
//
// This is part of the ManagedPubKeyAddress interface implementation.
func (a *managedAddress) PubKey() *btcec.PublicKey {
	return a.pubKey
}

// pubKeyBytes returns the serialized public key bytes for the managed address
// based on whether or not the managed address is marked as compressed.
func (a *managedAddress) pubKeyBytes() []byte {
	if a.addrType == TaprootPubKey {
		return schnorr.SerializePubKey(a.pubKey)
	}
	if a.compressed {
		return a.pubKey.SerializeCompressed()
	}
	return a.pubKey.SerializeUncompressed()
}

// ExportPubKey returns the public key associated with the address
// serialized as a hex encoded string.
//
// This is part of the ManagedPubKeyAddress interface implementation.
func (a *managedAddress) ExportPubKey() string {
	return hex.EncodeToString(a.pubKeyBytes())
}

// PrivKey returns the private key for the address.  It can fail if the address
// manager is watching-only or locked, or the address does not have any keys.
//
// This is part of the ManagedPubKeyAddress interface implementation.
func (a *managedAddress) PrivKey() (*btcec.PrivateKey, error) {
	// No private keys are available for a watching-only address manager.
	if a.manager.rootManager.WatchOnly() {
		return nil, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	a.manager.mtx.Lock()
	defer a.manager.mtx.Unlock()

	// Account manager must be unlocked to decrypt the private key.
	if a.manager.rootManager.IsLocked() {
		return nil, managerError(ErrLocked, errLocked, nil)
	}

	// Decrypt the key as needed.  Also, make sure it's a copy since the
	// private key stored in memory can be cleared at any time.  Otherwise
	// the returned private key could be invalidated from under the caller.
	privKeyCopy, err := a.unlock(a.manager.rootManager.cryptoKeyPriv)
	if err != nil {
		return nil, err
	}

	privKey, _ := btcec.PrivKeyFromBytes(privKeyCopy)
	zero.Bytes(privKeyCopy)
	return privKey, nil
}

// ExportPrivKey returns the private key associated with the address in Wallet
// Import Format (WIF).
//
// This is part of the ManagedPubKeyAddress interface implementation.
func (a *managedAddress) ExportPrivKey() (*btcutil.WIF, error) {
	pk, err := a.PrivKey()
	if err != nil {
		return nil, err
	}

	return btcutil.NewWIF(pk, a.manager.rootManager.chainParams, a.compressed)
}

// DerivationInfo contains the information required to derive the key that
// backs the address via traditional methods from the HD root. For imported
// keys, the first value will be set to false to indicate that we don't know
// exactly how the key was derived.
//
// This is part of the ManagedPubKeyAddress interface implementation.
func (a *managedAddress) DerivationInfo() (KeyScope, DerivationPath, bool) {
	var (
		scope KeyScope
		path  DerivationPath
	)

	// If this key is imported, then we can't return any information as we
	// don't know precisely how the key was derived.
	if a.imported {
		return scope, path, false
	}

	return a.manager.Scope(), a.derivationPath, true
}

// signature abstracts over a signature that can be verified given a message
// and public key.
type signature interface {
	// Verify returns true if the sig is valid, and false otherwise.
	Verify([]byte, *btcec.PublicKey) bool
}

// Validate takes a random message and a private key and ensures that:
//
//  1. The private key properly maps back to the target address.
//
//  2. The public key generated by the private key matches the public
//     key of the address.
//
//  3. We're able to generate a valid ECDSA/Schnorr signature based on
//     the passed private key validated against the internal public key.
//
// NOTE: This is part of the ValidatableManagedAddress interface .
func (a *managedAddress) Validate(msg [32]byte, priv *btcec.PrivateKey) error {
	// First, we'll obtain the mapping public key from the target private
	// key. This key should match up with the public key we store
	// internally.
	//
	// This can potentially catch an error in the original mapping of the
	// private key to a public key.
	basePubKey := priv.PubKey()
	if !a.pubKey.IsEqual(basePubKey) {
		return fmt.Errorf("%w: expected %x, got %x", ErrPubKeyMismatch,
			basePubKey.SerializeUncompressed(),
			a.pubKey.SerializeUncompressed())
	}

	// Next, we'll verify that if we take the base public key, and generate
	// an address of the corresponding type, that matches up w/ what we've
	// stored internally.
	//
	// This can potentially catch a hardware/software error when mapping
	// the public key to a Bitcoin address.
	addr, err := newManagedAddressWithoutPrivKey(
		a.manager, a.derivationPath, a.pubKey, a.compressed, a.addrType,
	)
	if err != nil {
		return fmt.Errorf("unable to re-create addr: %w", err)
	}
	if addr.address.String() != a.address.String() {
		return fmt.Errorf("%w: expected %v, got %v", ErrAddrMismatch,
			addr.address.String(), a.address.String())
	}

	// With the two above checks, we'll now execute our final sanity check:
	// make sure we can generate a signature that verifies under the target
	// public key.
	//
	// TODO(roasbeef): potentially run _all_ checks then see which one
	// fails?
	var sig signature

	addrPrivKey, _ := btcec.PrivKeyFromBytes(a.privKeyCT)

	switch a.addrType {
	// For the "legacy" addr types, we'll generate an ECDSA signature to
	// verify against.
	case NestedWitnessPubKey, PubKeyHash, WitnessPubKey:
		sig = ecdsa.Sign(addrPrivKey, msg[:])

	// For the newer taproot addr type, we'll generate a schnorr signature
	// to verify against.
	case TaprootPubKey:
		sig, err = schnorr.Sign(addrPrivKey, msg[:])
		if err != nil {
			return fmt.Errorf("unable to generate validate "+
				"schnorr sig: %w", err)
		}

	default:
		return fmt.Errorf("unable to validate addr, unknown type: %v",
			a.addrType)
	}

	if !sig.Verify(msg[:], basePubKey) {
		return ErrInvalidSignature
	}

	return nil
}

// newManagedAddressWithoutPrivKey returns a new managed address based on the
// passed account, public key, and whether or not the public key should be
// compressed.
func newManagedAddressWithoutPrivKey(m *ScopedKeyManager,
	derivationPath DerivationPath, pubKey *btcec.PublicKey, compressed bool,
	addrType AddressType) (*managedAddress, error) {

	// Create a pay-to-pubkey-hash address from the public key.
	var pubKeyHash []byte
	if compressed {
		pubKeyHash = btcutil.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = btcutil.Hash160(pubKey.SerializeUncompressed())
	}

	var address btcutil.Address
	var err error

	switch addrType {

	case NestedWitnessPubKey:
		// For this address type we'll generate an address which is
		// backwards compatible to Bitcoin nodes running 0.6.0 onwards, but
		// allows us to take advantage of segwit's scripting improvements,
		// and malleability fixes.

		// First, we'll generate a normal p2wkh address from the pubkey hash.
		witAddr, err := btcutil.NewAddressWitnessPubKeyHash(
			pubKeyHash, m.rootManager.chainParams,
		)
		if err != nil {
			return nil, err
		}

		// Next we'll generate the witness program which can be used as a
		// pkScript to pay to this generated address.
		witnessProgram, err := txscript.PayToAddrScript(witAddr)
		if err != nil {
			return nil, err
		}

		// Finally, we'll use the witness program itself as the pre-image
		// to a p2sh address. In order to spend, we first use the
		// witnessProgram as the sigScript, then present the proper
		// <sig, pubkey> pair as the witness.
		address, err = btcutil.NewAddressScriptHash(
			witnessProgram, m.rootManager.chainParams,
		)
		if err != nil {
			return nil, err
		}

	case PubKeyHash:
		address, err = btcutil.NewAddressPubKeyHash(
			pubKeyHash, m.rootManager.chainParams,
		)
		if err != nil {
			return nil, err
		}

	case WitnessPubKey:
		address, err = btcutil.NewAddressWitnessPubKeyHash(
			pubKeyHash, m.rootManager.chainParams,
		)
		if err != nil {
			return nil, err
		}

	case TaprootPubKey:
		tapKey := txscript.ComputeTaprootKeyNoScript(pubKey)
		address, err = btcutil.NewAddressTaproot(
			schnorr.SerializePubKey(tapKey), m.rootManager.chainParams,
		)
		if err != nil {
			return nil, err
		}
	}

	return &managedAddress{
		manager:          m,
		address:          address,
		derivationPath:   derivationPath,
		imported:         false,
		internal:         false,
		addrType:         addrType,
		compressed:       compressed,
		pubKey:           pubKey,
		privKeyEncrypted: nil,
		privKeyCT:        nil,
	}, nil
}

// newManagedAddress returns a new managed address based on the passed account,
// private key, and whether or not the public key is compressed.  The managed
// address will have access to the private and public keys.
func newManagedAddress(s *ScopedKeyManager, derivationPath DerivationPath,
	privKey *btcec.PrivateKey, compressed bool,
	addrType AddressType, acctInfo *accountInfo) (*managedAddress, error) {

	// Encrypt the private key.
	//
	// NOTE: The privKeyBytes here are set into the managed address which
	// are cleared when locked, so they aren't cleared here.
	privKeyBytes := privKey.Serialize()
	privKeyEncrypted, err := s.rootManager.cryptoKeyPriv.Encrypt(privKeyBytes)
	if err != nil {
		str := "failed to encrypt private key"
		return nil, managerError(ErrCrypto, str, err)
	}

	// Leverage the code to create a managed address without a private key
	// and then add the private key to it.
	ecPubKey := privKey.PubKey()
	managedAddr, err := newManagedAddressWithoutPrivKey(
		s, derivationPath, ecPubKey, compressed, addrType,
	)
	if err != nil {
		return nil, err
	}
	managedAddr.privKeyEncrypted = privKeyEncrypted
	managedAddr.privKeyCT = privKeyBytes

	// At this point, we've derived an address based on a private key which
	// was the output of a BIP 32 derivation. As a sanity check, we'll make
	// sure that we can properly generate a valid signature/witness for the
	// given address type.
	var msg [32]byte
	if _, err := rand.Read(msg[:]); err != nil {
		return nil, fmt.Errorf("unable to read random "+
			"challenge for addr validation: %w", err)
	}

	// We'll first validate things against the private key we got
	// from the original derivation.
	err = managedAddr.Validate(msg, privKey)
	if err != nil {
		return nil, fmt.Errorf("addr validation for addr=%v "+
			"failed: %w", managedAddr.address, err)
	}

	// If no account information was specified, then this is an
	// imported key, so we can't actually re-derive it to ensure
	// things match up. As a result, we'll exit early here.
	if acctInfo == nil || acctInfo.acctKeyPriv == nil {
		return managedAddr, nil
	}

	// As an additional layer of safety, we'll _re-derive_ this key
	// and then perform the same set of checks.
	rederivedKey, err := s.deriveKey(
		acctInfo, managedAddr.derivationPath.Branch,
		managedAddr.derivationPath.Index, true,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to re-derive "+
			"key: %w", err)
	}
	freshPrivKey, err := rederivedKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("unable to gen priv key: %w", err)
	}
	err = managedAddr.Validate(msg, freshPrivKey)
	if err != nil {
		return nil, fmt.Errorf("addr validation for addr=%v "+
			"failed after rederiving: %w",
			managedAddr.address, err)
	}

	return managedAddr, nil
}

// newManagedAddressFromExtKey returns a new managed address based on the passed
// account and extended key.  The managed address will have access to the
// private and public keys if the provided extended key is private, otherwise it
// will only have access to the public key.
func newManagedAddressFromExtKey(s *ScopedKeyManager,
	derivationPath DerivationPath, key *hdkeychain.ExtendedKey,
	addrType AddressType, acctInfo *accountInfo) (*managedAddress, error) {

	// Create a new managed address based on the public or private key
	// depending on whether the generated key is private.
	var managedAddr *managedAddress
	if key.IsPrivate() {
		privKey, err := key.ECPrivKey()
		if err != nil {
			return nil, err
		}

		// Ensure the temp private key big integer is cleared after
		// use.
		managedAddr, err = newManagedAddress(
			s, derivationPath, privKey, true, addrType, acctInfo,
		)
		if err != nil {
			return nil, err
		}
	} else {
		pubKey, err := key.ECPubKey()
		if err != nil {
			return nil, err
		}

		managedAddr, err = newManagedAddressWithoutPrivKey(
			s, derivationPath, pubKey, true,
			addrType,
		)
		if err != nil {
			return nil, err
		}
	}

	return managedAddr, nil
}

// clearTextScriptSetter is a non-exported interface to identify script types
// that allow their clear text script to be set.
type clearTextScriptSetter interface {
	// setClearText sets the unencrypted script on the struct after
	// unlocking/decrypting it.
	setClearTextScript([]byte)
}

// baseScriptAddress represents the common fields of a pay-to-script-hash and
// a pay-to-witness-script-hash address.
type baseScriptAddress struct {
	manager         *ScopedKeyManager
	account         uint32
	address         *btcutil.AddressScriptHash
	scriptEncrypted []byte
	scriptClearText []byte
	scriptMutex     sync.Mutex
}

var _ clearTextScriptSetter = (*baseScriptAddress)(nil)

// unlock decrypts and stores the associated script.  It will fail if the key is
// invalid or the encrypted script is not available.  The returned clear text
// script will always be a copy that may be safely used by the caller without
// worrying about it being zeroed during an address lock.
func (a *baseScriptAddress) unlock(key EncryptorDecryptor) ([]byte, error) {
	// Protect concurrent access to clear text script.
	a.scriptMutex.Lock()
	defer a.scriptMutex.Unlock()

	if len(a.scriptClearText) == 0 {
		script, err := key.Decrypt(a.scriptEncrypted)
		if err != nil {
			str := fmt.Sprintf("failed to decrypt script for %s",
				a.address)
			return nil, managerError(ErrCrypto, str, err)
		}

		a.scriptClearText = script
	}

	scriptCopy := make([]byte, len(a.scriptClearText))
	copy(scriptCopy, a.scriptClearText)
	return scriptCopy, nil
}

// lock zeroes the associated clear text script.
func (a *baseScriptAddress) lock() {
	// Zero and nil the clear text script associated with this address.
	a.scriptMutex.Lock()
	zero.Bytes(a.scriptClearText)
	a.scriptClearText = nil
	a.scriptMutex.Unlock()
}

// InternalAccount returns the account the address is associated with. This will
// always be the ImportedAddrAccount constant for script addresses.
//
// This is part of the ManagedAddress interface implementation.
func (a *baseScriptAddress) InternalAccount() uint32 {
	return a.account
}

// Imported always returns true since script addresses are always imported
// addresses and not part of any chain.
//
// This is part of the ManagedAddress interface implementation.
func (a *baseScriptAddress) Imported() bool {
	return true
}

// Internal always returns false since script addresses are always imported
// addresses and not part of any chain in order to be for internal use.
//
// This is part of the ManagedAddress interface implementation.
func (a *baseScriptAddress) Internal() bool {
	return false
}

// setClearText sets the unencrypted script on the struct after unlocking/
// decrypting it.
func (a *baseScriptAddress) setClearTextScript(script []byte) {
	a.scriptClearText = make([]byte, len(script))
	copy(a.scriptClearText, script)
}

// scriptAddress represents a pay-to-script-hash address.
type scriptAddress struct {
	baseScriptAddress
	address *btcutil.AddressScriptHash
}

// AddrType returns the address type of the managed address. This can be used
// to quickly discern the address type without further processing
//
// This is part of the ManagedAddress interface implementation.
func (a *scriptAddress) AddrType() AddressType {
	return Script
}

// Address returns the btcutil.Address which represents the managed address.
// This will be a pay-to-script-hash address.
//
// This is part of the ManagedAddress interface implementation.
func (a *scriptAddress) Address() btcutil.Address {
	return a.address
}

// AddrHash returns the script hash for the address.
//
// This is part of the ManagedAddress interface implementation.
func (a *scriptAddress) AddrHash() []byte {
	return a.address.Hash160()[:]
}

// Compressed returns false since script addresses are never compressed.
//
// This is part of the ManagedAddress interface implementation.
func (a *scriptAddress) Compressed() bool {
	return false
}

// Used returns true if the address has been used in a transaction.
//
// This is part of the ManagedAddress interface implementation.
func (a *scriptAddress) Used(ns walletdb.ReadBucket) bool {
	return a.manager.fetchUsed(ns, a.AddrHash())
}

// Script returns the script associated with the address.
//
// This is part of the ManagedAddress interface implementation.
func (a *scriptAddress) Script() ([]byte, error) {
	// No script is available for a watching-only address manager.
	if a.manager.rootManager.WatchOnly() {
		return nil, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	a.manager.mtx.Lock()
	defer a.manager.mtx.Unlock()

	// Account manager must be unlocked to decrypt the script.
	if a.manager.rootManager.IsLocked() {
		return nil, managerError(ErrLocked, errLocked, nil)
	}

	// Decrypt the script as needed.  Also, make sure it's a copy since the
	// script stored in memory can be cleared at any time.  Otherwise,
	// the returned script could be invalidated from under the caller.
	return a.unlock(a.manager.rootManager.cryptoKeyScript)
}

// Enforce scriptAddress satisfies the ManagedScriptAddress interface.
var _ ManagedScriptAddress = (*scriptAddress)(nil)

// newScriptAddress initializes and returns a new pay-to-script-hash address.
func newScriptAddress(m *ScopedKeyManager, account uint32, scriptHash,
	scriptEncrypted []byte) (*scriptAddress, error) {

	address, err := btcutil.NewAddressScriptHashFromHash(
		scriptHash, m.rootManager.chainParams,
	)
	if err != nil {
		return nil, err
	}

	return &scriptAddress{
		baseScriptAddress: baseScriptAddress{
			manager:         m,
			account:         account,
			scriptEncrypted: scriptEncrypted,
		},
		address: address,
	}, nil
}

// witnessScriptAddress represents a pay-to-witness-script-hash address.
type witnessScriptAddress struct {
	baseScriptAddress
	address btcutil.Address

	// witnessVersion is the version of the witness script.
	witnessVersion byte

	// isSecretScript denotes whether the script is considered to be "secret"
	// and encrypted with the script encryption key or "public" and
	// therefore only encrypted with the public encryption key.
	isSecretScript bool
}

// AddrType returns the address type of the managed address. This can be used
// to quickly discern the address type without further processing
//
// This is part of the ManagedAddress interface implementation.
func (a *witnessScriptAddress) AddrType() AddressType {
	return WitnessScript
}

// Address returns the btcutil.Address which represents the managed address.
// This will be a pay-to-witness-script-hash address.
//
// This is part of the ManagedAddress interface implementation.
func (a *witnessScriptAddress) Address() btcutil.Address {
	return a.address
}

// AddrHash returns the script hash for the address.
//
// This is part of the ManagedAddress interface implementation.
func (a *witnessScriptAddress) AddrHash() []byte {
	return a.address.ScriptAddress()
}

// Compressed returns true since witness script addresses are always compressed.
//
// This is part of the ManagedAddress interface implementation.
func (a *witnessScriptAddress) Compressed() bool {
	return true
}

// Used returns true if the address has been used in a transaction.
//
// This is part of the ManagedAddress interface implementation.
func (a *witnessScriptAddress) Used(ns walletdb.ReadBucket) bool {
	return a.manager.fetchUsed(ns, a.AddrHash())
}

// Script returns the script associated with the address.
//
// This is part of the ManagedAddress interface implementation.
func (a *witnessScriptAddress) Script() ([]byte, error) {
	// No script is available for a watching-only address manager.
	if a.isSecretScript && a.manager.rootManager.WatchOnly() {
		return nil, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	a.manager.mtx.Lock()
	defer a.manager.mtx.Unlock()

	// Account manager must be unlocked to decrypt the script.
	if a.isSecretScript && a.manager.rootManager.IsLocked() {
		return nil, managerError(ErrLocked, errLocked, nil)
	}

	cryptoKey := a.manager.rootManager.cryptoKeyScript
	if !a.isSecretScript {
		cryptoKey = a.manager.rootManager.cryptoKeyPub
	}

	// Decrypt the script as needed. Also, make sure it's a copy since the
	// script stored in memory can be cleared at any time. Otherwise,
	// the returned script could be invalidated from under the caller.
	return a.unlock(cryptoKey)
}

// Enforce witnessScriptAddress satisfies the ManagedScriptAddress interface.
var _ ManagedScriptAddress = (*witnessScriptAddress)(nil)

// newWitnessScriptAddress initializes and returns a new
// pay-to-witness-script-hash address.
func newWitnessScriptAddress(m *ScopedKeyManager, account uint32, scriptIdent,
	scriptEncrypted []byte, witnessVersion byte,
	isSecretScript bool) (ManagedScriptAddress, error) {

	switch witnessVersion {
	case witnessVersionV0:
		address, err := btcutil.NewAddressWitnessScriptHash(
			scriptIdent, m.rootManager.chainParams,
		)
		if err != nil {
			return nil, err
		}

		return &witnessScriptAddress{
			baseScriptAddress: baseScriptAddress{
				manager:         m,
				account:         account,
				scriptEncrypted: scriptEncrypted,
			},
			address:        address,
			witnessVersion: witnessVersion,
			isSecretScript: isSecretScript,
		}, nil

	case witnessVersionV1:
		address, err := btcutil.NewAddressTaproot(
			scriptIdent, m.rootManager.chainParams,
		)
		if err != nil {
			return nil, err
		}

		// Lift the x-only coordinate of the tweaked public key.
		tweakedPubKey, err := schnorr.ParsePubKey(scriptIdent)
		if err != nil {
			return nil, fmt.Errorf("error lifting public key from "+
				"script ident: %v", err)
		}

		return &taprootScriptAddress{
			witnessScriptAddress: witnessScriptAddress{
				baseScriptAddress: baseScriptAddress{
					manager:         m,
					account:         account,
					scriptEncrypted: scriptEncrypted,
				},
				address:        address,
				witnessVersion: witnessVersion,
				isSecretScript: isSecretScript,
			},
			TweakedPubKey: tweakedPubKey,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported witness version %d",
			witnessVersion)
	}
}

// taprootScriptAddress represents a pay-to-taproot address that commits to a
// script.
type taprootScriptAddress struct {
	witnessScriptAddress

	TweakedPubKey *btcec.PublicKey
}

// Enforce taprootScriptAddress satisfies the ManagedTaprootScriptAddress
// interface.
var _ ManagedTaprootScriptAddress = (*taprootScriptAddress)(nil)

// AddrType returns the address type of the managed address. This can be used
// to quickly discern the address type without further processing
//
// This is part of the ManagedAddress interface implementation.
func (a *taprootScriptAddress) AddrType() AddressType {
	return TaprootScript
}

// Address returns the btcutil.Address which represents the managed address.
// This will be a pay-to-taproot address.
//
// This is part of the ManagedAddress interface implementation.
func (a *taprootScriptAddress) Address() btcutil.Address {
	return a.address
}

// AddrHash returns the script hash for the address.
//
// This is part of the ManagedAddress interface implementation.
func (a *taprootScriptAddress) AddrHash() []byte {
	return schnorr.SerializePubKey(a.TweakedPubKey)
}

// TaprootScript returns all the information needed to derive the script tree
// root hash needed to arrive at the tweaked taproot key.
func (a *taprootScriptAddress) TaprootScript() (*Tapscript, error) {
	// Need to decrypt our internal script first. We need to be unlocked for
	// this.
	script, err := a.Script()
	if err != nil {
		return nil, err
	}

	// Decode the additional TLV encoded data.
	return tlvDecodeTaprootTaprootScript(script)
}
