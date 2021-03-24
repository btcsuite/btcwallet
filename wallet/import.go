package wallet

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

const (
	// accountPubKeyDepth is the maximum depth of an extended key for an
	// account public key.
	accountPubKeyDepth = 3

	// pubKeyDepth is the depth of an extended key for a derived public key.
	pubKeyDepth = 5
)

// keyScopeFromPubKey returns the corresponding wallet key scope for the given
// extended public key. The address type can usually be inferred from the key's
// version, but may be required for certain keys to map them into the proper
// scope.
func keyScopeFromPubKey(pubKey *hdkeychain.ExtendedKey,
	addrType *waddrmgr.AddressType) (waddrmgr.KeyScope,
	*waddrmgr.ScopeAddrSchema, error) {

	switch waddrmgr.HDVersion(binary.BigEndian.Uint32(pubKey.Version())) {
	// For BIP-0044 keys, an address type must be specified as we intend to
	// not support importing BIP-0044 keys into the wallet using the legacy
	// pay-to-pubkey-hash (P2PKH) scheme. A nested witness address type will
	// force the standard BIP-0049 derivation scheme (nested witness pubkeys
	// everywhere), while a witness address type will force the standard
	// BIP-0084 derivation scheme.
	case waddrmgr.HDVersionMainNetBIP0044, waddrmgr.HDVersionTestNetBIP0044:
		if addrType == nil {
			return waddrmgr.KeyScope{}, nil, errors.New("address " +
				"type must be specified for account public " +
				"key with legacy version")
		}

		switch *addrType {
		case waddrmgr.NestedWitnessPubKey:
			return waddrmgr.KeyScopeBIP0049Plus,
				&waddrmgr.KeyScopeBIP0049AddrSchema, nil

		case waddrmgr.WitnessPubKey:
			return waddrmgr.KeyScopeBIP0084, nil, nil

		default:
			return waddrmgr.KeyScope{}, nil,
				fmt.Errorf("unsupported address type %v",
					*addrType)
		}

	// For BIP-0049 keys, we'll need to make a distinction between the
	// traditional BIP-0049 address schema (nested witness pubkeys
	// everywhere) and our own BIP-0049Plus address schema (nested
	// externally, witness internally).
	case waddrmgr.HDVersionMainNetBIP0049, waddrmgr.HDVersionTestNetBIP0049:
		if addrType == nil {
			return waddrmgr.KeyScope{}, nil, errors.New("address " +
				"type must be specified for account public " +
				"key with BIP-0049 version")
		}

		switch *addrType {
		case waddrmgr.NestedWitnessPubKey:
			return waddrmgr.KeyScopeBIP0049Plus,
				&waddrmgr.KeyScopeBIP0049AddrSchema, nil

		case waddrmgr.WitnessPubKey:
			return waddrmgr.KeyScopeBIP0049Plus, nil, nil

		default:
			return waddrmgr.KeyScope{}, nil,
				fmt.Errorf("unsupported address type %v",
					*addrType)
		}

	case waddrmgr.HDVersionMainNetBIP0084, waddrmgr.HDVersionTestNetBIP0084:
		if addrType != nil && *addrType != waddrmgr.WitnessPubKey {
			return waddrmgr.KeyScope{}, nil,
				errors.New("address type mismatch")
		}
		return waddrmgr.KeyScopeBIP0084, nil, nil

	default:
		return waddrmgr.KeyScope{}, nil, fmt.Errorf("unknown version %x",
			pubKey.Version())
	}
}

// isPubKeyForNet determines if the given public key is for the current network
// the wallet is operating under.
func (w *Wallet) isPubKeyForNet(pubKey *hdkeychain.ExtendedKey) bool {
	version := waddrmgr.HDVersion(binary.BigEndian.Uint32(pubKey.Version()))
	switch w.chainParams.Net {
	case wire.MainNet:
		return version == waddrmgr.HDVersionMainNetBIP0044 ||
			version == waddrmgr.HDVersionMainNetBIP0049 ||
			version == waddrmgr.HDVersionMainNetBIP0084

	case wire.TestNet, wire.TestNet3:
		return version == waddrmgr.HDVersionTestNetBIP0044 ||
			version == waddrmgr.HDVersionTestNetBIP0049 ||
			version == waddrmgr.HDVersionTestNetBIP0084

	default:
		return false
	}
}

// validateExtendedPubKey ensures a sane derived public key is provided.
func (w *Wallet) validateExtendedPubKey(pubKey *hdkeychain.ExtendedKey,
	isAccountKey bool) error {

	// Private keys are not allowed.
	if pubKey.IsPrivate() {
		return errors.New("private keys cannot be imported")
	}

	// The public key must have a version corresponding to the current
	// chain.
	if !w.isPubKeyForNet(pubKey) {
		return fmt.Errorf("expected extended public key for current "+
			"network %v", w.chainParams.Name)
	}

	// Verify the extended public key's depth and child index based on
	// whether it's an account key or not.
	if isAccountKey {
		if pubKey.Depth() != accountPubKeyDepth {
			return errors.New("invalid account key, must be of the " +
				"form m/purpose'/coin_type'/account'")
		}
		if pubKey.ChildIndex() < hdkeychain.HardenedKeyStart {
			return errors.New("invalid account key, must be hardened")
		}
	} else {
		if pubKey.Depth() != pubKeyDepth {
			return errors.New("invalid account key, must be of the " +
				"form m/purpose'/coin_type'/account'/change/" +
				"address_index")
		}
		if pubKey.ChildIndex() >= hdkeychain.HardenedKeyStart {
			return errors.New("invalid pulic key, must not be " +
				"hardened")
		}
	}

	return nil
}

// ImportAccount imports an account backed by an account extended public key.
// The master key fingerprint denotes the fingerprint of the root key
// corresponding to the account public key (also known as the key with
// derivation path m/). This may be required by some hardware wallets for proper
// identification and signing.
//
// The address type can usually be inferred from the key's version, but may be
// required for certain keys to map them into the proper scope.
//
// For BIP-0044 keys, an address type must be specified as we intend to not
// support importing BIP-0044 keys into the wallet using the legacy
// pay-to-pubkey-hash (P2PKH) scheme. A nested witness address type will force
// the standard BIP-0049 derivation scheme, while a witness address type will
// force the standard BIP-0084 derivation scheme.
//
// For BIP-0049 keys, an address type must also be specified to make a
// distinction between the traditional BIP-0049 address schema (nested witness
// pubkeys everywhere) and our own BIP-0049Plus address schema (nested
// externally, witness internally).
func (w *Wallet) ImportAccount(name string, accountPubKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType *waddrmgr.AddressType) (
	*waddrmgr.AccountProperties, error) {

	// Ensure we have a valid account public key.
	if err := w.validateExtendedPubKey(accountPubKey, true); err != nil {
		return nil, err
	}

	// Determine what key scope the account public key should belong to and
	// whether it should use a custom address schema.
	keyScope, addrSchema, err := keyScopeFromPubKey(accountPubKey, addrType)
	if err != nil {
		return nil, err
	}
	scopedMgr, err := w.Manager.FetchScopedKeyManager(keyScope)
	if err != nil {
		return nil, err
	}

	// Store the account as watch-only within the database.
	var accountProps *waddrmgr.AccountProperties
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		account, err := scopedMgr.NewAccountWatchingOnly(
			ns, name, accountPubKey, masterKeyFingerprint,
			addrSchema,
		)
		if err != nil {
			return err
		}
		accountProps, err = scopedMgr.AccountProperties(ns, account)
		return err
	})
	return accountProps, err
}

// ImportPublicKey imports a single derived public key into the address manager.
// The address type can usually be inferred from the key's version, but in the
// case of legacy versions (xpub, tpub), an address type must be specified as we
// intend to not support importing BIP-44 keys into the wallet using the legacy
// pay-to-pubkey-hash (P2PKH) scheme.
func (w *Wallet) ImportPublicKey(pubKey *btcec.PublicKey,
	addrType waddrmgr.AddressType) error {

	// Determine what key scope the public key should belong to and import
	// it into the key scope's default imported account.
	var keyScope waddrmgr.KeyScope
	switch addrType {
	case waddrmgr.NestedWitnessPubKey:
		keyScope = waddrmgr.KeyScopeBIP0049Plus
	case waddrmgr.WitnessPubKey:
		keyScope = waddrmgr.KeyScopeBIP0084
	default:
		return fmt.Errorf("address type %v is not supported", addrType)
	}

	scopedKeyManager, err := w.Manager.FetchScopedKeyManager(keyScope)
	if err != nil {
		return err
	}

	// TODO: Perform rescan if requested.
	var addr waddrmgr.ManagedAddress
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		addr, err = scopedKeyManager.ImportPublicKey(ns, pubKey, nil)
		return err
	})
	if err != nil {
		return err
	}

	log.Infof("Imported address %v", addr.Address())

	err = w.chainClient.NotifyReceived([]btcutil.Address{addr.Address()})
	if err != nil {
		return fmt.Errorf("unable to subscribe for address "+
			"notifications: %v", err)
	}

	return nil
}

// ImportPrivateKey imports a private key to the wallet and writes the new
// wallet to disk.
//
// NOTE: If a block stamp is not provided, then the wallet's birthday will be
// set to the genesis block of the corresponding chain.
func (w *Wallet) ImportPrivateKey(scope waddrmgr.KeyScope, wif *btcutil.WIF,
	bs *waddrmgr.BlockStamp, rescan bool) (string, error) {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return "", err
	}

	// The starting block for the key is the genesis block unless otherwise
	// specified.
	if bs == nil {
		bs = &waddrmgr.BlockStamp{
			Hash:      *w.chainParams.GenesisHash,
			Height:    0,
			Timestamp: w.chainParams.GenesisBlock.Header.Timestamp,
		}
	} else if bs.Timestamp.IsZero() {
		// Only update the new birthday time from default value if we
		// actually have timestamp info in the header.
		header, err := w.chainClient.GetBlockHeader(&bs.Hash)
		if err == nil {
			bs.Timestamp = header.Timestamp
		}
	}

	// Attempt to import private key into wallet.
	var addr btcutil.Address
	var props *waddrmgr.AccountProperties
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		maddr, err := manager.ImportPrivateKey(addrmgrNs, wif, bs)
		if err != nil {
			return err
		}
		addr = maddr.Address()
		props, err = manager.AccountProperties(
			addrmgrNs, waddrmgr.ImportedAddrAccount,
		)
		if err != nil {
			return err
		}

		// We'll only update our birthday with the new one if it is
		// before our current one. Otherwise, if we do, we can
		// potentially miss detecting relevant chain events that
		// occurred between them while rescanning.
		birthdayBlock, _, err := w.Manager.BirthdayBlock(addrmgrNs)
		if err != nil {
			return err
		}
		if bs.Height >= birthdayBlock.Height {
			return nil
		}

		err = w.Manager.SetBirthday(addrmgrNs, bs.Timestamp)
		if err != nil {
			return err
		}

		// To ensure this birthday block is correct, we'll mark it as
		// unverified to prompt a sanity check at the next restart to
		// ensure it is correct as it was provided by the caller.
		return w.Manager.SetBirthdayBlock(addrmgrNs, *bs, false)
	})
	if err != nil {
		return "", err
	}

	// Rescan blockchain for transactions with txout scripts paying to the
	// imported address.
	if rescan {
		job := &RescanJob{
			Addrs:      []btcutil.Address{addr},
			OutPoints:  nil,
			BlockStamp: *bs,
		}

		// Submit rescan job and log when the import has completed.
		// Do not block on finishing the rescan.  The rescan success
		// or failure is logged elsewhere, and the channel is not
		// required to be read, so discard the return value.
		_ = w.SubmitRescan(job)
	} else {
		err := w.chainClient.NotifyReceived([]btcutil.Address{addr})
		if err != nil {
			return "", fmt.Errorf("failed to subscribe for address ntfns for "+
				"address %s: %s", addr.EncodeAddress(), err)
		}
	}

	addrStr := addr.EncodeAddress()
	log.Infof("Imported payment address %s", addrStr)

	w.NtfnServer.notifyAccountProperties(props)

	// Return the payment address string of the imported private key.
	return addrStr, nil
}
