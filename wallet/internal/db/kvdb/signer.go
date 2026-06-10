package kvdb

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// errAddrNotPubKey is returned when a managed address is not a public key
// address.
var errAddrNotPubKey = errors.New(
	"managed address is not a public key address",
)

// DeriveManagedAddress derives a legacy managed address from a scoped manager
// and key path inside a walletdb read transaction.
func DeriveManagedAddress(dbConn walletdb.DB,
	manager waddrmgr.AccountStore,
	path waddrmgr.DerivationPath) (waddrmgr.ManagedAddress, error) {

	var addr waddrmgr.ManagedAddress

	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		derivedAddr, err := manager.DeriveFromKeyPath(ns, path)
		if err != nil {
			return fmt.Errorf("cannot derive from key path: %w", err)
		}

		addr = derivedAddr

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cannot view wallet database: %w", err)
	}

	return addr, nil
}

// DeriveManagedAddress derives a legacy managed address from a scoped manager
// and key path inside a walletdb read transaction.
func (s *Store) DeriveManagedAddress(manager waddrmgr.AccountStore,
	path waddrmgr.DerivationPath) (waddrmgr.ManagedAddress, error) {

	return DeriveManagedAddress(s.db, manager, path)
}

// LoadManagedAddress loads a legacy managed address from the address manager
// inside a walletdb read transaction.
func LoadManagedAddress(dbConn walletdb.DB, addrStore waddrmgr.AddrStore,
	addr address.Address) (waddrmgr.ManagedAddress, error) {

	var managedAddr waddrmgr.ManagedAddress

	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		var err error

		managedAddr, err = addrStore.Address(ns, addr)
		if err != nil {
			return fmt.Errorf("fetch address: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("view signer address: %w", err)
	}

	return managedAddr, nil
}

// LoadManagedAddress loads a legacy managed address from the address manager
// inside a walletdb read transaction.
func (s *Store) LoadManagedAddress(addrStore waddrmgr.AddrStore,
	addr address.Address) (waddrmgr.ManagedAddress, error) {

	return LoadManagedAddress(s.db, addrStore, addr)
}

// ResolveDerivedPrivKey resolves one derived private key through the legacy
// database-backed derivation path after a cache miss.
func ResolveDerivedPrivKey(dbConn walletdb.DB,
	accountManager waddrmgr.AccountStore,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	var privKey *btcec.PrivateKey

	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		managedAddr, err := accountManager.DeriveFromKeyPath(ns, path)
		if err != nil {
			return fmt.Errorf("derive private key from db: %w", err)
		}

		pubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return fmt.Errorf("%w: %s", errAddrNotPubKey,
				managedAddr.Address())
		}

		privKey, err = pubKeyAddr.PrivKey()
		if err != nil {
			return fmt.Errorf("fetch derived private key: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("view signer derivation: %w", err)
	}

	return privKey, nil
}

// ResolveDerivedPrivKey resolves one derived private key through the legacy
// database-backed derivation path after a cache miss.
func (s *Store) ResolveDerivedPrivKey(
	accountManager waddrmgr.AccountStore,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	return ResolveDerivedPrivKey(s.db, accountManager, path)
}
