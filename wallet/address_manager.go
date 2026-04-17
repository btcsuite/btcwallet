// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet provides the AddressManager interface for generating and
// inspecting wallet addresses and scripts.
//
//nolint:wrapcheck
package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// ErrDerivationPathNotFound is returned when the derivation path for a
	// given script cannot be found. This may be because the script does
	// not belong to the wallet, is imported, or is not a pubkey-based
	// script.
	ErrDerivationPathNotFound = errors.New("derivation path not found")

	// ErrUnknownAddrType is an error returned when a wallet function is
	// called with an unknown address type.
	ErrUnknownAddrType = errors.New("unknown address type")

	// ErrImportedAccountNoAddrGen is an error returned when a new address
	// is requested for the default imported account within the wallet.
	ErrImportedAccountNoAddrGen = errors.New("addresses cannot be " +
		"generated for the default imported account")

	// ErrNotPubKeyAddress is an error returned when a function requires a
	// public key address, but a different type of address is provided.
	ErrNotPubKeyAddress = errors.New(
		"address is not a p2wkh or np2wkh address",
	)

	// ErrUnableToExtractAddress is returned when an address cannot be
	// extracted from a pkscript.
	ErrUnableToExtractAddress = errors.New("unable to extract address")

	// errStopIteration is a special error used to stop the iteration in
	// ForEachAccountAddress.
	errStopIteration = errors.New("stop iteration")
)

// AddressProperty represents an address and its balance.
type AddressProperty struct {
	// Address is the address.
	Address address.Address

	// Balance is the total unspent balance of the address, including both
	// confirmed and unconfirmed funds.
	Balance btcutil.Amount
}

// AddressInfo describes wallet-owned metadata about one managed address.
type AddressInfo struct {
	// Addr is the bitcoin address itself.
	Addr address.Address

	// AddrType identifies the wallet-managed address type for this concrete
	// address.
	AddrType waddrmgr.AddressType

	// Imported reports whether the address was imported instead of derived
	// from a wallet scope.
	Imported bool

	// Internal reports whether the address belongs to the wallet's internal
	// branch.
	Internal bool

	// Compressed reports whether the underlying pubkey address uses
	// compressed keys.
	Compressed bool

	// PubKey is set for managed pubkey addresses.
	PubKey *btcec.PublicKey

	// Derivation is set when the wallet knows how to derive the address from a
	// wallet scope.
	Derivation *AddressDerivation
}

// AddressDerivation captures the wallet derivation metadata for one address.
type AddressDerivation struct {
	// KeyScope identifies the scope that owns the address.
	KeyScope waddrmgr.KeyScope

	// Account is the BIP-32 account within the scope.
	Account uint32

	// Branch is the BIP-32 branch within the scope.
	Branch uint32

	// Index is the child index within the branch.
	Index uint32

	// MasterKeyFingerprint is the root fingerprint used by
	// hardware-wallet-aware flows.
	MasterKeyFingerprint uint32
}

// OutputScriptInfo captures the address metadata and scripts needed to spend a
// wallet-controlled output.
type OutputScriptInfo struct {
	AddressInfo

	// WitnessProgram is the script passed as the witness subscript for witness
	// signing. For native P2WPKH and P2TR spends, this is the output pkScript
	// itself. For nested P2WPKH-in-P2SH spends, this is the inner witness
	// program, for example `OP_0 <20-byte-key-hash>`.
	WitnessProgram []byte

	// RedeemScript is the redeem script committed to by the outer P2SH output.
	// For nested P2WPKH-in-P2SH spends, this is the inner witness program, for
	// example `OP_0 <20-byte-key-hash>`. Native witness spends, such as P2WPKH
	// and P2TR, leave this nil. The final scriptSig wrapper for nested witness
	// spends can be rebuilt from this script when assembling the input.
	RedeemScript []byte
}

// AddressManager provides an interface for generating and inspecting wallet
// addresses and scripts.
type AddressManager interface {
	// NewAddress returns a new address for the given account and address
	// type.
	//
	// NOTE: This method should be used with caution. Unlike
	// GetUnusedAddress, it does not scan for previously derived but unused
	// addresses. Using this method repeatedly can create gaps in the
	// address chain, which may negatively impact wallet recovery under
	// BIP44. It is primarily intended for advanced use cases such as bulk
	// address generation.
	NewAddress(ctx context.Context, accountName string,
		addrType waddrmgr.AddressType,
		change bool) (address.Address, error)

	// GetUnusedAddress returns the first, oldest, unused address by
	// scanning forward from the start of the derivation path. This method
	// is the recommended default for obtaining a new receiving address, as
	// it prevents address reuse and avoids creating gaps in the address
	// chain that could impact wallet recovery.
	GetUnusedAddress(ctx context.Context, accountName string,
		addrType waddrmgr.AddressType, change bool) (
		address.Address, error)

	// GetAddressInfo returns detailed information about a managed address. If
	// the address is not known to the wallet, an error is returned.
	GetAddressInfo(ctx context.Context, a address.Address) (AddressInfo, error)

	// ListAddresses lists all addresses for a given account, including
	// their balances.
	ListAddresses(ctx context.Context, accountName string,
		addrType waddrmgr.AddressType) ([]AddressProperty, error)

	// ImportPublicKey imports a single public key as a watch-only address.
	ImportPublicKey(ctx context.Context, pubKey *btcec.PublicKey,
		addrType waddrmgr.AddressType) error

	// ImportTaprootScript imports a taproot script for tracking and
	// spending.
	ImportTaprootScript(ctx context.Context,
		tapscript waddrmgr.Tapscript) (AddressInfo, error)

	// ScriptForOutput returns the wallet metadata and spending scripts for a
	// given UTXO.
	ScriptForOutput(ctx context.Context, output wire.TxOut) (
		OutputScriptInfo, error)

	// GetDerivationInfo returns the BIP-32 derivation path for a given
	// address.
	GetDerivationInfo(ctx context.Context,
		addr address.Address) (*psbt.Bip32Derivation, error)
}

// A compile time check to ensure that Wallet implements the interface.
var _ AddressManager = (*Wallet)(nil)

// addressInfoFromManagedAddress converts one legacy managed address into the
// wallet-owned metadata shape used by the prep work.
func addressInfoFromManagedAddress(
	managedAddr waddrmgr.ManagedAddress) (AddressInfo, error) {

	info := AddressInfo{
		Addr:       managedAddr.Address(),
		AddrType:   managedAddr.AddrType(),
		Imported:   managedAddr.Imported(),
		Internal:   managedAddr.Internal(),
		Compressed: managedAddr.Compressed(),
	}

	pubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return info, nil
	}

	info.PubKey = pubKeyAddr.PubKey()

	keyScope, derivationPath, ok := pubKeyAddr.DerivationInfo()
	if !ok {
		return info, nil
	}

	info.Derivation = &AddressDerivation{
		KeyScope:             keyScope,
		Account:              derivationPath.Account,
		Branch:               derivationPath.Branch,
		Index:                derivationPath.Index,
		MasterKeyFingerprint: derivationPath.MasterKeyFingerprint,
	}

	return info, nil
}

// NewAddress returns a new address for the given account and address type.
// This method is a low-level primitive that will always derive a new, unused
// address from the end of the address chain.
//
// It returns the next external or internal address for the wallet dictated by
// the value of the `change` parameter. If change is true, then an internal
// address will be returned, otherwise an external address should be returned.
// The account parameter is the name of the account from which the address
// should be generated. The addrType parameter specifies the type of address to
// be generated.
//
// NOTE: This method should be used with caution. Unlike GetUnusedAddress, it
// does not scan for previously derived but unused addresses. Using this method
// repeatedly can create gaps in the address chain. If a gap of 20 consecutive
// unused addresses is created, wallet recovery from seed may fail under BIP44.
// It is primarily intended for advanced use cases such as bulk address
// generation. For most applications, GetUnusedAddress is the recommended
// method for obtaining a receiving address.
//
// TODO(yy): The current implementation of NewAddress has several architectural
// issues that should be addressed:
//
//  1. **Lack of Separation of Concerns:** The method tightly couples the
//     database logic with the address generation and chain backend
//     notification logic. The `waddrmgr` package currently handles both
//     derivation and persistence within a single database transaction, which
//     makes the transaction larger and longer than necessary.
//
// 2. **Incorrect Ordering of Operations:** The current flow is:
//  1. Create DB transaction.
//  2. Derive address.
//  3. Save address to DB.
//  4. Commit DB transaction.
//  5. Notify the chain backend to watch the new address.
//     This creates a potential race condition. If the program crashes after
//     committing the address to the database but before successfully
//     notifying the chain backend, the wallet will own an address that the
//     backend is not aware of. This could lead to a permanent loss of funds
//     if coins are sent to that address.
//
// Refactoring Plan:
//   - **Decouple `waddrmgr`:** The `waddrmgr` package should be refactored to
//     separate its concerns. It should provide:
//   - A pure, stateless function to derive an address from account info.
//   - A simple method to persist a newly derived address to the database.
//   - **Improve Operation Ordering in `wallet`:** The `NewAddress` method in
//     the `wallet` package should be updated to follow a more robust
//     sequence:
//     1. Start a DB transaction to read the required account information.
//     2. Use the pure derivation function from `waddrmgr` to generate the
//     new address *outside* of any DB transaction.
//     3. Notify the chain backend to watch the new address.
//     4. If the notification is successful, start a *second*, short-lived DB
//     transaction to persist the new address.
//     This ensures that we only save an address after we are confident that
//     it is being watched by the backend, preventing fund loss.
func (w *Wallet) NewAddress(_ context.Context, accountName string,
	addrType waddrmgr.AddressType, change bool) (address.Address, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	// Addresses cannot be derived from the catch-all imported accounts.
	if accountName == waddrmgr.ImportedAddrAccountName {
		return nil, ErrImportedAccountNoAddrGen
	}

	keyScope, err := addrType.KeyScope()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownAddrType, addrType)
	}

	manager, err := w.addrStore.FetchScopedKeyManager(keyScope)
	if err != nil {
		return nil, err
	}

	addr, err := w.newAddress(manager, accountName, change)
	if err != nil {
		return nil, err
	}

	// Notify the rpc server about the newly created address.
	err = w.cfg.Chain.NotifyReceived([]address.Address{addr})
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// newAddress returns the next external chained address for a wallet. It
// wraps the database transaction and the call to the scoped key manager's
// NewAddress method. The underlying address manager handles its own
// synchronization to ensure that in-memory state remains consistent with the
// database, preventing race conditions during address creation.
func (w *Wallet) newAddress(manager waddrmgr.AccountStore,
	accountName string, change bool) (address.Address, error) {

	var (
		addr address.Address
		err  error
	)

	err = walletdb.Update(w.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		addr, err = manager.NewAddress(addrmgrNs, accountName, change)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// GetUnusedAddress returns the first, oldest, unused address by scanning
// forward from the start of the derivation path. The address is considered
// "unused" if it has never appeared in a transaction. This method is the
// recommended default for obtaining a new receiving address. It prevents
// address reuse and avoids creating gaps in the address chain, which is
// critical for reliable wallet recovery under standards like BIP44 that
// enforce a gap limit of 20 unused addresses. If all previously derived
// addresses have been used, this method will delegate to NewAddress to
// generate a new one.
//
// TODO(yy): The current implementation of GetUnusedAddress is inefficient for
// wallets with a large number of used addresses. It iterates from the first
// address (index 0) forward until it finds an unused one, resulting in an O(n)
// complexity where n is the number of used addresses.
//
// A potential optimization of scanning backwards from the last derived address
// is UNSAFE. While faster in the common case, it can create gaps in the
// address chain. For example, if addresses [0, 1, 3] are used but [2] is not,
// a backward scan would return a new address after 3, leaving 2 as a gap.
// This violates the BIP44 gap limit (typically 20) and can lead to fund loss
// upon wallet recovery from seed, as the recovery process would stop scanning
// at the gap.
//
// The correct optimization is to persist a "first unused address pointer"
// (e.g., `firstUnusedExternalIndex`) for each account in the database.
//
// This would change the logic to:
//  1. `GetUnusedAddress`: Becomes an O(1) lookup. It reads the index from the
//     database and derives the address at that index.
//  2. `MarkUsed`: When an address is marked as used, if its index matches the
//     stored pointer, a one-time forward scan is performed to find the next
//     unused address, and the pointer is updated in the database.
//
// This moves the expensive scan from the frequent "read" operation to the less
// frequent "write" operation, providing both performance and safety.
func (w *Wallet) GetUnusedAddress(ctx context.Context, accountName string,
	addrType waddrmgr.AddressType, change bool) (address.Address, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	if accountName == waddrmgr.ImportedAddrAccountName {
		return nil, ErrImportedAccountNoAddrGen
	}

	keyScope, err := addrType.KeyScope()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownAddrType, addrType)
	}

	manager, err := w.addrStore.FetchScopedKeyManager(keyScope)
	if err != nil {
		return nil, err
	}

	unusedAddr, err := w.findUnusedAddress(manager, accountName, change)
	// We'll ignore the special error that we use to stop the iteration.
	if err != nil && !errors.Is(err, errStopIteration) {
		return nil, err
	}

	// If we found an unused address, we can return it now.
	if unusedAddr != nil {
		return unusedAddr, nil
	}

	// Otherwise, we'll generate a new one.
	return w.NewAddress(ctx, accountName, addrType, change)
}

// findUnusedAddress scans for an unused address for the given account.
func (w *Wallet) findUnusedAddress(manager waddrmgr.AccountStore,
	accountName string, change bool) (address.Address, error) {

	var unusedAddr address.Address

	err := walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		// First, look up the account number for the passed account
		// name.
		acctNum, err := manager.LookupAccount(addrmgrNs, accountName)
		if err != nil {
			return err
		}

		// Now, iterate through all addresses for the account and
		// return the first one that is unused.
		return manager.ForEachAccountAddress(
			addrmgrNs, acctNum,
			func(maddr waddrmgr.ManagedAddress) error {
				// We only want to consider addresses that match
				// the change parameter.
				if maddr.Internal() != change {
					return nil
				}

				if !maddr.Used(addrmgrNs) {
					unusedAddr = maddr.Address()

					// Return a special error to signal
					// that the iteration should be
					// stopped. This is the idiomatic way
					// to halt a ForEach* loop in this
					// codebase.
					return errStopIteration
				}

				return nil
			},
		)
	})

	return unusedAddr, err
}

// GetAddressInfo returns detailed information regarding a wallet address.
//
// This method provides metadata about a managed address, such as its type,
// derivation path, and whether it's internal or compressed.
//
// How it works:
// The method performs a direct lookup in the address manager to find the
// requested address.
//
// Logical Steps:
//  1. Initiate a read-only database transaction.
//  2. Call the underlying address manager's `Address` method to look up the
//     address.
//  3. Return the managed address information.
//
// Database Actions:
//   - This method performs a single read-only database transaction
//     (`walletdb.View`).
//   - It reads from the `waddrmgr` namespace to find the address.
//
// Time Complexity:
//   - The operation is a direct database lookup, making its complexity roughly
//     O(1) or O(log N) depending on the database backend's indexing strategy
//     for addresses. It is a very fast operation.
func (w *Wallet) GetAddressInfo(_ context.Context, a address.Address) (
	AddressInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return AddressInfo{}, err
	}

	var managedAddress waddrmgr.ManagedAddress

	err = walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		managedAddress, err = w.addrStore.Address(addrmgrNs, a)

		return err
	})
	if err != nil {
		return AddressInfo{}, err
	}

	return addressInfoFromManagedAddress(managedAddress)
}

// ListAddresses lists all addresses for a given account, including their
// balances.
//
// This method provides a comprehensive view of all addresses within a
// specific account, along with their current confirmed balances.
//
// How it works:
// The method first calculates the balances of all UTXOs in the wallet and
// stores them in a map. It then iterates through all addresses of the
// specified account and looks up their balance in the map.
//
// Logical Steps:
//  1. Initiate a read-only database transaction.
//  2. Create a map to store address balances.
//  3. Iterate through all unspent transaction outputs (UTXOs) in the
//     wallet's `wtxmgr` namespace.
//  4. For each UTXO, extract the address and add the output's value to the
//     address's balance in the map.
//  5. Fetch the scoped key manager for the given address type.
//  6. Look up the account number for the given account name.
//  7. Iterate through all addresses in that account.
//  8. For each address, create an `AddressProperty` with the address and its
//     balance from the map.
//  9. Return the list of `AddressProperty` objects.
//
// Database Actions:
//   - This method performs a single read-only database transaction
//     (`walletdb.View`).
//   - It reads from both the `wtxmgr` and `waddrmgr` namespaces.
//
// Time Complexity:
//   - The complexity is O(U + A), where U is the number of unspent
//     transaction outputs in the wallet and A is the number of addresses in
//     the specified account. This is because it iterates through all UTXOs to
//     build the balance map and then iterates through all account addresses.
func (w *Wallet) ListAddresses(_ context.Context, accountName string,
	addrType waddrmgr.AddressType) ([]AddressProperty, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	var properties []AddressProperty

	err = walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// First, we'll create a map of address to balance by iterating
		// through all the unspent outputs.
		addrToBalance := make(map[string]btcutil.Amount)

		utxos, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}

		for _, utxo := range utxos {
			addr := extractAddrFromPKScript(
				utxo.PkScript, w.cfg.ChainParams,
			)
			if addr == nil {
				continue
			}

			addrToBalance[addr.String()] += utxo.Amount
		}

		keyScope, err := addrType.KeyScope()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrUnknownAddrType, addrType)
		}

		manager, err := w.addrStore.FetchScopedKeyManager(keyScope)
		if err != nil {
			return err
		}

		acctNum, err := manager.LookupAccount(addrmgrNs, accountName)
		if err != nil {
			return err
		}

		return manager.ForEachAccountAddress(addrmgrNs, acctNum,
			func(maddr waddrmgr.ManagedAddress) error {
				addr := maddr.Address()
				properties = append(properties, AddressProperty{
					Address: addr,
					Balance: addrToBalance[addr.String()],
				})

				return nil
			})
	})
	if err != nil {
		return nil, err
	}

	return properties, nil
}

// ImportPublicKey imports a single public key as a watch-only address.
//
// This method allows the wallet to track transactions related to a specific
// public key without having access to the corresponding private key. This is
// useful for monitoring addresses without compromising their security.
//
// How it works:
// The method determines the appropriate key scope based on the provided
// address type and then uses the corresponding scoped key manager to import
// the public key.
//
// Logical Steps:
//  1. Determine the key scope from the address type (e.g., P2WKH, NP2WKH).
//  2. Fetch the scoped key manager for that scope.
//  3. Initiate a database transaction.
//  4. Within the transaction, call the underlying address manager's
//     ImportPublicKey method to store the key.
//  5. Commit the transaction.
//
// Database Actions:
//   - This method performs a single database write transaction
//     (`walletdb.Update`).
//   - It stores the public key and its associated address information within
//     the `waddrmgr` namespace.
//
// Time Complexity:
//   - The operation is dominated by the database write, making its complexity
//     roughly O(1) or O(log N) depending on the database backend's indexing
//     strategy for keys. It is generally a fast operation.
func (w *Wallet) ImportPublicKey(_ context.Context, pubKey *btcec.PublicKey,
	addrType waddrmgr.AddressType) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	keyScope, err := addrType.KeyScope()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknownAddrType, addrType)
	}

	manager, err := w.addrStore.FetchScopedKeyManager(keyScope)
	if err != nil {
		return err
	}

	var addr address.Address

	err = walletdb.Update(w.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		ma, err := manager.ImportPublicKey(addrmgrNs, pubKey, nil)
		if err != nil {
			return err
		}

		addr = ma.Address()

		return nil
	})
	if err != nil {
		return err
	}

	return w.cfg.Chain.NotifyReceived([]address.Address{addr})
}

// ImportTaprootScript imports a taproot script for tracking and spending.
//
// This method allows the wallet to import a taproot script, which is
// necessary for spending from or tracking a taproot address.
//
// How it works:
// The method uses the BIP-0086 key scope to fetch the taproot-specific
// scoped key manager. It then calls the underlying manager's
// ImportTaprootScript method to store the script information.
//
// Logical Steps:
//  1. Fetch the scoped key manager for the taproot key scope (BIP-0086).
//  2. Initiate a database transaction.
//  3. Within the transaction, get the wallet's current sync state to use as
//     the "birthday" for the new script.
//  4. Call the underlying address manager's ImportTaprootScript method.
//  5. Commit the transaction.
//
// Database Actions:
//   - This method performs a single database write transaction
//     (`walletdb.Update`).
//   - It stores the taproot script and its derived address information within
//     the `waddrmgr` namespace.
//
// Time Complexity:
//   - Similar to ImportPublicKey, this operation is dominated by a database
//     write, making it a fast operation with a complexity of roughly O(1).
func (w *Wallet) ImportTaprootScript(_ context.Context,
	tapscript waddrmgr.Tapscript) (AddressInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return AddressInfo{}, err
	}

	manager, err := w.addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0086,
	)
	if err != nil {
		return AddressInfo{}, err
	}

	var addr waddrmgr.ManagedAddress

	err = walletdb.Update(w.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		syncedTo := w.addrStore.SyncedTo()
		addr, err = manager.ImportTaprootScript(
			ns, &tapscript, &syncedTo, 1, false,
		)

		return err
	})
	if err != nil {
		return AddressInfo{}, err
	}

	err = w.cfg.Chain.NotifyReceived([]address.Address{addr.Address()})
	if err != nil {
		return AddressInfo{}, err
	}

	return addressInfoFromManagedAddress(addr)
}

// ScriptForOutput returns the address metadata and spending scripts for a given
// UTXO.
//
// This method is essential for constructing the necessary scripts to spend a
// transaction output. It provides the components required to build the
// scriptSig and witness fields of a transaction input.
//
// How it works:
// The method first identifies which of the wallet's addresses corresponds to
// the output's script. It then determines the correct script format (redeem
// script, witness program) based on the address type.
//
// Logical Steps:
//  1. Look up the output's pkScript in the database to find the
//     corresponding managed address.
//  2. Verify that the address is a public key address that the wallet can
//     sign for (e.g., P2WKH, NP2WKH, P2TR).
//  3. Based on the address type, construct the appropriate scripts:
//     - For nested P2WKH (NP2WKH), it returns the inner witness program as the
//     redeem script.
//     - For native SegWit outputs (P2WKH, P2TR), the `witnessProgram` is the
//     output's `pkScript`, while the redeem script is nil.
//
// Database Actions:
//   - This method performs a read-only database access to fetch address
//     details from the `waddrmgr` namespace.
//
// Time Complexity:
//   - The operation is dominated by the database lookup for the address, which
//     is typically fast (O(log N) or O(1) with indexing). The script
//     generation is a constant-time operation.
func (w *Wallet) ScriptForOutput(ctx context.Context, output wire.TxOut) (
	OutputScriptInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return OutputScriptInfo{}, err
	}

	// First, we'll extract the address from the output's pkScript.
	addr := extractAddrFromPKScript(output.PkScript, w.cfg.ChainParams)
	if addr == nil {
		return OutputScriptInfo{}, fmt.Errorf("%w: from pkscript %x",
			ErrUnableToExtractAddress, output.PkScript)
	}

	addressInfo, err := w.GetAddressInfo(ctx, addr)
	if err != nil {
		return OutputScriptInfo{}, fmt.Errorf("unable to get address info "+
			"for %s: %w", addr.String(), err)
	}

	if addressInfo.PubKey == nil {
		return OutputScriptInfo{}, fmt.Errorf("%w: addr %s",
			ErrNotPubKeyAddress, addressInfo.Addr)
	}

	witnessProgram := output.PkScript

	var redeemScript []byte
	if addressInfo.AddrType == waddrmgr.NestedWitnessPubKey {
		redeemScript, err = nestedWitnessProgramFromPubKey(
			addressInfo.PubKey, w.cfg.ChainParams,
		)
		if err != nil {
			return OutputScriptInfo{}, err
		}

		// For nested P2WPKH-in-P2SH, the redeem script committed by the outer
		// P2SH output is the same inner witness program used for signing.
		witnessProgram = redeemScript
	} else if addressInfo.AddrType != waddrmgr.PubKeyHash &&
		addressInfo.AddrType != waddrmgr.WitnessPubKey &&
		addressInfo.AddrType != waddrmgr.TaprootPubKey {

		return OutputScriptInfo{}, fmt.Errorf("%w: %v",
			ErrUnsupportedAddressType, addressInfo.AddrType)
	}

	return OutputScriptInfo{
		AddressInfo:    addressInfo,
		WitnessProgram: witnessProgram,
		RedeemScript:   redeemScript,
	}, nil
}

// nestedWitnessProgramFromPubKey builds the inner witness program used by a
// nested P2WPKH-in-P2SH output from one compressed public key.
func nestedWitnessProgramFromPubKey(pubKey *btcec.PublicKey,
	chainParams *chaincfg.Params) ([]byte, error) {

	witnessAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), chainParams,
	)
	if err != nil {
		return nil, fmt.Errorf("new witness pubkey hash: %w", err)
	}

	witnessProgram, err := txscript.PayToAddrScript(witnessAddr)
	if err != nil {
		return nil, fmt.Errorf("pay to witness address: %w", err)
	}

	return witnessProgram, nil
}

// buildScriptsForManagedAddress constructs the witness and redeem scripts for a
// given managed public key address and its corresponding pkScript.
func buildScriptsForManagedAddress(pubKeyAddr waddrmgr.ManagedPubKeyAddress,
	pkScript []byte, chainParams *chaincfg.Params) ([]byte, []byte, error) {

	addressInfo, err := addressInfoFromManagedAddress(pubKeyAddr)
	if err != nil {
		return nil, nil, err
	}

	witnessProgram := pkScript
	var redeemScript []byte
	if addressInfo.AddrType == waddrmgr.NestedWitnessPubKey {
		redeemScript, err = nestedWitnessProgramFromPubKey(
			addressInfo.PubKey, chainParams,
		)
		if err != nil {
			return nil, nil, err
		}

		witnessProgram = redeemScript
	}

	return witnessProgram, redeemScript, nil
}

// GetDerivationInfo returns the BIP-32 derivation path for a given address.
func (w *Wallet) GetDerivationInfo(ctx context.Context,
	addr address.Address) (*psbt.Bip32Derivation, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	// We'll use the address to look up the derivation path.
	addressInfo, err := w.GetAddressInfo(ctx, addr)
	if err != nil {
		return nil, err
	}

	return derivationForAddressInfo(addressInfo)
}

// derivationForAddressInfo constructs a PSBT Bip32Derivation struct from a
// wallet-owned address metadata record.
func derivationForAddressInfo(addressInfo AddressInfo) (
	*psbt.Bip32Derivation, error) {

	// Imported addresses don't have derivation paths.
	if addressInfo.Imported {
		return nil, fmt.Errorf("%w: addr=%v is imported",
			ErrDerivationPathNotFound, addressInfo.Addr)
	}

	// Only public key addresses carry derivation metadata.
	if addressInfo.PubKey == nil {
		return nil, fmt.Errorf("%w: addr=%v not found",
			ErrDerivationPathNotFound, addressInfo.Addr)
	}

	// Rebuild the BIP-32 path from the wallet-owned derivation metadata.
	if addressInfo.Derivation == nil {
		return nil, fmt.Errorf("%w: derivation info not found for %v",
			ErrDerivationPathNotFound, addressInfo.Addr)
	}

	keyScope := addressInfo.Derivation.KeyScope

	return &psbt.Bip32Derivation{
		PubKey:               addressInfo.PubKey.SerializeCompressed(),
		MasterKeyFingerprint: addressInfo.Derivation.MasterKeyFingerprint,
		Bip32Path: []uint32{
			keyScope.Purpose + hdkeychain.HardenedKeyStart,
			keyScope.Coin + hdkeychain.HardenedKeyStart,
			addressInfo.Derivation.Account + hdkeychain.HardenedKeyStart,
			addressInfo.Derivation.Branch,
			addressInfo.Derivation.Index,
		},
	}, nil
}

// derivationForManagedAddress constructs a PSBT Bip32Derivation struct from a
// managed public key address.
func derivationForManagedAddress(pubKeyAddr waddrmgr.ManagedPubKeyAddress) (
	*psbt.Bip32Derivation, error) {

	addressInfo, err := addressInfoFromManagedAddress(pubKeyAddr)
	if err != nil {
		return nil, err
	}

	return derivationForAddressInfo(addressInfo)
}
