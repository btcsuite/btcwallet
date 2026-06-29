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
	"strconv"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
)

var (
	// errMissingAccountPubKey is returned by deriveAddressData when the
	// AddressDerivationParams arrive without the account-level extended public
	// key required to derive an address. The wallet's account loader is
	// expected to fill this in for every SQL-store account before address
	// derivation.
	errMissingAccountPubKey = errors.New(
		"missing account public key for derivation",
	)

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
)

// addressManagerPageLimit is the transitional address iteration page size.
// TODO(yy): Make this configurable once the address store is fully wired.
const addressManagerPageLimit = 500

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
	// and P2TR, leave this nil.
	RedeemScript []byte

	// SigScript is the final scriptSig wrapper needed to spend outputs that are
	// wrapped in P2SH.
	// For nested P2WPKH-in-P2SH spends, this is a single push of RedeemScript.
	// Native witness spends leave this nil.
	SigScript []byte
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
//
//nolint:unparam // Preserve the legacy caller error shape during migration.
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

// addressPageRequest returns the standard page request used by address-manager
// iteration helpers.
func addressPageRequest() (page.Request[uint32], error) {
	return page.NewRequest[uint32](addressManagerPageLimit)
}

// addressInfoFromStoreAddress converts one db-native address record into the
// wallet-owned address metadata shape exposed by the public API.
func addressInfoFromStoreAddress(storeAddr *db.AddressInfo,
	chainParams *chaincfg.Params) (AddressInfo, error) {

	addr := extractAddrFromPKScript(storeAddr.ScriptPubKey, chainParams)
	if addr == nil {
		return AddressInfo{}, fmt.Errorf("%w: from pkscript %x",
			ErrUnableToExtractAddress, storeAddr.ScriptPubKey)
	}

	addrType, err := addresstype.ToWallet(
		storeAddr.AddrType, storeAddr.HasScript,
	)
	if err != nil {
		return AddressInfo{}, fmt.Errorf("%w: %v", ErrUnknownAddrType,
			storeAddr.AddrType)
	}

	internal := storeAddr.HasDerivationPath && storeAddr.Branch == 1

	info := AddressInfo{
		Addr:       addr,
		AddrType:   addrType,
		Imported:   !storeAddr.HasDerivationPath,
		Internal:   internal,
		Compressed: storeAddressPubKeyCompressed(storeAddr.PubKey),
	}

	if len(storeAddr.PubKey) == 0 {
		return info, nil
	}

	pubKey, err := btcec.ParsePubKey(storeAddr.PubKey)
	if err != nil {
		return AddressInfo{}, fmt.Errorf("parse pubkey: %w", err)
	}

	info.PubKey = pubKey

	// Imported-xpub children have a real branch/index but no wallet-derived
	// account number. Do not fabricate account 0; without a BIP44 account
	// number the public BIP32 derivation shape is intentionally absent.
	if storeAddr.AccountNumber == nil {
		return info, nil
	}

	info.Derivation = &AddressDerivation{
		KeyScope: waddrmgr.KeyScope{
			Purpose: storeAddr.KeyScope.Purpose,
			Coin:    storeAddr.KeyScope.Coin,
		},
		Account:              *storeAddr.AccountNumber,
		Branch:               storeAddr.Branch,
		Index:                storeAddr.Index,
		MasterKeyFingerprint: storeAddr.MasterKeyFingerprint,
	}

	return info, nil
}

// deriveAddressData derives one SQL-store address from account public material.
func (w *Wallet) deriveAddressData(_ context.Context,
	params db.AddressDerivationParams) (*db.DerivedAddressData, error) {

	if len(params.AccountPubKey) == 0 {
		account := "none"
		if params.DerivedAccountNumber != nil {
			account = strconv.FormatUint(
				uint64(*params.DerivedAccountNumber), 10,
			)
		}

		return nil, fmt.Errorf("%w: scope=%v account=%s",
			errMissingAccountPubKey, params.Scope, account)
	}

	accountPubKey, err := hdkeychain.NewKeyFromString(
		string(params.AccountPubKey),
	)
	if err != nil {
		return nil, fmt.Errorf("parse account pubkey: %w", err)
	}

	branchKey, err := deriveChildKey(accountPubKey, params.Branch)
	if err != nil {
		return nil, fmt.Errorf("derive branch: %w", err)
	}
	defer branchKey.Zero()

	addrKey, err := deriveChildKey(branchKey, params.Index)
	if err != nil {
		return nil, fmt.Errorf("derive address index: %w", err)
	}
	defer addrKey.Zero()

	pubKey, err := addrKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("derive address pubkey: %w", err)
	}

	pubKeyBytes := pubKey.SerializeCompressed()

	walletAddrType, err := addresstype.ToWallet(params.AddrType, false)
	if err != nil {
		return nil, fmt.Errorf("address type: %w", err)
	}

	addr, err := walletAddrType.AddrFromPubKeyBytes(
		pubKeyBytes, w.cfg.ChainParams,
	)
	if err != nil {
		return nil, fmt.Errorf("derive address: %w", err)
	}

	scriptPubKey, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, fmt.Errorf("pay to addr: %w", err)
	}

	return &db.DerivedAddressData{
		ScriptPubKey: scriptPubKey,
		PubKey:       pubKeyBytes,
	}, nil
}

// storeAddressPubKeyCompressed reports whether store pubkey bytes use the
// compressed secp256k1 encoding.
func storeAddressPubKeyCompressed(pubKey []byte) bool {
	return len(pubKey) == btcec.PubKeyBytesLenCompressed
}

// addrBalances returns wallet address balances from store UTXO rows.
func (w *Wallet) addrBalances(ctx context.Context) (map[string]btcutil.Amount,
	error) {

	balances := make(map[string]btcutil.Amount)

	utxos, err := w.store.ListUTXOs(ctx, db.ListUtxosQuery{
		WalletID: w.id,
	})
	if err != nil {
		return nil, fmt.Errorf("list utxos: %w", err)
	}

	for i := range utxos {
		addr := extractAddrFromPKScript(
			utxos[i].PkScript, w.cfg.ChainParams,
		)
		if addr == nil {
			continue
		}

		balances[addr.String()] += utxos[i].Amount
	}

	return balances, nil
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
func (w *Wallet) NewAddress(ctx context.Context, accountName string,
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

	addrInfo, err := w.store.NewDerivedAddress(
		ctx, db.NewDerivedAddressParams{
			WalletID:    w.id,
			AccountName: accountName,
			Scope:       db.KeyScope(keyScope),
			Change:      change,
		},
	)
	if err != nil {
		return nil, err
	}

	addr := extractAddrFromPKScript(addrInfo.ScriptPubKey, w.cfg.ChainParams)
	if addr == nil {
		return nil, fmt.Errorf("%w: from pkscript %x",
			ErrUnableToExtractAddress, addrInfo.ScriptPubKey)
	}

	// Notify the rpc server about the newly created address.
	err = w.cfg.Chain.NotifyReceived([]address.Address{addr})
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

	req, err := addressPageRequest()
	if err != nil {
		return nil, err
	}

	addresses := w.store.IterAddresses(
		ctx, db.ListAddressesQuery{
			WalletID:    w.id,
			AccountName: &accountName,
			Scope:       (*db.KeyScope)(&keyScope),
			Page:        req,
		},
	)
	for storeAddr, err := range addresses {
		if err != nil {
			return nil, err
		}

		unusedAddr, ok, err := nextUnusedStoreAddress(
			storeAddr, change, w.cfg.ChainParams,
		)
		if err != nil {
			return nil, err
		}

		if !ok {
			continue
		}

		return unusedAddr, nil
	}

	// Otherwise, we'll generate a new one.
	return w.NewAddress(ctx, accountName, addrType, change)
}

// nextUnusedStoreAddress returns the unused address candidate represented by a
// store record, if it matches the requested branch and is not already used.
func nextUnusedStoreAddress(storeAddr db.AddressInfo,
	change bool,
	chainParams *chaincfg.Params) (address.Address, bool, error) {

	if !storeAddr.HasDerivationPath {
		return nil, false, nil
	}

	if (storeAddr.Branch == 1) != change {
		return nil, false, nil
	}

	if storeAddr.IsUsed {
		return nil, false, nil
	}

	addr := extractAddrFromPKScript(storeAddr.ScriptPubKey, chainParams)
	if addr == nil {
		return nil, false, fmt.Errorf("%w: from pkscript %x",
			ErrUnableToExtractAddress, storeAddr.ScriptPubKey)
	}

	return addr, true, nil
}

// GetAddressInfo returns detailed information regarding a wallet address.
func (w *Wallet) GetAddressInfo(ctx context.Context, a address.Address) (
	AddressInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return AddressInfo{}, err
	}

	scriptPubKey, err := txscript.PayToAddrScript(a)
	if err != nil {
		return AddressInfo{}, fmt.Errorf("pay to addr script: %w", err)
	}

	storeAddr, err := w.store.GetAddress(
		ctx, db.GetAddressQuery{
			WalletID:     w.id,
			ScriptPubKey: scriptPubKey,
		},
	)
	if err != nil {
		return AddressInfo{}, err
	}

	return addressInfoFromStoreAddress(storeAddr, w.cfg.ChainParams)
}

// ListAddresses lists all addresses for a given account, including their
// balances.
func (w *Wallet) ListAddresses(ctx context.Context, accountName string,
	addrType waddrmgr.AddressType) ([]AddressProperty, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	req, err := addressPageRequest()
	if err != nil {
		return nil, err
	}

	query, storeAddrType, err := listAddressesQuery(
		w.id, req, accountName, addrType,
	)
	if err != nil {
		return nil, err
	}

	balances, err := w.addrBalances(ctx)
	if err != nil {
		return nil, err
	}

	properties := make([]AddressProperty, 0)

	addresses := w.store.IterAddresses(ctx, query)
	for storeAddr, err := range addresses {
		if err != nil {
			return nil, err
		}

		if accountName == db.DefaultImportedAccountName &&
			!walletAddressTypeMatches(storeAddr, storeAddrType) {

			continue
		}

		addr := extractAddrFromPKScript(
			storeAddr.ScriptPubKey, w.cfg.ChainParams,
		)
		if addr == nil {
			continue
		}

		properties = append(properties, AddressProperty{
			Address: addr,
			Balance: balances[addr.String()],
		})
	}

	return properties, nil
}

// walletAddressTypeMatches reports whether a store address row matches a
// wallet-facing address type selector.
func walletAddressTypeMatches(info db.AddressInfo,
	addrType addresstype.StoreType) bool {

	return info.AddrType == addrType.Type &&
		info.HasScript == addrType.HasScript
}

// listAddressesQuery builds the store query for a wallet-facing account name.
// The reserved imported alias has no account row in the SQL store, so it uses a
// wallet-wide query and returns the address type needed for local filtering.
func listAddressesQuery(walletID uint32, req page.Request[uint32],
	accountName string, addrType waddrmgr.AddressType) (
	db.ListAddressesQuery, addresstype.StoreType, error) {

	query := db.ListAddressesQuery{
		WalletID: walletID,
		Page:     req,
	}

	if accountName == db.DefaultImportedAccountName {
		storeAddrType, err := addresstype.FromWallet(addrType)
		if err != nil {
			return query, addresstype.StoreType{}, fmt.Errorf(
				"%w: %v", ErrUnknownAddrType, addrType,
			)
		}

		return query, storeAddrType, nil
	}

	keyScope, err := addrType.KeyScope()
	if err != nil {
		return query, addresstype.StoreType{}, fmt.Errorf(
			"%w: %v", ErrUnknownAddrType, addrType,
		)
	}

	scope := db.KeyScope(keyScope)
	query.AccountName = &accountName
	query.Scope = &scope

	return query, addresstype.StoreType{}, nil
}

// ImportPublicKey imports a single public key as a watch-only address.
func (w *Wallet) ImportPublicKey(ctx context.Context, pubKey *btcec.PublicKey,
	addrType waddrmgr.AddressType) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	storeAddrType, err := addresstype.FromWallet(addrType)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknownAddrType, addrType)
	}

	serializedPubKey := pubKey.SerializeCompressed()

	addr, err := addrType.AddrFromPubKeyBytes(
		serializedPubKey, w.cfg.ChainParams,
	)
	if err != nil {
		return fmt.Errorf("derive imported address: %w", err)
	}

	scriptPubKey, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return fmt.Errorf("pay to addr script: %w", err)
	}

	_, err = w.store.NewImportedAddress(
		ctx, db.NewImportedAddressParams{
			WalletID:     w.id,
			AddressType:  storeAddrType.Type,
			ScriptPubKey: scriptPubKey,
			PubKey:       serializedPubKey,
		},
	)
	if err != nil {
		return err
	}

	return w.cfg.Chain.NotifyReceived([]address.Address{addr})
}

// ImportTaprootScript imports a taproot script for tracking and spending.
func (w *Wallet) ImportTaprootScript(ctx context.Context,
	tapscript waddrmgr.Tapscript) (AddressInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return AddressInfo{}, err
	}

	taprootKey, err := tapscript.TaprootKey()
	if err != nil {
		return AddressInfo{}, err
	}

	addr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(taprootKey), w.cfg.ChainParams,
	)
	if err != nil {
		return AddressInfo{}, fmt.Errorf("taproot address: %w", err)
	}

	scriptPubKey, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return AddressInfo{}, fmt.Errorf("pay to addr script: %w", err)
	}

	encryptedScript, err := encryptTaprootScript(w.keyVault, &tapscript)
	if err != nil {
		return AddressInfo{}, err
	}

	storeInfo, err := w.store.NewImportedAddress(
		ctx, db.NewImportedAddressParams{
			WalletID:        w.id,
			AddressType:     db.TaprootPubKey,
			ScriptPubKey:    scriptPubKey,
			EncryptedScript: encryptedScript,
		},
	)
	if err != nil {
		return AddressInfo{}, err
	}

	storeInfo.HasScript = true

	info, err := addressInfoFromStoreAddress(storeInfo, w.cfg.ChainParams)
	if err != nil {
		return AddressInfo{}, err
	}

	err = w.cfg.Chain.NotifyReceived([]address.Address{addr})
	if err != nil {
		return AddressInfo{}, err
	}

	return info, nil
}

// encryptTaprootScript encodes and encrypts taproot script data before the
// encrypted blob is handed to the store.
func encryptTaprootScript(vault keyvault.Vault,
	tapscript *waddrmgr.Tapscript) ([]byte, error) {

	encodedScript, err := waddrmgr.EncodeTaprootScript(tapscript)
	if err != nil {
		return nil, fmt.Errorf("encode tapscript: %w", err)
	}

	if vault == nil {
		return nil, fmt.Errorf("%w: keyVault", ErrMissingParam)
	}

	encryptedScript, err := vault.Encrypt(waddrmgr.CKTPublic, encodedScript)
	if err != nil {
		return nil, fmt.Errorf("encrypt tapscript: %w", err)
	}

	return encryptedScript, nil
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
//     redeem script and also builds the single-push sigScript wrapper used in
//     the final input.
//     - For native SegWit outputs (P2WKH, P2TR), the `witnessProgram` is the
//     output's `pkScript`, while the redeem script and sigScript are nil.
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

	witnessProgram, redeemScript, sigScript, err := buildScriptsForAddressInfo(
		addressInfo, output.PkScript, w.cfg.ChainParams,
	)
	if err != nil {
		return OutputScriptInfo{}, err
	}

	return OutputScriptInfo{
		AddressInfo:    addressInfo,
		WitnessProgram: witnessProgram,
		RedeemScript:   redeemScript,
		SigScript:      sigScript,
	}, nil
}

// buildScriptsForAddressInfo constructs the witness program, redeem script,
// and final sigScript for a wallet-owned address metadata record.
func buildScriptsForAddressInfo(addressInfo AddressInfo, pkScript []byte,
	_ *chaincfg.Params) ([]byte, []byte, []byte, error) {

	if addressInfo.PubKey == nil {
		return nil, nil, nil, fmt.Errorf("%w: addr %s", ErrNotPubKeyAddress,
			addressInfo.Addr)
	}

	// For nested witness spends, the redeem script committed to by the outer
	// P2SH output is the inner witness program, while the sigScript is a single
	// push of that redeem script. For all other supported single-key families,
	// the previous output pkScript remains the correct subscript for signing.
	witnessProgram := pkScript

	var (
		redeemScript []byte
		sigScript    []byte
		err          error
	)

	spendType := addressInfo.AddrType.SpendType()
	if spendType == waddrmgr.SpendTypeNestedWitnessKey {
		redeemScript, err = txscript.NewScriptBuilder().
			AddOp(txscript.OP_0).
			AddData(address.Hash160(addressInfo.PubKey.SerializeCompressed())).
			Script()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("build nested witness "+
				"program: %w", err)
		}

		sigScript, err = txscript.NewScriptBuilder().
			AddData(redeemScript).
			Script()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("encode redeem script: %w", err)
		}

		witnessProgram = redeemScript
	} else if spendType != waddrmgr.SpendTypeLegacyKey &&
		spendType != waddrmgr.SpendTypeWitnessKey &&
		spendType != waddrmgr.SpendTypeTaprootKeyPath {

		return nil, nil, nil, fmt.Errorf("%w: %v", ErrUnsupportedAddressType,
			addressInfo.AddrType)
	}

	return witnessProgram, redeemScript, sigScript, nil
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
	if keyScope == (waddrmgr.KeyScope{}) {
		return nil, fmt.Errorf("%w: derivation scope not found for %v",
			ErrDerivationPathNotFound, addressInfo.Addr)
	}

	derivationInfo := &psbt.Bip32Derivation{
		PubKey:               addressInfo.PubKey.SerializeCompressed(),
		MasterKeyFingerprint: addressInfo.Derivation.MasterKeyFingerprint,
		Bip32Path: []uint32{
			keyScope.Purpose + hdkeychain.HardenedKeyStart,
			keyScope.Coin + hdkeychain.HardenedKeyStart,
			addressInfo.Derivation.Account + hdkeychain.HardenedKeyStart,
			addressInfo.Derivation.Branch,
			addressInfo.Derivation.Index,
		},
	}

	return derivationInfo, nil
}
