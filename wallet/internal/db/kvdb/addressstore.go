package kvdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"iter"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/walletdb"
)

// A compile-time assertion to ensure Store implements the address store.
var _ db.AddressStore = (*Store)(nil)

var (
	// errUnexpectedAddressCount is returned when legacy address derivation
	// returns a number of addresses different from the requested count.
	errUnexpectedAddressCount = errors.New("unexpected derived address count")

	// errUnknownLegacyAddressType is returned when a legacy address type does
	// not have a store address type mapping.
	errUnknownLegacyAddressType = errors.New("unknown legacy address type")

	// errNilDerivedAddressData is returned when the derivation callback reports
	// success without returning derived address data.
	errNilDerivedAddressData = errors.New("derived address data is nil")

	// errDerivedAddressMismatch is returned when legacy derivation disagrees
	// with a caller-provided derivation callback.
	errDerivedAddressMismatch = errors.New("derived address mismatch")
	// errMissingLegacyAddrStore is returned when an addressstore operation
	// needs the legacy waddrmgr-backed addrStore but none is wired.
	errMissingLegacyAddrStore = errors.New(
		"kvdb: missing legacy addr store",
	)

	// errMissingAddrmgrNamespace is returned when the waddrmgr namespace
	// bucket is absent from the database.
	errMissingAddrmgrNamespace = errors.New(
		"kvdb: missing waddrmgr namespace",
	)
)

// NewDerivedAddress creates one derived address through the legacy address-
// manager path.
//
// NOTE: SQL backends use deriveFn as their derivation mechanism after
// allocating an index. The kvdb adapter must preserve legacy address-manager
// semantics, so it derives through waddrmgr and uses deriveFn only as optional
// post-create validation when the callback is non-nil.
func (s *Store) NewDerivedAddress(ctx context.Context,
	params db.NewDerivedAddressParams,
	deriveFn db.AddressDerivationFunc) (*db.AddressInfo, error) {

	err := ctx.Err()
	if err != nil {
		return nil, err
	}

	if s.addrStore == nil {
		return nil, fmt.Errorf("NewDerivedAddress: %w",
			errMissingLegacyAddrStore)
	}

	if params.AccountName == "" {
		return nil, db.ErrMissingAccountName
	}

	addrMgr := s.addrStore

	manager, err := addrMgr.FetchScopedKeyManager(
		waddrmgr.KeyScope(params.Scope),
	)
	if err != nil {
		return nil, fmt.Errorf("NewDerivedAddress: fetch scoped manager: "+
			"%w", err)
	}

	var info *db.AddressInfo

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		info, err = derivedAddressInfo(
			ns, manager, addrMgr.WatchOnly(), params,
		)
		if err != nil {
			return err
		}

		// Validate before commit so a failure rolls the persisted
		// state (index advance + address row) back.
		return validateDerivedAddress(ctx, deriveFn, info)
	})
	if err != nil {
		return nil, fmt.Errorf("NewDerivedAddress: %w", err)
	}

	return info, nil
}

// derivedAddressInfo creates one derived address info using the legacy scoped
// manager and assigns its synthetic address ID.
func derivedAddressInfo(ns walletdb.ReadWriteBucket,
	manager waddrmgr.AccountStore,
	walletIsWatchOnly bool,
	params db.NewDerivedAddressParams) (*db.AddressInfo, error) {

	account, err := manager.LookupAccount(ns, params.AccountName)
	if err != nil {
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return nil, db.ErrAccountNotFound
		}

		return nil, fmt.Errorf("lookup account: %w", err)
	}

	managedAddr, err := nextAddress(ns, manager, account, params.Change)
	if err != nil {
		return nil, err
	}

	info, err := managedAddressInfo(
		ns, manager, walletIsWatchOnly, managedAddr,
	)
	if err != nil {
		return nil, err
	}

	err = setAddressID(ns, manager, account, walletIsWatchOnly, info)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// NewImportedAddress imports one address through the legacy address-manager
// path.
func (s *Store) NewImportedAddress(ctx context.Context,
	params db.NewImportedAddressParams) (*db.AddressInfo, error) {

	err := ctx.Err()
	if err != nil {
		return nil, err
	}

	err = params.ValidateBasic()
	if err != nil {
		return nil, fmt.Errorf("validate params: %w", err)
	}

	if params.HasPrivateKey() {
		return nil, fmt.Errorf("NewImportedAddress: private key: %w",
			errNotImplemented)
	}

	addrMgr := s.addrStore

	manager, err := addrMgr.FetchScopedKeyManager(
		waddrmgr.KeyScope(params.Scope),
	)
	if err != nil {
		return nil, fmt.Errorf("NewImportedAddress: fetch scoped manager: "+
			"%w", err)
	}

	var info *db.AddressInfo

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		managedAddr, err := s.importAddress(ns, manager, params)
		if err != nil {
			return err
		}

		info, err = managedAddressInfo(
			ns, manager, addrMgr.WatchOnly(), managedAddr,
		)
		if err != nil {
			return err
		}

		return setAddressID(
			ns, manager, managedAddr.InternalAccount(),
			addrMgr.WatchOnly(), info,
		)
	})
	if err != nil {
		return nil, fmt.Errorf("NewImportedAddress: %w", err)
	}

	return info, nil
}

// GetAddress retrieves one address through the legacy address-manager path.
func (s *Store) GetAddress(ctx context.Context,
	query db.GetAddressQuery) (*db.AddressInfo, error) {

	err := ctx.Err()
	if err != nil {
		return nil, err
	}

	if len(query.ScriptPubKey) == 0 {
		return nil, db.ErrInvalidAddressQuery
	}

	addrMgr := s.addrStore

	addr := addressFromScript(
		query.ScriptPubKey, addrMgr.ChainParams(),
	)
	if addr == nil {
		return nil, db.ErrAddressNotFound
	}

	var info *db.AddressInfo

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		info, err = resolvedAddressInfo(ns, addrMgr, addr)

		return err
	})
	if err != nil {
		return nil, fmt.Errorf("GetAddress: %w", err)
	}

	return info, nil
}

// resolvedAddressInfo resolves one legacy managed address and assigns its
// synthetic address ID.
func resolvedAddressInfo(ns walletdb.ReadBucket,
	resolver waddrmgr.AddrStore,
	addr btcutil.Address) (*db.AddressInfo, error) {

	managedAddr, err := resolver.Address(ns, addr)
	if err != nil {
		if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
			return nil, db.ErrAddressNotFound
		}

		return nil, fmt.Errorf("lookup address: %w", err)
	}

	manager, account, err := resolver.AddrAccount(ns, addr)
	if err != nil {
		return nil, fmt.Errorf("lookup address account: %w", err)
	}

	info, err := managedAddressInfo(
		ns, manager, resolver.WatchOnly(), managedAddr,
	)
	if err != nil {
		return nil, err
	}

	err = setAddressID(ns, manager, account, resolver.WatchOnly(), info)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// ListAddresses returns one page of addresses from the legacy address-manager
// path.
func (s *Store) ListAddresses(ctx context.Context,
	query db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32], error) {

	err := ctx.Err()
	if err != nil {
		return page.Result[db.AddressInfo, uint32]{}, err
	}

	if query.Page.Limit() == 0 {
		return page.Result[db.AddressInfo, uint32]{}, db.ErrInvalidPageLimit
	}

	if s.addrStore == nil {
		return page.Result[db.AddressInfo, uint32]{},
			fmt.Errorf("ListAddresses: %w", errMissingLegacyAddrStore)
	}

	addrMgr := s.addrStore

	manager, err := addrMgr.FetchScopedKeyManager(
		waddrmgr.KeyScope(query.Scope),
	)
	if err != nil {
		return page.Result[db.AddressInfo, uint32]{},
			fmt.Errorf("ListAddresses: fetch scoped manager: %w", err)
	}

	items, err := listAddressItems(
		s.db, manager, addrMgr.WatchOnly(), query,
	)
	if err != nil {
		return page.Result[db.AddressInfo, uint32]{},
			fmt.Errorf("ListAddresses: %w", err)
	}

	result := page.BuildResult(
		query.Page, items,
		func(item db.AddressInfo) uint32 {
			return item.ID
		},
	)

	return result, nil
}

// IterAddresses returns an iterator over paginated legacy address-manager
// results.
func (s *Store) IterAddresses(ctx context.Context,
	query db.ListAddressesQuery) iter.Seq2[db.AddressInfo, error] {

	return page.Iter(
		ctx, query, s.ListAddresses, db.NextListAddressesQuery,
	)
}

// GetAddressSecret is not yet implemented for kvdb.
func (s *Store) GetAddressSecret(ctx context.Context,
	_ db.GetAddressSecretQuery) (*db.AddressSecret, error) {

	return nil, notImplemented(ctx, "GetAddressSecret")
}

// ListAddressTypes returns the static set of address types supported by the
// store contract.
func (s *Store) ListAddressTypes(ctx context.Context) ([]db.AddressTypeInfo,
	error) {

	err := ctx.Err()
	if err != nil {
		return nil, err
	}

	infos := make([]db.AddressTypeInfo, len(addressTypes))
	copy(infos, addressTypes)

	return infos, nil
}

// GetAddressType returns the static address type metadata for the given type.
func (s *Store) GetAddressType(ctx context.Context,
	id db.AddressType) (db.AddressTypeInfo, error) {

	err := ctx.Err()
	if err != nil {
		return db.AddressTypeInfo{}, err
	}

	for _, info := range addressTypes {
		if info.Type == id {
			return info, nil
		}
	}

	return db.AddressTypeInfo{}, db.ErrAddressTypeNotFound
}

var addressTypes = []db.AddressTypeInfo{
	{Type: db.RawPubKey, Description: "P2PK"},
	{Type: db.PubKeyHash, Description: "P2PKH"},
	{Type: db.ScriptHash, Description: "P2SH"},
	{Type: db.NestedWitnessPubKey, Description: "P2SH-P2WPKH"},
	{Type: db.WitnessPubKey, Description: "P2WPKH"},
	{Type: db.WitnessScript, Description: "P2WSH"},
	{Type: db.TaprootPubKey, Description: "P2TR"},
	{Type: db.Anchor, Description: "P2A"},
}

// nextAddress allocates the next external or internal address for an account.
func nextAddress(ns walletdb.ReadWriteBucket,
	manager waddrmgr.AccountStore, account uint32,
	change bool) (waddrmgr.ManagedAddress, error) {

	var (
		addrs []waddrmgr.ManagedAddress
		err   error
	)

	if change {
		addrs, err = manager.NextInternalAddresses(ns, account, 1)
	} else {
		addrs, err = manager.NextExternalAddresses(ns, account, 1)
	}

	if err != nil {
		return nil, fmt.Errorf("derive address: %w", err)
	}

	if len(addrs) != 1 {
		return nil, fmt.Errorf("derive address: expected 1, got %d: %w",
			len(addrs), errUnexpectedAddressCount)
	}

	return addrs[0], nil
}

// importAddress imports a public key or encrypted script through the legacy
// scoped manager.
func (s *Store) importAddress(ns walletdb.ReadWriteBucket,
	manager waddrmgr.AccountStore,
	params db.NewImportedAddressParams) (waddrmgr.ManagedAddress, error) {

	if params.HasScript() {
		return s.importScriptAddress(ns, manager, params)
	}

	if len(params.PubKey) == 0 {
		return nil, fmt.Errorf("kvdb imported raw script pubkey: %w",
			errNotImplemented)
	}

	pubKey, err := btcec.ParsePubKey(params.PubKey)
	if err != nil {
		return nil, fmt.Errorf("parse imported pubkey: %w", err)
	}

	managedAddr, err := manager.ImportPublicKey(ns, pubKey, nil)
	if err != nil {
		return nil, fmt.Errorf("import public key: %w", err)
	}

	return managedAddr, nil
}

// importScriptAddress decrypts and imports script material through the
// legacy scoped manager.
func (s *Store) importScriptAddress(ns walletdb.ReadWriteBucket,
	manager waddrmgr.AccountStore,
	params db.NewImportedAddressParams) (waddrmgr.ManagedAddress, error) {

	script, err := s.addrStore.Decrypt(
		waddrmgr.CKTPublic, params.EncryptedScript,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt imported script: %w", err)
	}

	blockStamp := s.addrStore.SyncedTo()
	switch params.AddressType {
	case db.ScriptHash:
		return importScriptHashAddress(
			ns, manager, script, &blockStamp,
		)

	case db.WitnessScript:
		return importWitnessScriptAddress(
			ns, manager, script, &blockStamp,
		)

	case db.TaprootPubKey:
		return importTaprootScriptAddress(
			ns, manager, script, &blockStamp,
		)

	case db.RawPubKey, db.PubKeyHash, db.NestedWitnessPubKey,
		db.WitnessPubKey, db.Anchor:

		return nil, fmt.Errorf("import script address type %d: %w",
			params.AddressType, errNotImplemented)

	default:
		return nil, fmt.Errorf("import script address type %d: %w",
			params.AddressType, errNotImplemented)
	}
}

// importScriptHashAddress imports legacy P2SH script material.
func importScriptHashAddress(ns walletdb.ReadWriteBucket,
	manager waddrmgr.AccountStore, script []byte,
	blockStamp *waddrmgr.BlockStamp) (waddrmgr.ManagedAddress, error) {

	managedAddr, err := manager.ImportScript(ns, script, blockStamp)
	if err != nil {
		return nil, fmt.Errorf("import script: %w", err)
	}

	return managedAddr, nil
}

// importWitnessScriptAddress imports legacy P2WSH script material.
func importWitnessScriptAddress(ns walletdb.ReadWriteBucket,
	manager waddrmgr.AccountStore, script []byte,
	blockStamp *waddrmgr.BlockStamp) (waddrmgr.ManagedAddress, error) {

	managedAddr, err := manager.ImportWitnessScript(
		ns, script, blockStamp, 0, false,
	)
	if err != nil {
		return nil, fmt.Errorf("import witness script: %w", err)
	}

	return managedAddr, nil
}

// importTaprootScriptAddress imports legacy taproot script material.
func importTaprootScriptAddress(ns walletdb.ReadWriteBucket,
	manager waddrmgr.AccountStore, script []byte,
	blockStamp *waddrmgr.BlockStamp) (waddrmgr.ManagedAddress, error) {

	tapscript, err := waddrmgr.DecodeTaprootScript(script)
	if err != nil {
		return nil, fmt.Errorf("decode tapscript: %w", err)
	}

	managedAddr, err := manager.ImportTaprootScript(
		ns, tapscript, blockStamp, 1, false,
	)
	if err != nil {
		return nil, fmt.Errorf("import tapscript: %w", err)
	}

	return managedAddr, nil
}

// listAddressItems loads, filters, and paginates account addresses from one
// legacy scoped manager.
func listAddressItems(dbConn walletdb.DB,
	manager waddrmgr.AccountStore, walletIsWatchOnly bool,
	query db.ListAddressesQuery) ([]db.AddressInfo, error) {

	var items []db.AddressInfo

	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		account, err := manager.LookupAccount(ns, query.AccountName)
		if err != nil {
			if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
				return db.ErrAccountNotFound
			}

			return fmt.Errorf("lookup account: %w", err)
		}

		items, err = accountAddressInfos(
			ns, manager, account, walletIsWatchOnly,
		)

		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list address items: %w", err)
	}

	return addressPageItems(items, query), nil
}

// setAddressID assigns target's synthetic ID from the current legacy account
// view.
func setAddressID(ns walletdb.ReadBucket, manager waddrmgr.AccountStore,
	account uint32, walletIsWatchOnly bool, target *db.AddressInfo) error {

	items, err := accountAddressInfos(
		ns, manager, account, walletIsWatchOnly,
	)
	if err != nil {
		return err
	}

	for i := range items {
		if bytes.Equal(items[i].ScriptPubKey, target.ScriptPubKey) {
			target.ID = items[i].ID

			return nil
		}
	}

	return db.ErrAddressNotFound
}

// accountAddressInfos loads all addresses for a legacy account and assigns
// collision-free synthetic IDs for the current sorted account view.
func accountAddressInfos(ns walletdb.ReadBucket,
	manager waddrmgr.AccountStore, account uint32,
	walletIsWatchOnly bool) ([]db.AddressInfo, error) {

	var items []db.AddressInfo

	err := manager.ForEachAccountAddress(
		ns, account, func(managedAddr waddrmgr.ManagedAddress) error {
			info, err := managedAddressInfo(
				ns, manager, walletIsWatchOnly, managedAddr,
			)
			if err != nil {
				return err
			}

			items = append(items, *info)

			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("iterate account addresses: %w", err)
	}

	// NOTE: waddrmgr does not expose SQL-style cursor queries, so the
	// transitional kvdb adapter materializes the full legacy account before
	// slicing a page.
	err = sortAddressInfos(items)
	if err != nil {
		return nil, err
	}

	return items, nil
}

// sortAddressInfos sorts address infos and assigns one-based ordinal IDs.
func sortAddressInfos(items []db.AddressInfo) error {
	sort.Slice(items, func(i, j int) bool {
		return addressLess(items[i], items[j])
	})

	for i := range items {
		id, err := db.Int64ToUint32(int64(i + 1))
		if err != nil {
			return fmt.Errorf("address ordinal: %w", err)
		}

		items[i].ID = id
	}

	return nil
}

// addressLess reports whether a sorts before b in the synthetic address view.
func addressLess(a, b db.AddressInfo) bool {
	if a.Origin != b.Origin {
		return a.Origin < b.Origin
	}

	if a.Branch != b.Branch {
		return a.Branch < b.Branch
	}

	if a.Index != b.Index {
		return a.Index < b.Index
	}

	return bytes.Compare(a.ScriptPubKey, b.ScriptPubKey) < 0
}

// addressPageItems applies cursor pagination to already sorted address items.
func addressPageItems(items []db.AddressInfo,
	query db.ListAddressesQuery) []db.AddressInfo {

	start := 0
	if query.Page.After != nil {
		for start < len(items) && items[start].ID <= *query.Page.After {
			start++
		}
	}

	limit := start + int(query.Page.Limit()) + 1
	if limit > len(items) {
		limit = len(items)
	}

	return items[start:limit]
}

// validateDerivedAddress checks that a caller-provided derivation callback
// agrees with the address generated by the legacy address manager.
func validateDerivedAddress(ctx context.Context,
	deriveFn db.AddressDerivationFunc, info *db.AddressInfo) error {

	if deriveFn == nil {
		return nil
	}

	derivedData, err := deriveFn(
		ctx, info.AccountID, info.Branch, info.Index,
	)
	if err != nil {
		return fmt.Errorf("validate derived address: %w", err)
	}

	if derivedData == nil {
		return fmt.Errorf("validate derived address: %w",
			errNilDerivedAddressData)
	}

	if !bytes.Equal(derivedData.ScriptPubKey, info.ScriptPubKey) {
		return fmt.Errorf("validate script pubkey: %w",
			errDerivedAddressMismatch)
	}

	if len(derivedData.PubKey) > 0 &&
		!bytes.Equal(derivedData.PubKey, info.PubKey) {

		return fmt.Errorf("validate pubkey: %w", errDerivedAddressMismatch)
	}

	return nil
}

// managedAddressInfo adapts one legacy managed address into the db address view
// used by store callers.
func managedAddressInfo(ns walletdb.ReadBucket,
	manager waddrmgr.AccountStore,
	walletIsWatchOnly bool,
	managedAddr waddrmgr.ManagedAddress) (*db.AddressInfo, error) {

	scriptPubKey, err := txscript.PayToAddrScript(managedAddr.Address())
	if err != nil {
		return nil, fmt.Errorf("pay to address script: %w", err)
	}

	addrType, err := storeAddressType(managedAddr.AddrType())
	if err != nil {
		return nil, err
	}

	accountNumber := managedAddr.InternalAccount()
	accountName := db.DefaultImportedAccountName
	keyScope := db.KeyScope(manager.Scope())
	origin := db.DerivedAccount

	if managedAddr.Imported() {
		accountNumber = 0
		origin = db.ImportedAccount
	} else {
		accountName, err = manager.AccountName(ns, accountNumber)
		if err != nil {
			return nil, fmt.Errorf("account name: %w", err)
		}
	}

	var (
		branch      uint32
		index       uint32
		fingerprint uint32
		pubKey      []byte
	)

	pubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
	if ok {
		pubKey = managedAddressPubKey(pubKeyAddr)

		scope, path, ok := pubKeyAddr.DerivationInfo()
		if ok {
			accountNumber = path.InternalAccount
			branch = path.Branch
			index = path.Index
			fingerprint = path.MasterKeyFingerprint
			keyScope = db.KeyScope(scope)
		}
	}

	_, hasScript := managedAddr.(waddrmgr.ManagedScriptAddress)

	return &db.AddressInfo{
		AccountID:            accountNumber,
		AccountNumber:        accountNumber,
		AccountName:          accountName,
		KeyScope:             keyScope,
		MasterKeyFingerprint: fingerprint,
		AddrType:             addrType,
		Origin:               origin,
		Branch:               branch,
		Index:                index,
		ScriptPubKey:         scriptPubKey,
		PubKey:               pubKey,
		HasScript:            hasScript,
		IsWatchOnly: managedAddressIsWatchOnly(
			walletIsWatchOnly, managedAddr,
		),
		IsUsed: managedAddr.Used(ns),
	}, nil
}

// managedAddressPubKey returns a managed address's public key using its
// actual legacy encoding.
func managedAddressPubKey(
	managedAddr waddrmgr.ManagedPubKeyAddress) []byte {

	if managedAddr.Compressed() {
		return managedAddr.PubKey().SerializeCompressed()
	}

	return managedAddr.PubKey().SerializeUncompressed()
}

// managedAddressIsWatchOnly reports whether a managed address is unable to
// spend due to wallet-level watch-only mode or missing private key material.
func managedAddressIsWatchOnly(walletIsWatchOnly bool,
	managedAddr waddrmgr.ManagedAddress) bool {

	if walletIsWatchOnly {
		return true
	}

	if !managedAddr.Imported() {
		return false
	}

	pubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return true
	}

	return !waddrmgr.ManagedPubKeyAddressHasPrivateKey(pubKeyAddr)
}

// storeAddressType maps legacy address types to the store enum.
func storeAddressType(addrType waddrmgr.AddressType) (db.AddressType,
	error) {

	switch addrType {
	case waddrmgr.RawPubKey:
		return db.RawPubKey, nil

	case waddrmgr.PubKeyHash:
		return db.PubKeyHash, nil

	case waddrmgr.Script:
		return db.ScriptHash, nil

	case waddrmgr.NestedWitnessPubKey:
		return db.NestedWitnessPubKey, nil

	case waddrmgr.WitnessPubKey:
		return db.WitnessPubKey, nil

	case waddrmgr.WitnessScript:
		return db.WitnessScript, nil

	case waddrmgr.TaprootPubKey, waddrmgr.TaprootScript:
		return db.TaprootPubKey, nil

	default:
		return 0, fmt.Errorf("legacy address type %d: %w", addrType,
			errUnknownLegacyAddressType)
	}
}

// addressFromScript extracts the first standard address from a script.
func addressFromScript(pkScript []byte,
	chainParams *chaincfg.Params) btcutil.Address {

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		pkScript, chainParams,
	)
	if err != nil || len(addrs) == 0 {
		return nil
	}

	return addrs[0]
}
