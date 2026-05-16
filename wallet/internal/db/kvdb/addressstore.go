package kvdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"iter"
	"sort"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/walletdb"
)

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

		info, err = derivedAddressInfo(ns, manager, params)
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

	info, err := managedAddressInfo(ns, manager, managedAddr)
	if err != nil {
		return nil, err
	}

	err = kvdbSetAddressID(ns, manager, account, info)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// NewImportedAddress is not yet implemented for kvdb.
func (s *Store) NewImportedAddress(ctx context.Context,
	_ db.NewImportedAddressParams) (*db.AddressInfo, error) {

	return nil, notImplemented(ctx, "NewImportedAddress")
}

// GetAddress is not yet implemented for kvdb.
func (s *Store) GetAddress(ctx context.Context,
	_ db.GetAddressQuery) (*db.AddressInfo, error) {

	return nil, notImplemented(ctx, "GetAddress")
}

// ListAddresses is not yet implemented for kvdb.
func (s *Store) ListAddresses(ctx context.Context,
	_ db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32], error) {

	return page.Result[db.AddressInfo, uint32]{}, notImplemented(
		ctx, "ListAddresses",
	)
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

// kvdbSetAddressID assigns target's synthetic ID from the current legacy
// account view.
func kvdbSetAddressID(ns walletdb.ReadBucket, manager waddrmgr.AccountStore,
	account uint32, target *db.AddressInfo) error {

	items, err := accountAddressInfos(ns, manager, account)
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
	manager waddrmgr.AccountStore, account uint32) ([]db.AddressInfo, error) {

	var items []db.AddressInfo

	err := manager.ForEachAccountAddress(
		ns, account, func(managedAddr waddrmgr.ManagedAddress) error {
			info, err := managedAddressInfo(ns, manager, managedAddr)
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

// kvdbValidateDerivedAddress checks that a caller-provided derivation callback
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
		IsWatchOnly:          managedAddressIsWatchOnly(managedAddr),
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

// managedAddressIsWatchOnly reports whether a legacy managed address lacks
// private key material.
func managedAddressIsWatchOnly(
	managedAddr waddrmgr.ManagedAddress) bool {

	return managedAddr.Imported()
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
