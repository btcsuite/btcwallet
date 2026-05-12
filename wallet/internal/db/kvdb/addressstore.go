package kvdb

import (
	"context"
	"iter"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
)

// NewDerivedAddress is not yet implemented for kvdb.
func (s *Store) NewDerivedAddress(ctx context.Context,
	_ db.NewDerivedAddressParams) (*db.AddressInfo, error) {

	return nil, notImplemented(ctx, "NewDerivedAddress")
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

// IterAddresses is not yet implemented for kvdb.
func (s *Store) IterAddresses(ctx context.Context,
	_ db.ListAddressesQuery) iter.Seq2[db.AddressInfo, error] {

	return func(yield func(db.AddressInfo, error) bool) {
		yield(db.AddressInfo{}, notImplemented(ctx, "IterAddresses"))
	}
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
