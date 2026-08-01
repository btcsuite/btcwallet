package db

import (
	"context"
	"fmt"
	"time"
)

// CreateImportedAddressRow contains the backend-independent fields the shared
// NewImportedAddress workflow needs from the inserted address row.
type CreateImportedAddressRow struct {
	ID        int64
	CreatedAt time.Time
}

// NewImportedAddressOps is the backend adapter the shared NewImportedAddress
// workflow uses.
//
// The shared imported-address algorithm is intentionally ordered:
//   - validate the request's static shape before any backend step runs
//   - load the wallet watch-only mode
//   - reject private-key material imported into a watch-only wallet
//   - reject an import without its own private key into a spendable wallet
//   - insert the imported address row
//   - persist encrypted secret material when the import carries any
//   - assemble the AddressInfo from the request and inserted row
//
// The adapter methods map directly to those stages so the shared helper keeps
// the validation and both-direction watch-only invariants while each backend
// keeps its sqlc query types and binding shapes local.
type NewImportedAddressOps interface {
	// WalletWatchOnly reports whether the target wallet currently runs in
	// watch-only mode.
	WalletWatchOnly(ctx context.Context, walletID uint32) (bool, error)

	// CreateImportedAddress inserts the imported address row and returns its
	// backend-independent identity fields.
	CreateImportedAddress(ctx context.Context,
		params NewImportedAddressParams) (CreateImportedAddressRow, error)

	// InsertAddressSecret persists the encrypted secret material for the
	// imported address identified by addressID.
	InsertAddressSecret(ctx context.Context, addressID int64,
		params NewImportedAddressParams) error
}

// NewImportedAddressWithOps runs the backend-independent imported-address
// workflow once the caller has opened a backend-specific write transaction.
//
// The helper owns the end-to-end sequencing so postgres and sqlite both:
// validate the request, load the wallet watch-only mode, enforce the
// watch-only invariant in both directions, insert the address, persist any
// secret material, and assemble the normalized AddressInfo result.
func NewImportedAddressWithOps(ctx context.Context,
	params NewImportedAddressParams,
	ops NewImportedAddressOps) (*AddressInfo, error) {

	err := params.ValidateBasic()
	if err != nil {
		return nil, err
	}

	walletIsWatchOnly, err := ops.WalletWatchOnly(ctx, params.WalletID)
	if err != nil {
		return nil, err
	}

	err = params.ValidateWatchOnly(walletIsWatchOnly)
	if err != nil {
		return nil, err
	}

	err = RequireAddressPrivKeyOnSpendable(
		params.WalletID, walletIsWatchOnly, params.HasPrivateKey(),
	)
	if err != nil {
		return nil, err
	}

	row, err := ops.CreateImportedAddress(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("create imported address: %w", err)
	}

	if params.HasSecretMaterial() {
		err = ops.InsertAddressSecret(ctx, row.ID, params)
		if err != nil {
			return nil, fmt.Errorf("insert address secret: %w", err)
		}
	}

	addrID, err := Int64ToUint32(row.ID)
	if err != nil {
		return nil, fmt.Errorf("address ID: %w", err)
	}

	return &AddressInfo{
		ID:           addrID,
		AddrType:     params.AddressType,
		CreatedAt:    row.CreatedAt,
		IsImported:   true,
		ScriptPubKey: params.ScriptPubKey,
		PubKey:       params.PubKey,
		HasScript:    params.HasScript(),
		IsWatchOnly:  walletIsWatchOnly,
		IsUsed:       false,
	}, nil
}

// ValidateBasic checks imported address creation parameters that do not depend
// on external state.
func (p NewImportedAddressParams) ValidateBasic() error {
	if len(p.ScriptPubKey) == 0 {
		return ErrMissingScriptPubKey
	}

	return nil
}

// ValidateWatchOnly checks imported address creation parameters against the
// parent wallet's watch-only state. A watch-only wallet must not receive
// private-key-bearing imports. The symmetric direction (a spendable wallet's
// imported address must carry its own encrypted private key) is enforced at the
// SQL-backend entry through RequireAddressPrivKeyOnSpendable; kvdb's data
// model carries different invariants around legacy imported address rows (a
// grandfathered legacy shape), so the symmetric check is not applied there.
func (p NewImportedAddressParams) ValidateWatchOnly(
	walletIsWatchOnly bool) error {

	if walletIsWatchOnly && p.HasPrivateKey() {
		return fmt.Errorf("watch-only wallet %d cannot import private-key-"+
			"bearing address into account %q: %w",
			p.WalletID, DefaultImportedAccountName, ErrWatchOnlyViolation)
	}

	return nil
}

// RequireAddressPrivKeyOnSpendable enforces the ADR 0012 symmetric invariant:
// on a spendable wallet, every imported address must carry its own encrypted
// private key. ADR 0012 rejects a public-only *or script-only* import with
// ErrSpendableWalletNeedsAddressPrivKey; a watch-only wallet accepts both.
//
// Holding a redeem, witness or tapscript is not spend capability. A script
// describes a spending *condition*, not the signing material that satisfies it
// -- a 2-of-3 multisig script is not spendable because the wallet holds its
// bytes. So script presence cannot substitute for the private key here.
//
// Script-only imports remain accepted on a uniformly watch-only wallet, which
// is where observing a script without being able to spend it is the point.
func RequireAddressPrivKeyOnSpendable(walletID uint32,
	walletIsWatchOnly bool, hasPrivKey bool) error {

	if walletIsWatchOnly || hasPrivKey {
		return nil
	}

	return fmt.Errorf("spendable wallet %d cannot import address "+
		"without private-key material into account %q: %w",
		walletID, DefaultImportedAccountName,
		ErrSpendableWalletNeedsAddressPrivKey)
}

// HasPrivateKey returns true if the params include private key material.
// Script material is tracked separately and does not make an imported address
// spend-capable by itself.
func (p NewImportedAddressParams) HasPrivateKey() bool {
	return len(p.EncryptedPrivateKey) > 0
}

// HasSecretMaterial returns true when the imported address carries any
// encrypted secret payload that should be persisted in address_secrets.
// Private keys and scripts are stored independently.
func (p NewImportedAddressParams) HasSecretMaterial() bool {
	return len(p.EncryptedPrivateKey) > 0 || len(p.EncryptedScript) > 0
}

// HasScript returns true if the params include script spend data.
func (p NewImportedAddressParams) HasScript() bool {
	return len(p.EncryptedScript) > 0
}
