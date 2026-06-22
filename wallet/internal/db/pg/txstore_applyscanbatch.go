package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// scanHorizonOps adapts the PostgreSQL sqlc queries to the shared horizon
// extension workflow.
type scanHorizonOps struct {
	qtx      *sqlc.Queries
	walletID uint32
}

// A compile-time assertion that scanHorizonOps satisfies the shared interface.
var _ db.ScanHorizonOps = (*scanHorizonOps)(nil)

// horizonAccountRow is the subset of an account lookup row that both the
// by-name and by-number horizon resolution paths produce, letting them share a
// single HorizonAccount builder.
type horizonAccountRow struct {
	id               int64
	accountNumber    sql.NullInt64
	publicKey        []byte
	internalTypeID   int16
	externalTypeID   int16
	externalKeyCount int64
	internalKeyCount int64
}

// GetHorizonAccount loads the account state needed to extend a horizon. The
// stable AccountID is mandatory because account names are mutable and imported
// xpub accounts do not have BIP44 account numbers.
func (o scanHorizonOps) GetHorizonAccount(ctx context.Context,
	horizon db.ScanHorizon) (*db.HorizonAccount, error) {

	if horizon.AccountID == nil {
		return nil, fmt.Errorf("%w: scan horizon account id is required",
			db.ErrInvalidParam)
	}

	return o.horizonAccountByID(ctx, *horizon.AccountID, horizon.Scope)
}

// buildHorizonAccount assembles the HorizonAccount the shared extension
// workflow needs from a resolved account row. An imported xpub account has a
// NULL account_number, surfaced as a nil AccountNumber so the derivation
// callback receives no wallet-derived number; xpub-based derivation keys off
// the account public key alone. A derived account's number is passed through.
func buildHorizonAccount(row horizonAccountRow) (*db.HorizonAccount, error) {
	schema, err := db.DerivedAddressAccountSchema(
		row.internalTypeID, row.externalTypeID,
	)
	if err != nil {
		return nil, fmt.Errorf("account addr schema: %w", err)
	}

	// A derived account carries a real BIP44 number; an imported xpub
	// account has a NULL account_number and is surfaced as nil so the shared
	// extension presents no wallet-derived number for it.
	var accountNumber *uint32
	if row.accountNumber.Valid {
		num, err := db.Int64ToUint32(row.accountNumber.Int64)
		if err != nil {
			return nil, fmt.Errorf("account number: %w", err)
		}

		accountNumber = &num
	}

	nextExternal, err := db.Int64ToUint32(row.externalKeyCount)
	if err != nil {
		return nil, fmt.Errorf("external next index: %w", err)
	}

	nextInternal, err := db.Int64ToUint32(row.internalKeyCount)
	if err != nil {
		return nil, fmt.Errorf("internal next index: %w", err)
	}

	return &db.HorizonAccount{
		AccountID:         row.id,
		AccountNumber:     accountNumber,
		AccountPubKey:     row.publicKey,
		AddrSchema:        schema,
		NextExternalIndex: nextExternal,
		NextInternalIndex: nextInternal,
	}, nil
}

// errAddressBranchOutOfRange is returned when a derived address branch index
// does not fit the SMALLINT address_branch column.
var errAddressBranchOutOfRange = errors.New(
	"address branch out of int16 range",
)

// InsertDerivedAddress persists one derived address row at a fixed index.
func (o scanHorizonOps) InsertDerivedAddress(ctx context.Context,
	accountID int64, addrType db.AddressType, branch uint32, index uint32,
	scriptPubKey []byte, pubKey []byte) error {

	if branch > math.MaxInt16 {
		return fmt.Errorf("%w: %d", errAddressBranchOutOfRange, branch)
	}

	row, err := o.qtx.CreateDerivedAddress(
		ctx, buildDerivedAddressParams(
			int64(o.walletID), accountID, addrType, scriptPubKey, pubKey,
		),
	)
	if err != nil {
		return fmt.Errorf("create derived address: %w", err)
	}

	err = o.qtx.CreateDerivedAddressPath(
		ctx, sqlc.CreateDerivedAddressPathParams{
			AddressID:     row.ID,
			AccountID:     accountID,
			AddressBranch: int16(branch),
			AddressIndex:  int64(index),
		},
	)
	if err != nil {
		return fmt.Errorf("create derived address path: %w", err)
	}

	return nil
}

// AdvanceNextIndex moves the branch's next-index counter up to nextIndex.
func (o scanHorizonOps) AdvanceNextIndex(ctx context.Context, accountID int64,
	branch uint32, nextIndex uint32) error {

	if branch == 1 {
		err := o.qtx.AdvanceNextInternalIndex(
			ctx, sqlc.AdvanceNextInternalIndexParams{
				NextIndex: int64(nextIndex),
				ID:        accountID,
			},
		)
		if err != nil {
			return fmt.Errorf("advance internal index: %w", err)
		}

		return nil
	}

	err := o.qtx.AdvanceNextExternalIndex(
		ctx, sqlc.AdvanceNextExternalIndexParams{
			NextIndex: int64(nextIndex),
			ID:        accountID,
		},
	)
	if err != nil {
		return fmt.Errorf("advance external index: %w", err)
	}

	return nil
}

// horizonAccountByID resolves the horizon's owning account by stable account
// row ID and verifies that the account belongs to the horizon's key scope.
func (o scanHorizonOps) horizonAccountByID(ctx context.Context,
	accountID uint32, scope db.KeyScope) (*db.HorizonAccount, error) {

	row, err := o.qtx.GetAccountPropsByWalletAndId(
		ctx, sqlc.GetAccountPropsByWalletAndIdParams{
			WalletID: int64(o.walletID),
			ID:       int64(accountID),
		},
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, db.ErrAccountNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get account by id %d: %w", accountID, err)
	}

	scopeMatches := row.Purpose == int64(scope.Purpose) &&
		row.CoinType == int64(scope.Coin)
	if !scopeMatches {
		return nil, db.ErrAccountNotFound
	}

	return buildHorizonAccount(horizonAccountRow{
		id:               int64(accountID),
		accountNumber:    row.AccountNumber,
		publicKey:        row.PublicKey,
		internalTypeID:   row.InternalTypeID,
		externalTypeID:   row.ExternalTypeID,
		externalKeyCount: row.ExternalKeyCount,
		internalKeyCount: row.InternalKeyCount,
	})
}
