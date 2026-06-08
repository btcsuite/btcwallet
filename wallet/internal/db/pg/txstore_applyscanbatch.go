package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// scanHorizonOps adapts the PostgreSQL sqlc queries to the shared horizon
// extension workflow.
type scanHorizonOps struct {
	qtx      *sqlc.Queries
	walletID uint32
}

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

// GetHorizonAccount loads the account state needed to extend a horizon. It
// resolves the owning account by the durable, scope-unique AccountName whenever
// the horizon carries one, falling back to the BIP44 account number only when
// the name is absent. Resolving by name is mandatory because the AccountInfo
// contract masks an imported account's number to 0, so a by-number lookup would
// resolve an imported-account horizon to the default derived account (also 0)
// and silently extend the wrong account.
func (o scanHorizonOps) GetHorizonAccount(ctx context.Context,
	horizon db.ScanHorizon) (*db.HorizonAccount, error) {

	if horizon.AccountName != "" {
		return o.horizonAccountByName(ctx, horizon)
	}

	return o.horizonAccountByNumber(ctx, horizon.Scope, horizon.Account)
}

// buildHorizonAccount assembles the HorizonAccount the shared extension
// workflow needs from a resolved account row. An imported account has a NULL
// account_number, masked to 0 here just as AccountInfo does; xpub-based
// derivation keys off the account public key, so the masked number is correct.
func buildHorizonAccount(row horizonAccountRow) (*db.HorizonAccount, error) {
	schema, err := db.DerivedAddressAccountSchema(
		row.internalTypeID, row.externalTypeID,
	)
	if err != nil {
		return nil, fmt.Errorf("account addr schema: %w", err)
	}

	var accountNumber uint32
	if row.accountNumber.Valid {
		accountNumber, err = db.Int64ToUint32(row.accountNumber.Int64)
		if err != nil {
			return nil, fmt.Errorf("account number: %w", err)
		}
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

// horizonAccountByName resolves the horizon's owning account by its scope and
// account name. A name miss returns the error unchanged rather than falling
// back to the account number: a renamed or removed account must fail the scan
// batch, never silently extend the default account 0 (mirrors the kvdb
// resolveLegacyHorizonAccount fail-safe).
func (o scanHorizonOps) horizonAccountByName(ctx context.Context,
	horizon db.ScanHorizon) (*db.HorizonAccount, error) {

	row, err := o.qtx.GetAccountByWalletScopeAndName(
		ctx, sqlc.GetAccountByWalletScopeAndNameParams{
			WalletID:    int64(o.walletID),
			Purpose:     int64(horizon.Scope.Purpose),
			CoinType:    int64(horizon.Scope.Coin),
			AccountName: horizon.AccountName,
		},
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, db.ErrAccountNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get account by name %q: %w",
			horizon.AccountName, err)
	}

	return buildHorizonAccount(horizonAccountRow{
		id:               row.ID,
		accountNumber:    row.AccountNumber,
		publicKey:        row.PublicKey,
		internalTypeID:   row.InternalTypeID,
		externalTypeID:   row.ExternalTypeID,
		externalKeyCount: row.ExternalKeyCount,
		internalKeyCount: row.InternalKeyCount,
	})
}

// horizonAccountByNumber resolves the horizon's owning account by its scope and
// BIP44 account number. It is the fast path used only when no account name
// accompanies the horizon and is trustworthy only for derived accounts.
func (o scanHorizonOps) horizonAccountByNumber(ctx context.Context,
	scope db.KeyScope, accountNumber uint32) (*db.HorizonAccount, error) {

	row, err := o.qtx.GetAccountByWalletScopeAndNumber(
		ctx, sqlc.GetAccountByWalletScopeAndNumberParams{
			WalletID:      int64(o.walletID),
			Purpose:       int64(scope.Purpose),
			CoinType:      int64(scope.Coin),
			AccountNumber: db.NullableUint32ToSQLInt64(&accountNumber),
		},
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, db.ErrAccountNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}

	return buildHorizonAccount(horizonAccountRow{
		id:               row.ID,
		accountNumber:    row.AccountNumber,
		publicKey:        row.PublicKey,
		internalTypeID:   row.InternalTypeID,
		externalTypeID:   row.ExternalTypeID,
		externalKeyCount: row.ExternalKeyCount,
		internalKeyCount: row.InternalKeyCount,
	})
}
