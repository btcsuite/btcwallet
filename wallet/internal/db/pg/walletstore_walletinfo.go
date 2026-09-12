package pg

import (
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// walletInfoRow is a type constraint for PostgreSQL wallet info row types
// that share the same field structure. This enables a single generic conversion
// function to handle all wallet query result types.
type walletInfoRow interface {
	sqlc.GetWalletByIDRow | sqlc.GetWalletByNameRow | sqlc.ListWalletsRow
}

// walletRowParams holds the parameters needed to build a WalletInfo
// from a wallet row.
type walletRowParams struct {
	id                     int64
	name                   string
	isImported             bool
	managerVersion         int32
	isWatchOnly            bool
	syncedHeight           sql.NullInt32
	syncedBlockHash        []byte
	syncedBlockTimestamp   sql.NullInt64
	birthdayHeight         sql.NullInt32
	birthdayTimestamp      sql.NullTime
	birthdayBlockHash      []byte
	birthdayBlockTimestamp sql.NullInt64
	masterPubKey           []byte
}

// walletRowToInfo converts a wallet row to WalletInfo, handling type
// conversions across different sqlc row types.
func walletRowToInfo[T walletInfoRow](row T) (*db.WalletInfo, error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlc.GetWalletByIDRow(row)

	return buildWalletInfo(walletRowParams{
		id:                     base.ID,
		name:                   base.WalletName,
		isImported:             base.IsImported,
		managerVersion:         base.ManagerVersion,
		isWatchOnly:            base.IsWatchOnly,
		syncedHeight:           base.SyncedHeight,
		syncedBlockHash:        base.SyncedBlockHash,
		syncedBlockTimestamp:   base.SyncedBlockTimestamp,
		birthdayHeight:         base.BirthdayHeight,
		birthdayTimestamp:      base.BirthdayTimestamp,
		birthdayBlockHash:      base.BirthdayBlockHash,
		birthdayBlockTimestamp: base.BirthdayBlockTimestamp,
		masterPubKey:           base.MasterHdPubKey,
	})
}

// buildWalletInfo constructs a WalletInfo from the given wallet row
// parameters.
func buildWalletInfo(row walletRowParams) (*db.WalletInfo, error) {
	walletID, err := db.Int64ToUint32(row.id)
	if err != nil {
		return nil, err
	}

	info := &db.WalletInfo{
		ID:             walletID,
		Name:           row.name,
		IsImported:     row.isImported,
		ManagerVersion: row.managerVersion,
		IsWatchOnly:    row.isWatchOnly,
		MasterPubKey:   row.masterPubKey,
	}

	if row.birthdayTimestamp.Valid {
		info.Birthday = row.birthdayTimestamp.Time
	}

	if row.syncedHeight.Valid {
		block, err := buildBlock(
			row.syncedHeight,
			row.syncedBlockHash,
			row.syncedBlockTimestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("synced block: %w", err)
		}

		info.SyncedTo = block
	}

	if row.birthdayHeight.Valid {
		block, err := buildBlock(
			row.birthdayHeight,
			row.birthdayBlockHash,
			row.birthdayBlockTimestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("birthday block: %w", err)
		}

		info.BirthdayBlock = block
	}

	return info, nil
}
