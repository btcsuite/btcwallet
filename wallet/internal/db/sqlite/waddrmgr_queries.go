package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	sqlitedb "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// sqliteScopeParams converts a key scope into SQLite generated-query
// parameters.
func sqliteScopeParams(walletID int64,
	scope waddrmgr.KeyScope) sqlitedb.GetKeyScopeParams {

	return sqlitedb.GetKeyScopeParams{
		WalletID: walletID,
		Purpose:  int64(scope.Purpose),
		CoinType: int64(scope.Coin),
	}
}

// sqliteKeyScope converts a SQLite key-scope row into durable manager state.
func sqliteKeyScope(
	row sqlitedb.KeyScope) (waddrmgr.KeyScopeState, error) {

	purpose, err := sqlstore.CheckedUint32(row.Purpose, "scope purpose")
	if err != nil {
		return waddrmgr.KeyScopeState{}, err
	}

	coin, err := sqlstore.CheckedUint32(row.CoinType, "scope coin type")
	if err != nil {
		return waddrmgr.KeyScopeState{}, err
	}

	external, err := sqlstore.CheckedUint8(
		row.ExternalAddrType, "external address type",
	)
	if err != nil {
		return waddrmgr.KeyScopeState{}, err
	}

	internal, err := sqlstore.CheckedUint8(
		row.InternalAddrType, "internal address type",
	)
	if err != nil {
		return waddrmgr.KeyScopeState{}, err
	}

	lastAccount := uint32(waddrmgr.NoAccount)
	if row.LastAccountNumber.Valid {
		lastAccount, err = sqlstore.CheckedUint32(
			row.LastAccountNumber.Int64, "last account number",
		)
		if err != nil {
			return waddrmgr.KeyScopeState{}, err
		}
	}

	return waddrmgr.KeyScopeState{
		Scope: waddrmgr.KeyScope{
			Purpose: purpose,
			Coin:    coin,
		},
		AddrSchema: waddrmgr.ScopeAddrSchema{
			ExternalAddrType: waddrmgr.AddressType(external),
			InternalAddrType: waddrmgr.AddressType(internal),
		},
		EncryptedCoinPubKey:  row.EncryptedCoinPubKey,
		EncryptedCoinPrivKey: row.EncryptedCoinPrivKey,
		LastAccount:          lastAccount,
	}, nil
}

// sqliteAccount converts a SQLite account row into durable manager state.
//
//nolint:cyclop // Nullable legacy account variants require explicit checks.
func sqliteAccount(scope waddrmgr.KeyScope,
	row sqlitedb.Account) (waddrmgr.AccountState, error) {

	account, err := sqlstore.CheckedUint32(row.AccountNumber, "account number")
	if err != nil {
		return waddrmgr.AccountState{}, err
	}

	accountType, err := sqlstore.CheckedUint8(row.AccountType, "account type")
	if err != nil {
		return waddrmgr.AccountState{}, err
	}

	nextExternal, err := sqlstore.CheckedUint32(
		row.NextExternalIndex, "next external index",
	)
	if err != nil {
		return waddrmgr.AccountState{}, err
	}

	nextInternal, err := sqlstore.CheckedUint32(
		row.NextInternalIndex, "next internal index",
	)
	if err != nil {
		return waddrmgr.AccountState{}, err
	}

	var fingerprint uint32
	if row.MasterKeyFingerprint.Valid {
		fingerprint, err = sqlstore.CheckedUint32(
			row.MasterKeyFingerprint.Int64, "master key fingerprint",
		)
		if err != nil {
			return waddrmgr.AccountState{}, err
		}
	}

	state := waddrmgr.AccountState{
		Scope:                scope,
		Account:              account,
		Type:                 waddrmgr.AccountType(accountType),
		Name:                 row.AccountName,
		EncryptedPubKey:      row.EncryptedPubKey,
		EncryptedPrivKey:     row.EncryptedPrivKey,
		MasterKeyFingerprint: fingerprint,
		NextExternalIndex:    nextExternal,
		NextInternalIndex:    nextInternal,
	}
	if row.ExternalAddrType.Valid && row.InternalAddrType.Valid {
		external, err := sqlstore.CheckedUint8(
			row.ExternalAddrType.Int64, "external address type",
		)
		if err != nil {
			return waddrmgr.AccountState{}, err
		}

		internal, err := sqlstore.CheckedUint8(
			row.InternalAddrType.Int64, "internal address type",
		)
		if err != nil {
			return waddrmgr.AccountState{}, err
		}

		state.AddrSchema = &waddrmgr.ScopeAddrSchema{
			ExternalAddrType: waddrmgr.AddressType(external),
			InternalAddrType: waddrmgr.AddressType(internal),
		}
	}

	return state, nil
}

// sqliteUint32 converts a SQLite nullable integer into an optional uint32.
//
//nolint:nilnil // A NULL SQL column maps to an absent optional field.
func sqliteUint32(value sql.NullInt64, field string) (*uint32, error) {
	if !value.Valid {
		return nil, nil
	}

	converted, err := sqlstore.CheckedUint32(value.Int64, field)
	if err != nil {
		return nil, err
	}

	return &converted, nil
}

// sqliteUint8 converts a SQLite nullable integer into an optional uint8.
//
//nolint:nilnil // A NULL SQL column maps to an absent optional field.
func sqliteUint8(value sql.NullInt64, field string) (*uint8, error) {
	if !value.Valid {
		return nil, nil
	}

	converted, err := sqlstore.CheckedUint8(value.Int64, field)
	if err != nil {
		return nil, err
	}

	return &converted, nil
}

// sqliteBool converts a SQLite nullable bool into an optional bool.
func sqliteBool(value sql.NullBool) *bool {
	if !value.Valid {
		return nil
	}

	converted := value.Bool

	return &converted
}

// sqliteAddress converts a SQLite address row into durable manager state.
func sqliteAddress(scope waddrmgr.KeyScope,
	row sqlitedb.Address) (waddrmgr.AddressState, error) {

	account, err := sqlstore.CheckedUint32(row.AccountNumber, "account number")
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	addressType, err := sqlstore.CheckedUint8(row.AddressType, "address type")
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	syncStatus, err := sqlstore.CheckedUint8(row.SyncStatus, "sync status")
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	branch, err := sqliteUint32(row.Branch, "address branch")
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	index, err := sqliteUint32(row.AddressIndex, "address index")
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	witnessVersion, err := sqliteUint8(
		row.WitnessVersion, "witness version",
	)
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	return waddrmgr.AddressState{
		Scope:            scope,
		Hash:             row.AddressHash,
		Account:          account,
		Type:             waddrmgr.StoreAddressType(addressType),
		AddedAt:          time.Unix(row.AddedAt, 0),
		SyncStatus:       waddrmgr.AddressSyncStatus(syncStatus),
		Branch:           branch,
		Index:            index,
		EncryptedPubKey:  row.EncryptedPubKey,
		EncryptedPrivKey: row.EncryptedPrivKey,
		EncryptedHash:    row.EncryptedHash,
		EncryptedScript:  row.EncryptedScript,
		WitnessVersion:   witnessVersion,
		IsSecretScript:   sqliteBool(row.IsSecretScript),
		Used:             row.Used,
	}, nil
}

// sqliteBlockStamp converts SQLite block columns into a validated BlockStamp.
func sqliteBlockStamp(height int64, hashBytes []byte,
	timestamp int64) (waddrmgr.BlockStamp, error) {

	hash, err := chainhash.NewHash(hashBytes)
	if err != nil {
		return waddrmgr.BlockStamp{}, err
	}

	heightValue, err := sqlstore.CheckedInt32(height, "block height")
	if err != nil {
		return waddrmgr.BlockStamp{}, err
	}

	return waddrmgr.BlockStamp{
		Height:    heightValue,
		Hash:      *hash,
		Timestamp: time.Unix(timestamp, 0),
	}, nil
}

// WalletIDByName resolves a SQLite wallet row identifier by name.
func (q *queryAdapter) WalletIDByName(ctx context.Context,
	name string) (int64, error) {

	row, err := q.queries.GetWalletByName(ctx, name)
	return row.ID, err
}

// CreateWallet creates the SQLite root manager row.
func (q *queryAdapter) CreateWallet(ctx context.Context, name string,
	state waddrmgr.ManagerState) (int64, error) {

	return q.queries.CreateWallet(ctx, sqlitedb.CreateWalletParams{
		WalletName:               name,
		ManagerVersion:           int64(state.Version),
		ManagerCreatedAt:         state.CreatedAt.Unix(),
		IsWatchOnly:              state.WatchOnly,
		MasterPubParams:          state.MasterPubParams,
		MasterPrivParams:         state.MasterPrivParams,
		EncryptedCryptoPubKey:    state.EncryptedCryptoPubKey,
		EncryptedCryptoPrivKey:   state.EncryptedCryptoPrivKey,
		EncryptedCryptoScriptKey: state.EncryptedCryptoScriptKey,
		EncryptedMasterHdPubKey:  state.EncryptedMasterHDPubKey,
		EncryptedMasterHdPrivKey: state.EncryptedMasterHDPrivKey,
	})
}

// CreateSyncState creates the initial SQLite wallet synchronization row.
func (q *queryAdapter) CreateSyncState(ctx context.Context, walletID int64,
	state waddrmgr.SyncState) error {

	birthdayHeight := sql.NullInt64{}
	if state.BirthdayBlock != nil {
		birthdayHeight = sql.NullInt64{
			Int64: int64(state.BirthdayBlock.Height),
			Valid: true,
		}
	}

	return q.queries.PutWalletSyncState(
		ctx, sqlitedb.PutWalletSyncStateParams{
			WalletID:              walletID,
			StartBlockHeight:      int64(state.StartBlock.Height),
			SyncedBlockHeight:     int64(state.SyncedTo.Height),
			BirthdayTimestamp:     state.Birthday.Unix(),
			BirthdayBlockHeight:   birthdayHeight,
			BirthdayBlockVerified: state.BirthdayBlockVerified,
		},
	)
}

// GetManagerState reads manager state from the transaction-bound backend.
func (q *queryAdapter) GetManagerState(ctx context.Context,
	walletID int64) (waddrmgr.ManagerState, error) {

	row, err := q.queries.GetManagerState(ctx, walletID)
	if err != nil {
		return waddrmgr.ManagerState{}, err
	}

	version, err := sqlstore.CheckedUint32(
		row.ManagerVersion, "manager version",
	)
	if err != nil {
		return waddrmgr.ManagerState{}, err
	}

	return waddrmgr.ManagerState{
		Version:                  version,
		CreatedAt:                time.Unix(row.ManagerCreatedAt, 0),
		WatchOnly:                row.IsWatchOnly,
		MasterPubParams:          row.MasterPubParams,
		MasterPrivParams:         row.MasterPrivParams,
		EncryptedCryptoPubKey:    row.EncryptedCryptoPubKey,
		EncryptedCryptoPrivKey:   row.EncryptedCryptoPrivKey,
		EncryptedCryptoScriptKey: row.EncryptedCryptoScriptKey,
		EncryptedMasterHDPubKey:  row.EncryptedMasterHdPubKey,
		EncryptedMasterHDPrivKey: row.EncryptedMasterHdPrivKey,
	}, nil
}

// PutManagerState stores manager state through the transaction-bound backend.
func (q *queryAdapter) PutManagerState(ctx context.Context, walletID int64,
	state waddrmgr.ManagerState) (int64, error) {

	return q.queries.PutManagerState(ctx, sqlitedb.PutManagerStateParams{
		ManagerVersion:           int64(state.Version),
		ManagerCreatedAt:         state.CreatedAt.Unix(),
		IsWatchOnly:              state.WatchOnly,
		MasterPubParams:          state.MasterPubParams,
		MasterPrivParams:         state.MasterPrivParams,
		EncryptedCryptoPubKey:    state.EncryptedCryptoPubKey,
		EncryptedCryptoPrivKey:   state.EncryptedCryptoPrivKey,
		EncryptedCryptoScriptKey: state.EncryptedCryptoScriptKey,
		EncryptedMasterHdPubKey:  state.EncryptedMasterHDPubKey,
		EncryptedMasterHdPrivKey: state.EncryptedMasterHDPrivKey,
		ID:                       walletID,
	})
}

// GetSyncState reads sync state from the transaction-bound backend.
func (q *queryAdapter) GetSyncState(ctx context.Context,
	walletID int64) (waddrmgr.SyncState, error) {

	row, err := q.queries.GetWalletSyncState(ctx, walletID)
	if err != nil {
		return waddrmgr.SyncState{}, err
	}

	start, err := sqliteBlockStamp(
		row.StartBlockHeight, row.StartBlockHash, row.StartBlockTimestamp,
	)
	if err != nil {
		return waddrmgr.SyncState{}, fmt.Errorf("decode start block: %w", err)
	}

	synced, err := sqliteBlockStamp(
		row.SyncedBlockHeight, row.SyncedBlockHash,
		row.SyncedBlockTimestamp,
	)
	if err != nil {
		return waddrmgr.SyncState{}, fmt.Errorf("decode synced block: %w", err)
	}

	state := waddrmgr.SyncState{
		StartBlock:            start,
		SyncedTo:              synced,
		Birthday:              time.Unix(row.BirthdayTimestamp, 0),
		BirthdayBlockVerified: row.BirthdayBlockVerified,
	}
	if row.BirthdayBlockHeight.Valid {
		birthday, err := sqliteBlockStamp(
			row.BirthdayBlockHeight.Int64, row.BirthdayBlockHash,
			row.BirthdayBlockTimestamp.Int64,
		)
		if err != nil {
			return waddrmgr.SyncState{}, fmt.Errorf(
				"decode birthday block: %w", err,
			)
		}

		state.BirthdayBlock = &birthday
	}

	return state, nil
}

// PutSyncState stores sync state through the transaction-bound backend.
func (q *queryAdapter) PutSyncState(ctx context.Context, walletID int64,
	state waddrmgr.SyncState) (int64, error) {

	birthdayHeight := sql.NullInt64{}
	if state.BirthdayBlock != nil {
		birthdayHeight = sql.NullInt64{
			Int64: int64(state.BirthdayBlock.Height),
			Valid: true,
		}
	}

	return q.queries.UpdateWalletSyncState(
		ctx, sqlitedb.UpdateWalletSyncStateParams{
			StartBlockHeight:      int64(state.StartBlock.Height),
			SyncedBlockHeight:     int64(state.SyncedTo.Height),
			BirthdayTimestamp:     state.Birthday.Unix(),
			BirthdayBlockHeight:   birthdayHeight,
			BirthdayBlockVerified: state.BirthdayBlockVerified,
			WalletID:              walletID,
		},
	)
}

// SetWalletBirthday updates wallet birthday through the transaction-bound
// backend.
func (q *queryAdapter) SetWalletBirthday(ctx context.Context, walletID,
	birthdayUnix int64) (int64, error) {

	return q.queries.SetWalletBirthday(ctx, sqlitedb.SetWalletBirthdayParams{
		BirthdayTimestamp: birthdayUnix,
		WalletID:          walletID,
	})
}

// SetWalletBirthdayBlock updates wallet birthday block through the
// transaction-bound backend.
func (q *queryAdapter) SetWalletBirthdayBlock(ctx context.Context,
	walletID int64, height *int32) (int64, error) {

	value := sql.NullInt64{}
	if height != nil {
		value = sql.NullInt64{Int64: int64(*height), Valid: true}
	}

	return q.queries.SetWalletBirthdayBlock(
		ctx, sqlitedb.SetWalletBirthdayBlockParams{
			BirthdayBlockHeight: value,
			WalletID:            walletID,
		},
	)
}

// SetWalletBirthdayBlockVerified updates wallet birthday block verified through
// the transaction-bound backend.
func (q *queryAdapter) SetWalletBirthdayBlockVerified(ctx context.Context,
	walletID int64, verified bool) (int64, error) {

	return q.queries.SetWalletBirthdayBlockVerified(
		ctx, sqlitedb.SetWalletBirthdayBlockVerifiedParams{
			BirthdayBlockVerified: verified,
			WalletID:              walletID,
		},
	)
}

// GetKeyScope reads key scope from the transaction-bound backend.
func (q *queryAdapter) GetKeyScope(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope) (waddrmgr.KeyScopeState, error) {

	row, err := q.queries.GetKeyScope(ctx, sqliteScopeParams(walletID, scope))
	if err != nil {
		return waddrmgr.KeyScopeState{}, err
	}

	return sqliteKeyScope(row)
}

// ListKeyScopes reads key scopes from the transaction-bound backend in stable
// order.
func (q *queryAdapter) ListKeyScopes(ctx context.Context,
	walletID int64) ([]waddrmgr.KeyScopeState, error) {

	rows, err := q.queries.ListKeyScopes(ctx, walletID)
	if err != nil {
		return nil, err
	}

	states := make([]waddrmgr.KeyScopeState, 0, len(rows))
	for _, row := range rows {
		state, err := sqliteKeyScope(row)
		if err != nil {
			return nil, err
		}

		states = append(states, state)
	}

	return states, nil
}

// PutKeyScope stores key scope through the transaction-bound backend.
func (q *queryAdapter) PutKeyScope(ctx context.Context, walletID int64,
	state waddrmgr.KeyScopeState) error {

	lastAccount := sql.NullInt64{}
	if state.LastAccount != waddrmgr.NoAccount {
		lastAccount = sql.NullInt64{
			Int64: int64(state.LastAccount),
			Valid: true,
		}
	}

	_, err := q.queries.PutKeyScope(ctx, sqlitedb.PutKeyScopeParams{
		WalletID:             walletID,
		Purpose:              int64(state.Scope.Purpose),
		CoinType:             int64(state.Scope.Coin),
		EncryptedCoinPubKey:  state.EncryptedCoinPubKey,
		EncryptedCoinPrivKey: state.EncryptedCoinPrivKey,
		LastAccountNumber:    lastAccount,
		ExternalAddrType:     int64(state.AddrSchema.ExternalAddrType),
		InternalAddrType:     int64(state.AddrSchema.InternalAddrType),
	})

	return err
}

// sqliteScopeID resolves the SQLite row identifier for a wallet key scope.
func (q *queryAdapter) sqliteScopeID(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope) (int64, error) {

	row, err := q.queries.GetKeyScope(ctx, sqliteScopeParams(walletID, scope))
	return row.ID, err
}

// SetCoinTypeKeys updates coin type keys through the transaction-bound backend.
func (q *queryAdapter) SetCoinTypeKeys(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope, encryptedPub,
	encryptedPriv []byte) (int64, error) {

	scopeID, err := q.sqliteScopeID(ctx, walletID, scope)
	if err != nil {
		return 0, err
	}

	return q.queries.UpdateKeyScopeKeys(
		ctx, sqlitedb.UpdateKeyScopeKeysParams{
			EncryptedCoinPubKey:  encryptedPub,
			EncryptedCoinPrivKey: encryptedPriv,
			ID:                   scopeID,
			WalletID:             walletID,
		},
	)
}

// SetLastAccount updates last account through the transaction-bound backend.
func (q *queryAdapter) SetLastAccount(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope, account uint32) (int64, error) {

	scopeID, err := q.sqliteScopeID(ctx, walletID, scope)
	if err != nil {
		return 0, err
	}

	return q.queries.UpdateLastAccountNumber(
		ctx, sqlitedb.UpdateLastAccountNumberParams{
			LastAccountNumber: sql.NullInt64{
				Int64: int64(account),
				Valid: true,
			},
			ID:       scopeID,
			WalletID: walletID,
		},
	)
}

// sqliteManagerAccountParams converts a scoped account identity into SQLite
// query parameters.
func sqliteManagerAccountParams(walletID int64, scope waddrmgr.KeyScope,
	account uint32) sqlitedb.GetManagerAccountParams {

	return sqlitedb.GetManagerAccountParams{
		WalletID:      walletID,
		Purpose:       int64(scope.Purpose),
		CoinType:      int64(scope.Coin),
		AccountNumber: int64(account),
	}
}

// GetAccount reads account from the transaction-bound backend.
func (q *queryAdapter) GetAccount(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope, account uint32) (waddrmgr.AccountState, error) {

	row, err := q.queries.GetManagerAccount(
		ctx, sqliteManagerAccountParams(walletID, scope, account),
	)
	if err != nil {
		return waddrmgr.AccountState{}, err
	}

	return sqliteAccount(scope, row)
}

// GetAccountByName reads account by name from the transaction-bound backend.
func (q *queryAdapter) GetAccountByName(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope, name string) (waddrmgr.AccountState, error) {

	row, err := q.queries.GetManagerAccountByName(
		ctx, sqlitedb.GetManagerAccountByNameParams{
			WalletID:    walletID,
			Purpose:     int64(scope.Purpose),
			CoinType:    int64(scope.Coin),
			AccountName: name,
		},
	)
	if err != nil {
		return waddrmgr.AccountState{}, err
	}

	return sqliteAccount(scope, row)
}

// ListAccounts reads accounts from the transaction-bound backend in stable
// order.
func (q *queryAdapter) ListAccounts(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope) ([]waddrmgr.AccountState, error) {

	rows, err := q.queries.ListManagerAccounts(
		ctx, sqlitedb.ListManagerAccountsParams{
			WalletID: walletID,
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		},
	)
	if err != nil {
		return nil, err
	}

	states := make([]waddrmgr.AccountState, 0, len(rows))
	for _, row := range rows {
		state, err := sqliteAccount(scope, row)
		if err != nil {
			return nil, err
		}

		states = append(states, state)
	}

	return states, nil
}

// sqliteNullAddrTypes converts an optional address schema into SQLite nullable
// values.
func sqliteNullAddrTypes(schema *waddrmgr.ScopeAddrSchema) (
	sql.NullInt64, sql.NullInt64) {

	if schema == nil {
		return sql.NullInt64{}, sql.NullInt64{}
	}

	return sql.NullInt64{
			Int64: int64(schema.ExternalAddrType), Valid: true,
		}, sql.NullInt64{
			Int64: int64(schema.InternalAddrType), Valid: true,
		}
}

// PutAccount stores account through the transaction-bound backend.
func (q *queryAdapter) PutAccount(ctx context.Context, walletID int64,
	state waddrmgr.AccountState) (int64, error) {

	external, internal := sqliteNullAddrTypes(state.AddrSchema)

	fingerprint := sql.NullInt64{}
	if state.Type == waddrmgr.AccountWatchOnly {
		fingerprint = sql.NullInt64{
			Int64: int64(state.MasterKeyFingerprint), Valid: true,
		}
	}

	return q.queries.PutManagerAccount(
		ctx, sqlitedb.PutManagerAccountParams{
			AccountNumber:        int64(state.Account),
			AccountType:          int64(state.Type),
			AccountName:          state.Name,
			EncryptedPubKey:      state.EncryptedPubKey,
			EncryptedPrivKey:     state.EncryptedPrivKey,
			MasterKeyFingerprint: fingerprint,
			NextExternalIndex:    int64(state.NextExternalIndex),
			NextInternalIndex:    int64(state.NextInternalIndex),
			ExternalAddrType:     external,
			InternalAddrType:     internal,
			WalletID:             walletID,
			Purpose:              int64(state.Scope.Purpose),
			CoinType:             int64(state.Scope.Coin),
		},
	)
}

// RenameAccount updates an account name through the transaction-bound backend.
func (q *queryAdapter) RenameAccount(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope, account uint32, name string) (int64, error) {

	scopeID, err := q.sqliteScopeID(ctx, walletID, scope)
	if err != nil {
		return 0, err
	}

	return q.queries.RenameAccount(ctx, sqlitedb.RenameAccountParams{
		AccountName:   name,
		ScopeID:       scopeID,
		AccountNumber: int64(account),
	})
}

// SetAccountIndexes updates account indexes through the transaction-bound
// backend.
func (q *queryAdapter) SetAccountIndexes(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope, account, nextExternal,
	nextInternal uint32) (int64, error) {

	scopeID, err := q.sqliteScopeID(ctx, walletID, scope)
	if err != nil {
		return 0, err
	}

	return q.queries.UpdateAccountIndexes(
		ctx, sqlitedb.UpdateAccountIndexesParams{
			NextExternalIndex: int64(nextExternal),
			NextInternalIndex: int64(nextInternal),
			ScopeID:           scopeID,
			AccountNumber:     int64(account),
		},
	)
}

// GetAddress reads address from the transaction-bound backend.
func (q *queryAdapter) GetAddress(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope, hash []byte) (waddrmgr.AddressState, error) {

	row, err := q.queries.GetManagerAddress(
		ctx, sqlitedb.GetManagerAddressParams{
			WalletID:    walletID,
			Purpose:     int64(scope.Purpose),
			CoinType:    int64(scope.Coin),
			AddressHash: hash,
		},
	)
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	return sqliteAddress(scope, row)
}

// ListAccountAddresses reads account addresses from the transaction-bound
// backend in stable order.
func (q *queryAdapter) ListAccountAddresses(ctx context.Context,
	walletID int64, scope waddrmgr.KeyScope,
	account uint32) ([]waddrmgr.AddressState, error) {

	rows, err := q.queries.ListManagerAccountAddresses(
		ctx, sqlitedb.ListManagerAccountAddressesParams{
			WalletID:      walletID,
			Purpose:       int64(scope.Purpose),
			CoinType:      int64(scope.Coin),
			AccountNumber: int64(account),
		},
	)
	if err != nil {
		return nil, err
	}

	states := make([]waddrmgr.AddressState, 0, len(rows))
	for _, row := range rows {
		state, err := sqliteAddress(scope, row)
		if err != nil {
			return nil, err
		}

		states = append(states, state)
	}

	return states, nil
}

// ListActiveAddresses reads active addresses from the transaction-bound backend
// in stable order.
func (q *queryAdapter) ListActiveAddresses(ctx context.Context,
	walletID int64,
	scope waddrmgr.KeyScope) ([]waddrmgr.AddressState, error) {

	rows, err := q.queries.ListManagerActiveAddresses(
		ctx, sqlitedb.ListManagerActiveAddressesParams{
			WalletID: walletID,
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		},
	)
	if err != nil {
		return nil, err
	}

	states := make([]waddrmgr.AddressState, 0, len(rows))
	for _, row := range rows {
		state, err := sqliteAddress(scope, row)
		if err != nil {
			return nil, err
		}

		states = append(states, state)
	}

	return states, nil
}

// sqliteNullUint32 converts an optional uint32 into a SQLite nullable value.
func sqliteNullUint32(value *uint32) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{Int64: int64(*value), Valid: true}
}

// sqliteNullUint8 converts an optional uint8 into a SQLite nullable value.
func sqliteNullUint8(value *uint8) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{Int64: int64(*value), Valid: true}
}

// sqliteNullBool converts an optional bool into a SQLite nullable value.
func sqliteNullBool(value *bool) sql.NullBool {
	if value == nil {
		return sql.NullBool{}
	}

	return sql.NullBool{Bool: *value, Valid: true}
}

// PutAddress stores address through the transaction-bound backend.
func (q *queryAdapter) PutAddress(ctx context.Context, walletID int64,
	state waddrmgr.AddressState) (int64, error) {

	return q.queries.PutManagerAddress(
		ctx, sqlitedb.PutManagerAddressParams{
			AddressHash:      state.Hash,
			AccountNumber:    int64(state.Account),
			AddressType:      int64(state.Type),
			AddedAt:          state.AddedAt.Unix(),
			SyncStatus:       int64(state.SyncStatus),
			Branch:           sqliteNullUint32(state.Branch),
			AddressIndex:     sqliteNullUint32(state.Index),
			EncryptedPubKey:  state.EncryptedPubKey,
			EncryptedPrivKey: state.EncryptedPrivKey,
			EncryptedHash:    state.EncryptedHash,
			EncryptedScript:  state.EncryptedScript,
			WitnessVersion:   sqliteNullUint8(state.WitnessVersion),
			IsSecretScript:   sqliteNullBool(state.IsSecretScript),
			Used:             state.Used,
			WalletID:         walletID,
			Purpose:          int64(state.Scope.Purpose),
			CoinType:         int64(state.Scope.Coin),
		},
	)
}

// MarkAddressUsed marks address used in the transaction-bound backend.
func (q *queryAdapter) MarkAddressUsed(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope, hash []byte) (int64, error) {

	scopeID, err := q.sqliteScopeID(ctx, walletID, scope)
	if err != nil {
		return 0, err
	}

	return q.queries.MarkAddressUsed(ctx, sqlitedb.MarkAddressUsedParams{
		WalletID:    walletID,
		ScopeID:     scopeID,
		AddressHash: hash,
	})
}

// DeletePrivateKeys removes private keys through the transaction-bound backend.
func (q *queryAdapter) DeletePrivateKeys(ctx context.Context,
	walletID int64) error {

	operations := []func(context.Context, int64) (int64, error){
		q.queries.DeleteManagerPrivateKeys,
		q.queries.DeleteKeyScopePrivateKeys,
		q.queries.DeleteAccountPrivateKeys,
		q.queries.DeleteAddressPrivateKeys,
	}
	for _, operation := range operations {
		_, err := operation(ctx, walletID)
		if err != nil {
			return err
		}
	}

	return nil
}
