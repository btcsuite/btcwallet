package pg

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	pgdb "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// pgScopeParams converts a key scope into PostgreSQL generated-query
// parameters.
func pgScopeParams(walletID int64,
	scope waddrmgr.KeyScope) pgdb.GetKeyScopeParams {

	return pgdb.GetKeyScopeParams{
		WalletID: walletID,
		Purpose:  int64(scope.Purpose),
		CoinType: int64(scope.Coin),
	}
}

// pgKeyScope converts a PostgreSQL key-scope row into durable manager state.
func pgKeyScope(row pgdb.KeyScope) (waddrmgr.KeyScopeState, error) {
	purpose, err := sqlstore.CheckedUint32(row.Purpose, "scope purpose")
	if err != nil {
		return waddrmgr.KeyScopeState{}, err
	}

	coin, err := sqlstore.CheckedUint32(row.CoinType, "scope coin type")
	if err != nil {
		return waddrmgr.KeyScopeState{}, err
	}

	external, err := sqlstore.CheckedUint8(
		int64(row.ExternalAddrType), "external address type",
	)
	if err != nil {
		return waddrmgr.KeyScopeState{}, err
	}

	internal, err := sqlstore.CheckedUint8(
		int64(row.InternalAddrType), "internal address type",
	)
	if err != nil {
		return waddrmgr.KeyScopeState{}, err
	}

	// A NULL last-account column means the scope has never allocated an
	// account, which the legacy manager reports with the no-account
	// sentinel rather than a real account 0.
	lastAccount := waddrmgr.NoAccountAllocated
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

// pgAccount converts a PostgreSQL account row into durable manager state.
//
//nolint:cyclop // Nullable legacy account variants require explicit checks.
func pgAccount(scope waddrmgr.KeyScope,
	row pgdb.Account) (waddrmgr.AccountState, error) {

	account, err := sqlstore.CheckedUint32(row.AccountNumber, "account number")
	if err != nil {
		return waddrmgr.AccountState{}, err
	}

	accountType, err := sqlstore.CheckedUint8(
		int64(row.AccountType), "account type",
	)
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
			int64(row.ExternalAddrType.Int16), "external address type",
		)
		if err != nil {
			return waddrmgr.AccountState{}, err
		}

		internal, err := sqlstore.CheckedUint8(
			int64(row.InternalAddrType.Int16), "internal address type",
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

// pgUint32 converts a PostgreSQL nullable integer into an optional uint32.
//
//nolint:nilnil // A NULL SQL column maps to an absent optional field.
func pgUint32(value sql.NullInt64, field string) (*uint32, error) {
	if !value.Valid {
		return nil, nil
	}

	converted, err := sqlstore.CheckedUint32(value.Int64, field)
	if err != nil {
		return nil, err
	}

	return &converted, nil
}

// pgUint8 converts a PostgreSQL nullable integer into an optional uint8.
//
//nolint:nilnil // A NULL SQL column maps to an absent optional field.
func pgUint8(value sql.NullInt16, field string) (*uint8, error) {
	if !value.Valid {
		return nil, nil
	}

	converted, err := sqlstore.CheckedUint8(int64(value.Int16), field)
	if err != nil {
		return nil, err
	}

	return &converted, nil
}

// pgBool converts a PostgreSQL nullable bool into an optional bool.
func pgBool(value sql.NullBool) *bool {
	if !value.Valid {
		return nil
	}

	converted := value.Bool

	return &converted
}

// pgAddress converts a PostgreSQL address row into durable manager state.
func pgAddress(scope waddrmgr.KeyScope,
	row pgdb.Address) (waddrmgr.AddressState, error) {

	account, err := sqlstore.CheckedUint32(row.AccountNumber, "account number")
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	addressType, err := sqlstore.CheckedUint8(
		int64(row.AddressType), "address type",
	)
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	syncStatus, err := sqlstore.CheckedUint8(
		int64(row.SyncStatus), "sync status",
	)
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	branch, err := pgUint32(row.Branch, "address branch")
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	index, err := pgUint32(row.AddressIndex, "address index")
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	witnessVersion, err := pgUint8(row.WitnessVersion, "witness version")
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
		IsSecretScript:   pgBool(row.IsSecretScript),
		Used:             row.Used,
	}, nil
}

// pgBlockStamp converts PostgreSQL block columns into a validated BlockStamp.
func pgBlockStamp(height int32, hashBytes []byte,
	timestamp int64) (waddrmgr.BlockStamp, error) {

	hash, err := chainhash.NewHash(hashBytes)
	if err != nil {
		return waddrmgr.BlockStamp{}, err
	}

	return waddrmgr.BlockStamp{
		Height:    height,
		Hash:      *hash,
		Timestamp: time.Unix(timestamp, 0),
	}, nil
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

	return q.queries.PutManagerState(ctx, pgdb.PutManagerStateParams{
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

	start, err := pgBlockStamp(
		row.StartBlockHeight, row.StartBlockHash, row.StartBlockTimestamp,
	)
	if err != nil {
		return waddrmgr.SyncState{}, fmt.Errorf("decode start block: %w", err)
	}

	synced, err := pgBlockStamp(
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
		birthday, err := pgBlockStamp(
			row.BirthdayBlockHeight.Int32, row.BirthdayBlockHash,
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

	var birthdayHash []byte
	if state.BirthdayBlock != nil {
		birthdayHash = state.BirthdayBlock.Hash[:]
	}

	return q.queries.UpdateWalletSyncState(
		ctx, pgdb.UpdateWalletSyncStateParams{
			StartBlockHash:        state.StartBlock.Hash[:],
			SyncedBlockHash:       state.SyncedTo.Hash[:],
			BirthdayTimestamp:     state.Birthday.Unix(),
			BirthdayBlockHash:     birthdayHash,
			BirthdayBlockVerified: state.BirthdayBlockVerified,
			WalletID:              walletID,
		},
	)
}

// SetWalletBirthday updates wallet birthday through the transaction-bound
// backend.
func (q *queryAdapter) SetWalletBirthday(ctx context.Context, walletID,
	birthdayUnix int64) (int64, error) {

	return q.queries.SetWalletBirthday(ctx, pgdb.SetWalletBirthdayParams{
		BirthdayTimestamp: birthdayUnix,
		WalletID:          walletID,
	})
}

// SetWalletBirthdayBlock updates wallet birthday block through the
// transaction-bound backend.
func (q *queryAdapter) SetWalletBirthdayBlock(ctx context.Context,
	walletID int64, blockHash []byte) (int64, error) {

	return q.queries.SetWalletBirthdayBlock(
		ctx, pgdb.SetWalletBirthdayBlockParams{
			BlockHash: blockHash,
			WalletID:  walletID,
		},
	)
}

// SetWalletBirthdayBlockVerified updates wallet birthday block verified through
// the transaction-bound backend.
func (q *queryAdapter) SetWalletBirthdayBlockVerified(ctx context.Context,
	walletID int64, verified bool) (int64, error) {

	return q.queries.SetWalletBirthdayBlockVerified(
		ctx, pgdb.SetWalletBirthdayBlockVerifiedParams{
			BirthdayBlockVerified: verified,
			WalletID:              walletID,
		},
	)
}

// GetKeyScope reads key scope from the transaction-bound backend.
func (q *queryAdapter) GetKeyScope(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope) (waddrmgr.KeyScopeState, error) {

	row, err := q.queries.GetKeyScope(ctx, pgScopeParams(walletID, scope))
	if err != nil {
		return waddrmgr.KeyScopeState{}, err
	}

	return pgKeyScope(row)
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
		state, err := pgKeyScope(row)
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

	_, err := q.queries.PutKeyScope(ctx, pgdb.PutKeyScopeParams{
		WalletID:             walletID,
		Purpose:              int64(state.Scope.Purpose),
		CoinType:             int64(state.Scope.Coin),
		EncryptedCoinPubKey:  state.EncryptedCoinPubKey,
		EncryptedCoinPrivKey: state.EncryptedCoinPrivKey,
		LastAccountNumber:    sqlstore.NullableLastAccount(state.LastAccount),
		ExternalAddrType:     int16(state.AddrSchema.ExternalAddrType),
		InternalAddrType:     int16(state.AddrSchema.InternalAddrType),
	})

	return err
}

// pgScopeID resolves the PostgreSQL row identifier for a wallet key scope.
func (q *queryAdapter) pgScopeID(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope) (int64, error) {

	row, err := q.queries.GetKeyScope(ctx, pgScopeParams(walletID, scope))
	return row.ID, err
}

// SetCoinTypeKeys updates coin type keys through the transaction-bound backend.
func (q *queryAdapter) SetCoinTypeKeys(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope, encryptedPub,
	encryptedPriv []byte) (int64, error) {

	scopeID, err := q.pgScopeID(ctx, walletID, scope)
	if err != nil {
		return 0, err
	}

	return q.queries.UpdateKeyScopeKeys(
		ctx, pgdb.UpdateKeyScopeKeysParams{
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

	scopeID, err := q.pgScopeID(ctx, walletID, scope)
	if err != nil {
		return 0, err
	}

	return q.queries.UpdateLastAccountNumber(
		ctx, pgdb.UpdateLastAccountNumberParams{
			LastAccountNumber: sqlstore.NullableLastAccount(account),
			ID:                scopeID,
			WalletID:          walletID,
		},
	)
}

// pgManagerAccountParams converts a scoped account identity into PostgreSQL
// query parameters.
func pgManagerAccountParams(walletID int64, scope waddrmgr.KeyScope,
	account uint32) pgdb.GetManagerAccountParams {

	return pgdb.GetManagerAccountParams{
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
		ctx, pgManagerAccountParams(walletID, scope, account),
	)
	if err != nil {
		return waddrmgr.AccountState{}, err
	}

	return pgAccount(scope, row)
}

// GetAccountByName reads account by name from the transaction-bound backend.
func (q *queryAdapter) GetAccountByName(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope, name string) (waddrmgr.AccountState, error) {

	row, err := q.queries.GetManagerAccountByName(
		ctx, pgdb.GetManagerAccountByNameParams{
			WalletID:    walletID,
			Purpose:     int64(scope.Purpose),
			CoinType:    int64(scope.Coin),
			AccountName: name,
		},
	)
	if err != nil {
		return waddrmgr.AccountState{}, err
	}

	return pgAccount(scope, row)
}

// ListAccounts reads accounts from the transaction-bound backend in stable
// order.
func (q *queryAdapter) ListAccounts(ctx context.Context, walletID int64,
	scope waddrmgr.KeyScope) ([]waddrmgr.AccountState, error) {

	rows, err := q.queries.ListManagerAccounts(
		ctx, pgdb.ListManagerAccountsParams{
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
		state, err := pgAccount(scope, row)
		if err != nil {
			return nil, err
		}

		states = append(states, state)
	}

	return states, nil
}

// pgNullAddrTypes converts an optional address schema into PostgreSQL nullable
// values.
func pgNullAddrTypes(schema *waddrmgr.ScopeAddrSchema) (
	sql.NullInt16, sql.NullInt16) {

	if schema == nil {
		return sql.NullInt16{}, sql.NullInt16{}
	}

	return sql.NullInt16{
			Int16: int16(schema.ExternalAddrType), Valid: true,
		}, sql.NullInt16{
			Int16: int16(schema.InternalAddrType), Valid: true,
		}
}

// PutAccount stores account through the transaction-bound backend.
func (q *queryAdapter) PutAccount(ctx context.Context, walletID int64,
	state waddrmgr.AccountState) (int64, error) {

	external, internal := pgNullAddrTypes(state.AddrSchema)

	fingerprint := sql.NullInt64{}
	if state.Type == waddrmgr.AccountWatchOnly {
		fingerprint = sql.NullInt64{
			Int64: int64(state.MasterKeyFingerprint), Valid: true,
		}
	}

	return q.queries.PutManagerAccount(
		ctx, pgdb.PutManagerAccountParams{
			AccountNumber:        int64(state.Account),
			AccountType:          int16(state.Type),
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

	scopeID, err := q.pgScopeID(ctx, walletID, scope)
	if err != nil {
		return 0, err
	}

	return q.queries.RenameAccount(ctx, pgdb.RenameAccountParams{
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

	scopeID, err := q.pgScopeID(ctx, walletID, scope)
	if err != nil {
		return 0, err
	}

	return q.queries.UpdateAccountIndexes(
		ctx, pgdb.UpdateAccountIndexesParams{
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
		ctx, pgdb.GetManagerAddressParams{
			WalletID:    walletID,
			Purpose:     int64(scope.Purpose),
			CoinType:    int64(scope.Coin),
			AddressHash: hash,
		},
	)
	if err != nil {
		return waddrmgr.AddressState{}, err
	}

	return pgAddress(scope, row)
}

// ListAccountAddresses reads account addresses from the transaction-bound
// backend in stable order.
func (q *queryAdapter) ListAccountAddresses(ctx context.Context,
	walletID int64, scope waddrmgr.KeyScope,
	account uint32) ([]waddrmgr.AddressState, error) {

	rows, err := q.queries.ListManagerAccountAddresses(
		ctx, pgdb.ListManagerAccountAddressesParams{
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
		state, err := pgAddress(scope, row)
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
		ctx, pgdb.ListManagerActiveAddressesParams{
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
		state, err := pgAddress(scope, row)
		if err != nil {
			return nil, err
		}

		states = append(states, state)
	}

	return states, nil
}

// pgNullUint32 converts an optional uint32 into a PostgreSQL nullable value.
func pgNullUint32(value *uint32) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{Int64: int64(*value), Valid: true}
}

// pgNullUint8 converts an optional uint8 into a PostgreSQL nullable value.
func pgNullUint8(value *uint8) sql.NullInt16 {
	if value == nil {
		return sql.NullInt16{}
	}

	return sql.NullInt16{Int16: int16(*value), Valid: true}
}

// pgNullBool converts an optional bool into a PostgreSQL nullable value.
func pgNullBool(value *bool) sql.NullBool {
	if value == nil {
		return sql.NullBool{}
	}

	return sql.NullBool{Bool: *value, Valid: true}
}

// PutAddress stores address through the transaction-bound backend.
func (q *queryAdapter) PutAddress(ctx context.Context, walletID int64,
	state waddrmgr.AddressState) (int64, error) {

	return q.queries.PutManagerAddress(
		ctx, pgdb.PutManagerAddressParams{
			AddressHash:      state.Hash,
			AccountNumber:    int64(state.Account),
			AddressType:      int16(state.Type),
			AddedAt:          state.AddedAt.Unix(),
			SyncStatus:       int16(state.SyncStatus),
			Branch:           pgNullUint32(state.Branch),
			AddressIndex:     pgNullUint32(state.Index),
			EncryptedPubKey:  state.EncryptedPubKey,
			EncryptedPrivKey: state.EncryptedPrivKey,
			EncryptedHash:    state.EncryptedHash,
			EncryptedScript:  state.EncryptedScript,
			WitnessVersion:   pgNullUint8(state.WitnessVersion),
			IsSecretScript:   pgNullBool(state.IsSecretScript),
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

	scopeID, err := q.pgScopeID(ctx, walletID, scope)
	if err != nil {
		return 0, err
	}

	return q.queries.MarkAddressUsed(ctx, pgdb.MarkAddressUsedParams{
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
