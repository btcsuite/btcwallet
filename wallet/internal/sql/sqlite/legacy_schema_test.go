package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	"github.com/stretchr/testify/require"
)

// TestLegacySchemaQueries verifies that the SQL shape can represent the legacy
// wallet, scope, account, and address records without decrypting them.
func TestLegacySchemaQueries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db, err := Open(ctx, Config{
		DBPath: filepath.Join(t.TempDir(), "wallet.db"),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})
	require.NoError(t, ApplyMigrations(db))
	requireNoPlaintextColumns(t, db)

	queries := sqlc.New(db)
	genesisHash := bytesOf(0x01, 32)
	birthdayHash := bytesOf(0x02, 32)

	walletID, err := queries.CreateWallet(ctx, sqlc.CreateWalletParams{
		WalletName:            "watch-only",
		ManagerVersion:        8,
		ManagerCreatedAt:      123,
		IsWatchOnly:           true,
		MasterPubParams:       []byte("encrypted-master-public-params"),
		EncryptedCryptoPubKey: []byte("encrypted-crypto-public-key"),
	})
	require.NoError(t, err)

	for _, block := range []sqlc.EnsureBlockHeightParams{
		{
			BlockHeight:    0,
			HeaderHash:     genesisHash,
			BlockTimestamp: 1,
		},
		{
			BlockHeight:    100,
			HeaderHash:     birthdayHash,
			BlockTimestamp: 2,
		},
	} {
		require.NoError(t, queries.EnsureBlockHeight(ctx, block))
		require.NoError(t, queries.InsertBlock(
			ctx, sqlc.InsertBlockParams{
				WalletID:       walletID,
				BlockHeight:    block.BlockHeight,
				HeaderHash:     block.HeaderHash,
				BlockTimestamp: block.BlockTimestamp,
			},
		))
	}

	wallet, err := queries.GetWalletByName(ctx, "watch-only")
	require.NoError(t, err)
	require.Equal(t, int64(123), wallet.ManagerCreatedAt)
	require.Equal(t, []byte("encrypted-master-public-params"),
		wallet.MasterPubParams)
	require.Nil(t, wallet.MasterPrivParams)
	require.Equal(t, []byte("encrypted-crypto-public-key"),
		wallet.EncryptedCryptoPubKey)
	require.Nil(t, wallet.EncryptedCryptoPrivKey)
	require.Nil(t, wallet.EncryptedCryptoScriptKey)

	require.NoError(t, queries.PutWalletSyncState(
		ctx, sqlc.PutWalletSyncStateParams{
			WalletID:              walletID,
			StartBlockHeight:      0,
			SyncedBlockHeight:     100,
			BirthdayTimestamp:     1234,
			BirthdayBlockHeight:   sql.NullInt64{Int64: 100, Valid: true},
			BirthdayBlockVerified: true,
		},
	))
	syncState, err := queries.GetWalletSyncState(ctx, walletID)
	require.NoError(t, err)
	require.Equal(t, genesisHash, syncState.StartBlockHash)
	require.Equal(t, birthdayHash, syncState.SyncedBlockHash)
	require.Equal(t, birthdayHash, syncState.BirthdayBlockHash)

	scopeID, err := queries.CreateKeyScope(ctx, sqlc.CreateKeyScopeParams{
		WalletID:         walletID,
		Purpose:          84,
		CoinType:         0,
		ExternalAddrType: 4,
		InternalAddrType: 4,
	})
	require.NoError(t, err)
	scope, err := queries.GetKeyScope(ctx, sqlc.GetKeyScopeParams{
		WalletID: walletID,
		Purpose:  84,
		CoinType: 0,
	})
	require.NoError(t, err)
	require.Nil(t, scope.EncryptedCoinPubKey)
	require.Nil(t, scope.EncryptedCoinPrivKey)
	require.False(t, scope.LastAccountNumber.Valid)
	rows, err := queries.UpdateLastAccountNumber(
		ctx, sqlc.UpdateLastAccountNumberParams{
			LastAccountNumber: sql.NullInt64{Int64: 7, Valid: true},
			ID:                scopeID,
			WalletID:          walletID,
		},
	)
	require.NoError(t, err)
	require.Equal(t, int64(1), rows)

	scope, err = queries.GetKeyScope(ctx, sqlc.GetKeyScopeParams{
		WalletID: walletID,
		Purpose:  84,
		CoinType: 0,
	})
	require.NoError(t, err)
	require.Equal(t, int64(7), scope.LastAccountNumber.Int64)

	err = queries.CreateAccount(ctx, sqlc.CreateAccountParams{
		WalletID:             walletID,
		ScopeID:              scopeID,
		AccountNumber:        7,
		AccountType:          1,
		AccountName:          "imported",
		EncryptedPubKey:      []byte("encrypted-account-public-key"),
		MasterKeyFingerprint: sql.NullInt64{Int64: 42, Valid: true},
		ExternalAddrType:     sql.NullInt64{Int64: 3, Valid: true},
		InternalAddrType:     sql.NullInt64{Int64: 4, Valid: true},
	})
	require.NoError(t, err)
	account, err := queries.GetAccount(ctx, sqlc.GetAccountParams{
		ScopeID:       scopeID,
		AccountNumber: 7,
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), account.AccountType)
	require.Equal(t, []byte("encrypted-account-public-key"),
		account.EncryptedPubKey)
	require.Nil(t, account.EncryptedPrivKey)
	require.Equal(t, int64(42), account.MasterKeyFingerprint.Int64)

	createLegacyAddressRows(t, ctx, db, queries, walletID, scopeID)
}

// requireNoPlaintextColumns verifies that secret manager values have no clear
// text schema representation.
func requireNoPlaintextColumns(t *testing.T, db *sql.DB) {
	t.Helper()

	columns := map[string][]string{
		"wallets":    {"master_hd_pub_key"},
		"key_scopes": {"coin_pub_key", "coin_priv_key"},
		"accounts":   {"public_key", "private_key"},
		"addresses":  {"address_id", "script_pub_key", "pub_key", "script"},
	}
	for table, tableColumns := range columns {
		for _, column := range tableColumns {
			var count int

			err := db.QueryRowContext(
				context.Background(),
				"SELECT count(*) FROM pragma_table_info(?) WHERE name = ?",
				table, column,
			).Scan(&count)
			require.NoError(t, err)
			require.Zero(t, count, "%s.%s", table, column)
		}
	}
}

// createLegacyAddressRows verifies every legacy address variant and sticky used
// state through generated queries.
func createLegacyAddressRows(t *testing.T, ctx context.Context, db *sql.DB,
	queries *sqlc.Queries, walletID, scopeID int64) {

	t.Helper()

	chainHash := sha256.Sum256([]byte("chain-address-id"))
	require.NoError(t, queries.CreateAddress(ctx, sqlc.CreateAddressParams{
		WalletID:      walletID,
		ScopeID:       scopeID,
		AddressHash:   chainHash[:],
		AccountNumber: 7,
		AddressType:   0,
		AddedAt:       10,
		SyncStatus:    2,
		Branch:        sql.NullInt64{Int64: 0, Valid: true},
		AddressIndex:  sql.NullInt64{Int64: 9, Valid: true},
	}))

	importedHash := sha256.Sum256([]byte("imported-address-id"))
	require.NoError(t, queries.CreateAddress(ctx, sqlc.CreateAddressParams{
		WalletID:         walletID,
		ScopeID:          scopeID,
		AddressHash:      importedHash[:],
		AccountNumber:    7,
		AddressType:      1,
		AddedAt:          11,
		SyncStatus:       2,
		EncryptedPubKey:  []byte("encrypted-imported-public-key"),
		EncryptedPrivKey: []byte{},
	}))

	scriptHash := sha256.Sum256([]byte("script-address-id"))
	require.NoError(t, queries.CreateAddress(ctx, sqlc.CreateAddressParams{
		WalletID:        walletID,
		ScopeID:         scopeID,
		AddressHash:     scriptHash[:],
		AccountNumber:   7,
		AddressType:     2,
		AddedAt:         12,
		SyncStatus:      2,
		EncryptedHash:   []byte("encrypted-script-hash"),
		EncryptedScript: []byte("encrypted-script"),
	}))

	watchOnlyScriptHash := sha256.Sum256([]byte("watch-only-script-address-id"))
	require.NoError(t, queries.CreateAddress(ctx, sqlc.CreateAddressParams{
		WalletID:      walletID,
		ScopeID:       scopeID,
		AddressHash:   watchOnlyScriptHash[:],
		AccountNumber: 7,
		AddressType:   2,
		AddedAt:       12,
		SyncStatus:    2,
		EncryptedHash: []byte("encrypted-watch-only-script-hash"),
	}))

	witnessHash := sha256.Sum256([]byte("witness-address-id"))
	require.NoError(t, queries.CreateAddress(ctx, sqlc.CreateAddressParams{
		WalletID:        walletID,
		ScopeID:         scopeID,
		AddressHash:     witnessHash[:],
		AccountNumber:   7,
		AddressType:     3,
		AddedAt:         13,
		SyncStatus:      2,
		EncryptedHash:   []byte("encrypted-witness-hash"),
		EncryptedScript: []byte("encrypted-witness-script"),
		WitnessVersion:  sql.NullInt64{Int64: 0, Valid: true},
		IsSecretScript:  sql.NullBool{Bool: true, Valid: true},
	}))

	taprootHash := sha256.Sum256([]byte("taproot-address-id"))
	require.NoError(t, queries.CreateAddress(ctx, sqlc.CreateAddressParams{
		WalletID:        walletID,
		ScopeID:         scopeID,
		AddressHash:     taprootHash[:],
		AccountNumber:   7,
		AddressType:     4,
		AddedAt:         14,
		SyncStatus:      2,
		EncryptedHash:   []byte("encrypted-taproot-hash"),
		EncryptedScript: []byte("encrypted-taproot-script"),
		WitnessVersion:  sql.NullInt64{Int64: 1, Valid: true},
		IsSecretScript:  sql.NullBool{Bool: false, Valid: true},
	}))

	rows, err := queries.MarkAddressUsed(ctx, sqlc.MarkAddressUsedParams{
		WalletID:    walletID,
		ScopeID:     scopeID,
		AddressHash: importedHash[:],
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), rows)

	address, err := queries.GetAddress(ctx, sqlc.GetAddressParams{
		WalletID:    walletID,
		ScopeID:     scopeID,
		AddressHash: importedHash[:],
	})
	require.NoError(t, err)
	require.True(t, address.Used)
	require.Equal(t, []byte("encrypted-imported-public-key"),
		address.EncryptedPubKey)

	_, err = db.ExecContext(ctx, `
		UPDATE addresses SET used = FALSE
		WHERE wallet_id = ? AND scope_id = ? AND address_hash = ?
	`, walletID, scopeID, importedHash[:])
	require.ErrorContains(t, err, "address used state cannot be cleared")

	invalidHash := sha256.Sum256([]byte("invalid-chain-address-id"))
	err = queries.CreateAddress(ctx, sqlc.CreateAddressParams{
		WalletID:      walletID,
		ScopeID:       scopeID,
		AddressHash:   invalidHash[:],
		AccountNumber: 7,
		AddressType:   0,
		AddedAt:       15,
		SyncStatus:    2,
	})
	require.Error(t, err)
}

// bytesOf returns a deterministic byte fixture of the requested length.
func bytesOf(value byte, count int) []byte {
	b := make([]byte, count)
	for i := range b {
		b[i] = value
	}

	return b
}
