//go:build test_db_postgres

package pg

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestLegacySchemaQueries verifies the legacy ciphertext and sticky address
// state through the generated PostgreSQL queries.
func TestLegacySchemaQueries(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	container, err := postgres.Run(
		ctx, "postgres:18-alpine",
		postgres.WithDatabase("btcwallet"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(2*time.Minute),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, container.Terminate(context.Background()))
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	db, err := Open(ctx, Config{DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})
	require.NoError(t, ApplyMigrations(db))
	requireNoPostgresPlaintextColumns(t, db)

	queries := sqlc.New(db)
	genesisHash := pgBytesOf(0x01, 32)
	birthdayHash := pgBytesOf(0x02, 32)
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
	require.Nil(t, wallet.MasterPrivParams)
	require.Nil(t, wallet.EncryptedCryptoPrivKey)
	require.Equal(t, []byte("encrypted-crypto-public-key"),
		wallet.EncryptedCryptoPubKey)

	require.NoError(t, queries.PutWalletSyncState(
		ctx, sqlc.PutWalletSyncStateParams{
			WalletID:              walletID,
			StartBlockHeight:      0,
			SyncedBlockHeight:     100,
			BirthdayTimestamp:     1234,
			BirthdayBlockHeight:   sql.NullInt32{Int32: 100, Valid: true},
			BirthdayBlockVerified: true,
		},
	))
	syncState, err := queries.GetWalletSyncState(ctx, walletID)
	require.NoError(t, err)
	require.Equal(t, genesisHash, syncState.StartBlockHash)
	require.Equal(t, birthdayHash, syncState.BirthdayBlockHash)

	scopeID, err := queries.CreateKeyScope(ctx, sqlc.CreateKeyScopeParams{
		WalletID:         walletID,
		Purpose:          84,
		CoinType:         0,
		ExternalAddrType: 4,
		InternalAddrType: 4,
	})
	require.NoError(t, err)
	rows, err := queries.UpdateLastAccountNumber(
		ctx, sqlc.UpdateLastAccountNumberParams{
			LastAccountNumber: sql.NullInt64{Int64: 7, Valid: true},
			ID:                scopeID,
			WalletID:          walletID,
		},
	)
	require.NoError(t, err)
	require.Equal(t, int64(1), rows)
	scope, err := queries.GetKeyScope(ctx, sqlc.GetKeyScopeParams{
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
		ExternalAddrType:     sql.NullInt16{Int16: 3, Valid: true},
		InternalAddrType:     sql.NullInt16{Int16: 4, Valid: true},
	})
	require.NoError(t, err)

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

	addressHash := sha256.Sum256([]byte("imported-address-id"))
	require.NoError(t, queries.CreateAddress(ctx, sqlc.CreateAddressParams{
		WalletID:         walletID,
		ScopeID:          scopeID,
		AddressHash:      addressHash[:],
		AccountNumber:    7,
		AddressType:      1,
		AddedAt:          11,
		SyncStatus:       2,
		EncryptedPubKey:  []byte("encrypted-imported-public-key"),
		EncryptedPrivKey: []byte{},
	}))
	rows, err = queries.MarkAddressUsed(ctx, sqlc.MarkAddressUsedParams{
		WalletID:    walletID,
		ScopeID:     scopeID,
		AddressHash: addressHash[:],
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), rows)
	address, err := queries.GetAddress(ctx, sqlc.GetAddressParams{
		WalletID:    walletID,
		ScopeID:     scopeID,
		AddressHash: addressHash[:],
	})
	require.NoError(t, err)
	require.True(t, address.Used)
	require.Equal(t, []byte("encrypted-imported-public-key"),
		address.EncryptedPubKey)

	_, err = db.ExecContext(ctx, `
		UPDATE addresses SET used = FALSE
		WHERE wallet_id = $1 AND scope_id = $2 AND address_hash = $3
	`, walletID, scopeID, addressHash[:])
	require.ErrorContains(t, err, "address used state cannot be cleared")
}

// requireNoPostgresPlaintextColumns verifies that secret manager values have no
// clear text PostgreSQL schema representation.
func requireNoPostgresPlaintextColumns(t *testing.T, db *sql.DB) {
	t.Helper()

	columns := map[string][]string{
		"wallets":    {"master_hd_pub_key"},
		"key_scopes": {"coin_pub_key", "coin_priv_key"},
		"accounts":   {"public_key", "private_key"},
		"addresses":  {"address_id", "script_pub_key", "pub_key", "script"},
	}
	for table, tableColumns := range columns {
		for _, column := range tableColumns {
			var exists bool
			err := db.QueryRow(`
				SELECT EXISTS (
					SELECT 1 FROM information_schema.columns
					WHERE table_schema = 'public'
						AND table_name = $1
						AND column_name = $2
				)
			`, table, column).Scan(&exists)
			require.NoError(t, err)
			require.False(t, exists, "%s.%s", table, column)
		}
	}
}

// pgBytesOf returns a deterministic PostgreSQL byte fixture of the requested
// length.
func pgBytesOf(value byte, count int) []byte {
	b := make([]byte, count)
	for i := range b {
		b[i] = value
	}

	return b
}
