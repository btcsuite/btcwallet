package itest

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// CreateWalletParamsFixture creates test parameters for wallet creation.
func CreateWalletParamsFixture(name string) db.CreateWalletParams {
	return db.CreateWalletParams{
		Name:                     name,
		IsImported:               false,
		ManagerVersion:           1,
		IsWatchOnly:              false,
		EncryptedMasterPrivKey:   RandomBytes(32),
		EncryptedMasterPubKey:    RandomBytes(32),
		MasterKeyPubParams:       RandomBytes(16),
		MasterKeyPrivParams:      RandomBytes(16),
		EncryptedCryptoPrivKey:   RandomBytes(32),
		EncryptedCryptoPubKey:    RandomBytes(32),
		EncryptedCryptoScriptKey: RandomBytes(32),
	}
}

// CreateImportedWalletParams creates test parameters for an imported wallet.
func CreateImportedWalletParams(name string) db.CreateWalletParams {
	params := CreateWalletParamsFixture(name)
	params.IsImported = true

	return params
}

// CreateWatchOnlyWalletParams creates test parameters for a watch-only wallet.
func CreateWatchOnlyWalletParams(name string) db.CreateWalletParams {
	params := CreateWalletParamsFixture(name)
	params.IsWatchOnly = true
	params.EncryptedMasterPrivKey = nil
	params.MasterKeyPrivParams = nil
	params.EncryptedCryptoPrivKey = nil
	params.EncryptedCryptoScriptKey = nil

	return params
}

// CreateBlockFixture inserts a test block into the database and returns it.
func CreateBlockFixture(t *testing.T, dbConn *sql.DB, height uint32) db.Block {
	t.Helper()

	hash := RandomHash()
	timestamp := time.Now().UTC()

	// TODO(gustavostingelin): use the block store to insert the block when
	// available.
	query := `
		INSERT INTO blocks (block_height, header_hash, timestamp)
		VALUES ($1, $2, $3)
	`
	_, err := dbConn.ExecContext(t.Context(), query,
		height, hash[:], timestamp.Unix())
	require.NoError(t, err, "failed to insert block")

	return db.Block{
		Hash:      hash,
		Height:    height,
		Timestamp: timestamp,
	}
}

// RandomBytes generates random bytes for test data.
func RandomBytes(n int) []byte {
	b := make([]byte, n)

	_, err := rand.Read(b)
	if err != nil {
		// This should never happen.
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}

	return b
}

// RandomHash generates a random chainhash.Hash for testing.
func RandomHash() chainhash.Hash {
	var h chainhash.Hash

	_, err := rand.Read(h[:])
	if err != nil {
		// This should never happen.
		panic(fmt.Sprintf("failed to generate random hash: %v", err))
	}

	return h
}
