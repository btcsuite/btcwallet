// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

// loadSchema reads the actual production migration schema.
// This ensures tests use the exact same schema as production.
func loadSchema(t *testing.T, schema string) string {
	t.Helper()

	cwd, err := os.Getwd()
	require.NoError(t, err)

	parentDir := filepath.Dir(cwd)

	schemaPath := filepath.Join(
		parentDir, "internal", "store", "sqldb", "migrations", schema,
	)
	schemaBytes, err := os.ReadFile(schemaPath)
	require.NoError(t, err)

	return string(schemaBytes)
}

// TestPutBlockRecordSQL tests inserting block records into SQL database.
func TestPutBlockRecordSQL(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	t.Cleanup(func() {
		db.Close()
	})
	require.NoError(t, err)

	schemaFile := "000002__blocks.up.sql"
	schemaLoaded := loadSchema(t, schemaFile)

	_, err = db.Exec(schemaLoaded)
	require.NoError(t, err)

	store := NewSQLStore(db)

	// Test Case 1: Insert a new block with first transaction.
	hash1, _ := chainhash.NewHashFromStr(
		"00000000000000017188b968a371bab95aa43522665353b646e41865abae" +
			"02a4",
	)
	txHash1, _ := chainhash.NewHashFromStr(
		"8c18cf9ad4a950f7bd0174da3ddbde77269091c47ac3a7471fbd9888953f" +
			"4645",
	)

	block1 := &BlockMeta{
		Block: Block{
			Height: 100,
			Hash:   *hash1,
		},
		Time: time.Unix(1387737310, 0),
	}

	err = store.putBlockRecordSQL(t.Context(), block1, txHash1)
	require.NoError(t, err)

	// Verify block was inserted correctly.
	block, err := store.queries.GetBlockByHeight(t.Context(), 100)
	require.NoError(t, err, "Failed to query block")
	require.Equal(t, int64(100), block.BlockHeight)
	require.Equal(t, int64(1387737310), block.Timestamp)
	require.Equal(t, 32, len(block.HeaderHash))

	// Test Case 2: Add another transaction to the same block.
	txHash2, _ := chainhash.NewHashFromStr(
		"9c18cf9ad4a950f7bd0174da3ddbde77269091c47ac3a7471fbd9888953f" +
			"4646",
	)

	err = store.putBlockRecordSQL(t.Context(), block1, txHash2)
	require.NoError(t, err, "Failed to add transaction to existing block")

	// Verify block still exists (should be idempotent).
	block2, err := store.queries.GetBlockByHeight(t.Context(), 100)
	require.NoError(t, err, "Failed to query block after second insert")
	require.Equal(t, int64(100), block2.BlockHeight)

	// Test Case 3: Insert a different block.
	hash2, _ := chainhash.NewHashFromStr(
		"00000000000000027188b968a371bab95aa43522665353b646e41865abae" +
			"02a4",
	)
	txHash3, _ := chainhash.NewHashFromStr(
		"7c18cf9ad4a950f7bd0174da3ddbde77269091c47ac3a7471fbd9888953f" +
			"4647",
	)

	block3 := &BlockMeta{
		Block: Block{
			Height: 101,
			Hash:   *hash2,
		},
		Time: time.Unix(1387737320, 0),
	}

	err = store.putBlockRecordSQL(t.Context(), block3, txHash3)
	require.NoError(t, err)

	_, err = store.queries.GetBlockByHeight(t.Context(), 100)
	require.NoError(t, err)

	_, err = store.queries.GetBlockByHeight(t.Context(), 101)
	require.NoError(t, err)
}

// TestDeleteBlockRecordSQL tests deleting block records (reorg scenario).
func TestDeleteBlockRecordSQL(t *testing.T) {
	// Create in-memory SQLite database
	db, err := sql.Open("sqlite3", ":memory:")
	t.Cleanup(func() {
		db.Close()
	})
	require.NoError(t, err)

	schemaFile := "000002__blocks.up.sql"
	schemaLoaded := loadSchema(t, schemaFile)

	if _, err := db.Exec(schemaLoaded); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	store := NewSQLStore(db)

	hash, _ := chainhash.NewHashFromStr(
		"00000000000000017188b968a371bab95aa43522665353b646e41865abae" +
			"02a4",
	)
	txHash, _ := chainhash.NewHashFromStr("8c18cf9ad4a950f7bd0174da3ddbde" +
		"77269091c47ac3a7471fbd9888953f4645",
	)

	block := &BlockMeta{
		Block: Block{
			Height: 100,
			Hash:   *hash,
		},
		Time: time.Unix(1387737310, 0),
	}

	err = store.putBlockRecordSQL(t.Context(), block, txHash)
	require.NoError(t, err)

	err = store.deleteBlockRecordSQL(t.Context(), 100)
	require.NoError(t, err)

	_, err = store.queries.GetBlockByHeight(t.Context(), 100)
	require.Error(t, err)
	require.ErrorIs(t, err, sql.ErrNoRows)
}
