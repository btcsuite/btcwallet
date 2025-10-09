// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"context"
	"database/sql"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/internal/store/sqldb/sqlc"
)

// SQLStore wraps the sqlc-generated queries for block operations.
// This is used alongside the existing KV store during the migration period.
type SQLStore struct {
	db      *sql.DB
	queries *sqlc.Queries
}

// NewSQLStore creates a new SQL store for block operations.
func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{
		db:      db,
		queries: sqlc.New(db),
	}
}

// putBlockRecordSQL inserts a block record into the SQL database.
// This is a parallel implementation to putBlockRecord (KV store).
//
// Following the WET (Write Everything Twice) approach, this function
// operates independently of the KV store. Eventually, the KV store
// implementation will be removed.
func (s *SQLStore) putBlockRecordSQL(
	ctx context.Context, block *BlockMeta, txHash *chainhash.Hash) error {

	// Check if block already exists.
	existingBlock, err := s.queries.GetBlockByHeight(
		ctx, int64(block.Height),
	)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	// If block doesn't exist, insert it with the first transaction.
	if err == sql.ErrNoRows {
		return s.queries.InsertBlock(ctx, sqlc.InsertBlockParams{
			BlockHeight: int64(block.Height),
			HeaderHash:  block.Hash[:],
			Timestamp:   block.Time.Unix(),
		})
	}

	// Block already exists - this means we're adding another transaction
	// to the same block. For now, we just verify the block hash matches.
	// Transaction hashes are not stored in the SQL schema yet (future work).
	if existingBlock.HeaderHash == nil ||
		len(existingBlock.HeaderHash) != chainhash.HashSize {

		return storeError(ErrData, "invalid block hash in database",
			nil)
	}

	var existingHash chainhash.Hash
	copy(existingHash[:], existingBlock.HeaderHash)

	if existingHash != block.Hash {
		return storeError(ErrData, "block hash mismatch", nil)
	}

	// Block already exists with correct hash - nothing to do
	// Note: In the KV store, we append transaction hashes here.
	// In the SQL schema, we're starting with just block metadata.
	// Transaction associations will be handled in future iterations.
	return nil
}
