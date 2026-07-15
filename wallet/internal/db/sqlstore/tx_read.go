// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sqlstore

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// txRecordFromRaw deserializes a transaction row into the record shape expected
// by wtxmgr.
func txRecordFromRaw(raw []byte, received int64) (*wtxmgr.TxRecord, error) {
	record, err := wtxmgr.NewTxRecord(raw, time.Unix(received, 0))
	if err != nil {
		return nil, fmt.Errorf("decode transaction: %w", err)
	}

	return record, nil
}

// loadTxDetails assembles complete wtxmgr details from one transaction row and
// its related rows.
//
//nolint:nilnil // A missing transaction is the established wtxmgr result.
func (s *txStore) loadTxDetails(row TransactionDetailsRow, err error) (
	*wtxmgr.TxDetails, error) {

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("load transaction details: %w", err)
	}

	record, err := txRecordFromRaw(row.RawTx, row.Received)
	if err != nil {
		return nil, err
	}

	// An unmined transaction has the sentinel height until the nullable mined
	// metadata below proves otherwise.
	details := &wtxmgr.TxDetails{
		TxRecord: *record,
		Block: wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Height: -1},
		},
		Label: string(row.Label),
	}

	// A mined incidence must carry the complete block tuple. Treat a partial
	// tuple as corruption instead of returning ambiguous transaction details.
	if row.BlockHeight.Valid {
		if !row.ConfirmedOrder.Valid || !row.BlockTimestamp.Valid {
			return nil, fmt.Errorf("incomplete block metadata for tx %s",
				record.Hash)
		}

		hash, err := chainhash.NewHash(row.BlockHash)
		if err != nil {
			return nil, fmt.Errorf("decode transaction block hash: %w", err)
		}

		details.Block = wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Hash:   *hash,
				Height: int32(row.BlockHeight.Int64),
			},
			Time: time.Unix(row.BlockTimestamp.Int64, 0),
		}
	}

	// Credits and debits are stored separately so the same transaction row can
	// represent either a mined or an unmined incidence.
	err = s.loadTxCredits(row.ID, details)
	if err != nil {
		return nil, err
	}

	err = s.loadTxDebits(row.ID, details)
	if err != nil {
		return nil, err
	}

	return details, nil
}

// loadTxCredits loads the credits attached to one transaction incidence.
//
//nolint:wsl_v5 // Keeping each scanned credit together aids parity review.
func (s *txStore) loadTxCredits(transactionID int64,
	details *wtxmgr.TxDetails) error {

	rows, err := s.queries.ListTransactionDetailCredits(
		s.ctx, s.walletID, transactionID,
	)
	if err != nil {
		return fmt.Errorf("list transaction credits: %w", err)
	}
	for _, row := range rows {
		if row.OutputIndex < 0 || row.OutputIndex > int64(^uint32(0)) {
			return fmt.Errorf("transaction credit index out of range: %d",
				row.OutputIndex)
		}

		details.Credits = append(details.Credits, wtxmgr.CreditRecord{
			Amount: btcutil.Amount(row.Amount),
			Index:  uint32(row.OutputIndex),
			Spent:  row.IsSpent,
			Change: row.IsChange,
		})
	}

	return nil
}

// loadTxDebits loads the debits attached to one transaction incidence.
//
//nolint:wsl_v5 // Keeping each scanned debit together aids parity review.
func (s *txStore) loadTxDebits(transactionID int64,
	details *wtxmgr.TxDetails) error {

	rows, err := s.queries.ListTransactionDebits(
		s.ctx, s.walletID, transactionID,
	)
	if err != nil {
		return fmt.Errorf("list transaction debits: %w", err)
	}
	for _, row := range rows {
		if row.InputIndex < 0 || row.InputIndex > int64(^uint32(0)) {
			return fmt.Errorf("transaction debit index out of range: %d",
				row.InputIndex)
		}

		details.Debits = append(details.Debits, wtxmgr.DebitRecord{
			Amount: btcutil.Amount(row.Amount),
			Index:  uint32(row.InputIndex),
		})
	}

	return nil
}

// TxDetails returns the unmined incidence for a hash when present, otherwise
// the newest mined incidence.
func (s *txStore) TxDetails(hash *chainhash.Hash) (*wtxmgr.TxDetails, error) {
	row, err := s.queries.GetTransactionDetailsByHash(
		s.ctx, s.walletID, hash[:],
	)

	return s.loadTxDetails(row, err)
}

// UniqueTxDetails returns the transaction incidence selected by block.
func (s *txStore) UniqueTxDetails(hash *chainhash.Hash,
	block *wtxmgr.Block) (*wtxmgr.TxDetails, error) {

	if block == nil {
		row, err := s.queries.GetUnminedTransactionDetails(
			s.ctx, s.walletID, hash[:],
		)

		return s.loadTxDetails(row, err)
	}

	row, err := s.queries.GetMinedTransactionDetails(
		s.ctx, s.walletID, hash[:], block.Height, block.Hash[:],
	)

	return s.loadTxDetails(row, err)
}

// TxLabel returns the label associated with a transaction hash.
func (s *txStore) TxLabel(hash chainhash.Hash) (string, error) {
	label, err := s.queries.GetTransactionLabel(s.ctx, s.walletID, hash[:])
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("get transaction label: %w", err)
	}

	return string(label), nil
}

// loadDetailsByID loads complete transaction details by the SQL transaction
// identifier.
func (s *txStore) loadDetailsByID(transactionID int64) (
	*wtxmgr.TxDetails, error) {

	row, err := s.queries.GetTransactionDetailsByID(
		s.ctx, s.walletID, transactionID,
	)

	return s.loadTxDetails(row, err)
}

// rangeUnmined visits the unmined transaction batch used by RangeTransactions.
func (s *txStore) rangeUnmined(
	visit func([]wtxmgr.TxDetails) (bool, error)) (bool, error) {

	rows, err := s.queries.ListUnminedTransactions(s.ctx, s.walletID)
	if err != nil {
		return false, fmt.Errorf("list unmined transactions: %w", err)
	}

	details := make([]wtxmgr.TxDetails, 0, len(rows))
	for _, row := range rows {
		detail, err := s.loadDetailsByID(row.ID)
		if err != nil {
			return false, err
		}

		details = append(details, *detail)
	}

	if len(details) == 0 {
		return false, nil
	}

	return visit(details)
}

// rangeMined visits mined transaction batches in the requested height order.
//
//nolint:cyclop // The branches preserve wtxmgr's bidirectional range contract.
func (s *txStore) rangeMined(begin, end int32,
	visit func([]wtxmgr.TxDetails) (bool, error)) (bool, error) {

	forward := begin < end

	// wtxmgr uses a negative height as the unbounded chain tip. Normalize it
	// only for the mined query because unmined placement is handled by the
	// caller.
	if begin < 0 {
		begin = int32(^uint32(0) >> 1)
	}

	if end < 0 {
		end = int32(^uint32(0) >> 1)
	}

	// Preserve wtxmgr's caller-selected traversal direction in SQL so each
	// callback sees heights in the expected order.
	var (
		incidences []TransactionIncidenceRow
		err        error
	)

	if forward {
		incidences, err = s.queries.ListMinedTransactionsForward(
			s.ctx, s.walletID, begin, end,
		)
	} else {
		incidences, err = s.queries.ListMinedTransactionsReverse(
			s.ctx, s.walletID, begin, end,
		)
	}

	if err != nil {
		return false, fmt.Errorf("list mined transactions: %w", err)
	}

	// The callback contract groups every transaction mined at the same height
	// into one batch.
	for start := 0; start < len(incidences); {
		endIndex := start + 1
		for endIndex < len(incidences) &&
			incidences[endIndex].Height == incidences[start].Height {
			endIndex++
		}

		details := make([]wtxmgr.TxDetails, 0, endIndex-start)
		for _, item := range incidences[start:endIndex] {
			detail, err := s.loadDetailsByID(item.ID)
			if err != nil {
				return false, err
			}

			details = append(details, *detail)
		}

		stop, err := visit(details)
		if err != nil || stop {
			return stop, err
		}

		start = endIndex
	}

	return false, nil
}

// RangeTransactions visits transaction details using the existing wtxmgr
// range and callback semantics.
func (s *txStore) RangeTransactions(begin, end int32,
	visit func([]wtxmgr.TxDetails) (bool, error)) error {

	// A negative begin places the unmined batch before all mined batches.
	addedUnmined := false
	if begin < 0 {
		stop, err := s.rangeUnmined(visit)
		if err != nil || stop {
			return err
		}

		addedUnmined = true
	}

	stop, err := s.rangeMined(begin, end, visit)
	if err != nil || stop || addedUnmined || end >= 0 {
		return err
	}

	// A negative end places the unmined batch after all mined batches when it
	// was not already visited at the beginning.
	_, err = s.rangeUnmined(visit)

	return err
}

// UnminedTxHashes returns all hashes in the unmined set.
func (s *txStore) UnminedTxHashes() ([]*chainhash.Hash, error) {
	rows, err := s.queries.ListUnminedTransactions(s.ctx, s.walletID)
	if err != nil {
		return nil, fmt.Errorf("list unmined transaction hashes: %w", err)
	}

	hashes := make([]*chainhash.Hash, 0, len(rows))
	for _, row := range rows {
		hash, err := chainhash.NewHash(row.Hash)
		if err != nil {
			return nil, fmt.Errorf("decode unmined transaction hash: %w", err)
		}

		hashes = append(hashes, hash)
	}

	return hashes, nil
}

// UnminedTxs returns the unmined transactions in dependency order.
func (s *txStore) UnminedTxs() ([]*wire.MsgTx, error) {
	rows, err := s.queries.ListUnminedTransactions(s.ctx, s.walletID)
	if err != nil {
		return nil, fmt.Errorf("list unmined transactions: %w", err)
	}

	transactions := make(map[chainhash.Hash]*wire.MsgTx)
	for _, row := range rows {
		hash, err := chainhash.NewHash(row.Hash)
		if err != nil {
			return nil, fmt.Errorf("decode unmined transaction hash: %w", err)
		}

		transaction := &wire.MsgTx{}

		err = transaction.Deserialize(bytes.NewReader(row.RawTx))
		if err != nil {
			return nil, fmt.Errorf("decode unmined transaction: %w", err)
		}

		transactions[*hash] = transaction
	}

	return wtxmgr.DependencySort(transactions), nil
}

// creditsFromRows converts SQL credit rows into the public wtxmgr credit
// representation. The full form includes value and block metadata, while the
// watch form contains only the outpoint and public key script.
//
//nolint:nestif // Parity validates nullable block metadata.
func creditsFromRows(rows []CreditRow, full bool) ([]wtxmgr.Credit, error) {
	credits := make([]wtxmgr.Credit, 0, len(rows))
	for _, row := range rows {
		hash, err := chainhash.NewHash(row.Hash)
		if err != nil {
			return nil, fmt.Errorf("decode credit transaction hash: %w", err)
		}

		if row.OutputIndex < 0 || row.OutputIndex > int64(^uint32(0)) {
			return nil, fmt.Errorf("credit index out of range: %d",
				row.OutputIndex)
		}

		credit := wtxmgr.Credit{
			OutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: uint32(row.OutputIndex),
			},
			PkScript: append([]byte(nil), row.PkScript...),
		}
		if full {
			// Unmined credits use the established negative-height sentinel.
			credit.Height = -1
			credit.Amount = btcutil.Amount(row.Amount)
			credit.Received = time.Unix(row.Received, 0)
			credit.FromCoinBase = row.IsCoinbase

			// A present height requires the complete block tuple, just as it
			// does for transaction details.
			if row.BlockHeight.Valid {
				hash, err := chainhash.NewHash(row.BlockHash)
				if err != nil {
					return nil, fmt.Errorf("decode credit block hash: %w", err)
				}

				if !row.BlockTimestamp.Valid {
					return nil, errors.New("credit block timestamp missing")
				}

				credit.BlockMeta = wtxmgr.BlockMeta{
					Block: wtxmgr.Block{
						Hash:   *hash,
						Height: int32(row.BlockHeight.Int64),
					},
					Time: time.Unix(row.BlockTimestamp.Int64, 0),
				}
			}
		}

		credits = append(credits, credit)
	}

	return credits, nil
}

// OutputsToWatch returns all unspent credits, including locked outputs and
// outputs spent by another unmined transaction.
func (s *txStore) OutputsToWatch() ([]wtxmgr.Credit, error) {
	rows, err := s.queries.ListOutputsToWatch(s.ctx, s.walletID)
	if err != nil {
		return nil, fmt.Errorf("list outputs to watch: %w", err)
	}

	return creditsFromRows(rows, false)
}

// UnspentOutputs returns all currently spendable credits.
func (s *txStore) UnspentOutputs() ([]wtxmgr.Credit, error) {
	rows, err := s.queries.ListUnspentCredits(
		s.ctx, s.walletID, time.Now().Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("list unspent outputs: %w", err)
	}

	return creditsFromRows(rows, true)
}

// Balance returns the spendable wallet balance for the requested confirmation
// policy and sync height.
func (s *txStore) Balance(minConf, syncHeight int32) (btcutil.Amount, error) {
	credits, err := s.UnspentOutputs()
	if err != nil {
		return 0, err
	}

	var balance btcutil.Amount
	for _, credit := range credits {
		confirmations := int32(0)
		if credit.Height >= 0 {
			confirmations = syncHeight - credit.Height + 1
		}

		if confirmations < minConf {
			continue
		}

		if credit.FromCoinBase && confirmations < s.coinbaseMaturity {
			continue
		}

		balance += credit.Amount
	}

	return balance, nil
}

// PreviousPkScripts returns the scripts for wallet-owned inputs. The caller
// supplies a block only when selecting a specific mined transaction incidence.
func (s *txStore) PreviousPkScripts(rec *wtxmgr.TxRecord,
	block *wtxmgr.Block) ([][]byte, error) {

	// A mined lookup first resolves the selected transaction incidence so an
	// input index cannot accidentally match another incidence of the same
	// transaction hash.
	var transactionID int64
	if block != nil {
		var err error

		transactionID, err = s.queries.GetMinedTransactionID(
			s.ctx, s.walletID, rec.Hash[:], block.Height,
			block.Hash[:],
		)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}

		if err != nil {
			return nil, fmt.Errorf("find spending transaction: %w", err)
		}
	}

	scripts := make([][]byte, 0, len(rec.MsgTx.TxIn))
	for index, input := range rec.MsgTx.TxIn {
		var (
			script []byte
			err    error
		)

		// Unmined inputs are identified by previous outpoint. Mined inputs use
		// the selected incidence and input index recorded at confirmation.
		if block == nil {
			script, err = s.queries.GetUnminedPreviousPkScript(
				s.ctx, s.walletID, input.PreviousOutPoint.Hash[:],
				input.PreviousOutPoint.Index,
			)
		} else {
			script, err = s.queries.GetMinedPreviousPkScript(
				s.ctx, s.walletID, transactionID, uint32(index),
			)
		}

		if errors.Is(err, sql.ErrNoRows) {
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("get previous output script: %w", err)
		}

		scripts = append(scripts, script)
	}

	return scripts, nil
}
