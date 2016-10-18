// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"bytes"
	"time"

	"github.com/jadeblaquiere/ctcd/blockchain"
	"github.com/jadeblaquiere/ctcd/chaincfg"
	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcd/wire"
	"github.com/jadeblaquiere/ctcutil"
	"github.com/jadeblaquiere/ctcwallet/walletdb"
)

// Block contains the minimum amount of data to uniquely identify any block on
// either the best or side chain.
type Block struct {
	Hash   chainhash.Hash
	Height int32
}

// BlockMeta contains the unique identification for a block and any metadata
// pertaining to the block.  At the moment, this additional metadata only
// includes the block time from the block header.
type BlockMeta struct {
	Block
	Time time.Time
}

// blockRecord is an in-memory representation of the block record saved in the
// database.
type blockRecord struct {
	Block
	Time         time.Time
	transactions []chainhash.Hash
}

// incidence records the block hash and blockchain height of a mined transaction.
// Since a transaction hash alone is not enough to uniquely identify a mined
// transaction (duplicate transaction hashes are allowed), the incidence is used
// instead.
type incidence struct {
	txHash chainhash.Hash
	block  Block
}

// indexedIncidence records the transaction incidence and an input or output
// index.
type indexedIncidence struct {
	incidence
	index uint32
}

// debit records the debits a transaction record makes from previous wallet
// transaction credits.
type debit struct {
	txHash chainhash.Hash
	index  uint32
	amount btcutil.Amount
	spends indexedIncidence
}

// credit describes a transaction output which was or is spendable by wallet.
type credit struct {
	outPoint wire.OutPoint
	block    Block
	amount   btcutil.Amount
	change   bool
	spentBy  indexedIncidence // Index == ^uint32(0) if unspent
}

// TxRecord represents a transaction managed by the Store.
type TxRecord struct {
	MsgTx        wire.MsgTx
	Hash         chainhash.Hash
	Received     time.Time
	SerializedTx []byte // Optional: may be nil
}

// NewTxRecord creates a new transaction record that may be inserted into the
// store.  It uses memoization to save the transaction hash and the serialized
// transaction.
func NewTxRecord(serializedTx []byte, received time.Time) (*TxRecord, error) {
	rec := &TxRecord{
		Received:     received,
		SerializedTx: serializedTx,
	}
	err := rec.MsgTx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		str := "failed to deserialize transaction"
		return nil, storeError(ErrInput, str, err)
	}
	copy(rec.Hash[:], chainhash.DoubleHashB(serializedTx))
	return rec, nil
}

// NewTxRecordFromMsgTx creates a new transaction record that may be inserted
// into the store.
func NewTxRecordFromMsgTx(msgTx *wire.MsgTx, received time.Time) (*TxRecord, error) {
	buf := bytes.NewBuffer(make([]byte, 0, msgTx.SerializeSize()))
	err := msgTx.Serialize(buf)
	if err != nil {
		str := "failed to serialize transaction"
		return nil, storeError(ErrInput, str, err)
	}
	rec := &TxRecord{
		MsgTx:        *msgTx,
		Received:     received,
		SerializedTx: buf.Bytes(),
	}
	copy(rec.Hash[:], chainhash.DoubleHashB(rec.SerializedTx))
	return rec, nil
}

// Credit is the type representing a transaction output which was spent or
// is still spendable by wallet.  A UTXO is an unspent Credit, but not all
// Credits are UTXOs.
type Credit struct {
	wire.OutPoint
	BlockMeta
	Amount       btcutil.Amount
	PkScript     []byte
	Received     time.Time
	FromCoinBase bool
}

// Store implements a transaction store for storing and managing wallet
// transactions.
type Store struct {
	namespace   walletdb.Namespace
	chainParams *chaincfg.Params

	// Event callbacks.  These execute in the same goroutine as the wtxmgr
	// caller.
	NotifyUnspent func(hash *chainhash.Hash, index uint32)
}

// Open opens the wallet transaction store from a walletdb namespace.  If the
// store does not exist, ErrNoExist is returned.  Existing stores will be
// upgraded to new database formats as necessary.
func Open(namespace walletdb.Namespace, chainParams *chaincfg.Params) (*Store, error) {
	// Open the store, upgrading to the latest version as needed.
	err := openStore(namespace)
	if err != nil {
		return nil, err
	}
	return &Store{namespace, chainParams, nil}, nil // TODO: set callbacks
}

// Create creates a new persistent transaction store in the walletdb namespace.
// Creating the store when one already exists in this namespace will error with
// ErrAlreadyExists.
func Create(namespace walletdb.Namespace) error {
	return createStore(namespace)
}

// moveMinedTx moves a transaction record from the unmined buckets to block
// buckets.
func (s *Store) moveMinedTx(ns walletdb.Bucket, rec *TxRecord, recKey, recVal []byte, block *BlockMeta) error {
	log.Infof("Marking unconfirmed transaction %v mined in block %d",
		&rec.Hash, block.Height)

	// Insert block record as needed.
	blockKey, blockVal := existsBlockRecord(ns, block.Height)
	var err error
	if blockVal == nil {
		blockVal = valueBlockRecord(block, &rec.Hash)
	} else {
		blockVal, err = appendRawBlockRecord(blockVal, &rec.Hash)
		if err != nil {
			return err
		}
	}
	err = putRawBlockRecord(ns, blockKey, blockVal)
	if err != nil {
		return err
	}

	err = putRawTxRecord(ns, recKey, recVal)
	if err != nil {
		return err
	}
	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	// For all mined transactions with unspent credits spent by this
	// transaction, mark each spent, remove from the unspents map, and
	// insert a debit record for the spent credit.
	debitIncidence := indexedIncidence{
		incidence: incidence{txHash: rec.Hash, block: block.Block},
		// index set for each rec input below.
	}
	for i, input := range rec.MsgTx.TxIn {
		unspentKey, credKey := existsUnspent(ns, &input.PreviousOutPoint)
		if credKey == nil {
			continue
		}
		debitIncidence.index = uint32(i)
		amt, err := spendCredit(ns, credKey, &debitIncidence)
		if err != nil {
			return err
		}
		minedBalance -= amt
		err = deleteRawUnspent(ns, unspentKey)
		if err != nil {
			return err
		}

		err = putDebit(ns, &rec.Hash, uint32(i), amt, &block.Block, credKey)
		if err != nil {
			return err
		}

		err = deleteRawUnminedInput(ns, unspentKey)
		if err != nil {
			return err
		}
	}

	// For each output of the record that is marked as a credit, if the
	// output is marked as a credit by the unconfirmed store, remove the
	// marker and mark the output as a credit in the db.
	//
	// Moved credits are added as unspents, even if there is another
	// unconfirmed transaction which spends them.
	cred := credit{
		outPoint: wire.OutPoint{Hash: rec.Hash},
		block:    block.Block,
		spentBy:  indexedIncidence{index: ^uint32(0)},
	}
	it := makeUnminedCreditIterator(ns, &rec.Hash)
	for it.next() {
		// TODO: This should use the raw apis.  The credit value (it.cv)
		// can be moved from unmined directly to the credits bucket.
		// The key needs a modification to include the block
		// height/hash.
		index, err := fetchRawUnminedCreditIndex(it.ck)
		if err != nil {
			return err
		}
		amount, change, err := fetchRawUnminedCreditAmountChange(it.cv)
		if err != nil {
			return err
		}
		cred.outPoint.Index = index
		cred.amount = amount
		cred.change = change

		err = it.delete()
		if err != nil {
			return err
		}
		err = putUnspentCredit(ns, &cred)
		if err != nil {
			return err
		}
		err = putUnspent(ns, &cred.outPoint, &block.Block)
		if err != nil {
			return err
		}
		minedBalance += amount
	}
	if it.err != nil {
		return it.err
	}

	err = putMinedBalance(ns, minedBalance)
	if err != nil {
		return err
	}

	return deleteRawUnmined(ns, rec.Hash[:])
}

// InsertTx records a transaction as belonging to a wallet's transaction
// history.  If block is nil, the transaction is considered unspent, and the
// transaction's index must be unset.
func (s *Store) InsertTx(rec *TxRecord, block *BlockMeta) error {
	return scopedUpdate(s.namespace, func(ns walletdb.Bucket) error {
		if block == nil {
			return s.insertMemPoolTx(ns, rec)
		}
		return s.insertMinedTx(ns, rec, block)
	})
}

// insertMinedTx inserts a new transaction record for a mined transaction into
// the database.  It is expected that the exact transation does not already
// exist in the unmined buckets, but unmined double spends (including mutations)
// are removed.
func (s *Store) insertMinedTx(ns walletdb.Bucket, rec *TxRecord, block *BlockMeta) error {
	// If a transaction record for this tx hash and block already exist,
	// there is nothing left to do.
	k, v := existsTxRecord(ns, &rec.Hash, &block.Block)
	if v != nil {
		return nil
	}

	// If the exact tx (not a double spend) is already included but
	// unconfirmed, move it to a block.
	v = existsRawUnmined(ns, rec.Hash[:])
	if v != nil {
		return s.moveMinedTx(ns, rec, k, v, block)
	}

	// As there may be unconfirmed transactions that are invalidated by this
	// transaction (either being duplicates, or double spends), remove them
	// from the unconfirmed set.  This also handles removing unconfirmed
	// transaction spend chains if any other unconfirmed transactions spend
	// outputs of the removed double spend.
	err := s.removeDoubleSpends(ns, rec)
	if err != nil {
		return err
	}

	// If a block record does not yet exist for any transactions from this
	// block, insert the record.  Otherwise, update it by adding the
	// transaction hash to the set of transactions from this block.
	blockKey, blockValue := existsBlockRecord(ns, block.Height)
	if blockValue == nil {
		err = putBlockRecord(ns, block, &rec.Hash)
	} else {
		blockValue, err = appendRawBlockRecord(blockValue, &rec.Hash)
		if err != nil {
			return err
		}
		err = putRawBlockRecord(ns, blockKey, blockValue)
	}
	if err != nil {
		return err
	}

	err = putTxRecord(ns, rec, &block.Block)
	if err != nil {
		return err
	}

	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	// Add a debit record for each unspent credit spent by this tx.
	spender := indexedIncidence{
		incidence: incidence{
			txHash: rec.Hash,
			block:  block.Block,
		},
		// index set for each iteration below
	}
	for i, input := range rec.MsgTx.TxIn {
		unspentKey, credKey := existsUnspent(ns, &input.PreviousOutPoint)
		if credKey == nil {
			// Debits for unmined transactions are not explicitly
			// tracked.  Instead, all previous outputs spent by any
			// unmined transaction are added to a map for quick
			// lookups when it must be checked whether a mined
			// output is unspent or not.
			//
			// Tracking individual debits for unmined transactions
			// could be added later to simplify (and increase
			// performance of) determining some details that need
			// the previous outputs (e.g. determining a fee), but at
			// the moment that is not done (and a db lookup is used
			// for those cases instead).  There is also a good
			// chance that all unmined transaction handling will
			// move entirely to the db rather than being handled in
			// memory for atomicity reasons, so the simplist
			// implementation is currently used.
			continue
		}
		spender.index = uint32(i)
		amt, err := spendCredit(ns, credKey, &spender)
		if err != nil {
			return err
		}
		err = putDebit(ns, &rec.Hash, uint32(i), amt, &block.Block,
			credKey)
		if err != nil {
			return err
		}

		minedBalance -= amt

		err = deleteRawUnspent(ns, unspentKey)
		if err != nil {
			return err
		}
	}

	return putMinedBalance(ns, minedBalance)
}

// AddCredit marks a transaction record as containing a transaction output
// spendable by wallet.  The output is added unspent, and is marked spent
// when a new transaction spending the output is inserted into the store.
//
// TODO(jrick): This should not be necessary.  Instead, pass the indexes
// that are known to contain credits when a transaction or merkleblock is
// inserted into the store.
func (s *Store) AddCredit(rec *TxRecord, block *BlockMeta, index uint32, change bool) error {
	if int(index) >= len(rec.MsgTx.TxOut) {
		str := "transaction output does not exist"
		return storeError(ErrInput, str, nil)
	}

	var isNew bool
	err := scopedUpdate(s.namespace, func(ns walletdb.Bucket) error {
		var err error
		isNew, err = s.addCredit(ns, rec, block, index, change)
		return err
	})
	if err == nil && isNew && s.NotifyUnspent != nil {
		s.NotifyUnspent(&rec.Hash, index)
	}
	return err
}

// addCredit is an AddCredit helper that runs in an update transaction.  The
// bool return specifies whether the unspent output is newly added (true) or a
// duplicate (false).
func (s *Store) addCredit(ns walletdb.Bucket, rec *TxRecord, block *BlockMeta, index uint32, change bool) (bool, error) {
	if block == nil {
		k := canonicalOutPoint(&rec.Hash, index)
		if existsRawUnminedCredit(ns, k) != nil {
			return false, nil
		}
		v := valueUnminedCredit(btcutil.Amount(rec.MsgTx.TxOut[index].Value), change)
		return true, putRawUnminedCredit(ns, k, v)
	}

	k, v := existsCredit(ns, &rec.Hash, index, &block.Block)
	if v != nil {
		return false, nil
	}

	txOutAmt := btcutil.Amount(rec.MsgTx.TxOut[index].Value)
	log.Debugf("Marking transaction %v output %d (%v) spendable",
		rec.Hash, index, txOutAmt)

	cred := credit{
		outPoint: wire.OutPoint{
			Hash:  rec.Hash,
			Index: index,
		},
		block:   block.Block,
		amount:  txOutAmt,
		change:  change,
		spentBy: indexedIncidence{index: ^uint32(0)},
	}
	v = valueUnspentCredit(&cred)
	err := putRawCredit(ns, k, v)
	if err != nil {
		return false, err
	}

	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return false, err
	}
	err = putMinedBalance(ns, minedBalance+txOutAmt)
	if err != nil {
		return false, err
	}

	return true, putUnspent(ns, &cred.outPoint, &block.Block)
}

// Rollback removes all blocks at height onwards, moving any transactions within
// each block to the unconfirmed pool.
func (s *Store) Rollback(height int32) error {
	return scopedUpdate(s.namespace, func(ns walletdb.Bucket) error {
		return s.rollback(ns, height)
	})
}

func (s *Store) rollback(ns walletdb.Bucket, height int32) error {
	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	// Keep track of all credits that were removed from coinbase
	// transactions.  After detaching all blocks, if any transaction record
	// exists in unmined that spends these outputs, remove them and their
	// spend chains.
	//
	// It is necessary to keep these in memory and fix the unmined
	// transactions later since blocks are removed in increasing order.
	var coinBaseCredits []wire.OutPoint

	it := makeBlockIterator(ns, height)
	for it.next() {
		b := &it.elem

		log.Infof("Rolling back %d transactions from block %v height %d",
			len(b.transactions), b.Hash, b.Height)

		for i := range b.transactions {
			txHash := &b.transactions[i]

			recKey := keyTxRecord(txHash, &b.Block)
			recVal := existsRawTxRecord(ns, recKey)
			var rec TxRecord
			err = readRawTxRecord(txHash, recVal, &rec)
			if err != nil {
				return err
			}

			err = deleteTxRecord(ns, txHash, &b.Block)
			if err != nil {
				return err
			}

			// Handle coinbase transactions specially since they are
			// not moved to the unconfirmed store.  A coinbase cannot
			// contain any debits, but all credits should be removed
			// and the mined balance decremented.
			if blockchain.IsCoinBaseTx(&rec.MsgTx) {
				op := wire.OutPoint{Hash: rec.Hash}
				for i, output := range rec.MsgTx.TxOut {
					k, v := existsCredit(ns, &rec.Hash,
						uint32(i), &b.Block)
					if v == nil {
						continue
					}
					op.Index = uint32(i)

					coinBaseCredits = append(coinBaseCredits, op)

					unspentKey, credKey := existsUnspent(ns, &op)
					if credKey != nil {
						minedBalance -= btcutil.Amount(output.Value)
						err = deleteRawUnspent(ns, unspentKey)
						if err != nil {
							return err
						}
					}
					err = deleteRawCredit(ns, k)
					if err != nil {
						return err
					}
				}

				continue
			}

			err = putRawUnmined(ns, txHash[:], recVal)
			if err != nil {
				return err
			}

			// For each debit recorded for this transaction, mark
			// the credit it spends as unspent (as long as it still
			// exists) and delete the debit.  The previous output is
			// recorded in the unconfirmed store for every previous
			// output, not just debits.
			for i, input := range rec.MsgTx.TxIn {
				prevOut := &input.PreviousOutPoint
				prevOutKey := canonicalOutPoint(&prevOut.Hash,
					prevOut.Index)
				err = putRawUnminedInput(ns, prevOutKey, rec.Hash[:])
				if err != nil {
					return err
				}

				// If this input is a debit, remove the debit
				// record and mark the credit that it spent as
				// unspent, incrementing the mined balance.
				debKey, credKey, err := existsDebit(ns,
					&rec.Hash, uint32(i), &b.Block)
				if err != nil {
					return err
				}
				if debKey == nil {
					continue
				}

				// unspendRawCredit does not error in case the
				// no credit exists for this key, but this
				// behavior is correct.  Since blocks are
				// removed in increasing order, this credit
				// may have already been removed from a
				// previously removed transaction record in
				// this rollback.
				var amt btcutil.Amount
				amt, err = unspendRawCredit(ns, credKey)
				if err != nil {
					return err
				}
				err = deleteRawDebit(ns, debKey)
				if err != nil {
					return err
				}

				// If the credit was previously removed in the
				// rollback, the credit amount is zero.  Only
				// mark the previously spent credit as unspent
				// if it still exists.
				if amt == 0 {
					continue
				}
				unspentVal, err := fetchRawCreditUnspentValue(credKey)
				if err != nil {
					return err
				}
				minedBalance += amt
				err = putRawUnspent(ns, prevOutKey, unspentVal)
				if err != nil {
					return err
				}
			}

			// For each detached non-coinbase credit, move the
			// credit output to unmined.  If the credit is marked
			// unspent, it is removed from the utxo set and the
			// mined balance is decremented.
			//
			// TODO: use a credit iterator
			for i, output := range rec.MsgTx.TxOut {
				k, v := existsCredit(ns, &rec.Hash, uint32(i),
					&b.Block)
				if v == nil {
					continue
				}

				amt, change, err := fetchRawCreditAmountChange(v)
				if err != nil {
					return err
				}
				outPointKey := canonicalOutPoint(&rec.Hash, uint32(i))
				unminedCredVal := valueUnminedCredit(amt, change)
				err = putRawUnminedCredit(ns, outPointKey, unminedCredVal)
				if err != nil {
					return err
				}

				err = deleteRawCredit(ns, k)
				if err != nil {
					return err
				}

				credKey := existsRawUnspent(ns, outPointKey)
				if credKey != nil {
					minedBalance -= btcutil.Amount(output.Value)
					err = deleteRawUnspent(ns, outPointKey)
					if err != nil {
						return err
					}
				}
			}
		}

		err = it.delete()
		if err != nil {
			return err
		}
	}
	if it.err != nil {
		return it.err
	}

	for _, op := range coinBaseCredits {
		opKey := canonicalOutPoint(&op.Hash, op.Index)
		unminedKey := existsRawUnminedInput(ns, opKey)
		if unminedKey != nil {
			unminedVal := existsRawUnmined(ns, unminedKey)
			var unminedRec TxRecord
			copy(unminedRec.Hash[:], unminedKey) // Silly but need an array
			err = readRawTxRecord(&unminedRec.Hash, unminedVal, &unminedRec)
			if err != nil {
				return err
			}

			log.Debugf("Transaction %v spends a removed coinbase "+
				"output -- removing as well", unminedRec.Hash)
			err = s.removeConflict(ns, &unminedRec)
			if err != nil {
				return err
			}
		}
	}

	return putMinedBalance(ns, minedBalance)
}

// UnspentOutputs returns all unspent received transaction outputs.
// The order is undefined.
func (s *Store) UnspentOutputs() ([]Credit, error) {
	var credits []Credit
	err := scopedView(s.namespace, func(ns walletdb.Bucket) error {
		var err error
		credits, err = s.unspentOutputs(ns)
		return err
	})
	return credits, err
}

func (s *Store) unspentOutputs(ns walletdb.Bucket) ([]Credit, error) {
	var unspent []Credit

	var op wire.OutPoint
	var block Block
	err := ns.Bucket(bucketUnspent).ForEach(func(k, v []byte) error {
		err := readCanonicalOutPoint(k, &op)
		if err != nil {
			return err
		}
		if existsRawUnminedInput(ns, k) != nil {
			// Output is spent by an unmined transaction.
			// Skip this k/v pair.
			return nil
		}
		err = readUnspentBlock(v, &block)
		if err != nil {
			return err
		}

		blockTime, err := fetchBlockTime(ns, block.Height)
		if err != nil {
			return err
		}
		// TODO(jrick): reading the entire transaction should
		// be avoidable.  Creating the credit only requires the
		// output amount and pkScript.
		rec, err := fetchTxRecord(ns, &op.Hash, &block)
		if err != nil {
			return err
		}
		txOut := rec.MsgTx.TxOut[op.Index]
		cred := Credit{
			OutPoint: op,
			BlockMeta: BlockMeta{
				Block: block,
				Time:  blockTime,
			},
			Amount:       btcutil.Amount(txOut.Value),
			PkScript:     txOut.PkScript,
			Received:     rec.Received,
			FromCoinBase: blockchain.IsCoinBaseTx(&rec.MsgTx),
		}
		unspent = append(unspent, cred)
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unspent bucket"
		return nil, storeError(ErrDatabase, str, err)
	}

	err = ns.Bucket(bucketUnminedCredits).ForEach(func(k, v []byte) error {
		if existsRawUnminedInput(ns, k) != nil {
			// Output is spent by an unmined transaction.
			// Skip to next unmined credit.
			return nil
		}

		err := readCanonicalOutPoint(k, &op)
		if err != nil {
			return err
		}

		// TODO(jrick): Reading/parsing the entire transaction record
		// just for the output amount and script can be avoided.
		recVal := existsRawUnmined(ns, op.Hash[:])
		var rec TxRecord
		err = readRawTxRecord(&op.Hash, recVal, &rec)
		if err != nil {
			return err
		}

		txOut := rec.MsgTx.TxOut[op.Index]
		cred := Credit{
			OutPoint: op,
			BlockMeta: BlockMeta{
				Block: Block{Height: -1},
			},
			Amount:       btcutil.Amount(txOut.Value),
			PkScript:     txOut.PkScript,
			Received:     rec.Received,
			FromCoinBase: blockchain.IsCoinBaseTx(&rec.MsgTx),
		}
		unspent = append(unspent, cred)
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unmined credits bucket"
		return nil, storeError(ErrDatabase, str, err)
	}

	return unspent, nil
}

// Balance returns the spendable wallet balance (total value of all unspent
// transaction outputs) given a minimum of minConf confirmations, calculated
// at a current chain height of curHeight.  Coinbase outputs are only included
// in the balance if maturity has been reached.
//
// Balance may return unexpected results if syncHeight is lower than the block
// height of the most recent mined transaction in the store.
func (s *Store) Balance(minConf, syncHeight int32) (btcutil.Amount, error) {
	var amt btcutil.Amount
	err := scopedView(s.namespace, func(ns walletdb.Bucket) error {
		var err error
		amt, err = s.balance(ns, minConf, syncHeight)
		return err
	})
	return amt, err
}

func (s *Store) balance(ns walletdb.Bucket, minConf int32, syncHeight int32) (btcutil.Amount, error) {
	bal, err := fetchMinedBalance(ns)
	if err != nil {
		return 0, err
	}

	// Subtract the balance for each credit that is spent by an unmined
	// transaction.
	var op wire.OutPoint
	var block Block
	err = ns.Bucket(bucketUnspent).ForEach(func(k, v []byte) error {
		err := readCanonicalOutPoint(k, &op)
		if err != nil {
			return err
		}
		err = readUnspentBlock(v, &block)
		if err != nil {
			return err
		}
		if existsRawUnminedInput(ns, k) != nil {
			_, v := existsCredit(ns, &op.Hash, op.Index, &block)
			amt, err := fetchRawCreditAmount(v)
			if err != nil {
				return err
			}
			bal -= amt
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return 0, err
		}
		str := "failed iterating unspent outputs"
		return 0, storeError(ErrDatabase, str, err)
	}

	// Decrement the balance for any unspent credit with less than
	// minConf confirmations and any (unspent) immature coinbase credit.
	coinbaseMaturity := int32(s.chainParams.CoinbaseMaturity)
	stopConf := minConf
	if coinbaseMaturity > stopConf {
		stopConf = coinbaseMaturity
	}
	lastHeight := syncHeight - stopConf
	blockIt := makeReverseBlockIterator(ns)
	for blockIt.prev() {
		block := &blockIt.elem

		if block.Height < lastHeight {
			break
		}

		for i := range block.transactions {
			txHash := &block.transactions[i]
			rec, err := fetchTxRecord(ns, txHash, &block.Block)
			if err != nil {
				return 0, err
			}
			numOuts := uint32(len(rec.MsgTx.TxOut))
			for i := uint32(0); i < numOuts; i++ {
				// Avoid double decrementing the credit amount
				// if it was already removed for being spent by
				// an unmined tx.
				opKey := canonicalOutPoint(txHash, i)
				if existsRawUnminedInput(ns, opKey) != nil {
					continue
				}

				_, v := existsCredit(ns, txHash, i, &block.Block)
				if v == nil {
					continue
				}
				amt, spent, err := fetchRawCreditAmountSpent(v)
				if err != nil {
					return 0, err
				}
				if spent {
					continue
				}
				confs := syncHeight - block.Height + 1
				if confs < minConf || (blockchain.IsCoinBaseTx(&rec.MsgTx) &&
					confs < coinbaseMaturity) {
					bal -= amt
				}
			}
		}
	}
	if blockIt.err != nil {
		return 0, blockIt.err
	}

	// If unmined outputs are included, increment the balance for each
	// output that is unspent.
	if minConf == 0 {
		err = ns.Bucket(bucketUnminedCredits).ForEach(func(k, v []byte) error {
			if existsRawUnminedInput(ns, k) != nil {
				// Output is spent by an unmined transaction.
				// Skip to next unmined credit.
				return nil
			}

			amount, err := fetchRawUnminedCreditAmount(v)
			if err != nil {
				return err
			}
			bal += amount
			return nil
		})
		if err != nil {
			if _, ok := err.(Error); ok {
				return 0, err
			}
			str := "failed to iterate over unmined credits bucket"
			return 0, storeError(ErrDatabase, str, err)
		}
	}

	return bal, nil
}
