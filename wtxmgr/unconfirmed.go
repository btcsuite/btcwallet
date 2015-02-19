package wtxmgr

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/walletdb"
)

// unconfirmedStore stores all unconfirmed transactions managed by the Store.
type unconfirmedStore struct {
	namespace walletdb.Namespace
}

// records returns a slice of all unconfirmed transaction records
// saved by the unconfirmed store.
func (u *unconfirmedStore) records() ([]*txRecord, error) {
	var records []*txRecord
	err := u.namespace.View(func(wtx walletdb.Tx) error {
		var err error
		records, err = fetchAllUnconfirmedTxRecords(wtx)
		return err
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}
	return records, nil
}

// lookupTxRecord fetches the unconfirmed transaction record with the given
// transaction hash.
// It returns ErrTxRecordNotFound if no unconfirmed transaction record with
// the given hash is found.
func (u *unconfirmedStore) lookupTxRecord(hash *wire.ShaHash) (*txRecord,
	error) {
	var record *txRecord
	err := u.namespace.View(func(wtx walletdb.Tx) error {
		var err error
		record, err = fetchUnconfirmedTxRecord(wtx, hash)
		return err
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}
	return record, nil
}

func (u *unconfirmedStore) putCredits(hash *wire.ShaHash, c []*credit) error {
	return u.namespace.Update(func(wtx walletdb.Tx) error {
		return putCredits(wtx, hash, c)
	})
}

func (u *unconfirmedStore) putDebits(hash *wire.ShaHash, d *debits) error {
	return u.namespace.Update(func(wtx walletdb.Tx) error {
		return putDebits(wtx, hash, d)
	})
}

// insertTxRecord inserts the given unconfirmed transaction record into the
// unconfirmed store.
// It also marks the inputs, i.e. previous outpoints spent.
func (u *unconfirmedStore) insertTxRecord(tx *btcutil.Tx) (*txRecord, error) {
	r, err := u.lookupTxRecord(tx.Sha())
	if err != nil {
		log.Infof("Inserting unconfirmed transaction %v", tx.Sha())
		r = &txRecord{tx: tx}
		err := u.namespace.Update(func(wtx walletdb.Tx) error {
			return putUnconfirmedTxRecord(wtx, r)
		})
		if err != nil {
			return nil, maybeConvertDbError(err)
		}
		for _, input := range r.Tx().MsgTx().TxIn {
			if err := u.setPrevOutPointSpender(&input.PreviousOutPoint,
				r); err != nil {
				return nil, maybeConvertDbError(err)
			}
		}
	}
	return r, nil
}

// deleteTxRecord deletes the unconfirmed transaction record with the given
// transaction from the unconfirmed store.
func (u *unconfirmedStore) deleteTxRecord(tx *btcutil.Tx) error {
	return u.namespace.Update(func(wtx walletdb.Tx) error {
		return deleteUnconfirmedTxRecord(wtx, tx.Sha())
	})
}

// deleteSpentBlockOutpoint deletes the given outpoint and block output key
// from the unconfirmed store.
func (u *unconfirmedStore) deleteSpentBlockOutpoint(op *wire.OutPoint,
	key *BlockOutputKey) error {
	return u.namespace.Update(func(wtx walletdb.Tx) error {
		return deleteBlockOutPointSpender(wtx, op, key)
	})
}

// deleteOutPointSpender deletes the spender of the given
// unconfirmed outpoint and marks the outpoint as unspent.
func (u *unconfirmedStore) deleteOutPointSpender(
	op *wire.OutPoint) error {
	return u.namespace.Update(func(wtx walletdb.Tx) error {
		return deleteUnconfirmedOutPointSpender(wtx, op)
	})
}

// setPrevOutPointSpender marks the given previous outpoint as spent
// by the given transaction record.
func (u *unconfirmedStore) setPrevOutPointSpender(op *wire.OutPoint,
	r *txRecord) error {
	return u.namespace.Update(func(wtx walletdb.Tx) error {
		return setPrevOutPointSpender(wtx, op, r)
	})
}

// fetchPrevOutPointSpender fetches the spender of the previous outpoint.
func (u *unconfirmedStore) fetchPrevOutPointSpender(op *wire.OutPoint) (
	*txRecord, error) {
	var record *txRecord
	err := u.namespace.View(func(wtx walletdb.Tx) error {
		var err error
		record, err = fetchPrevOutPointSpender(wtx, op)
		return err
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}
	return record, nil
}

// deletePrevOutPointSpender deletes the spender of the previous outpoint and
// marks the previous outpoint as unspent.
func (u *unconfirmedStore) deletePrevOutPointSpender(
	op *wire.OutPoint) error {
	return u.namespace.Update(func(wtx walletdb.Tx) error {
		return deletePrevOutPointSpender(wtx, op)
	})
}

// fetchBlockOutPointSpender fetches the spender of the given block output key.
func (u *unconfirmedStore) fetchBlockOutPointSpender(key *BlockOutputKey) (
	*txRecord, error) {
	var record *txRecord
	err := u.namespace.View(func(wtx walletdb.Tx) error {
		var err error
		record, err = fetchBlockOutPointSpender(wtx, key)
		return err
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}
	return record, nil
}

// lookupSpentBlockOutPointKey fetches the block output key corresponding to
// the given outpoint.
func (u *unconfirmedStore) lookupSpentBlockOutPointKey(op *wire.OutPoint) (
	*BlockOutputKey, error) {
	var key *BlockOutputKey
	err := u.namespace.View(func(wtx walletdb.Tx) error {
		var err error
		key, err = fetchSpentBlockOutPointKey(wtx, op)
		return err
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}
	return key, nil
}

// fetchUnconfirmedSpends returns a slice of all the unconfirmed transaction
// records in the unconfirmed store.
func (u *unconfirmedStore) fetchUnconfirmedSpends() ([]*txRecord, error) {
	var records []*txRecord
	err := u.namespace.View(func(wtx walletdb.Tx) error {
		var err error
		records, err = fetchUnconfirmedSpends(wtx)
		return err
	})
	if err != nil {
		return records, maybeConvertDbError(err)
	}
	return records, nil
}

// fetchSpentBlockOutPoints returns a slice of all the spent block output
// keys in the unconfirmed store.
func (u *unconfirmedStore) fetchSpentBlockOutPoints() ([]*BlockOutputKey,
	error) {
	var keys []*BlockOutputKey
	err := u.namespace.View(func(wtx walletdb.Tx) error {
		var err error
		keys, err = fetchAllSpentBlockOutPoints(wtx)
		return err
	})
	if err != nil {
		return keys, maybeConvertDbError(err)
	}
	return keys, nil
}

// fetchConfirmedSpends returns a slice of all unconfirmed transaction records
// which spend a confirmed output from the unconfirmed store.
func (u *unconfirmedStore) fetchConfirmedSpends() ([]*txRecord, error) {
	var records []*txRecord
	err := u.namespace.View(func(wtx walletdb.Tx) error {
		var err error
		records, err = fetchConfirmedSpends(wtx)
		return err
	})
	if err != nil {
		return records, maybeConvertDbError(err)
	}
	return records, nil
}

// setOutPointSpender sets the unconfirmed outpoint as spent by the
// given spender.
func (u *unconfirmedStore) setOutPointSpender(op *wire.OutPoint,
	r *txRecord) error {
	return u.namespace.Update(func(wtx walletdb.Tx) error {
		return setUnconfirmedOutPointSpender(wtx, op, r)
	})
}

// setBlockOutPointSpender marks the given outpoint as spent by the given
// spender.
func (u *unconfirmedStore) setBlockOutPointSpender(op *wire.OutPoint,
	key *BlockOutputKey, r *txRecord) error {
	return u.namespace.Update(func(wtx walletdb.Tx) error {
		return setBlockOutPointSpender(wtx, op, key, r)
	})
}

// findDoubleSpend finds the double spending transaction record of the given
// transaction from the unconfirmed store.
func (u *unconfirmedStore) findDoubleSpend(tx *btcutil.Tx) *txRecord {
	for _, input := range tx.MsgTx().TxIn {
		if r, err := u.fetchPrevOutPointSpender(
			&input.PreviousOutPoint); err == nil {
			return r
		}
	}
	return nil
}
