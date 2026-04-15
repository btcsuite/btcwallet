package wtxmgr

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/walletdb"
)

// PutTxLabel validates transaction labels and writes them to disk if they
// are non-zero and within the label length limit. The entry is keyed by the
// transaction hash:
// [0:32] Transaction hash (32 bytes)
//
// The label itself is written to disk in length value format:
// [0:2] Label length
// [2: +len] Label
func (s *Store) PutTxLabel(ns walletdb.ReadWriteBucket, txid chainhash.Hash,
	label string) error {

	if len(label) == 0 {
		return ErrEmptyLabel
	}

	if len(label) > TxLabelLimit {
		return ErrLabelTooLong
	}

	labelBucket, err := ns.CreateBucketIfNotExists(bucketTxLabels)
	if err != nil {
		return err
	}

	return PutTxLabel(labelBucket, txid, label)
}

// TxDetails looks up all recorded details regarding a transaction with some
// hash.  In case of a hash collision, the most recent transaction with a
// matching hash is returned.
//
// Not finding a transaction with this hash is not an error.  In this case,
// a nil TxDetails is returned.
func (s *Store) TxDetails(ns walletdb.ReadBucket,
	txHash *chainhash.Hash) (*TxDetails, error) {
	// First, check whether there exists an unmined transaction with this
	// hash.  Use it if found.
	v := existsRawUnmined(ns, txHash[:])
	if v != nil {
		return s.unminedTxDetails(ns, txHash, v)
	}

	// Otherwise, if there exists a mined transaction with this matching
	// hash, skip over to the newest and begin fetching all details.
	k, v := latestTxRecord(ns, txHash)
	if v == nil {
		// not found
		return nil, nil
	}

	return s.minedTxDetails(ns, txHash, k, v)
}

// RangeTransactions runs the function f on all transaction details between
// blocks on the best chain over the height range [begin,end].  The special
// height -1 may be used to also include unmined transactions.  If the end
// height comes before the begin height, blocks are iterated in reverse order
// and unmined transactions (if any) are processed first.
//
// The function f may return an error which, if non-nil, is propagated to the
// caller.  Additionally, a boolean return value allows exiting the function
// early without reading any additional transactions early when true.
//
// All calls to f are guaranteed to be passed a slice with more than zero
// elements.  The slice may be reused for multiple blocks, so it is not safe to
// use it after the loop iteration it was acquired.
func (s *Store) RangeTransactions(ns walletdb.ReadBucket, begin, end int32,
	f func([]TxDetails) (bool, error)) error {

	var addedUnmined bool
	if begin < 0 {
		brk, err := s.rangeUnminedTransactions(ns, f)
		if err != nil || brk {
			return err
		}
		addedUnmined = true
	}

	brk, err := s.rangeBlockTransactions(ns, begin, end, f)
	if err == nil && !brk && !addedUnmined && end < 0 {
		_, err = s.rangeUnminedTransactions(ns, f)
	}

	return err
}
