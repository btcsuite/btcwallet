package bwtest

import (
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// NodeBenchmarkPointValue is the cooperative wallet return: 500000-sat capacity
// minus a 100000-sat peer output and 1930-sat close fee. Native readers choose
// the smallest txid:index at this value, aligning address, outpoint and
// one-input/two-output transaction requests across case sizes.
const NodeBenchmarkPointValue = 398_070

// SelectNodeBenchmarkTarget returns the retained cooperative output with the
// smallest displayed txid/index, independent of native enumeration order.
// project exposes native fields without coupling this package to Wallet or
// legacy JSON result types. A missing cooperative return yields false.
func SelectNodeBenchmarkTarget[T any](outputs []T,
	project func(T) (btcutil.Amount, string, uint32)) (T, bool) {

	var (
		target      T
		targetTxID  string
		targetIndex uint32
		found       bool
	)

	for _, output := range outputs {
		amount, txid, index := project(output)
		if amount != NodeBenchmarkPointValue {
			continue
		}

		// The first match initializes the minimum; later matches use the
		// same display-order key for every backend's point-read request.
		if !found || txid < targetTxID ||
			(txid == targetTxID && index < targetIndex) {

			target = output
			targetTxID = txid
			targetIndex = index
			found = true
		}
	}

	return target, found
}

// lndTransaction builds an unsigned version-2 Store record from the supplied
// inputs and outputs. Only the owned output indexes become wallet credits;
// lifecycle ordering and confirmation metadata belong to lndChannelHistory.
func lndTransaction(walletID uint32, inputs []wire.OutPoint,
	outputs []*wire.TxOut, owned []uint32) db.CreateTxParams {

	const version = 2

	tx := wire.NewMsgTx(version)
	for _, point := range inputs {
		tx.AddTxIn(wire.NewTxIn(&point, nil, nil))
	}

	for _, output := range outputs {
		tx.AddTxOut(output)
	}

	credits := make(map[uint32]address.Address, len(owned))
	for _, index := range owned {
		credits[index] = nil
	}

	return db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Credits:  credits,
		Status:   db.TxStatusPublished,
	}
}

// lndScript retains the observed foreign output types without adding
// signing or another key derivation implementation to fixture preparation.
func lndScript(tag string, index uint32, version byte) []byte {
	hash := chainhash.DoubleHashH([]byte(fmt.Sprintf("%s/%d", tag, index)))
	if version == txscript.OP_DUP {
		return append(append([]byte{
			txscript.OP_DUP, txscript.OP_HASH160, txscript.OP_DATA_20,
		}, hash[:20]...), txscript.OP_EQUALVERIFY, txscript.OP_CHECKSIG)
	}

	return append([]byte{version, txscript.OP_DATA_32}, hash[:]...)
}
