package bwtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// syncBenchmarkDepositFee keeps external funding fees separate from the
// canonical wallet-owned model values.
const syncBenchmarkDepositFee = 1000

// syncBenchmarkBackgroundLanes calibrates unrelated traffic near full-block
// payload while leaving room for the complete lnd graph in one matching block.
const (
	syncBenchmarkBackgroundLanes = 6000
	syncBenchmarkPaymentValue    = 1000
	syncBenchmarkPaymentFee      = 1000
	syncBenchmarkTxVersion       = 2
)

// SyncBenchmarkCase separates block placement from the shared Wallet inventory.
// HistoryBlocks gives each modeled transaction's one-based catch-up block;
// an empty schedule requests metadata only, including populated zero-hit cases.
type SyncBenchmarkCase struct {
	ID                     string
	Workload               NodeBenchmarkWorkload
	Blocks                 int32
	BackgroundTransactions int
	HistoryBlocks          []int32
}

// SyncBenchmarkCases holds Wallet inventory fixed. Primary cases vary graph
// placement; payload diagnostics vary unrelated traffic without Wallet hits.
// Each value owns its deterministic seed.
func SyncBenchmarkCases() []SyncBenchmarkCase {
	const (
		smokeBlocks               int32 = 10
		historyBlocks             int32 = 1000
		denseStep                 int32 = 10
		periodicStep              int32 = 100
		diagnosticBackgroundLanes       = 100
	)

	transactions := NodeBenchmarkCases()[0].NumTransactions

	var periodic, dense []int32
	for height := denseStep; height <= historyBlocks; height += denseStep {
		dense = append(dense, height)
		if height%periodicStep == 0 {
			periodic = append(periodic, height)
		}
	}

	cases := []SyncBenchmarkCase{
		{
			ID:                     "smoke",
			Blocks:                 smokeBlocks,
			BackgroundTransactions: syncBenchmarkBackgroundLanes,
			HistoryBlocks: syncBenchmarkHistoryBlocks(
				transactions, []int32{smokeBlocks / 2},
			),
		},
		{
			ID:     "empty",
			Blocks: historyBlocks,
		},
		{
			ID:                     "hits-0",
			Blocks:                 historyBlocks,
			BackgroundTransactions: syncBenchmarkBackgroundLanes,
		},
		{
			ID:                     "hits-1",
			Blocks:                 historyBlocks,
			BackgroundTransactions: syncBenchmarkBackgroundLanes,
			HistoryBlocks: syncBenchmarkHistoryBlocks(
				transactions, []int32{historyBlocks / 2},
			),
		},
		{
			ID:                     "small-node",
			Blocks:                 historyBlocks,
			BackgroundTransactions: syncBenchmarkBackgroundLanes,
			HistoryBlocks: syncBenchmarkHistoryBlocks(
				transactions, periodic,
			),
		},
		{
			ID:                     "hits-100",
			Blocks:                 historyBlocks,
			BackgroundTransactions: syncBenchmarkBackgroundLanes,
			HistoryBlocks: syncBenchmarkHistoryBlocks(
				transactions, dense,
			),
		},
		{
			ID:                     "payload-1",
			Blocks:                 historyBlocks,
			BackgroundTransactions: 1,
		},
		{
			ID:                     "payload-100",
			Blocks:                 historyBlocks,
			BackgroundTransactions: diagnosticBackgroundLanes,
		},
	}

	// Reuse native allocation inputs without sharing mutable seed storage
	// between independent case preparations or changing the read cases.
	for i := range cases {
		cases[i].Workload = NodeBenchmarkCases()[0]
	}

	return cases
}

// syncBenchmarkHistoryBlocks evenly groups the ordered graph into the explicit
// occupied blocks without changing parent-before-child transaction order.
func syncBenchmarkHistoryBlocks(transactions uint32,
	occupied []int32) []int32 {

	heights := make([]int32, transactions)
	for i := range heights {
		heights[i] = occupied[i*len(occupied)/len(heights)]
	}

	return heights
}

// BuildSyncBenchmarkHistory materializes the existing graph using real funding.
// Funding contains one miner coinbase per deposit, in model order. The caller's
// unlocked preparation Wallet signs owned inputs before its baseline is closed.
func BuildSyncBenchmarkHistory(ctx context.Context,
	workload NodeBenchmarkWorkload, scripts [][]byte, funding []*wire.MsgTx,
	sign func(context.Context, *wire.MsgTx, int, *wire.TxOut,
		*txscript.TxSigHashes) (wire.TxWitness, error)) ([]*wire.MsgTx, error) {

	_, minerKey, err := syncBenchmarkMinerAddress()
	if err != nil {
		return nil, err
	}
	defer minerKey.Zero()

	// Keep the established graph and credit ownership; only identities and
	// foreign witness contracts change to make its unsigned records spendable.
	records := workload.Batch(0, scripts).Transactions
	root := records[0].Tx.TxIn[0].PreviousOutPoint.Hash
	parents := make(map[chainhash.Hash]chainhash.Hash)
	prevouts := txscript.NewMultiPrevOutFetcher(nil)

	minerInputs := make(map[wire.OutPoint]bool)
	for _, coinbase := range funding {
		point := wire.OutPoint{Hash: coinbase.TxHash()}
		prevouts.AddPrevOut(point, coinbase.TxOut[0])
		minerInputs[point] = true
	}

	history := make([]*wire.MsgTx, 0, len(records))
	for _, record := range records {
		tx := materializeSyncBenchmarkTransaction(
			record.Tx, root, funding, parents,
		)

		// The complete prevout set is required for Taproot sighashes, including
		// the wallet fee input alongside foreign timeout inputs in the sweep.
		hashes := txscript.NewTxSigHashes(tx, prevouts)
		for index, input := range tx.TxIn {
			point := input.PreviousOutPoint
			output := prevouts.FetchPrevOutput(point)

			var witness wire.TxWitness
			switch {
			case minerInputs[point]:
				// Real coinbases belong to the fixed preparation miner,
				// independently of the Wallet's derived inventory.
				witness, err = txscript.WitnessSignature(
					tx, hashes, index, output.Value, output.PkScript,
					txscript.SigHashAll, minerKey, true,
				)

			case txscript.IsPayToWitnessScriptHash(output.PkScript):
				// Reconstruct the parent's distinct contract from the
				// original outpoint, without another retained key map.
				_, witnessScript := syncBenchmarkContract(
					record.Tx.TxIn[index].PreviousOutPoint,
				)
				witness = wire.TxWitness{witnessScript}

			default:
				// Ordinary owned scripts retain native key derivation,
				// so only the unlocked Wallet may sign their inputs.
				witness, err = sign(ctx, tx, index, output, hashes)
			}

			if err != nil {
				return nil, fmt.Errorf("sign modeled input: %w", err)
			}

			input.Witness = witness
		}

		// Descendants must reference the materialized parent, never the
		// synthetic template identity. Keep all graph bytes only in memory.
		txid := tx.TxHash()
		parents[record.Tx.TxHash()] = txid

		var index uint32
		for _, output := range tx.TxOut {
			prevouts.AddPrevOut(wire.OutPoint{
				Hash: txid, Index: index,
			}, output)
			index++
		}

		history = append(history, tx)
	}

	return history, nil
}

// materializeSyncBenchmarkTransaction replaces synthetic parent identities.
// Ordinary model scripts are P2WPKH/P2TR; all P2WSH outputs are foreign.
func materializeSyncBenchmarkTransaction(original *wire.MsgTx,
	root chainhash.Hash, funding []*wire.MsgTx,
	parents map[chainhash.Hash]chainhash.Hash) *wire.MsgTx {

	tx := original.Copy()
	for _, input := range tx.TxIn {
		point := input.PreviousOutPoint
		if point.Hash == root {
			coinbase := funding[point.Index]
			input.PreviousOutPoint = wire.OutPoint{
				Hash: coinbase.TxHash(),
			}
			// The wallet deposit stays fixed; miner change absorbs
			// the real coinbase value and a fixed preparation fee.
			tx.TxOut[1].Value = coinbase.TxOut[0].Value -
				tx.TxOut[0].Value - syncBenchmarkDepositFee
		} else {
			input.PreviousOutPoint.Hash = parents[point.Hash]
		}
	}

	var index uint32
	for _, output := range tx.TxOut {
		if txscript.IsPayToWitnessScriptHash(output.PkScript) {
			// Preserve foreign address distinctness while replacing
			// Lightning timelocks with a valid controlled witness.
			output.PkScript, _ = syncBenchmarkContract(wire.OutPoint{
				Hash: original.TxHash(), Index: index,
			})
		}

		index++
	}

	return tx
}

// syncBenchmarkContract gives each foreign output a distinct known witness.
// The outpoint tag preserves script diversity without modeling CSV or CLTV.
func syncBenchmarkContract(point wire.OutPoint) ([]byte, []byte) {
	var material [chainhash.HashSize + 4]byte
	copy(material[:], point.Hash[:])
	binary.LittleEndian.PutUint32(material[chainhash.HashSize:], point.Index)
	tag := sha256.Sum256(material[:])
	witness := append([]byte{txscript.OP_DATA_32}, tag[:]...)
	witness = append(witness, txscript.OP_DROP, txscript.OP_TRUE)
	hash := sha256.Sum256(witness)
	script := append([]byte{txscript.OP_0, txscript.OP_DATA_32}, hash[:]...)

	return script, witness
}

// BuildSyncBenchmarkFunding fans mature miner coinbases into independent
// P2WPKH lanes. Callers supply positive lanes and mature miner-owned coinbases;
// three coinbases fund 6,000 lanes through the full 1,000-block history.
func BuildSyncBenchmarkFunding(funding []*wire.MsgTx,
	lanes int) (*wire.MsgTx, error) {

	addr, key, err := syncBenchmarkMinerAddress()
	if err != nil {
		return nil, err
	}
	defer key.Zero()

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, fmt.Errorf("miner script: %w", err)
	}

	// All source outputs belong to the existing preparation miner; divide
	// their value after the fixed fee rather than introducing funding state.
	tx := wire.NewMsgTx(syncBenchmarkTxVersion)
	prevouts := txscript.NewMultiPrevOutFetcher(nil)

	value := -int64(syncBenchmarkDepositFee)
	for _, parent := range funding {
		point := wire.OutPoint{Hash: parent.TxHash()}
		tx.AddTxIn(wire.NewTxIn(&point, nil, nil))
		prevouts.AddPrevOut(point, parent.TxOut[0])
		value += parent.TxOut[0].Value
	}

	for range lanes {
		tx.AddTxOut(wire.NewTxOut(value/int64(lanes), script))
	}

	hashes := txscript.NewTxSigHashes(tx, prevouts)
	for index, parent := range funding {
		tx.TxIn[index].Witness, err = txscript.WitnessSignature(
			tx, hashes, index, parent.TxOut[0].Value, script,
			txscript.SigHashAll, key, true,
		)
		if err != nil {
			return nil, fmt.Errorf("sign background funding: %w", err)
		}
	}

	return tx, nil
}

// BuildSyncBenchmarkBackground spends miner outputs from either the initial
// fan-out or the prior background block. Each payment leaves one miner change
// output for the next block, so callers retain only the previous block.
func BuildSyncBenchmarkBackground(ctx context.Context,
	previous []*wire.MsgTx) ([]*wire.MsgTx, error) {

	addr, key, err := syncBenchmarkMinerAddress()
	if err != nil {
		return nil, err
	}
	defer key.Zero()

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, fmt.Errorf("miner script: %w", err)
	}

	var transactions []*wire.MsgTx
	for _, parent := range previous {
		hash := parent.TxHash()

		var index uint32
		for _, output := range parent.TxOut {
			point := wire.OutPoint{Hash: hash, Index: index}
			index++

			// Only miner change rolls forward. Distinct foreign P2WSH
			// payments stay unrelated to every Wallet and later lane.
			if !bytes.Equal(output.PkScript, script) {
				continue
			}

			err = ctx.Err()
			if err != nil {
				return nil, err
			}

			recipient, _ := syncBenchmarkContract(point)
			tx := wire.NewMsgTx(syncBenchmarkTxVersion)
			tx.AddTxIn(wire.NewTxIn(&point, nil, nil))
			tx.AddTxOut(wire.NewTxOut(syncBenchmarkPaymentValue, recipient))
			tx.AddTxOut(wire.NewTxOut(
				output.Value-syncBenchmarkPaymentValue-syncBenchmarkPaymentFee,
				script,
			))
			prevout := txscript.NewCannedPrevOutputFetcher(script, output.Value)
			hashes := txscript.NewTxSigHashes(tx, prevout)

			tx.TxIn[0].Witness, err = txscript.WitnessSignature(
				tx, hashes, 0, output.Value, script,
				txscript.SigHashAll, key, true,
			)
			if err != nil {
				return nil, fmt.Errorf("sign background payment: %w", err)
			}

			transactions = append(transactions, tx)
		}
	}

	return transactions, nil
}

// syncBenchmarkMinerAddress fixes coinbase ownership independently of Wallet
// allocation, so the shared fixture needs neither bitcoind's wallet nor lnd.
func syncBenchmarkMinerAddress() (address.Address, *btcec.PrivateKey, error) {
	key, pub := btcec.PrivKeyFromBytes([]byte{1})

	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pub.SerializeCompressed()),
		&chaincfg.RegressionNetParams,
	)
	if err != nil {
		key.Zero()
		return nil, nil, fmt.Errorf("miner address: %w", err)
	}

	return addr, key, nil
}
