package bwtest

import (
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// NodeBenchmarkPointValue identifies retained cooperative returns for point
// reads. Their one-input, two-output parent has the same shape in every case.
const NodeBenchmarkPointValue = 398_070

// ListUnspentWorkload describes independent initial funding UTXO lifecycles.
// Accounts counts regular scoped accounts; Addresses excludes internal channel
// keys. Transactions and UTXOs describe the resolved wallet endpoint.
// FundingUTXOs counts deposits; Channels totals their channels.
// The value owns its seed and contains no backend or Wallet execution policy.
type ListUnspentWorkload struct {
	ID           string
	Accounts     uint32
	Addresses    uint32
	Transactions uint32
	UTXOs        uint32
	FundingUTXOs uint32
	Channels     uint32
	Seed         []byte
	Birthday     time.Time
	Account      string
	MinConfs     int32
	MaxConfs     int32
}

// ListUnspentAddressBatch fixes scope/account/branch allocation order across
// native seeders. Internal channel-key batches remain separate from ordinary
// address scripts and never receive wallet credits in this workload.
type ListUnspentAddressBatch struct {
	Scope    waddrmgr.KeyScope
	Account  uint32
	Internal bool
	Count    uint32
}

// ListUnspentCases returns the observed one-deposit model, scaled ten/hundred
// deposit histories, and a tiny smoke case. Accounts remain fixed across sizes.
func ListUnspentCases() []ListUnspentWorkload {
	const (
		fullChannels     = 100
		smokeChannels    = 20
		mediumFunding    = 10
		largeFunding     = 100
		regularAccounts  = 260
		ordinaryBranches = 2
		addressOverhead  = 3
		historyOverhead  = 4
		birthdayUnix     = 1_700_000_000
	)

	cases := []ListUnspentWorkload{
		{
			ID:           "small-node",
			FundingUTXOs: 1,
			Channels:     fullChannels,
		},
		{
			ID:           "medium-node",
			FundingUTXOs: mediumFunding,
			Channels:     mediumFunding * fullChannels,
		},
		{
			ID:           "large-node",
			FundingUTXOs: largeFunding,
			Channels:     largeFunding * fullChannels,
		},
		{
			ID:           "smoke",
			FundingUTXOs: 1,
			Channels:     smokeChannels,
		},
	}
	// Each case owns the same deterministic seed, avoiding shared mutable
	// storage while all native seeders derive identical wallet scripts.
	for i := range cases {
		w := &cases[i]
		w.Accounts = regularAccounts
		w.Addresses = ordinaryBranches*w.Channels +
			addressOverhead*w.FundingUTXOs
		w.Transactions = ordinaryBranches*w.Channels +
			historyOverhead*w.FundingUTXOs
		w.UTXOs = w.Channels + w.FundingUTXOs
		w.Birthday = time.Unix(birthdayUnix, 0).UTC()
		w.MaxConfs = math.MaxInt32

		w.Seed = make([]byte, hdkeychain.RecommendedSeedLen)
		for j := range w.Seed {
			w.Seed[j] = byte(j + 1)
		}
	}

	return cases
}

// AddressBatches shares exact ordinary paths and internal key-family indexes.
// Family five retains the wallet-wide skipped revocation-root index zero.
func (w ListUnspentWorkload) AddressBatches() []ListUnspentAddressBatch {
	const (
		closingExtra     = 2
		channelPurpose   = 1017
		families         = 6
		revocationFamily = 5
	)

	batches := []ListUnspentAddressBatch{
		{
			Scope: waddrmgr.KeyScopeBIP0084,
			Count: w.FundingUTXOs,
		},
		{
			Scope:    waddrmgr.KeyScopeBIP0086,
			Internal: true,
			Count:    w.Channels,
		},
		{
			Scope: waddrmgr.KeyScopeBIP0086,
			Count: w.Channels + closingExtra*w.FundingUTXOs,
		},
	}
	for family := range uint32(families) {
		count := w.Channels
		if family == revocationFamily {
			count++
		}

		batches = append(batches, ListUnspentAddressBatch{
			Scope:   waddrmgr.KeyScope{Purpose: channelPurpose, Coin: 1},
			Account: family,
			Count:   count,
		})
	}

	return batches
}

// Batch constructs matching normalized history without touching a database.
// Scripts follow the three ordinary AddressBatches; internal key batches are
// not wallet payment addresses. Each unit retains two unconfirmed force-close
// records while ordinary credits and the final tip are confirmed, as observed.
func (w ListUnspentWorkload) Batch(walletID uint32,
	scripts [][]byte) db.TxBatchParams {

	const closingExtra = 2

	// Native allocation groups all receiving, change and closing branches.
	// Slice each deposit's distinct paths back into the observed unit order.
	channels := w.Channels / w.FundingUTXOs
	history := make([]db.CreateTxParams, 0, w.Transactions)

	for funding := range w.FundingUTXOs {
		change := w.FundingUTXOs + funding*channels
		closing := w.FundingUTXOs + w.Channels + funding*(channels+closingExtra)
		unitScripts := [][]byte{scripts[funding]}
		unitScripts = append(unitScripts, scripts[change:change+channels]...)
		unitScripts = append(unitScripts,
			scripts[closing:closing+channels+closingExtra]...)
		history = append(history, lndChannelHistory(
			walletID, channels, funding, w.Birthday, unitScripts,
		)...)
	}

	return db.TxBatchParams{
		WalletID:     walletID,
		Transactions: history,
		SyncedTo:     history[len(history)-1].Block,
	}
}

// lndChannelHistory models the observed one-deposit lifecycle without running
// lnd. Scripts contain receiving, funding change and closing/sweep addresses
// in that order. Foreign contracts retain script types and outpoint links;
// their unsigned scripts are not intended for broadcast or channel replay.
// Funding offsets keep replicated units distinct and leave unit zero unchanged.
func lndChannelHistory(walletID, channels, unit uint32, birthday time.Time,
	scripts [][]byte) []db.CreateTxParams {

	const (
		depositValue       int64  = 100_000_000
		minerChange               = 2_398_575_000
		capacity                  = 500_000
		peerValue                 = 100_000
		localValue                = 292_230
		anchorValue               = 330
		htlcValue                 = 10_000
		forceCount         uint32 = 2
		anchorCount        uint32 = 2
		htlcCount          uint32 = 10
		sweepCount                = forceCount * htlcCount
		balanceSweepValue         = 584_244
		timeoutChangeValue        = 394_800
		htlcSweepValue            = 198_327
		firstOpeningFee    int64  = 1647
		openingFee         int64  = 1540
		confirmedExtra            = 2
		historyExtra              = 4
	)

	var history []db.CreateTxParams

	// Continue dense metadata and contract-key indexes across units, including
	// the two unconfirmed records in each unit's received-time progression.
	height, channelOffset := unit*(2*channels+confirmedExtra), unit*channels

	// Keep wallet confirmation metadata separate from contract resolution,
	// matching the reference's two unconfirmed close records.
	add := func(inputs []wire.OutPoint, outputs []*wire.TxOut,
		confirmed bool, owned ...uint32) chainhash.Hash {

		record := lndTransaction(walletID, inputs, outputs, owned)
		elapsed := (time.Duration(unit*(2*channels+historyExtra)) +
			time.Duration(len(history)+1)) * time.Second
		record.Received = birthday.Add(elapsed)

		if confirmed {
			height++
			record.Block = &db.Block{
				Hash: chainhash.DoubleHashH([]byte(fmt.Sprintf(
					"lnd-reference-block/%d", height,
				))),
				Height: height, Timestamp: record.Received,
			}
		}

		history = append(history, record)

		return record.Tx.TxHash()
	}

	// All channel funding inputs descend from this single wallet deposit.
	deposit := add([]wire.OutPoint{
		{
			Hash:  chainhash.DoubleHashH([]byte("lnd-reference-deposit")),
			Index: unit,
		},
	}, []*wire.TxOut{
		wire.NewTxOut(depositValue, scripts[0]),
		wire.NewTxOut(minerChange, lndScript("miner", unit, txscript.OP_DUP)),
	}, true, 0)
	change := wire.OutPoint{Hash: deposit}
	remaining := depositValue

	funding := make([]wire.OutPoint, channels)
	// Spend successive owned change to open channels. The observed first fee
	// is higher for the P2WPKH deposit; later openings spend P2TR change.
	for i := range channels {
		fee := openingFee
		if i == 0 {
			fee = firstOpeningFee
		}

		remaining -= capacity + fee
		hash := add([]wire.OutPoint{change}, []*wire.TxOut{
			wire.NewTxOut(capacity, lndScript(
				"funding", channelOffset+i, txscript.OP_0,
			)),
			wire.NewTxOut(remaining, scripts[1+i]),
		}, true, 1)
		funding[i] = wire.OutPoint{Hash: hash}
		change = wire.OutPoint{Hash: hash, Index: 1}
	}

	// Preserve cooperative returns until one later contributes sweep fees.
	cooperative := make([]wire.OutPoint, 0, channels-forceCount)
	for i := range channels - forceCount {
		hash := add([]wire.OutPoint{funding[i]}, []*wire.TxOut{
			wire.NewTxOut(peerValue, lndScript(
				"peer-close", channelOffset+i, txscript.OP_1,
			)),
			wire.NewTxOut(NodeBenchmarkPointValue, scripts[channels+1+i]),
		}, true, 1)
		cooperative = append(cooperative, wire.OutPoint{Hash: hash, Index: 1})
	}

	// Commitments hold two anchors, ten HTLCs and two-sided balances each.
	// Contract outputs are resolved by lnd, not ordinary wallet credits.
	var localBalances, timeouts []wire.OutPoint
	for i := channels - forceCount; i < channels; i++ {
		outputs := []*wire.TxOut{
			wire.NewTxOut(anchorValue, lndScript(
				"anchor-a", channelOffset+i, txscript.OP_0,
			)),
			wire.NewTxOut(anchorValue, lndScript(
				"anchor-b", channelOffset+i, txscript.OP_0,
			)),
		}
		for j := range htlcCount {
			outputs = append(outputs, wire.NewTxOut(htlcValue, lndScript(
				"commitment-htlc", (channelOffset+i)*htlcCount+j,
				txscript.OP_0,
			)))
		}

		outputs = append(outputs,
			wire.NewTxOut(peerValue, lndScript(
				"remote", channelOffset+i, txscript.OP_0,
			)),
			wire.NewTxOut(localValue, lndScript(
				"local", channelOffset+i, txscript.OP_0,
			)),
		)
		hash := add([]wire.OutPoint{funding[i]}, outputs, false)
		localBalances = append(localBalances, wire.OutPoint{
			Hash:  hash,
			Index: anchorCount + htlcCount + 1,
		})

		for j := range htlcCount {
			timeouts = append(timeouts, wire.OutPoint{
				Hash:  hash,
				Index: j + anchorCount,
			})
		}
	}

	add(localBalances, []*wire.TxOut{
		wire.NewTxOut(balanceSweepValue, scripts[2*channels-1]),
	}, true, 0)

	// One fee input supports the combined timeout transaction. Its twenty
	// contract outputs become a single wallet credit in the final sweep.
	timeouts = append(timeouts, cooperative[len(cooperative)-1])

	outputs := make([]*wire.TxOut, 0, sweepCount+1)
	for i := range sweepCount {
		outputs = append(outputs, wire.NewTxOut(htlcValue,
			lndScript("second-stage", unit*sweepCount+i, txscript.OP_0)))
	}

	outputs = append(outputs, wire.NewTxOut(
		timeoutChangeValue, scripts[2*channels],
	))
	hash := add(timeouts, outputs, true, sweepCount)

	secondStage := make([]wire.OutPoint, 0, sweepCount)
	for i := range sweepCount {
		secondStage = append(secondStage, wire.OutPoint{Hash: hash, Index: i})
	}

	add(secondStage, []*wire.TxOut{
		wire.NewTxOut(htlcSweepValue, scripts[2*channels+1]),
	}, true, 0)

	return history
}

// lndTransaction constructs the shared unsigned Store record. Keeping
// input/output assembly here leaves lifecycle ordering visible in the scenario.
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
		WalletID: walletID, Tx: tx, Credits: credits,
		Status: db.TxStatusPublished,
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
