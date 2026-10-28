package bwtest

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
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

// NodeBenchmarkWorkload describes node data shared by native read benchmarks.
// NumAccounts counts derived scoped accounts, including channel key families
// but excluding imported pseudo-accounts. NumAddresses counts ordinary payment
// and change addresses, excluding channel keys. NumTransactions and NumUTXOs
// describe the resolved endpoint. NumFundingUTXOs counts deposits;
// NumChannels totals their channels.
// The value owns its seed and contains no backend or Wallet execution policy.
type NodeBenchmarkWorkload struct {
	ID              string
	NumAccounts     uint32
	NumAddresses    uint32
	NumTransactions uint32
	NumUTXOs        uint32
	NumFundingUTXOs uint32
	NumChannels     uint32
	Seed            []byte
	Birthday        time.Time
	Account         string
	MinConfs        int32
	MaxConfs        int32
}

// NodeBenchmarkAddressBatch fixes scope/account/branch allocation order across
// native seeders. Internal channel-key batches remain separate from ordinary
// address scripts and never receive wallet credits in this workload.
type NodeBenchmarkAddressBatch struct {
	Scope    waddrmgr.KeyScope
	Account  uint32
	Internal bool
	Count    uint32
}

// NodeBenchmarkCases returns shared models: one observed deposit, ten/hundred
// repeated deposits and a tiny smoke case. Accounts stay fixed across sizes.
func NodeBenchmarkCases() []NodeBenchmarkWorkload {
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

	cases := []NodeBenchmarkWorkload{
		{
			ID:              "small-node",
			NumFundingUTXOs: 1,
			NumChannels:     fullChannels,
		},
		{
			ID:              "medium-node",
			NumFundingUTXOs: mediumFunding,
			NumChannels:     mediumFunding * fullChannels,
		},
		{
			ID:              "large-node",
			NumFundingUTXOs: largeFunding,
			NumChannels:     largeFunding * fullChannels,
		},
		{
			ID:              "smoke",
			NumFundingUTXOs: 1,
			NumChannels:     smokeChannels,
		},
	}
	// Each case owns the same deterministic seed, avoiding shared mutable
	// storage while all native seeders derive identical wallet scripts.
	for i := range cases {
		w := &cases[i]
		w.NumAccounts = regularAccounts
		w.NumAddresses = ordinaryBranches*w.NumChannels +
			addressOverhead*w.NumFundingUTXOs
		w.NumTransactions = ordinaryBranches*w.NumChannels +
			historyOverhead*w.NumFundingUTXOs
		w.NumUTXOs = w.NumChannels + w.NumFundingUTXOs
		w.Birthday = time.Unix(birthdayUnix, 0).UTC()
		w.MaxConfs = math.MaxInt32

		w.Seed = make([]byte, hdkeychain.RecommendedSeedLen)
		for j := range w.Seed {
			w.Seed[j] = byte(j + 1)
		}
	}

	return cases
}

// NodeBenchmarkChannelScope identifies the lnd key families shared by native
// account creation, address allocation and fixture validation.
func NodeBenchmarkChannelScope() waddrmgr.KeyScope {
	const purpose = 1017

	return waddrmgr.KeyScope{
		Purpose: purpose,
		Coin:    1,
	}
}

// AddressBatches describes three ordinary address branches and six channel key
// families for native seeders. Family five includes lnd's extra allocation for
// the revocation-root index zero that it leaves unused once per Wallet.
func (w NodeBenchmarkWorkload) AddressBatches() []NodeBenchmarkAddressBatch {
	const (
		closingExtra     = 2
		families         = 6
		revocationFamily = 5
	)

	batches := []NodeBenchmarkAddressBatch{
		{
			Scope: waddrmgr.KeyScopeBIP0084,
			Count: w.NumFundingUTXOs,
		},
		{
			Scope:    waddrmgr.KeyScopeBIP0086,
			Internal: true,
			Count:    w.NumChannels,
		},
		{
			Scope: waddrmgr.KeyScopeBIP0086,
			Count: w.NumChannels + closingExtra*w.NumFundingUTXOs,
		},
	}

	// Each internal family allocates one key per channel.
	for family := range uint32(families) {
		count := w.NumChannels

		// lnd derives again when its first revocation-root key has index zero,
		// avoiding its legacy private-key lookup special case. Retain that
		// unused slot once per Wallet, followed by one key per channel.
		if family == revocationFamily {
			count++
		}

		batches = append(batches, NodeBenchmarkAddressBatch{
			Scope:   NodeBenchmarkChannelScope(),
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
func (w NodeBenchmarkWorkload) Batch(walletID uint32,
	scripts [][]byte) db.TxBatchParams {

	const closingExtra = 2

	// Native allocation groups all receiving, change and closing branches.
	// Slice each deposit's distinct paths back into the observed unit order.
	channels := w.NumChannels / w.NumFundingUTXOs
	history := make([]db.CreateTxParams, 0, w.NumTransactions)

	for funding := range w.NumFundingUTXOs {
		change := w.NumFundingUTXOs + funding*channels
		closing := w.NumFundingUTXOs + w.NumChannels +
			funding*(channels+closingExtra)
		unitScripts := [][]byte{scripts[funding]}
		unitScripts = append(unitScripts, scripts[change:change+channels]...)
		unitScripts = append(
			unitScripts, scripts[closing:closing+channels+closingExtra]...,
		)
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

// AssertNodeBenchmarkWallet checks committed fixture counts after seeding and
// before saving a new snapshot. Branch counters verify address/key allocation
// without an expensive address/balance scan. Cached restores do not repeat it.
func AssertNodeBenchmarkWallet(tb testing.TB, store db.Store,
	walletID uint32, workload NodeBenchmarkWorkload) {

	tb.Helper()

	// Full Store lists exclude legacy imported pseudo-accounts. Skip balances
	// because this check needs only the derived account identities and counts.
	accounts, err := store.ListAccounts(
		tb.Context(), db.ListAccountsQuery{
			WalletID:    walletID,
			SkipBalance: true,
		},
	)
	require.NoError(tb, err)
	require.Len(
		tb, accounts, int(workload.NumAccounts),
		"fixture %s accounts", workload.ID,
	)

	// Read the recorded branch counter for each allocation group. Ordinary
	// branches also contribute to the independent NumAddresses total.
	var ordinaryAddresses uint32

	for _, batch := range workload.AddressBatches() {
		account, err := store.GetAccount(
			tb.Context(), db.GetAccountQuery{
				WalletID:      walletID,
				Scope:         db.KeyScope(batch.Scope),
				AccountNumber: &batch.Account,
				SkipBalance:   true,
			},
		)
		require.NoError(tb, err)

		count := account.ExternalKeyCount
		if batch.Internal {
			count = account.InternalKeyCount
		}

		require.Equal(
			tb, batch.Count, count,
			"fixture %s branch %v/%d internal=%t", workload.ID,
			batch.Scope, batch.Account, batch.Internal,
		)

		// Channel keys do not contribute to ordinary-address totals.
		if batch.Scope != NodeBenchmarkChannelScope() {
			ordinaryAddresses += count
		}
	}

	require.Equal(
		tb, workload.NumAddresses, ordinaryAddresses,
		"fixture %s ordinary addresses", workload.ID,
	)

	// Confirmed-range reads exclude the retained unmined force closes. Count
	// both views so the assertion covers the complete stored history.
	confirmed, err := store.ListTxns(
		tb.Context(), db.ListTxnsQuery{
			WalletID:  walletID,
			EndHeight: math.MaxInt32,
		},
	)
	require.NoError(tb, err)

	unmined, err := store.ListTxns(
		tb.Context(), db.ListTxnsQuery{
			WalletID:    walletID,
			UnminedOnly: true,
		},
	)
	require.NoError(tb, err)
	require.Equal(
		tb, int(workload.NumTransactions), len(confirmed)+len(unmined),
		"fixture %s transactions", workload.ID,
	)

	// The current owned set is the resolved endpoint, after all history writes.
	utxos, err := store.ListUTXOs(
		tb.Context(), db.ListUtxosQuery{
			WalletID: walletID,
		},
	)
	require.NoError(tb, err)
	require.Len(
		tb, utxos, int(workload.NumUTXOs),
		"fixture %s UTXOs", workload.ID,
	)
}

// lndChannelHistory models one observed deposit without running lnd:
//
//	deposit -> openings -> cooperative closes
//	                   \-> two force closes -> balance sweep
//	                                       \-> timeouts -> HTLC sweep
//
// - Deposit and openings confirm; successive change funds each channel.
// - Cooperative closes confirm and credit the wallet's return.
// - Two force closes stay unconfirmed; contract outputs are not wallet credits.
// - Confirmed balance/timeout/HTLC sweeps credit their owned outputs.
// Scripts order receiving, funding change and closing/sweep addresses. Foreign
// scripts preserve types and links but are unsigned, not channel replay data.
func lndChannelHistory(walletID, channels, unit uint32, birthday time.Time,
	scripts [][]byte) []db.CreateTxParams {

	const (
		// Observed output amounts reproduce the reference lifecycle; see the
		// transaction census in docs/developer/benchmark/reproducibility.md.
		depositValue int64  = 100_000_000
		minerChange         = 2_398_575_000
		capacity            = 500_000
		peerValue           = 100_000
		localValue          = 292_230
		anchorValue         = 330
		htlcValue           = 10_000
		forceCount   uint32 = 2
		anchorCount  uint32 = 2
		htlcCount    uint32 = 10
		// Each force close contributes its HTLCs to the final sweep.
		sweepCount         = forceCount * htlcCount
		balanceSweepValue  = 584_244
		timeoutChangeValue = 394_800
		htlcSweepValue     = 198_327
		// Observed opening fees differ for the first P2WPKH input.
		firstOpeningFee int64 = 1647
		openingFee      int64 = 1540
		// Per-deposit offsets account for sweeps and unconfirmed closes.
		confirmedExtra = 2
		historyExtra   = 4
	)

	var history []db.CreateTxParams

	// Derived offsets keep replicated block and contract-key indexes distinct.
	height, channelOffset := unit*(2*channels+confirmedExtra), unit*channels

	add := func(inputs []wire.OutPoint, outputs []*wire.TxOut,
		confirmed bool, owned ...uint32) chainhash.Hash {

		record := lndTransaction(walletID, inputs, outputs, owned)
		elapsed := (time.Duration(unit*(2*channels+historyExtra)) +
			time.Duration(len(history)+1)) * time.Second
		record.Received = birthday.Add(elapsed)

		// Give each confirmed record its own synthetic height for deterministic
		// ordering and tip metadata across repeated units. This does not model
		// real block packing; unconfirmed force closes keep their block unset.
		if confirmed {
			height++
			record.Block = &db.Block{
				Hash: chainhash.DoubleHashH([]byte(fmt.Sprintf(
					"lnd-reference-block/%d", height,
				))),
				Height:    height,
				Timestamp: record.Received,
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
		change = wire.OutPoint{
			Hash:  hash,
			Index: 1,
		}
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
		cooperative = append(cooperative, wire.OutPoint{
			Hash:  hash,
			Index: 1,
		})
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
		outputs = append(outputs, wire.NewTxOut(
			htlcValue, lndScript(
				"second-stage", unit*sweepCount+i, txscript.OP_0,
			),
		))
	}

	outputs = append(outputs, wire.NewTxOut(
		timeoutChangeValue, scripts[2*channels],
	))
	hash := add(timeouts, outputs, true, sweepCount)

	secondStage := make([]wire.OutPoint, 0, sweepCount)
	for i := range sweepCount {
		secondStage = append(secondStage, wire.OutPoint{
			Hash:  hash,
			Index: i,
		})
	}

	add(secondStage, []*wire.TxOut{
		wire.NewTxOut(htlcSweepValue, scripts[2*channels+1]),
	}, true, 0)

	return history
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
