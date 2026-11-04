//go:build itest

package itest

import (
	"bytes"
	"slices"
	"sync"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// txCreatorFundingType is the address type the TxCreator cases fund and select
// from. Each case derives its key scope from this value, so the funded scope is
// never stated twice.
const txCreatorFundingType = waddrmgr.WitnessPubKey

// deriveWalletPayment derives a fresh external address of the requested type
// from the wallet and returns a payment of amount to it.
//
// Paying the wallet itself keeps the destination wallet-visible, and the
// external branch is what tells the payment apart from an internal change
// output, which the cases rely on when they identify the change.
//
// Deriving the address changes the wallet but not its synchronization state,
// which the harness has already asserted for every registered wallet while
// mining the funding block.
func deriveWalletPayment(h *bwtest.HarnessTest, w *wallet.Wallet,
	addrType waddrmgr.AddressType, amount btcutil.Amount) wire.TxOut {

	h.Helper()

	addr := h.NewWalletAddressOfType(w, addrType)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	return wire.TxOut{
		Value:    int64(amount),
		PkScript: pkScript,
	}
}

// testCreateTransactionSelectCoins verifies that policy-based selection funds
// a payment from the named account, returns the remainder to an internal
// change address, and reserves nothing.
func testCreateTransactionSelectCoins(h *bwtest.HarnessTest) {
	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		Unlocked: true,
	})

	outpoints := funding.WalletOutpoints

	payment := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)

	account := &wallet.ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    scope,
	}

	before, err := w.GetAccount(
		h.Context(), scope, waddrmgr.DefaultAccountName,
	)
	require.NoError(h, err, "failed to read account")

	authored, err := w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{payment},
		Inputs: &wallet.InputsPolicy{
			Strategy: wallet.CoinSelectionLargest,
			MinConfs: 1,
			Source:   account,
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})
	require.NoError(h, err, "failed to create transaction")

	// Largest-first selection covers the payment with the two BTC coin on
	// its own, and reports that coin as the spent input.
	require.Len(h, authored.Tx.TxIn, 1, "unexpected input count")
	require.Equal(
		h, outpoints[1], authored.Tx.TxIn[0].PreviousOutPoint,
		"unexpected selected input",
	)
	require.Equal(
		h, btcutil.Amount(twoBTC), authored.TotalInput,
		"unexpected total input",
	)
	require.Equal(
		h, []btcutil.Amount{twoBTC}, authored.PrevInputValues,
		"unexpected input values",
	)

	// The transaction pays the requested output and one change output.
	require.Len(h, authored.Tx.TxOut, 2, "unexpected output count")
	require.GreaterOrEqual(h, authored.ChangeIndex, 0, "no change output")

	paid := authored.Tx.TxOut[1-authored.ChangeIndex]
	require.Equal(h, payment.Value, paid.Value, "payment value changed")
	require.Equal(h, payment.PkScript, paid.PkScript, "payment script changed")

	// The remainder returns to the wallet on an internal address of the
	// funded account.
	change := authored.Tx.TxOut[authored.ChangeIndex]
	_, changeAddrs, _, err := txscript.ExtractPkScriptAddrs(
		change.PkScript, h.NetParams(),
	)
	require.NoError(h, err, "failed to extract change address")
	require.Len(h, changeAddrs, 1, "unexpected change address count")

	changeInfo, err := w.GetAddressInfo(h.Context(), changeAddrs[0])
	require.NoError(h, err, "change address is unknown to the wallet")
	require.True(h, changeInfo.Internal, "change address is not internal")
	require.Equal(
		h, txCreatorFundingType, changeInfo.AddrType,
		"unexpected change address type",
	)

	// Kept change commits exactly one change address.
	after, err := w.GetAccount(
		h.Context(), scope, waddrmgr.DefaultAccountName,
	)
	require.NoError(h, err, "failed to read account")
	require.Equal(
		h, before.InternalKeyCount+1, after.InternalKeyCount,
		"change address not committed once",
	)

	// The inputs cover both outputs, leaving a fee behind.
	require.Greater(
		h, int64(authored.TotalInput), paid.Value+change.Value,
		"authored transaction pays no fee",
	)

	// Creating a transaction neither spends nor reserves the coin it
	// selected.
	utxos, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent")

	unspent := make([]wire.OutPoint, 0, len(utxos))
	for _, utxo := range utxos {
		unspent = append(unspent, utxo.OutPoint)
	}

	require.ElementsMatch(h, outpoints, unspent, "wallet utxo set changed")

	leases, err := w.ListLeasedOutputs(h.Context())
	require.NoError(h, err, "failed to list leased outputs")
	require.Empty(h, leases, "creating a transaction reserved a coin")
}

// testCreateTransactionWatchChange proves an authored change address is live
// before CreateTransaction returns: a later unmined payment to it is observed
// without any block or restart revealing it.
func testCreateTransactionWatchChange(h *bwtest.HarnessTest) {
	// Kvdb keeps its legacy unwatched change allocation.
	//nolint:staticcheck // This guard intentionally selects legacy kvdb.
	if *dbBackend == string(wallet.DBBackendKVDB) {
		h.Skip("live change registration requires SQL")
	}

	if _, ok := h.ChainClient.(*chain.NeutrinoClient); ok {
		h.Skip("SPV does not deliver mempool transactions")
	}

	// Arrange: Author a payment from the funded account that leaves change,
	// and resolve that change output's script.
	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{twoBTC},
		Unlocked: true,
	})

	payment := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)

	account := &wallet.ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    scope,
	}

	authored, err := w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs:      []wire.TxOut{payment},
		Inputs:       &wallet.InputsPolicy{Source: account},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})
	require.NoError(h, err, "failed to create transaction")
	require.GreaterOrEqual(h, authored.ChangeIndex, 0, "no change output")

	changeScript := authored.Tx.TxOut[authored.ChangeIndex].PkScript

	// Act: Pay the change address from outside the wallet, leaving the
	// payment unmined so only the live watch can deliver it.
	received := h.SendOutput(&wire.TxOut{
		Value:    oneBTC,
		PkScript: changeScript,
	}, bwtest.MinerFeeRate)

	// Assert: The unmined payment becomes a spendable wallet coin on the
	// change address before any block could reveal it.
	paymentTx := h.AssertTxInMempool(*received)

	paid := wire.OutPoint{Hash: *received, Index: 0}
	for i, txOut := range paymentTx.TxOut {
		if bytes.Equal(txOut.PkScript, changeScript) {
			paid.Index = uint32(i)
		}
	}

	var utxo *wallet.Utxo

	err = wait.NoError(func() error {
		var err error

		utxo, err = w.GetUtxo(h.Context(), paid)

		return err
	}, pollTimeout)
	require.NoError(h, err, "authored change missed unmined payment")
	require.Equal(h, changeScript, utxo.PkScript, "unexpected coin script")
	require.Equal(
		h, btcutil.Amount(oneBTC), utxo.Amount, "unexpected coin amount",
	)
	require.Zero(h, utxo.Confirmations, "payment was already confirmed")
	require.True(h, utxo.Spendable, "change payment is not spendable")

	// The harness requires an empty miner mempool when a case succeeds.
	h.MineBlocksAndAssertNumTxns(1, 1)
}

// testCreateTransactionMultipleOutputs verifies that every requested output
// reaches the authored transaction intact when an intent asks for more than
// one, alongside the change output.
func testCreateTransactionMultipleOutputs(h *bwtest.HarnessTest) {
	// quarterBTC is the second payment amount. It differs from the first so
	// the two payments are distinguishable by value as well as by script.
	const quarterBTC = btcutil.SatoshiPerBitcoin / 4

	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		Unlocked: true,
	})

	// Each payment gets its own address, so an authored transaction that
	// collapsed its outputs onto one recipient fails the assertions below.
	addrs := h.NewWalletAddressesOfType(w, txCreatorFundingType, 2)
	firstScript, err := txscript.PayToAddrScript(addrs[0])
	require.NoError(h, err, "failed to create payment pkscript")
	secondScript, err := txscript.PayToAddrScript(addrs[1])
	require.NoError(h, err, "failed to create payment pkscript")

	first := wire.TxOut{Value: int64(halfBTC), PkScript: firstScript}
	second := wire.TxOut{Value: quarterBTC, PkScript: secondScript}
	require.NotEqual(
		h, first.PkScript, second.PkScript, "payments share a script",
	)

	account := &wallet.ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    scope,
	}

	authored, err := w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{first, second},
		Inputs: &wallet.InputsPolicy{
			Strategy: wallet.CoinSelectionLargest,
			MinConfs: 1,
			Source:   account,
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})
	require.NoError(h, err, "failed to create transaction")

	// Both payments and one change output are present. The change position
	// is randomized, so the payments are located by content.
	require.Len(h, authored.Tx.TxOut, 3, "unexpected output count")
	require.GreaterOrEqual(h, authored.ChangeIndex, 0, "no change output")

	paid := make(map[string]int64, len(authored.Tx.TxOut))
	for i, output := range authored.Tx.TxOut {
		if i == authored.ChangeIndex {
			continue
		}

		paid[string(output.PkScript)] = output.Value
	}

	require.Equal(
		h, first.Value, paid[string(first.PkScript)],
		"first payment missing or altered",
	)
	require.Equal(
		h, second.Value, paid[string(second.PkScript)],
		"second payment missing or altered",
	)
}

// testCreateTransactionManualInputs verifies that caller-selected inputs are
// used exactly as given, bypassing coin selection.
func testCreateTransactionManualInputs(h *bwtest.HarnessTest) {
	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC, threeBTC},
		Unlocked: true,
	})

	outpoints := funding.WalletOutpoints

	// The first payment needs two coins, the second needs one.
	large := deriveWalletPayment(h, w, txCreatorFundingType, threeBTC+halfBTC)
	small := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)

	account := &wallet.ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    scope,
	}

	// A payment no single coin covers is funded by exactly the two coins
	// the caller named, and not by the pair selection would have reached
	// for: largest first would have taken the three and two BTC coins.
	authored, err := w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{large},
		Inputs: &wallet.InputsManual{
			UTXOs: []wire.OutPoint{outpoints[0], outpoints[2]},
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})
	require.NoError(h, err, "failed to create transaction")

	spent := make([]wire.OutPoint, 0, len(authored.Tx.TxIn))
	for _, txIn := range authored.Tx.TxIn {
		spent = append(spent, txIn.PreviousOutPoint)
	}

	require.ElementsMatch(
		h, []wire.OutPoint{outpoints[0], outpoints[2]}, spent,
		"unexpected manual inputs",
	)
	require.Equal(
		h, btcutil.Amount(oneBTC+threeBTC), authored.TotalInput,
		"unexpected total input",
	)

	// A signer reads the input metadata positionally, so entry i must
	// describe the coin spent by input i, whatever order selection put
	// them in.
	require.Len(
		h, authored.PrevScripts, len(authored.Tx.TxIn),
		"unexpected prev script count",
	)
	require.Len(
		h, authored.PrevInputValues, len(authored.Tx.TxIn),
		"unexpected prev input value count",
	)

	for i, txIn := range authored.Tx.TxIn {
		utxo, err := w.GetUtxo(h.Context(), txIn.PreviousOutPoint)
		require.NoError(h, err, "input %d is not a wallet coin", i)

		require.Equal(
			h, utxo.Amount, authored.PrevInputValues[i],
			"input %d value mismatch", i,
		)
		require.Equal(
			h, utxo.PkScript, authored.PrevScripts[i],
			"input %d script mismatch", i,
		)
	}

	// A payment one named coin covers spends that coin alone, even though
	// the wallet holds larger coins selection would have preferred.
	authored, err = w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{small},
		Inputs: &wallet.InputsManual{
			UTXOs: []wire.OutPoint{outpoints[0]},
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})
	require.NoError(h, err, "failed to create transaction")

	require.Len(h, authored.Tx.TxIn, 1, "unexpected input count")
	require.Equal(
		h, outpoints[0], authored.Tx.TxIn[0].PreviousOutPoint,
		"unexpected manual input",
	)
	require.Equal(
		h, btcutil.Amount(oneBTC), authored.TotalInput,
		"unexpected total input",
	)
}

// testCreateTransactionDefaultAccount verifies that an intent naming neither
// an input source nor a change source funds itself from the default account,
// which the wallet resolves under the Taproot key scope.
func testCreateTransactionDefaultAccount(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: waddrmgr.TaprootPubKey,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	outpoints := funding.WalletOutpoints

	payment := deriveWalletPayment(h, w, waddrmgr.TaprootPubKey, halfBTC)

	authored, err := w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{payment},
		FeeRate: relayFeeRate,
	})
	require.NoError(h, err, "failed to create transaction")

	// The implicit source is the default account of the Taproot scope, the
	// only account holding coins here.
	require.Len(h, authored.Tx.TxIn, 1, "unexpected input count")
	require.Equal(
		h, outpoints[0], authored.Tx.TxIn[0].PreviousOutPoint,
		"unexpected selected input",
	)

	// The implicit change source is that same account, so the change output
	// is an internal Taproot address of the wallet.
	require.Len(h, authored.Tx.TxOut, 2, "unexpected output count")
	require.GreaterOrEqual(h, authored.ChangeIndex, 0, "no change output")

	change := authored.Tx.TxOut[authored.ChangeIndex]
	_, changeAddrs, _, err := txscript.ExtractPkScriptAddrs(
		change.PkScript, h.NetParams(),
	)
	require.NoError(h, err, "failed to extract change address")
	require.Len(h, changeAddrs, 1, "unexpected change address count")

	changeInfo, err := w.GetAddressInfo(h.Context(), changeAddrs[0])
	require.NoError(h, err, "change address is unknown to the wallet")
	require.True(h, changeInfo.Internal, "change address is not internal")
	require.Equal(
		h, waddrmgr.TaprootPubKey, changeInfo.AddrType,
		"unexpected change address type",
	)
}

// testCreateTransactionCoinSource verifies that a policy restricted to a
// candidate list selects only from that list and honors its confirmation
// bound.
func testCreateTransactionCoinSource(h *bwtest.HarnessTest) {
	// unreachableConfs is a confirmation floor no candidate in this case
	// can meet: the funding block is the chain tip, so every coin the
	// wallet holds has exactly one confirmation.
	const unreachableConfs = 2

	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC, threeBTC},
		Unlocked: true,
	})

	outpoints := funding.WalletOutpoints

	payment := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)

	account := &wallet.ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    scope,
	}

	// Only the candidate coin is spendable here, even though the wallet
	// holds larger coins outside the list.
	authored, err := w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{payment},
		Inputs: &wallet.InputsPolicy{
			MinConfs: 1,
			Source: &wallet.CoinSourceUTXOs{
				UTXOs: []wire.OutPoint{outpoints[0]},
			},
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})
	require.NoError(h, err, "failed to create transaction")

	require.Len(h, authored.Tx.TxIn, 1, "unexpected input count")
	require.Equal(
		h, outpoints[0], authored.Tx.TxIn[0].PreviousOutPoint,
		"unexpected candidate selected",
	)

	// A confirmation bound the candidate cannot meet leaves the policy with
	// nothing to select.
	_, err = w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{payment},
		Inputs: &wallet.InputsPolicy{
			MinConfs: unreachableConfs,
			Source: &wallet.CoinSourceUTXOs{
				UTXOs: []wire.OutPoint{outpoints[0]},
			},
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})

	var sourceErr txauthor.InputSourceError
	require.ErrorAs(
		h, err, &sourceErr, "under-confirmed candidate not skipped",
	)
}

// testCreateTransactionOmitChange verifies that a transaction whose remainder
// would be zero or dust is authored without a change output, and that no change
// address is committed for it.
func testCreateTransactionOmitChange(h *bwtest.HarnessTest) {
	// smallCoin is the value of each funded coin. Every row spends its own,
	// so its payment is funded by that coin alone.
	const smallCoin btcutil.Amount = 100_000

	// zeroChangeFee is the fee for one P2WPKH input, the P2WPKH payment,
	// and the P2WPKH change output the fee is sized for, at the relay rate.
	// It is computed independently of the wallet, so paying the rest of the
	// coin leaves exactly zero change.
	zeroChangeFee := txrules.FeeForSerializeSize(
		relayFeeRate.Val(), txsizes.EstimateVirtualSize(
			0, 0, 1, 0, []*wire.TxOut{{
				PkScript: make([]byte, txsizes.P2WPKHPkScriptSize),
			}}, txsizes.P2WPKHPkScriptSize,
		),
	)

	testCases := []struct {
		name    string
		payment btcutil.Amount
	}{
		{
			name:    "zero change",
			payment: smallCoin - zeroChangeFee,
		},
		{
			// The coin keeps 300 sat over the payment. The fee for
			// this single input, single output shape takes most of
			// it, and what is left is below the dust limit for a
			// witness pubkey change output, so the wallet must drop
			// the change. Only that omission is asserted here; the
			// fee itself is not.
			name:    "dust change",
			payment: smallCoin - 300,
		},
	}

	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{smallCoin, smallCoin},
		Unlocked: true,
	})

	for i, tc := range testCases {
		payment := deriveWalletPayment(
			h, w, txCreatorFundingType, tc.payment,
		)

		before, err := w.GetAccount(
			h.Context(), scope, waddrmgr.DefaultAccountName,
		)
		require.NoError(h, err, "failed to read account")

		authored, err := w.CreateTransaction(
			h.Context(), &wallet.TxIntent{
				Outputs: []wire.TxOut{payment},
				Inputs: &wallet.InputsManual{
					UTXOs: []wire.OutPoint{
						funding.WalletOutpoints[i],
					},
				},
				ChangeSource: &wallet.ScopedAccount{
					AccountName: waddrmgr.DefaultAccountName,
					KeyScope:    scope,
				},
				FeeRate: relayFeeRate,
			},
		)
		require.NoError(h, err, "%s: failed to create transaction",
			tc.name)

		require.Equal(
			h, -1, authored.ChangeIndex,
			"%s: change output not omitted", tc.name,
		)
		require.Len(
			h, authored.Tx.TxOut, 1, "%s: unexpected output count",
			tc.name,
		)
		require.Equal(
			h, payment.PkScript, authored.Tx.TxOut[0].PkScript,
			"%s: payment script changed", tc.name,
		)
		require.Equal(
			h, payment.Value, authored.Tx.TxOut[0].Value,
			"%s: payment value changed", tc.name,
		)

		// The omitted change commits no change address.
		after, err := w.GetAccount(
			h.Context(), scope, waddrmgr.DefaultAccountName,
		)
		require.NoError(h, err, "failed to read account")
		require.Equal(
			h, before.InternalKeyCount, after.InternalKeyCount,
			"%s: change address committed", tc.name,
		)
	}
}

// testCreateTransactionRejectIntent verifies the stable errors a malformed or
// unresolvable intent produces, that the fee rate bound admits its own limit,
// and that a rejection leaves the wallet's coins and leases untouched.
func testCreateTransactionRejectIntent(h *bwtest.HarnessTest) {
	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	outpoints := funding.WalletOutpoints

	payment := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)

	account := &wallet.ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    scope,
	}
	unknownAccount := &wallet.ScopedAccount{
		AccountName: "no-such-account",
		KeyScope:    scope,
	}

	testCases := []struct {
		name        string
		intent      *wallet.TxIntent
		expectedErr error
	}{{
		name:        "nil intent",
		intent:      nil,
		expectedErr: wallet.ErrNilTxIntent,
	}, {
		name: "no outputs",
		intent: &wallet.TxIntent{
			Inputs:  &wallet.InputsPolicy{Source: account},
			FeeRate: relayFeeRate,
		},
		expectedErr: wallet.ErrNoTxOutputs,
	}, {
		name: "negative output",
		intent: &wallet.TxIntent{
			Outputs: []wire.TxOut{{
				Value:    -1,
				PkScript: payment.PkScript,
			}},
			Inputs:  &wallet.InputsPolicy{Source: account},
			FeeRate: relayFeeRate,
		},
		expectedErr: txrules.ErrAmountNegative,
	}, {
		name: "unnamed change account",
		intent: &wallet.TxIntent{
			Outputs:      []wire.TxOut{payment},
			Inputs:       &wallet.InputsPolicy{Source: account},
			ChangeSource: &wallet.ScopedAccount{KeyScope: scope},
			FeeRate:      relayFeeRate,
		},
		expectedErr: wallet.ErrMissingAccountName,
	}, {
		name: "empty manual inputs",
		intent: &wallet.TxIntent{
			Outputs: []wire.TxOut{payment},
			Inputs:  &wallet.InputsManual{},
			FeeRate: relayFeeRate,
		},
		expectedErr: wallet.ErrManualInputsEmpty,
	}, {
		name: "duplicate manual inputs",
		intent: &wallet.TxIntent{
			Outputs: []wire.TxOut{payment},
			Inputs: &wallet.InputsManual{
				UTXOs: []wire.OutPoint{
					outpoints[0], outpoints[0],
				},
			},
			FeeRate: relayFeeRate,
		},
		expectedErr: wallet.ErrDuplicatedUtxo,
	}, {
		name: "empty coin source",
		intent: &wallet.TxIntent{
			Outputs: []wire.TxOut{payment},
			Inputs: &wallet.InputsPolicy{
				Source: &wallet.CoinSourceUTXOs{},
			},
			FeeRate: relayFeeRate,
		},
		expectedErr: wallet.ErrManualInputsEmpty,
	}, {
		name: "unnamed source account",
		intent: &wallet.TxIntent{
			Outputs: []wire.TxOut{payment},
			Inputs: &wallet.InputsPolicy{
				Source: &wallet.ScopedAccount{KeyScope: scope},
			},
			FeeRate: relayFeeRate,
		},
		expectedErr: wallet.ErrMissingAccountName,
	}, {
		name: "zero fee rate",
		intent: &wallet.TxIntent{
			Outputs: []wire.TxOut{payment},
			Inputs:  &wallet.InputsPolicy{Source: account},
			FeeRate: btcunit.NewSatPerKVByte(0),
		},
		expectedErr: wallet.ErrMissingFeeRate,
	}, {
		name: "excessive fee rate",
		intent: &wallet.TxIntent{
			Outputs: []wire.TxOut{payment},
			Inputs:  &wallet.InputsPolicy{Source: account},
			FeeRate: btcunit.NewSatPerKVByte(
				wallet.DefaultMaxFeeRate.Val() + 1,
			),
		},
		expectedErr: wallet.ErrFeeRateTooLarge,
	}, {
		name: "unknown source account",
		intent: &wallet.TxIntent{
			Outputs: []wire.TxOut{payment},
			Inputs: &wallet.InputsPolicy{
				MinConfs: 1,
				Source:   unknownAccount,
			},
			ChangeSource: account,
			FeeRate:      relayFeeRate,
		},
		expectedErr: wallet.ErrAccountNotFound,
	}, {
		name: "unknown change account",
		intent: &wallet.TxIntent{
			Outputs: []wire.TxOut{payment},
			Inputs: &wallet.InputsPolicy{
				MinConfs: 1,
				Source:   account,
			},
			ChangeSource: unknownAccount,
			FeeRate:      relayFeeRate,
		},
		expectedErr: wallet.ErrAccountNotFound,
	}}

	// A refused intent must leave the wallet's coins and leases as they
	// were. Snapshot before the loop and compare straight after it, before
	// anything succeeds.
	utxosBefore, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent")

	leasesBefore, err := w.ListLeasedOutputs(h.Context())
	require.NoError(h, err, "failed to list leased outputs")

	for _, tc := range testCases {
		_, err := w.CreateTransaction(h.Context(), tc.intent)
		require.ErrorIs(
			h, err, tc.expectedErr, "%s not rejected", tc.name,
		)
	}

	utxosAfter, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent")
	require.Equal(
		h, utxosBefore, utxosAfter, "a rejection changed the wallet's coins",
	)

	leasesAfter, err := w.ListLeasedOutputs(h.Context())
	require.NoError(h, err, "failed to list leased outputs")
	require.Equal(
		h, leasesBefore, leasesAfter, "a rejection changed the wallet's leases",
	)

	// The maximum sane fee rate is itself allowed.
	authored, err := w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{payment},
		Inputs: &wallet.InputsPolicy{
			MinConfs: 1,
			Source:   account,
		},
		ChangeSource: account,
		FeeRate:      wallet.DefaultMaxFeeRate,
	})
	require.NoError(h, err, "maximum fee rate rejected")
	require.NotEmpty(h, authored.Tx.TxIn, "authored transaction has no inputs")

	// No rejection consumed a coin or reserved one.
	utxos, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent")

	unspent := make([]wire.OutPoint, 0, len(utxos))
	for _, utxo := range utxos {
		unspent = append(unspent, utxo.OutPoint)
	}

	require.ElementsMatch(h, outpoints, unspent, "wallet utxo set changed")

	leases, err := w.ListLeasedOutputs(h.Context())
	require.NoError(h, err, "failed to list leased outputs")
	require.Empty(h, leases, "a rejection reserved a coin")
}

// testCreateTransactionOutputBoundaries verifies the output amount policy at
// its edges: the largest dust amount and the smallest payable one, and the
// largest amount a transaction output may carry.
func testCreateTransactionOutputBoundaries(h *bwtest.HarnessTest) {
	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	outpoints := funding.WalletOutpoints

	payment := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)

	account := &wallet.ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    scope,
	}

	// The dust limit depends on the output's script, and the harness derives
	// it from the relay policy, so the edge here cannot drift from the one
	// the publication cases use.
	smallestPayment := int64(h.DustThreshold(payment.PkScript))

	// One satoshi below that edge is dust, and the edge itself is payable.
	_, err = w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{{
			Value:    smallestPayment - 1,
			PkScript: payment.PkScript,
		}},
		Inputs: &wallet.InputsPolicy{
			MinConfs: 1,
			Source:   account,
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})
	require.ErrorIs(
		h, err, txrules.ErrOutputIsDust, "dust output not rejected",
	)

	authored, err := w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{{
			Value:    smallestPayment,
			PkScript: payment.PkScript,
		}},
		Inputs: &wallet.InputsPolicy{
			MinConfs: 1,
			Source:   account,
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})
	require.NoError(h, err, "smallest payable output rejected")
	require.Equal(
		h, outpoints[0], authored.Tx.TxIn[0].PreviousOutPoint,
		"unexpected selected input",
	)

	// One satoshi above the maximum an output may carry is rejected on its
	// value.
	_, err = w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{{
			Value:    btcutil.MaxSatoshi + 1,
			PkScript: payment.PkScript,
		}},
		Inputs: &wallet.InputsPolicy{
			MinConfs: 1,
			Source:   account,
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})
	require.ErrorIs(
		h, err, txrules.ErrAmountExceedsMax,
		"output above the maximum not rejected",
	)

	// The maximum itself passes the amount policy: this wallet simply
	// cannot fund it, so it fails for want of coins instead.
	_, err = w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{{
			Value:    btcutil.MaxSatoshi,
			PkScript: payment.PkScript,
		}},
		Inputs: &wallet.InputsPolicy{
			MinConfs: 1,
			Source:   account,
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})

	var sourceErr txauthor.InputSourceError
	require.ErrorAs(
		h, err, &sourceErr, "maximum amount rejected on its value",
	)
}

// testCreateTransactionRejectInputs verifies that inputs the wallet cannot
// spend are refused, that selection skips a leased coin rather than spending
// it, and that a refusal leaves the wallet's coins and leases untouched.
func testCreateTransactionRejectInputs(h *bwtest.HarnessTest) {
	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		Unlocked: true,
	})

	outpoints := funding.WalletOutpoints

	payment := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)

	// The wallet holds three BTC in two coins. This payment needs both of
	// them, so it is only fundable while neither is leased.
	needsBothCoins := deriveWalletPayment(
		h, w, txCreatorFundingType, twoBTC+halfBTC,
	)

	// This one exceeds everything the wallet holds.
	beyondBalance := deriveWalletPayment(
		h, w, txCreatorFundingType, oneBTC+twoBTC+halfBTC,
	)

	lockID := wtxmgr.LockID{1}
	_, err = w.LeaseOutput(
		h.Context(), lockID, outpoints[0], leaseDuration,
	)
	require.NoError(h, err, "failed to lease output")

	account := &wallet.ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    scope,
	}

	require.Len(
		h, funding.ForeignOutpoints, 1, "unexpected foreign output count",
	)

	foreign := funding.ForeignOutpoints[0]

	ineligible := []struct {
		name   string
		inputs wallet.Inputs
	}{{
		name: "leased manual input",
		inputs: &wallet.InputsManual{
			UTXOs: []wire.OutPoint{outpoints[0]},
		},
	}, {
		name: "unknown manual input",
		inputs: &wallet.InputsManual{
			UTXOs: []wire.OutPoint{unknownOutpoint()},
		},
	}, {
		name: "foreign manual input",
		inputs: &wallet.InputsManual{
			UTXOs: []wire.OutPoint{foreign},
		},
	}, {
		name: "leased candidate",
		inputs: &wallet.InputsPolicy{
			MinConfs: 1,
			Source: &wallet.CoinSourceUTXOs{
				UTXOs: []wire.OutPoint{outpoints[0]},
			},
		},
	}, {
		name: "foreign candidate",
		inputs: &wallet.InputsPolicy{
			MinConfs: 1,
			Source: &wallet.CoinSourceUTXOs{
				UTXOs: []wire.OutPoint{foreign},
			},
		},
	}}

	for _, tc := range ineligible {
		_, err = w.CreateTransaction(h.Context(), &wallet.TxIntent{
			Outputs:      []wire.TxOut{payment},
			Inputs:       tc.inputs,
			ChangeSource: account,
			FeeRate:      relayFeeRate,
		})
		require.ErrorIs(
			h, err, wallet.ErrUtxoNotEligible,
			"%s not rejected", tc.name,
		)
	}

	// Account selection skips the leased coin instead of spending it, so a
	// payment that needs both coins can no longer be funded.
	_, err = w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{needsBothCoins},
		Inputs: &wallet.InputsPolicy{
			MinConfs: 1,
			Source:   account,
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})

	var sourceErr txauthor.InputSourceError
	require.ErrorAs(h, err, &sourceErr, "leased coin was selected")

	// A payment beyond everything the wallet holds cannot be funded either.
	_, err = w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{beyondBalance},
		Inputs: &wallet.InputsPolicy{
			MinConfs: 1,
			Source:   account,
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})
	require.ErrorAs(
		h, err, &sourceErr, "payment beyond the balance was funded",
	)

	// Every refusal left the coins in place and the lease as it was.
	utxos, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent")

	unspent := make([]wire.OutPoint, 0, len(utxos))
	for _, utxo := range utxos {
		unspent = append(unspent, utxo.OutPoint)
	}

	require.ElementsMatch(h, outpoints, unspent, "wallet utxo set changed")

	leases, err := w.ListLeasedOutputs(h.Context())
	require.NoError(h, err, "failed to list leased outputs")
	require.Len(h, leases, 1, "wallet lease set changed")
	require.Equal(h, outpoints[0], leases[0].OutPoint, "unexpected lease")
}

// testCreateTransactionWalletState verifies locked wallets can author
// unsigned transactions while stopped pointers reject the same intent.
func testCreateTransactionWalletState(h *bwtest.HarnessTest) {
	// witnessProgramSize is the length of a witness pubkey hash program.
	const witnessProgramSize = 20

	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	// Retain the Manager so this case can stop its Wallet directly.
	manager := h.NewWalletManager()
	_, err = manager.Start(h.Context())
	require.NoError(h, err, "failed to start wallet manager")

	w, err := manager.Create(h.TestWalletParams())
	require.NoError(h, err, "failed to create wallet")
	h.RegisterWallet(manager, w)

	// A fixed witness program supplies a valid destination without changing
	// the fixture lock state through address derivation.
	addr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, witnessProgramSize), h.NetParams(),
	)
	require.NoError(h, err, "failed to create witness address")

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	account := &wallet.ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    scope,
	}
	intent := &wallet.TxIntent{
		Outputs: []wire.TxOut{{
			Value:    halfBTC,
			PkScript: pkScript,
		}},
		Inputs: &wallet.InputsPolicy{
			MinConfs: 1,
			Source:   account,
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	}

	funding := h.FundWalletOfType(w, txCreatorFundingType, oneBTC)
	outpoints := funding.WalletOutpoints

	// Funding derives an address, which the harness unlocks for when the
	// account is missing, but it restores the locked state afterwards.
	info, err := w.Info(h.Context())
	require.NoError(h, err, "failed to query wallet info")
	require.True(h, info.Locked, "wallet is not locked")

	// Authoring an unsigned transaction does not require the private key.
	authored, err := w.CreateTransaction(h.Context(), intent)
	require.NoError(h, err, "locked wallet failed to create transaction")

	require.Len(h, authored.Tx.TxIn, 1, "unexpected input count")
	require.Equal(
		h, outpoints[0], authored.Tx.TxIn[0].PreviousOutPoint,
		"unexpected selected input",
	)

	// Stop joins the runtime before the retained pointer is exercised.
	require.NoError(h, manager.Stop(), "failed to stop wallet manager")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")

	_, err = w.CreateTransaction(h.Context(), intent)
	require.ErrorIs(
		h, err, wallet.ErrWalletStopped,
		"create transaction after stop not rejected",
	)
}

// testCreateTransactionConcurrentChange verifies that CreateTransaction calls
// made at once, each keeping change, commit one distinct change address each.
// Wallet requests run concurrently, so the calls race on change allocation.
func testCreateTransactionConcurrentChange(h *bwtest.HarnessTest) {
	// concurrentAuthors is the number of payments authored at once.
	const concurrentAuthors = 4

	// Arrange: Fund one coin per author, derive each author's payment,
	// and record the account's committed change key count.
	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts: slices.Repeat(
			[]btcutil.Amount{oneBTC}, concurrentAuthors,
		),
		Unlocked: true,
	})

	payments := make([]wire.TxOut, concurrentAuthors)
	for i := range payments {
		payments[i] = deriveWalletPayment(
			h, w, txCreatorFundingType, halfBTC,
		)
	}

	before, err := w.GetAccount(
		h.Context(), scope, waddrmgr.DefaultAccountName,
	)
	require.NoError(h, err, "failed to read account")

	// Act: Author every payment concurrently, each from its own coin.
	var (
		wg       sync.WaitGroup
		authored = make([]*txauthor.AuthoredTx, concurrentAuthors)
		errs     = make([]error, concurrentAuthors)
	)

	for i := range concurrentAuthors {
		wg.Go(func() {
			authored[i], errs[i] = w.CreateTransaction(
				h.Context(), &wallet.TxIntent{
					Outputs: []wire.TxOut{payments[i]},
					Inputs: &wallet.InputsManual{
						UTXOs: []wire.OutPoint{
							funding.WalletOutpoints[i],
						},
					},
					ChangeSource: &wallet.ScopedAccount{
						AccountName: waddrmgr.DefaultAccountName,
						KeyScope:    scope,
					},
					FeeRate: relayFeeRate,
				},
			)
		})
	}

	wg.Wait()

	// Assert: Every transaction keeps change to its own change script,
	// and exactly one change address is committed per transaction.
	changeScripts := make(map[string]struct{}, concurrentAuthors)
	for i, tx := range authored {
		require.NoError(h, errs[i], "failed to create transaction")
		require.GreaterOrEqual(h, tx.ChangeIndex, 0, "change not kept")

		changeScripts[string(tx.Tx.TxOut[tx.ChangeIndex].PkScript)] =
			struct{}{}
	}

	require.Len(
		h, changeScripts, concurrentAuthors, "change address reused",
	)

	after, err := w.GetAccount(
		h.Context(), scope, waddrmgr.DefaultAccountName,
	)
	require.NoError(h, err, "failed to read account")
	require.Equal(
		h, before.InternalKeyCount+concurrentAuthors,
		after.InternalKeyCount, "change addresses not committed once",
	)
}

// fundPsbtPacket keeps packet construction separate from the funding call so
// cases can supply either caller-selected inputs or an empty automatic source.
func fundPsbtPacket(h *bwtest.HarnessTest, payment wire.TxOut,
	inputs ...wire.OutPoint) *psbt.Packet {

	h.Helper()

	tx := wire.NewMsgTx(wire.TxVersion)
	for _, input := range inputs {
		tx.AddTxIn(wire.NewTxIn(&input, nil, nil))
	}

	tx.AddTxOut(&payment)
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(h, err)

	return packet
}

// testFundPsbtDeferChange verifies that FundPsbt commits no change address
// when the funded packet keeps no change. Each row leaves the coin with either
// nothing or only dust over the payment and fee, so the account's committed
// change key count must not move.
func testFundPsbtDeferChange(h *bwtest.HarnessTest) {
	// coin is the value of each funded coin. Every row spends its own.
	const coin btcutil.Amount = 100_000

	// zeroChangeFee is the fee for one P2WPKH input, the P2WPKH payment,
	// and the P2WPKH change output the fee is sized for, at the relay rate.
	// It is computed independently of the wallet, so paying the rest of the
	// coin leaves exactly zero change.
	zeroChangeFee := txrules.FeeForSerializeSize(
		relayFeeRate.Val(), txsizes.EstimateVirtualSize(
			0, 0, 1, 0, []*wire.TxOut{{
				PkScript: make(
					[]byte, txsizes.P2WPKHPkScriptSize,
				),
			}}, txsizes.P2WPKHPkScriptSize,
		),
	)

	testCases := []struct {
		name    string
		payment btcutil.Amount
	}{
		{
			name:    "zero change",
			payment: coin - zeroChangeFee,
		},
		{
			// A 300 sat leftover is below the P2WPKH dust limit.
			name:    "dust change",
			payment: coin - 300,
		},
	}

	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, funding := h.NewWallet(
		bwtest.WalletFixture{
			AddrType: txCreatorFundingType,
			Amounts:  []btcutil.Amount{coin, coin},
			Unlocked: true,
		},
	)

	for i, tc := range testCases {
		// Arrange: Build a packet paying a fresh wallet address from the
		// row's own coin, and record the account's committed change key
		// count.
		payment := deriveWalletPayment(
			h, w, txCreatorFundingType, tc.payment,
		)

		packet := fundPsbtPacket(h, payment, funding.WalletOutpoints[i])
		original, err := packet.B64Encode()
		require.NoError(h, err)

		before, err := w.GetAccount(
			h.Context(), scope, waddrmgr.DefaultAccountName,
		)
		require.NoError(h, err, "failed to read account")

		// Act: Complete the caller-selected packet at the relay rate;
		// the exact or dust surplus must be absorbed into its fee.
		result, err := w.FundPsbt(
			h.Context(), &wallet.FundIntent{
				Packet: packet,
				ChangeSource: &wallet.ScopedAccount{
					AccountName: waddrmgr.DefaultAccountName,
					KeyScope:    scope,
				},
				FeeRate: relayFeeRate,
			},
		)

		// Assert: No change survives, so the decorated input's value minus
		// the sole output must equal the row's independently chosen fee.
		require.NoError(h, err, tc.name)
		require.EqualValues(h, -1, result.ChangeIndex, tc.name)
		require.Len(h, result.Packet.UnsignedTx.TxIn, 1)
		require.Len(h, result.Packet.UnsignedTx.TxOut, 1)
		require.EqualValues(
			h, coin-tc.payment,
			result.Packet.Inputs[0].WitnessUtxo.Value-
				result.Packet.UnsignedTx.TxOut[0].Value,
		)

		// Funding returns a copy; even a no-change result must preserve
		// the caller's serialized packet and committed allocation count.
		unchanged, err := packet.B64Encode()
		require.NoError(h, err)
		require.Equal(h, original, unchanged)

		after, err := w.GetAccount(
			h.Context(), scope, waddrmgr.DefaultAccountName,
		)
		require.NoError(h, err, "failed to read account")
		require.Equal(
			h, before.InternalKeyCount, after.InternalKeyCount,
			tc.name,
		)

		// The caller releases exactly the inputs funding handed back.
		require.NotEqual(h, wtxmgr.LockID{}, result.LeaseID)

		for _, input := range result.Packet.UnsignedTx.TxIn {
			require.NoError(
				h, w.ReleaseOutput(
					h.Context(), result.LeaseID,
					input.PreviousOutPoint,
				),
			)
		}
	}
}

// testFundPsbtCommitChange checks the first accepted payment/fee values and
// preserves caller metadata through sorting and input decoration. Its returned
// change pays one committed internal address, and its caller-owned lease is
// released without changing the original packet.
func testFundPsbtCommitChange(h *bwtest.HarnessTest) {
	// Arrange: Use the first accepted output and fee values, and attach
	// caller choices that authoring and sorting must carry to the result.
	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, funding := h.NewWallet(
		bwtest.WalletFixture{
			AddrType: txCreatorFundingType,
			Amounts:  []btcutil.Amount{oneBTC},
			Unlocked: true,
		},
	)

	payment := deriveWalletPayment(h, w, txCreatorFundingType, 0)
	payment.Value = int64(h.DustThreshold(payment.PkScript))
	packet := fundPsbtPacket(h, payment, funding.WalletOutpoints...)

	// Non-default headers, replaceable sequence and output metadata expose
	// accidental replacement. SigHashNone is supported without introducing
	// the separate SIGHASH_SINGLE refusal covered by the unit matrix.
	packet.UnsignedTx.Version = 3
	packet.UnsignedTx.LockTime = 7
	packet.UnsignedTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum - 2
	packet.Inputs[0].SighashType = txscript.SigHashNone
	packet.Outputs[0].WitnessScript = []byte{0x54, 0x55}
	original, err := packet.B64Encode()
	require.NoError(h, err)

	before, err := w.GetAccount(
		h.Context(), scope, waddrmgr.DefaultAccountName,
	)
	require.NoError(h, err, "failed to read account")

	// Act: Fund the packet without changing the caller's representation.
	result, err := w.FundPsbt(
		h.Context(), &wallet.FundIntent{
			Packet: packet,
			ChangeSource: &wallet.ScopedAccount{
				AccountName: waddrmgr.DefaultAccountName,
				KeyScope:    scope,
			},
			FeeRate: btcunit.NewSatPerKVByte(1),
		},
	)

	// Assert: Boundary funding returns the caller's payment and one sorted
	// change output, with a reservation owned by the caller.
	require.NoError(h, err, "failed to fund packet")
	require.NotEqual(h, wtxmgr.LockID{}, result.LeaseID)

	funded := result.Packet
	require.Len(h, funded.UnsignedTx.TxIn, 1)
	require.Len(h, funded.UnsignedTx.TxOut, 2)
	// The small caller payment sorts before its much larger change.
	require.EqualValues(h, 1, result.ChangeIndex)
	require.Equal(h, &payment, funded.UnsignedTx.TxOut[0])

	// Compare the original encoding and metadata separately: sorting must
	// retain the caller's choices while decorating the returned input from
	// its real parent transaction. The payment remains at sorted index zero.
	unchanged, err := packet.B64Encode()
	require.NoError(h, err)
	require.Equal(h, original, unchanged)
	require.Equal(h, packet.UnsignedTx.Version, funded.UnsignedTx.Version)
	require.Equal(h, packet.UnsignedTx.LockTime, funded.UnsignedTx.LockTime)
	require.Equal(h, packet.UnsignedTx.TxIn[0], funded.UnsignedTx.TxIn[0])
	require.Equal(
		h, packet.Inputs[0].SighashType, funded.Inputs[0].SighashType,
	)
	require.Equal(h, packet.Outputs[0], funded.Outputs[0])
	require.Equal(
		h, funding.Tx.TxOut[funding.WalletOutpoints[0].Index],
		funded.Inputs[0].WitnessUtxo,
	)

	// The new internal key must be committed once, and the returned change
	// script must pay that wallet-owned internal branch.
	after, err := w.GetAccount(
		h.Context(), scope, waddrmgr.DefaultAccountName,
	)
	require.NoError(h, err, "failed to read account")
	require.Equal(
		h, before.InternalKeyCount+1, after.InternalKeyCount,
		"change address not committed once",
	)

	changeOut := result.Packet.UnsignedTx.TxOut[result.ChangeIndex]
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		changeOut.PkScript, h.NetParams(),
	)
	require.NoError(h, err, "failed to decode change script")
	require.Len(h, addrs, 1, "change script has no single address")

	info, err := w.GetAddressInfo(h.Context(), addrs[0])
	require.NoError(h, err, "change address not in wallet")
	require.True(h, info.Internal, "change pays a non-change address")

	// Release the caller's reservation without publishing the transaction.
	for _, input := range funded.UnsignedTx.TxIn {
		require.NoError(
			h, w.ReleaseOutput(
				h.Context(), result.LeaseID,
				input.PreviousOutPoint,
			),
		)
	}
}

// testFundPsbtFundingLeases checks the public reservation lifecycle across a
// Manager reopen, including availability and fresh ownership after release.
func testFundPsbtFundingLeases(h *bwtest.HarnessTest) {
	// Arrange: The locked fixture has unequal coins, making largest-first
	// selection observable without needing private signing material.
	ctx := h.Context()
	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err)
	w, funding := h.NewWallet(
		bwtest.WalletFixture{
			AddrType: txCreatorFundingType,
			Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		},
	)
	payment := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)
	intent := &wallet.FundIntent{
		Packet: fundPsbtPacket(h, payment),
		Policy: &wallet.InputsPolicy{
			Strategy: wallet.CoinSelectionLargest,
			MinConfs: 1,
			Source: &wallet.ScopedAccount{
				KeyScope:    scope,
				AccountName: waddrmgr.DefaultAccountName,
			},
		},
		FeeRate: wallet.DefaultMaxFeeRate,
	}

	// Act: Fund at the accepted maximum rate through automatic selection.
	result, err := w.FundPsbt(ctx, intent)

	// Assert: Only the largest coin backs the packet and its exact lease.
	require.NoError(h, err)
	require.Len(h, result.Packet.UnsignedTx.TxIn, 1)
	op := result.Packet.UnsignedTx.TxIn[0].PreviousOutPoint
	require.Equal(h, funding.WalletOutpoints[1], op)
	require.NotEqual(h, wtxmgr.LockID{}, result.LeaseID)

	// Size one P2WPKH input plus payment/change independently of FundPsbt;
	// the returned values must pay that fee at the accepted maximum rate.
	fee := txrules.FeeForSerializeSize(
		intent.FeeRate.Val(), txsizes.EstimateVirtualSize(
			0, 0, 1, 0, []*wire.TxOut{&payment},
			txsizes.P2WPKHPkScriptSize,
		),
	)
	require.Len(h, result.Packet.UnsignedTx.TxOut, 2)
	change := result.Packet.UnsignedTx.TxOut[result.ChangeIndex]
	require.EqualValues(h, fee, twoBTC-payment.Value-change.Value)

	// The complete public lease set must name the exact selected outpoint
	// and caller owner, rather than merely report that some coin is locked.
	leases, err := w.ListLeasedOutputs(ctx)
	require.NoError(h, err)
	require.Len(h, leases, 1)
	require.Equal(h, op, leases[0].OutPoint)
	require.Equal(h, result.LeaseID, leases[0].LockID)

	// Both public coin views expose the lease through Locked. Match the
	// list entry by outpoint identity so ordering is irrelevant to this check.
	coin, err := w.GetUtxo(ctx, op)
	require.NoError(h, err)
	require.True(h, coin.Locked)

	query := wallet.UtxoQuery{MaxConfs: maxConfsLimit}
	coins, err := w.ListUnspent(ctx, query)
	require.NoError(h, err)
	require.Len(h, coins, 2)
	index := slices.IndexFunc(
		coins, func(coin *wallet.Utxo) bool {
			return coin.OutPoint == op
		},
	)
	require.NotEqual(h, -1, index)
	require.True(h, coins[index].Locked)

	// Keep complete account/address observations as the reopen baseline;
	// losing either committed change fact must fail the durable comparison.
	account, err := w.GetAccount(ctx, scope, waddrmgr.DefaultAccountName)
	require.NoError(h, err)
	addresses, err := w.ListAddresses(
		ctx, waddrmgr.DefaultAccountName, txCreatorFundingType,
	)
	require.NoError(h, err)

	// Unsigned funding and reservation must not require unlocking the wallet.
	info, err := w.Info(ctx)
	require.NoError(h, err)
	require.True(h, info.Locked)

	// Act: Reopen both the Wallet and its Manager using the harness owner.
	w = h.ReloadWallet(w)
	h.AssertWalletSynced(w)

	// Assert: Complete persisted observations agree after watch reconstruction.
	reloadedLeases, err := w.ListLeasedOutputs(ctx)
	require.NoError(h, err)
	require.Equal(h, leases, reloadedLeases)

	reloadedCoins, err := w.ListUnspent(ctx, query)
	require.NoError(h, err)
	require.Equal(h, coins, reloadedCoins)

	reloadedAccount, err := w.GetAccount(
		ctx, scope, waddrmgr.DefaultAccountName,
	)
	require.NoError(h, err)
	require.Equal(h, account, reloadedAccount)

	reloadedAddresses, err := w.ListAddresses(
		ctx, waddrmgr.DefaultAccountName, txCreatorFundingType,
	)
	require.NoError(h, err)
	require.Equal(h, addresses, reloadedAddresses)

	// Act: Release the persisted packet inputs, then fund the same caller
	// packet again; its new owner must be independent of the first attempt.
	for _, input := range result.Packet.UnsignedTx.TxIn {
		require.NoError(
			h, w.ReleaseOutput(
				ctx, result.LeaseID, input.PreviousOutPoint,
			),
		)
	}

	coin, err = w.GetUtxo(ctx, op)
	require.NoError(h, err)
	require.False(h, coin.Locked)

	retried, err := w.FundPsbt(ctx, intent)

	// Assert: The released coin is available and receives a fresh lease ID.
	require.NoError(h, err)
	require.NotEqual(h, wtxmgr.LockID{}, retried.LeaseID)
	require.NotEqual(h, result.LeaseID, retried.LeaseID)

	leases, err = w.ListLeasedOutputs(ctx)
	require.NoError(h, err)
	require.Len(h, leases, 1)
	require.Equal(h, retried.LeaseID, leases[0].LockID)
	require.Equal(h, op, leases[0].OutPoint)

	for _, input := range retried.Packet.UnsignedTx.TxIn {
		require.NoError(
			h, w.ReleaseOutput(
				ctx, retried.LeaseID, input.PreviousOutPoint,
			),
		)
	}

	leases, err = w.ListLeasedOutputs(ctx)
	require.NoError(h, err)
	require.Empty(h, leases)
}

// testFundPsbtWatchOnly checks unsigned funding with a complete public origin
// while the Wallet has no private keys that could satisfy a signing request.
func testFundPsbtWatchOnly(h *bwtest.HarnessTest) {
	// Arrange: The existing shell fixture retains its explicit BIP84 scope
	// and fingerprint, avoiding the unknown-origin work owned by Task 482.
	keys := deterministicImportedAccountKeys(h)
	fingerprint := wallet.MasterFingerprint(keys.masterKeyFingerprint)
	w, funding := h.NewWallet(
		bwtest.WalletFixture{
			AddrType: keys.addrType,
			Amounts:  []btcutil.Amount{oneBTC},
			InitialAccounts: []wallet.ImportAccountParams{{
				Scope:                &keys.scope,
				XPub:                 keys.accountKey,
				MasterKeyFingerprint: &fingerprint,
				Name:                 waddrmgr.DefaultAccountName,
				AddrType:             keys.addrType,
			}},
		},
	)
	payment := deriveWalletPayment(h, w, keys.addrType, halfBTC)
	packet := fundPsbtPacket(h, payment, funding.WalletOutpoints...)

	// Observe the funded child's coordinates instead of assuming the
	// account cursor has not advanced during historical discovery.
	coin, err := w.GetUtxo(h.Context(), funding.WalletOutpoints[0])
	require.NoError(h, err)
	inputInfo, err := w.GetAddressInfo(h.Context(), coin.Address)
	require.NoError(h, err)

	// Act: Fund the explicit input without attempting to unlock or sign.
	result, err := w.FundPsbt(
		h.Context(), &wallet.FundIntent{
			Packet: packet, FeeRate: relayFeeRate,
			ChangeSource: &wallet.ScopedAccount{
				KeyScope:    keys.scope,
				AccountName: waddrmgr.DefaultAccountName,
			},
		},
	)

	// Assert: The packet carries the known public origin and a caller-owned
	// lease that can be released without acquiring private signing material.
	require.NoError(h, err)
	require.NotEqual(h, wtxmgr.LockID{}, result.LeaseID)
	require.True(h, w.IsWatchOnly())
	require.Len(h, result.Packet.UnsignedTx.TxIn, 1)
	require.Equal(
		h, funding.WalletOutpoints[0],
		result.Packet.UnsignedTx.TxIn[0].PreviousOutPoint,
	)
	require.Len(h, result.Packet.Inputs[0].Bip32Derivation, 1)
	origin := result.Packet.Inputs[0].Bip32Derivation[0]
	require.Equal(h, keys.masterKeyFingerprint, origin.MasterKeyFingerprint)
	require.Equal(
		h, []uint32{
			keys.scope.Purpose + hdkeychain.HardenedKeyStart,
			keys.scope.Coin + hdkeychain.HardenedKeyStart,
			keys.accountKey.ChildIndex(),
			inputInfo.Derivation.Branch, inputInfo.Derivation.Index,
		}, origin.Bip32Path,
	)
	leases, err := w.ListLeasedOutputs(h.Context())
	require.NoError(h, err)
	require.Len(h, leases, 1)
	require.Equal(h, result.LeaseID, leases[0].LockID)
	require.Equal(h, funding.WalletOutpoints[0], leases[0].OutPoint)

	for _, input := range result.Packet.UnsignedTx.TxIn {
		require.NoError(
			h, w.ReleaseOutput(
				h.Context(), result.LeaseID,
				input.PreviousOutPoint,
			),
		)
	}
}

// testFundPsbtRejectIntent checks that representative validation failures
// preserve the caller and every public funding/allocation observation.
func testFundPsbtRejectIntent(h *bwtest.HarnessTest) {
	// Arrange: Use one funded fixture and baseline for the data-only refusal
	// rows; the existing success cases own each accepted boundary control.
	ctx := h.Context()
	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err)
	w, _ := h.NewWallet(
		bwtest.WalletFixture{
			AddrType: txCreatorFundingType,
			Amounts:  []btcutil.Amount{oneBTC},
		},
	)
	payment := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)
	source := &wallet.ScopedAccount{
		KeyScope:    scope,
		AccountName: waddrmgr.DefaultAccountName,
	}
	query := wallet.UtxoQuery{MaxConfs: maxConfsLimit}
	account, err := w.GetAccount(ctx, scope, source.AccountName)
	require.NoError(h, err)
	addresses, err := w.ListAddresses(
		ctx, source.AccountName, txCreatorFundingType,
	)
	require.NoError(h, err)
	coins, err := w.ListUnspent(ctx, query)
	require.NoError(h, err)
	testCases := []struct {
		name    string
		amount  int64
		records int
		feeRate btcunit.SatPerKVByte
		wantErr error
	}{
		{
			name:    "malformed records",
			amount:  payment.Value,
			records: 0,
			feeRate: relayFeeRate,
			wantErr: wallet.ErrPacketMalformed,
		},
		{
			name:    "dust payment",
			amount:  int64(h.DustThreshold(payment.PkScript)) - 1,
			records: 1,
			feeRate: relayFeeRate,
			wantErr: txrules.ErrOutputIsDust,
		},
		{
			name:    "zero fee",
			amount:  payment.Value,
			records: 1,
			feeRate: btcunit.ZeroSatPerKVByte,
			wantErr: wallet.ErrMissingFeeRate,
		},
		{
			name:    "excessive fee",
			amount:  payment.Value,
			records: 1,
			feeRate: btcunit.NewSatPerKVByte(
				wallet.DefaultMaxFeeRate.Val() + 1,
			),
			wantErr: wallet.ErrFeeRateTooLarge,
		},
	}

	for _, tc := range testCases {
		// Arrange: Vary only the caller's output, record count, and fee;
		// encoding also works for the deliberately incomplete record list.
		output := payment
		output.Value = tc.amount
		packet := fundPsbtPacket(h, output)
		packet.Outputs = make([]psbt.POutput, tc.records)
		original, err := packet.B64Encode()
		require.NoError(h, err)

		// Act: Ask the same real Wallet to fund each invalid representation.
		result, err := w.FundPsbt(
			ctx, &wallet.FundIntent{
				Packet: packet, FeeRate: tc.feeRate,
				Policy: &wallet.InputsPolicy{Source: source},
			},
		)

		// Assert: A stable refusal returns no packet and leaves all caller,
		// allocation, coin and reservation observations exactly unchanged.
		require.ErrorIs(h, err, tc.wantErr, tc.name)
		require.Nil(h, result)

		unchanged, err := packet.B64Encode()
		require.NoError(h, err)
		require.Equal(h, original, unchanged)

		afterAccount, err := w.GetAccount(
			ctx, scope, source.AccountName,
		)
		require.NoError(h, err)
		require.Equal(h, account, afterAccount)

		afterAddresses, err := w.ListAddresses(
			ctx, source.AccountName, txCreatorFundingType,
		)
		require.NoError(h, err)
		require.ElementsMatch(h, addresses, afterAddresses)

		afterCoins, err := w.ListUnspent(ctx, query)
		require.NoError(h, err)
		require.Equal(h, coins, afterCoins)

		leases, err := w.ListLeasedOutputs(ctx)
		require.NoError(h, err)
		require.Empty(h, leases)
	}
}

// testFundPsbtRejectInputs checks both unavailable manual inputs and an
// insufficient automatic source without acquiring leases or allocating change.
func testFundPsbtRejectInputs(h *bwtest.HarnessTest) {
	// Arrange: Retain one real control lease and both wallet/foreign coins,
	// so a refusal cannot pass by silently dropping preexisting ownership.
	ctx := h.Context()
	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err)
	w, funding := h.NewWallet(
		bwtest.WalletFixture{
			AddrType: txCreatorFundingType,
			Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		},
	)
	payment := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)
	source := &wallet.ScopedAccount{
		KeyScope:    scope,
		AccountName: waddrmgr.DefaultAccountName,
	}
	owner := wtxmgr.LockID{1}
	_, err = w.LeaseOutput(
		ctx, owner, funding.WalletOutpoints[0], leaseDuration,
	)
	require.NoError(h, err)
	leases, err := w.ListLeasedOutputs(ctx)
	require.NoError(h, err)

	query := wallet.UtxoQuery{MaxConfs: maxConfsLimit}
	coins, err := w.ListUnspent(ctx, query)
	require.NoError(h, err)
	account, err := w.GetAccount(ctx, scope, source.AccountName)
	require.NoError(h, err)
	addresses, err := w.ListAddresses(
		ctx, source.AccountName, txCreatorFundingType,
	)
	require.NoError(h, err)

	testCases := []struct {
		name  string
		input wire.OutPoint
	}{
		{
			name:  "leased input",
			input: funding.WalletOutpoints[0],
		},
		{
			name:  "foreign input",
			input: funding.ForeignOutpoints[0],
		},
	}
	for _, tc := range testCases {
		// Arrange: Each manual packet selects one unavailable real outpoint.
		packet := fundPsbtPacket(h, payment, tc.input)
		original, err := packet.B64Encode()
		require.NoError(h, err)

		// Act: Complete that packet without permission to replace its input.
		result, err := w.FundPsbt(
			ctx, &wallet.FundIntent{
				Packet: packet, FeeRate: relayFeeRate,
				ChangeSource: source,
			},
		)

		// Assert: Each refusal preserves the original owner's complete lease
		// and all relevant public state before the next attempt starts.
		require.ErrorIs(h, err, wallet.ErrUtxoNotEligible, tc.name)
		require.Nil(h, result)

		unchanged, err := packet.B64Encode()
		require.NoError(h, err)
		require.Equal(h, original, unchanged)

		afterLeases, err := w.ListLeasedOutputs(ctx)
		require.NoError(h, err)
		require.Equal(h, leases, afterLeases)

		afterCoins, err := w.ListUnspent(ctx, query)
		require.NoError(h, err)
		require.Equal(h, coins, afterCoins)

		afterAccount, err := w.GetAccount(
			ctx, scope, source.AccountName,
		)
		require.NoError(h, err)
		require.Equal(h, account, afterAccount)

		afterAddresses, err := w.ListAddresses(
			ctx, source.AccountName, txCreatorFundingType,
		)
		require.NoError(h, err)
		require.ElementsMatch(h, addresses, afterAddresses)
	}

	// Arrange: Exceed the entire balance, not merely the unleased balance,
	// so the typed insufficient-funds result has a distinct public oracle.
	payment.Value = oneBTC + twoBTC + halfBTC
	packet := fundPsbtPacket(h, payment)
	original, err := packet.B64Encode()
	require.NoError(h, err)

	// Act: Request automatic funding from the same scoped account.
	result, err := w.FundPsbt(
		ctx, &wallet.FundIntent{
			Packet: packet, FeeRate: relayFeeRate,
			Policy: &wallet.InputsPolicy{Source: source},
		},
	)

	// Assert: Insufficiency also preserves every public funding observation;
	// release only the fixture's control lease once both refusal paths finish.
	var inputErr txauthor.InputSourceError
	require.ErrorAs(h, err, &inputErr)
	require.Nil(h, result)

	unchanged, err := packet.B64Encode()
	require.NoError(h, err)
	require.Equal(h, original, unchanged)

	afterLeases, err := w.ListLeasedOutputs(ctx)
	require.NoError(h, err)
	require.Equal(h, leases, afterLeases)

	afterCoins, err := w.ListUnspent(ctx, query)
	require.NoError(h, err)
	require.Equal(h, coins, afterCoins)

	afterAccount, err := w.GetAccount(ctx, scope, source.AccountName)
	require.NoError(h, err)
	require.Equal(h, account, afterAccount)

	afterAddresses, err := w.ListAddresses(
		ctx, source.AccountName, txCreatorFundingType,
	)
	require.NoError(h, err)
	require.ElementsMatch(h, addresses, afterAddresses)
	require.NoError(
		h, w.ReleaseOutput(
			ctx, owner, funding.WalletOutpoints[0],
		),
	)
}
