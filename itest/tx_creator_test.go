//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
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

	// Each payment is derived separately, so an authored transaction that
	// collapsed its outputs onto one recipient fails the assertions below.
	first := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)
	second := deriveWalletPayment(h, w, txCreatorFundingType, quarterBTC)
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
// would be dust is authored without a change output.
func testCreateTransactionOmitChange(h *bwtest.HarnessTest) {
	// smallCoin is the only coin the wallet holds, so the payment below is
	// funded by it alone.
	const smallCoin = 100_000

	// changeLeftover is what remains of the coin after the payment. The fee
	// for this single input, single output shape at the default relay rate
	// takes most of it, and what is left is below the dust limit for a
	// witness pubkey change output, so the wallet must drop the change.
	// Only that omission is asserted here; the fee itself is not.
	const changeLeftover = 300

	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{smallCoin},
		Unlocked: true,
	})

	outpoints := funding.WalletOutpoints

	payment := deriveWalletPayment(
		h, w, txCreatorFundingType, smallCoin-changeLeftover,
	)

	authored, err := w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{payment},
		Inputs: &wallet.InputsManual{
			UTXOs: []wire.OutPoint{outpoints[0]},
		},
		ChangeSource: &wallet.ScopedAccount{
			AccountName: waddrmgr.DefaultAccountName,
			KeyScope:    scope,
		},
		FeeRate: relayFeeRate,
	})
	require.NoError(h, err, "failed to create transaction")

	require.Equal(
		h, -1, authored.ChangeIndex, "dust change output not omitted",
	)
	require.Len(h, authored.Tx.TxOut, 1, "unexpected output count")
	require.Equal(
		h, payment.PkScript, authored.Tx.TxOut[0].PkScript,
		"payment script changed",
	)
	require.Equal(
		h, payment.Value, authored.Tx.TxOut[0].Value,
		"payment value changed",
	)
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

// testCreateTransactionWalletState verifies the lifecycle gate on transaction
// creation: it is forbidden before Start and after Stop, and a locked wallet
// still authors, since an unsigned transaction needs no private key.
func testCreateTransactionWalletState(h *bwtest.HarnessTest) {
	// witnessProgramSize is the length of a witness pubkey hash program.
	const witnessProgramSize = 20

	scope, err := txCreatorFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{
		AddrType:  txCreatorFundingType,
		Unstarted: true,
	})

	// A wallet that has not started cannot derive an address, so this
	// payment goes to an arbitrary witness program. The intent is otherwise
	// well formed, which keeps the assertion below about the state gate
	// alone rather than about the order in which the gate and intent
	// validation run.
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

	_, err = w.CreateTransaction(h.Context(), intent)
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"create transaction before start not rejected",
	)

	require.NoError(h, h.StartWallet(w), "failed to start wallet")

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

	// Stop the wallet, then deregister it so the harness does not drive a
	// stopped wallet during teardown.
	require.NoError(h, h.StopWallet(w), "failed to stop wallet")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")

	_, err = w.CreateTransaction(h.Context(), intent)
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"create transaction after stop not rejected",
	)
}
