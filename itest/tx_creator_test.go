//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/stretchr/testify/require"
)

const (
	// halfBTC is the payment amount the TxCreator cases use. It is small
	// enough that any single funded coin covers it.
	halfBTC = btcutil.SatoshiPerBitcoin / 2

	// txCreatorFundingType is the address type the TxCreator cases fund and
	// select from. Each case derives its key scope from this value, so the
	// funded scope is never stated twice.
	txCreatorFundingType = waddrmgr.WitnessPubKey
)

// relayFeeRate is the fee rate the TxCreator cases author at. It is the
// default relay fee, one satoshi per virtual byte, which keeps the fee
// negligible against the funded amounts.
var relayFeeRate = btcunit.NewSatPerKVByte(txrules.DefaultRelayFeePerKb)

// deriveWalletPayment derives a fresh external address of the requested type
// from the wallet and returns a payment of amount to it.
//
// Paying the wallet itself keeps the destination wallet-visible, and the
// external branch is what tells the payment apart from an internal change
// output, which the cases rely on when they identify the change.
//
// Deriving the address changes the wallet, so a case must cross
// AssertWalletSynced after its last call to this, not merely after funding.
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

	w, outpoints := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		Unlocked: true,
	})

	payment := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)

	// Funding and the derivation above are both wallet side effects, so
	// the synchronization boundary belongs here, after the last of them.
	h.AssertWalletSynced(w)

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

	h.AssertWalletSynced(w)

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

	w, outpoints := h.NewWallet(bwtest.WalletFixture{
		AddrType: txCreatorFundingType,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC, threeBTC},
		Unlocked: true,
	})

	// The first payment needs two coins, the second needs one.
	large := deriveWalletPayment(h, w, txCreatorFundingType, threeBTC+halfBTC)
	small := deriveWalletPayment(h, w, txCreatorFundingType, halfBTC)

	h.AssertWalletSynced(w)

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

