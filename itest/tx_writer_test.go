//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// txWriterFundingType is the address type the TxWriter cases fund. A label
// describes a transaction rather than the coins it pays, so the type is
// immaterial here; naming one keeps the fixture explicit instead of resting on
// a zero value that means something to other components.
const txWriterFundingType = waddrmgr.WitnessPubKey

// testLabelTx verifies that labeling a transaction the wallet holds succeeds
// and that the label becomes what both maintained readers report for it.
func testLabelTx(h *bwtest.HarnessTest) {
	const label = "rent for march"

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txWriterFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
	})

	// The transaction that paid the wallet is mined and wallet-relevant, so
	// it is a transaction the wallet's readers report, and nothing has
	// labeled it yet.
	txHash := funding.WalletOutpoints[0].Hash

	before, err := w.GetTx(h.Context(), txHash)
	require.NoError(h, err, "failed to read the funding transaction")
	require.Empty(h, before.Label, "funding transaction arrived labeled")

	err = w.LabelTx(h.Context(), txHash, label)

	require.NoError(h, err, "failed to label transaction")

	after, err := w.GetTx(h.Context(), txHash)
	require.NoError(h, err, "failed to read the labeled transaction")
	require.Equal(h, label, after.Label, "point read lost the label")

	// The label is metadata of the transaction, not of the read, so the
	// list reader must report the same one. The range covers everything the
	// wallet holds, and the transaction is selected by hash rather than by
	// position, so this asserts the label and nothing about what else that
	// history contains.
	details, err := w.ListTxns(h.Context(), unminedHeight, 0)
	require.NoError(h, err, "failed to list transactions")

	listed := make(map[chainhash.Hash]string, len(details))
	for _, detail := range details {
		listed[detail.Hash] = detail.Label
	}

	require.Equal(h, label, listed[txHash], "list read lost the label")
}

// testLabelTxReplace verifies the documented replacement contract: a label
// written over an existing one takes its place, rather than being refused as a
// duplicate or accumulating alongside it.
func testLabelTxReplace(h *bwtest.HarnessTest) {
	const (
		original    = "rent for march"
		replacement = "rent for april"
	)

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txWriterFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
	})

	txHash := funding.WalletOutpoints[0].Hash

	err := w.LabelTx(h.Context(), txHash, original)
	require.NoError(h, err, "failed to write the original label")

	err = w.LabelTx(h.Context(), txHash, replacement)

	require.NoError(h, err, "labeling an already-labeled transaction "+
		"was refused")

	detail, err := w.GetTx(h.Context(), txHash)
	require.NoError(h, err, "failed to read the relabeled transaction")
	require.Equal(
		h, replacement, detail.Label, "transaction kept its first label",
	)
}
