//go:build itest

package itest

import (
	"strings"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
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

// testLabelTxClear verifies that an empty label removes the label a
// transaction already had, that removing a label a transaction never had is
// not an error, and that a cleared label stays cleared across a reload.
//
// The empty label is the only way to remove one through this API, so a wallet
// that refused it would leave a caller no way to undo a label at all.
func testLabelTxClear(h *bwtest.HarnessTest) {
	const label = "rent for march"

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txWriterFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
	})

	txHash := funding.WalletOutpoints[0].Hash

	err := w.LabelTx(h.Context(), txHash, label)
	require.NoError(h, err, "failed to label transaction")

	err = w.LabelTx(h.Context(), txHash, "")

	require.NoError(h, err, "clearing a label was refused")

	detail, err := w.GetTx(h.Context(), txHash)
	require.NoError(h, err, "failed to read the cleared transaction")
	require.Empty(h, detail.Label, "point read still reports a label")

	details, err := w.ListTxns(h.Context(), unminedHeight, 0)
	require.NoError(h, err, "failed to list transactions")

	listed := make(map[chainhash.Hash]string, len(details))
	for _, detail := range details {
		listed[detail.Hash] = detail.Label
	}

	require.Empty(h, listed[txHash], "list read still reports a label")

	// A transaction with no label is what the caller asked for and already
	// has, so asking again is not an error.
	err = w.LabelTx(h.Context(), txHash, "")
	require.NoError(h, err, "clearing an absent label was refused")

	// The removal is durable rather than a property of the running wallet.
	reloaded := h.ReloadWallet(w)

	detail, err = reloaded.GetTx(h.Context(), txHash)
	require.NoError(h, err, "reloaded wallet lost the transaction")
	require.Empty(
		h, detail.Label, "reloaded wallet restored the cleared label",
	)
}

// testLabelTxBoundaries verifies the ends of the label length range the wallet
// accepts: one byte, and a label of exactly wallet.MaxTxLabelLength bytes.
//
// The limit is stated in bytes, so a label of multi-byte runes reaches it in
// fewer characters. Both spellings of the longest accepted label are rows here,
// because the stores under this API do not agree on the unit and the wallet's
// own limit is what settles it.
//
// The first value past the limit is refused rather than accepted, so it is
// asserted separately in testLabelTxRejectOversize. The empty label below this
// range is not a boundary of it at all: it removes a label rather than setting
// a short one, and testLabelTxClear covers it.
func testLabelTxBoundaries(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txWriterFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
	})

	txHash := funding.WalletOutpoints[0].Hash

	labels := []struct {
		name  string
		label string
	}{
		{
			name:  "shortest label",
			label: strings.Repeat("x", 1),
		},
		{
			name:  "longest label",
			label: strings.Repeat("x", wallet.MaxTxLabelLength),
		},
		{
			// Three bytes per rune, so a third of the limit in
			// characters already spends nearly all of it in bytes.
			// A character limit of the same size would leave room
			// for three times as many.
			name: "multi-byte label near the limit",
			label: strings.Repeat(
				"€", wallet.MaxTxLabelLength/3,
			),
		},
	}

	for _, tc := range labels {
		err := w.LabelTx(h.Context(), txHash, tc.label)
		require.NoError(h, err, "%s was refused", tc.name)

		detail, err := w.GetTx(h.Context(), txHash)
		require.NoError(
			h, err, "failed to read transaction after %s", tc.name,
		)
		require.Equal(
			h, tc.label, detail.Label, "%s came back altered",
			tc.name,
		)
	}
}

// testLabelTxRejectUnknown verifies that labeling a transaction the wallet does
// not hold is refused with the same identity a read of it reports, and that the
// refusal leaves no trace: no transaction is invented for the label to hang on,
// and the label already stored elsewhere is untouched.
func testLabelTxRejectUnknown(h *bwtest.HarnessTest) {
	const (
		kept     = "rent for march"
		rejected = "for a transaction the wallet has never seen"
	)

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txWriterFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
	})

	txHash := funding.WalletOutpoints[0].Hash

	err := w.LabelTx(h.Context(), txHash, kept)
	require.NoError(h, err, "failed to label the funding transaction")

	// The outpoint no wallet knows names a transaction no wallet knows.
	unknown := unknownOutpoint().Hash

	err = w.LabelTx(h.Context(), unknown, rejected)

	require.ErrorIs(
		h, err, wallet.ErrTxNotFound,
		"labeling an unknown transaction was accepted",
	)

	// A label cannot bring its transaction into existence, so the wallet
	// still does not hold the one it just refused to label.
	_, err = w.GetTx(h.Context(), unknown)
	require.ErrorIs(
		h, err, wallet.ErrTxNotFound,
		"refused label created a transaction",
	)

	// Nor may the refusal reach the transaction the wallet does hold.
	detail, err := w.GetTx(h.Context(), txHash)
	require.NoError(h, err, "failed to read the labeled transaction")
	require.Equal(
		h, kept, detail.Label, "refused label displaced the stored one",
	)
}

// testLabelTxRejectOversize verifies that the first label past the limit is
// refused with the wallet's own identity on every backend, and that the refusal
// leaves the transaction's existing label in place rather than truncating it to
// fit.
//
// One identity is the point of the case. Each store also enforces a limit and
// reports its own violation, and before the wallet published a limit of its own
// a caller met whichever of those three the backend happened to produce.
func testLabelTxRejectOversize(h *bwtest.HarnessTest) {
	const kept = "rent for march"

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txWriterFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
	})

	txHash := funding.WalletOutpoints[0].Hash

	err := w.LabelTx(h.Context(), txHash, kept)
	require.NoError(h, err, "failed to label the funding transaction")

	// One byte past the longest label testLabelTxBoundaries stores, so
	// length is the only thing wrong with it.
	oversize := strings.Repeat("x", wallet.MaxTxLabelLength+1)

	err = w.LabelTx(h.Context(), txHash, oversize)

	require.ErrorIs(
		h, err, wallet.ErrLabelTooLong,
		"label longer than the limit was not refused as too long",
	)

	detail, err := w.GetTx(h.Context(), txHash)
	require.NoError(h, err, "failed to read the labeled transaction")
	require.Equal(
		h, kept, detail.Label,
		"refused label replaced or truncated the stored one",
	)
}

// testLabelTxSurvivesReload verifies that a label is durable rather than
// remembered by the running wallet: after the wallet is stopped, its database
// closed, and the same wallet loaded again, both readers still report it.
func testLabelTxSurvivesReload(h *bwtest.HarnessTest) {
	const label = "rent for march"

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txWriterFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
	})

	txHash := funding.WalletOutpoints[0].Hash

	err := w.LabelTx(h.Context(), txHash, label)
	require.NoError(h, err, "failed to label transaction")

	reloaded := h.ReloadWallet(w)

	detail, err := reloaded.GetTx(h.Context(), txHash)
	require.NoError(
		h, err, "reloaded wallet lost the labeled transaction",
	)
	require.Equal(
		h, label, detail.Label, "reloaded wallet lost the label",
	)

	details, err := reloaded.ListTxns(h.Context(), unminedHeight, 0)
	require.NoError(h, err, "failed to list transactions")

	listed := make(map[chainhash.Hash]string, len(details))
	for _, detail := range details {
		listed[detail.Hash] = detail.Label
	}

	require.Equal(
		h, label, listed[txHash],
		"reloaded wallet listed the transaction without its label",
	)
}

// testLabelTxWalletState verifies the lifecycle gate on labeling: it is
// unavailable before the wallet starts and after it stops, so a caller writing
// during startup or shutdown is told the wallet is not running rather than
// something about the transaction.
func testLabelTxWalletState(h *bwtest.HarnessTest) {
	const label = "rent for march"

	w, _ := h.NewWallet(bwtest.WalletFixture{
		AddrType:  txWriterFundingType,
		Unstarted: true,
	})

	// The gate refuses before anything looks the transaction up, so this
	// only has to be a hash. Nothing is labeled.
	txHash := unknownOutpoint().Hash

	err := w.LabelTx(h.Context(), txHash, label)
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"labeling before start not rejected",
	)

	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

	// Stop the wallet, then deregister it so the harness does not drive a
	// stopped wallet during teardown.
	require.NoError(h, w.Stop(h.Context()), "failed to stop wallet")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")

	err = w.LabelTx(h.Context(), txHash, label)
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"labeling after stop not rejected",
	)
}
