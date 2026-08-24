//go:build itest

package itest

import (
	"strings"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wtxmgr"
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

// testLabelTxBoundaries verifies the ends of the label length range every
// backend accepts: one character, and the longest label the wallet stores.
//
// The upper limit is wtxmgr.TxLabelLimit, which is the only exported name for
// it; the SQL schemas restate the same number as a column constraint. Labels
// are built from ASCII deliberately, because kvdb counts the limit in bytes
// while the SQL schemas count it in characters, and only ASCII makes the one
// number mean the same thing on all three backends.
//
// The values just outside this range are not rows here. One character above it
// is refused by every backend, but with a backend-specific error rather than a
// wallet error identity, so it is asserted separately in
// testLabelTxRejectOversize. The empty label below it has no single behavior to
// assert at all: the SQL backends accept it and clear the label, while kvdb
// refuses it.
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
			label: strings.Repeat("x", wtxmgr.TxLabelLimit),
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

// testLabelTxRejectOversize verifies that the first label longer than the
// wallet stores is refused by every backend, and that the refusal leaves the
// transaction's existing label in place rather than truncating it to fit.
//
// The rejection is asserted only as an error. Every backend enforces the limit
// itself, so the caller receives whichever of three unrelated values that
// backend produces: kvdb reports wtxmgr.ErrLabelTooLong, SQLite a violated
// CHECK constraint, and PostgreSQL an overlong value for its column type. There
// is no wallet error identity to match on, and matching any one backend's text
// would tie this case to a detail no contract promises. That missing identity
// is a gap in LabelTx, not in this case.
//
// The identities LabelTx does publish are ruled out instead, so the case still
// fails if the write is ever refused for a reason other than the label it was
// given.
func testLabelTxRejectOversize(h *bwtest.HarnessTest) {
	const kept = "rent for march"

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txWriterFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
	})

	txHash := funding.WalletOutpoints[0].Hash

	err := w.LabelTx(h.Context(), txHash, kept)
	require.NoError(h, err, "failed to label the funding transaction")

	// One character past the longest label testLabelTxBoundaries stores, so
	// length is the only thing wrong with it.
	oversize := strings.Repeat("x", wtxmgr.TxLabelLimit+1)

	err = w.LabelTx(h.Context(), txHash, oversize)

	require.Error(h, err, "label longer than the limit was accepted")
	require.NotErrorIs(
		h, err, wallet.ErrTxNotFound,
		"label was refused for a transaction the wallet holds",
	)
	require.NotErrorIs(
		h, err, wallet.ErrStateForbidden,
		"label was refused by the lifecycle gate on a running wallet",
	)

	detail, err := w.GetTx(h.Context(), txHash)
	require.NoError(h, err, "failed to read the labeled transaction")
	require.Equal(
		h, kept, detail.Label,
		"refused label replaced or truncated the stored one",
	)
}
