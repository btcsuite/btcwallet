package wallet

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stroomnetwork/btcwallet/waddrmgr"
	"github.com/stroomnetwork/btcwallet/wallet/txauthor"
	"testing"
)

func TestMinedTxDoubleSpend(t *testing.T) {
	doubleSpendTest(t, true)
}

func TestUnminedTxDoubleSpendFrom(t *testing.T) {
	doubleSpendTest(t, false)
}

func doubleSpendTest(t *testing.T, mineTx bool) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	addUtxoToWallet(t, w)

	tx, err := createTx(t, w)
	assert.NoError(t, err)
	assert.NotNil(t, tx)

	if mineTx {
		addUtxo(t, w, tx.Tx)
	} else {
		_ = w.PublishTransaction(tx.Tx, "")
	}

	// double spend the same redemptionId
	tx, err = createTx(t, w)

	assert.Error(t, err)
	assert.Nil(t, tx)
}

func createTx(t *testing.T, w *Wallet) (*txauthor.AuthoredTx, error) {

	var redemptionId uint32 = 1

	return w.CheckDoubleSpendAndCreateTxWithRedemptionId(
		NewBlockIdentifierFromHeight(0), NewBlockIdentifierFromHeight(testBlockHeight),
		redemptionId, &waddrmgr.KeyScopeBIP0049Plus, 0, []*wire.TxOut{getTxOut(t)}, 1, 100,
		CoinSelectionLargest, false)
}

func addUtxoToWallet(t *testing.T, w *Wallet) {

	keyScope := waddrmgr.KeyScopeBIP0049Plus

	addr, err := w.CurrentAddress(0, keyScope)
	assert.NoError(t, err)

	p2shAddr, err := txscript.PayToAddrScript(addr)
	assert.NoError(t, err)

	incomingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{},
		},
		TxOut: []*wire.TxOut{},
	}
	for amt := int64(5000); amt <= 125000; amt += 10000 {
		incomingTx.AddTxOut(wire.NewTxOut(amt, p2shAddr))
	}

	addUtxo(t, w, incomingTx)
}

func getTxOut(t *testing.T) *wire.TxOut {
	addr, err := btcutil.DecodeAddress("SR9zEMt5qG7o1Q7nGcLPCMqv5BrNHcw2zi", &chaincfg.SimNetParams)
	assert.NoError(t, err)

	p2shAddr, err := txscript.PayToAddrScript(addr)
	assert.NoError(t, err)

	return wire.NewTxOut(10000, p2shAddr)
}
