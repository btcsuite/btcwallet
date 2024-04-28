package wallet

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"github.com/stroomnetwork/btcwallet/frost"
	"github.com/stroomnetwork/btcwallet/waddrmgr"
	"testing"
	"time"
)

func TestFrostSigning(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	validators := frost.GetValidators(5, 3)
	pk1, err := validators[0].MakePubKey("test1")
	require.NoError(t, err)
	require.NotNil(t, pk1)

	pk2, err := validators[0].MakePubKey("test2")
	require.NoError(t, err)
	require.NotNil(t, pk1)

	w.FrostSigner = validators[0]
	w.Pk1 = pk1
	w.Pk2 = pk2

	err = w.Unlock([]byte("world"), time.After(10*time.Minute))
	require.NoError(t, err)

	pubKey, err := w.ImportBtcAddressWithEthAddr("tb1pgdyx9mulkelunyg9rkj384sajls7xx2y3jlagdpup2l2wl6tppasterqm2", "0x7b3f4f4b3cCf7f3fDf3f3f3f3f3f3f3f3f3f3f3f")
	require.NoError(t, err)

	p2shAddr, err := txscript.PayToTaprootScript(pubKey)
	require.NoError(t, err)
	require.NotNil(t, p2shAddr)

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

	accounts, err := w.Accounts(waddrmgr.KeyScopeBIP0086)
	require.NoError(t, err)
	require.NotNil(t, accounts)
	require.True(t, len(accounts.Accounts) > 1)

	address, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	require.NoError(t, err)

	out := wire.NewTxOut(10000, address.ScriptAddress())

	tx, err := w.CreateSimpleTx(&waddrmgr.KeyScopeBIP0086, accounts.Accounts[1].AccountNumber, []*wire.TxOut{out}, 1, 10, CoinSelectionLargest, false)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = w.PublishTransaction(tx.Tx, "")
	require.NoError(t, err)
}
