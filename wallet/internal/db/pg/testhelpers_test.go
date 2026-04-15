package pg

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// testRegularMsgTx builds one simple non-coinbase transaction fixture.
func testRegularMsgTx() *wire.MsgTx {
	return &wire.MsgTx{
		Version: wire.TxVersion,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{1, 2, 3},
				Index: 0,
			},
		}},
		TxOut: []*wire.TxOut{{
			Value:    int64(btcutil.SatoshiPerBitcoin),
			PkScript: []byte{0x51},
		}},
	}
}

// testCreateTxRequest builds one prepared CreateTx request for pg tests.
func testCreateTxRequest(t *testing.T) db.CreateTxRequest {
	t.Helper()

	req, err := db.NewCreateTxRequest(db.CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	return req
}
