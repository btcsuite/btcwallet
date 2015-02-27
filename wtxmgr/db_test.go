package wtxmgr

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

var (
	TstSerializedTx, _          = hex.DecodeString("010000000114d9ff358894c486b4ae11c2a8cf7851b1df64c53d2e511278eff17c22fb7373000000008c493046022100995447baec31ee9f6d4ec0e05cb2a44f6b817a99d5f6de167d1c75354a946410022100c9ffc23b64d770b0e01e7ff4d25fbc2f1ca8091053078a247905c39fce3760b601410458b8e267add3c1e374cf40f1de02b59213a82e1d84c2b94096e22e2f09387009c96debe1d0bcb2356ffdcf65d2a83d4b34e72c62eccd8490dbf2110167783b2bffffffff0280969800000000001976a914479ed307831d0ac19ebc5f63de7d5f1a430ddb9d88ac38bfaa00000000001976a914dadf9e3484f28b385ddeaa6c575c0c0d18e9788a88ac00000000")
	TstTx, _                    = btcutil.NewTxFromBytes(TstSerializedTx)
	TstTxSpendingTxBlockHash, _ = wire.NewShaHashFromStr("00000000000000017188b968a371bab95aa43522665353b646e41865abae02a4")
	TstAmt                      = int64(10000000)
	TstIndex                    = 684
	TstTxBlockDetails           = &Block{
		Height: 276425,
		Hash:   *TstTxSpendingTxBlockHash,
		Time:   time.Unix(1387737310, 0),
	}
)

func BenchmarkSerializeBlock(b *testing.B) {
	for n := 0; n < b.N; n++ {
		serializeBlock(TstTxBlockDetails)
	}
}

func BenchmarkSerializeTxRecord(b *testing.B) {
	r := new(txRecord)
	r.tx = TstTx
	for n := 0; n < b.N; n++ {
		serializeTxRecord(r)
	}
}
