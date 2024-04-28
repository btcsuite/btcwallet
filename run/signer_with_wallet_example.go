package run

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stroomnetwork/btcwallet/frost"
	"github.com/stroomnetwork/btcwallet/waddrmgr"
	"github.com/stroomnetwork/btcwallet/wallet"
	"os"
	"runtime"
	"time"
)

func RunExample() {
	// Use all processor cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

	validators := frost.GetValidators(5, 3)
	pk1, err := validators[0].MakePubKey("test1")
	if err != nil {
		log.Info(err)
		return
	}

	pk2, err := validators[0].MakePubKey("test2")
	if err != nil {
		log.Info(err)
		return
	}

	w, err := RunWallet(validators[0], pk1, pk2)
	if err != nil {
		os.Exit(1)
	}

	w.Unlock([]byte("passphrase"), time.After(10*time.Minute))
	_, err = w.ImportBtcAddressWithEthAddr("sb1pgdyx9mulkelunyg9rkj384sajls7xx2y3jlagdpup2l2wl6tppasvgf8z0", "0x7b3f4f4b3cCf7f3fDf3f3f3f3f3f3f3f3f3f3f3f")

	f := false
	if f {
		<-interruptHandlersDone
		log.Info("Shutdown complete")
	}

	addr, err := btcutil.DecodeAddress("SR9zEMt5qG7o1Q7nGcLPCMqv5BrNHcw2zi", &chaincfg.SimNetParams)
	if err != nil {
		log.Info(err)
		return
	}
	p2shAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		log.Info(err)
		return
	}
	txOut := wire.NewTxOut(10000000, p2shAddr)

	accounts, err := w.Accounts(waddrmgr.KeyScopeBIP0086)
	if err != nil {
		log.Info(err)
		return
	}

	_, err = w.CheckDoubleSpendAndCreateTxWithRedemptionId(nil, nil, 0, &waddrmgr.KeyScopeBIP0086, accounts.Accounts[1].AccountNumber, []*wire.TxOut{txOut}, 1, 1000, wallet.CoinSelectionLargest, false)
	if err != nil {
		log.Info(err)
		return
	}

	<-interruptHandlersDone
	log.Info("Shutdown complete")
}
