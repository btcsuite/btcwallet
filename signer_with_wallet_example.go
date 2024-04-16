package main

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/frost"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"os"
	"runtime"
	"time"
)

func main() {
	// Use all processor cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

	validators := frost.GetValidators(5, 3)
	pubKey, err := validators[0].MakePubKey("test")
	if err != nil {
		log.Info(err)
		return
	}

	w, err := RunWallet(validators[0])
	if err != nil {
		os.Exit(1)
	}

	w.Unlock([]byte("passphrase"), time.After(10*time.Minute))

	_ = w.ImportPublicKey(pubKey, waddrmgr.TaprootPubKey)

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
	txOut := wire.NewTxOut(100000000, p2shAddr)

	accounts, err := w.Accounts(waddrmgr.KeyScopeBIP0086)
	if err != nil {
		log.Info(err)
		return
	}

	simpleTx, err := w.CreateSimpleTx(&waddrmgr.KeyScopeBIP0086, accounts.Accounts[1].AccountNumber, []*wire.TxOut{txOut}, 1, 1, wallet.CoinSelectionLargest, false)
	if err != nil {
		log.Info(err)
		return
	}
	err = w.PublishTransaction(simpleTx.Tx, "")
	if err != nil {
		log.Info(err)
		return
	}

	<-interruptHandlersDone
	log.Info("Shutdown complete")
}
