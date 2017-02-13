package spvchain

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcutil/gcs/builder"
)

func buildBasicFilter(block *wire.MsgBlock) (*gcs.Filter, error) {
	blockHash := block.BlockHash()
	b := builder.WithKeyHash(&blockHash)
	_, err := b.Key()
	if err != nil {
		str := "failed to create filter builder: %v"
		return nil, log.Errorf(str, err)
	}
	for i, tx := range block.Transactions {
		// Skip the inputs for the coinbase transaction
		if i != 0 {
			for _, txIn := range tx.TxIn {
				b.AddOutPoint(txIn.PreviousOutPoint)
			}
		}
		for _, txOut := range tx.TxOut {
			b.AddScript(txOut.PkScript)
		}
	}
	f, err := b.Build()
	if err != nil {
		str := "failed to build filter: %v"
		return nil, log.Errorf(str, err)
	}
	return f, nil
}

func buildExtFilter(block *wire.MsgBlock) (*gcs.Filter, error) {
	blockHash := block.BlockHash()
	b := builder.WithKeyHash(&blockHash)
	_, err := b.Key()
	if err != nil {
		str := "failed to create filter builder: %v"
		return nil, log.Errorf(str, err)
	}
	for i, tx := range block.Transactions {
		txHash := tx.TxHash()
		b.AddHash(&txHash)
		// Skip the inputs for the coinbase transaction
		if i != 0 {
			for _, txIn := range tx.TxIn {
				b.AddScript(txIn.SignatureScript)
			}
		}
	}
	f, err := b.Build()
	if err != nil {
		str := "failed to build filter: %v"
		return nil, log.Errorf(str, err)
	}
	return f, nil
}

func getFilterHash(filter *gcs.Filter) chainhash.Hash {
	return chainhash.HashH(filter.NBytes())
}

func makeHeaderForFilter(filter *gcs.Filter, prevHeader chainhash.Hash) chainhash.Hash {
	filterTip := make([]byte, 2*chainhash.HashSize)
	filterHash := getFilterHash(filter)
	copy(filterTip, filterHash[:])
	copy(filterTip[chainhash.HashSize:], prevHeader[:])
	return chainhash.HashH(filterTip)
}
