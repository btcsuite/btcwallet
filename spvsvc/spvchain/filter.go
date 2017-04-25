package spvchain

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcutil/gcs/builder"
)

// TODO: Move these functions into github.com/btcsuite/btcutil/gcs/builder.

// BuildBasicFilter will be factored out into gcs.builder
func BuildBasicFilter(block *wire.MsgBlock) (*gcs.Filter, error) {
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

// BuildExtFilter will be factored out into gcs.builder
func BuildExtFilter(block *wire.MsgBlock) (*gcs.Filter, error) {
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

// GetFilterHash will be factored out into gcs.builder
func GetFilterHash(filter *gcs.Filter) chainhash.Hash {
	return chainhash.HashH(filter.NBytes())
}

// MakeHeaderForFilter will be factored out into gcs.builder
func MakeHeaderForFilter(filter *gcs.Filter, prevHeader chainhash.Hash) chainhash.Hash {
	filterTip := make([]byte, 2*chainhash.HashSize)
	filterHash := GetFilterHash(filter)
	copy(filterTip, filterHash[:])
	copy(filterTip[chainhash.HashSize:], prevHeader[:])
	return chainhash.HashH(filterTip)
}
