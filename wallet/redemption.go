package wallet

import (
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stroomnetwork/btcwallet/waddrmgr"
	"github.com/stroomnetwork/btcwallet/wallet/txauthor"
	"golang.org/x/net/context"
	"time"
)

func (w *Wallet) CheckDoubleSpendAndCreateTxWithRedemptionId(start, end *BlockIdentifier, redemptionId uint32,
	coinSelectKeyScope *waddrmgr.KeyScope, account uint32, outputs []*wire.TxOut, minconf int32,
	satPerKb btcutil.Amount, coinSelectionStrategy CoinSelectionStrategy,
	dryRun bool, optFuncs ...TxCreateOption) (*txauthor.AuthoredTx, error) {

	isSpent, hash, err := w.IsRedemptionIdAlreadySpent(redemptionId, start, end)

	if err != nil {
		return nil, err
	}

	if isSpent {
		return nil, fmt.Errorf("redemption id %d already spent in tx %s", redemptionId, hash)
	}

	return w.CreateSimpleTxWithRedemptionId(coinSelectKeyScope, account, outputs, minconf, satPerKb, coinSelectionStrategy, dryRun, redemptionId, nil, optFuncs...)
}
func (w *Wallet) IsRedemptionIdAlreadySpent(redemptionId uint32, start, end *BlockIdentifier) (bool, chainhash.Hash, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	minedTx, err := w.GetTransactions(start, end, "", ctx.Done())
	if err != nil {
		return false, nilHash(), err
	}

	for _, block := range minedTx.MinedTransactions {
		isPresent, hash, err := w.isRedemptionIdPresent(redemptionId, block.Transactions)
		if isPresent {
			return isPresent, hash, err
		}
	}

	unminedTx, err := w.GetTransactions(NewBlockIdentifierFromHeight(-1), end, "", ctx.Done())
	if err != nil {
		return false, nilHash(), err
	}
	return w.isRedemptionIdPresent(redemptionId, unminedTx.UnminedTransactions)
}

func (w *Wallet) isRedemptionIdPresent(redemptionId uint32, txs []TransactionSummary) (bool, chainhash.Hash, error) {
	for _, tx := range txs {
		if tx.MyInputs != nil {
			txDetails, _ := UnstableAPI(w).TxDetails(tx.Hash)
			for _, input := range txDetails.MsgTx.TxIn {
				if input.Sequence == redemptionId {
					return true, txDetails.Hash, nil
				}
			}
		}
	}
	return false, nilHash(), nil
}

func nilHash() chainhash.Hash {
	return chainhash.Hash{}
}
