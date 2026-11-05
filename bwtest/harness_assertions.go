package bwtest

import (
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

var (
	// ErrWalletNotSynced is returned when a wallet has not reached the chain
	// tip.
	ErrWalletNotSynced = errors.New("wallet not synced")
)

// AssertPsbtExecutes extracts a finalized packet's transaction and runs every
// input through the script engine, against the previous outputs the packet
// records. It shares no code with the Wallet's signing or finalization paths.
func (h *HarnessTest) AssertPsbtExecutes(packet *psbt.Packet) {
	h.Helper()

	tx, err := psbt.Extract(packet)
	require.NoError(h, err, "failed to extract final transaction")

	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	prevOuts := make([]*wire.TxOut, len(tx.TxIn))

	for i, txIn := range tx.TxIn {
		prevOuts[i] = packet.Inputs[i].WitnessUtxo
		if prevOuts[i] == nil {
			parent := packet.Inputs[i].NonWitnessUtxo
			prevOuts[i] = parent.TxOut[txIn.PreviousOutPoint.Index]
		}

		fetcher.AddPrevOut(txIn.PreviousOutPoint, prevOuts[i])
	}

	hashes := txscript.NewTxSigHashes(tx, fetcher)

	for i, prevOut := range prevOuts {
		engine, err := txscript.NewEngine(
			prevOut.PkScript, tx, i, txscript.StandardVerifyFlags,
			nil, hashes, prevOut.Value, fetcher,
		)
		require.NoError(h, err, "failed to create engine for input %d", i)
		require.NoError(h, engine.Execute(), "input %d failed to execute", i)
	}
}

// AssertWalletSynced polls until the wallet reports it is synced to the
// miner's exact best block. Once this returns, wallet reads for that block may
// be asserted without another retry.
func (h *HarnessTest) AssertWalletSynced(w *wallet.Wallet) {
	h.Helper()

	if w == nil {
		h.Fatalf("nil wallet")
	}

	err := wait.NoError(func() error {
		info, err := w.Info(h.Context())
		if err != nil {
			return fmt.Errorf("get wallet info: %w", err)
		}

		bestHash, bestHeight, err := h.miner.Client.GetBestBlock()
		if err != nil {
			return fmt.Errorf("get best block: %w", err)
		}

		if !info.Synced || info.SyncedTo.Height != bestHeight ||
			!info.SyncedTo.Hash.IsEqual(bestHash) {

			return fmt.Errorf("%w: synced=%v wallet=%v:%d "+
				"chain=%v:%d", ErrWalletNotSynced, info.Synced,
				info.SyncedTo.Hash, info.SyncedTo.Height, bestHash,
				bestHeight)
		}

		return nil
	}, defaultTestTimeout)
	if err != nil {
		h.Fatalf("wallet sync timeout: %v", err)
	}
}

// ReceiveTxEvent waits for the requested transaction and confirmation
// state. Other observations may repeat or arrive out of order, so one harness
// timeout bounds the whole search rather than restarting for every event.
func (h *HarnessTest) ReceiveTxEvent(events <-chan *wallet.TxEvent,
	txHash chainhash.Hash, confirmed bool) *wallet.TxEvent {

	h.Helper()

	timer := time.NewTimer(defaultTestTimeout)
	defer timer.Stop()

	for {
		select {
		case notification, open := <-events:
			require.True(h, open, "subscription ended")

			// Match only the requested observation; the scenario retains
			// responsibility for checking the returned Wallet payload.
			detail := notification.Detail
			if detail.Hash == txHash && (detail.Block != nil) == confirmed {
				return notification
			}

		case <-timer.C:
			h.Fatalf("transaction subscription did not deliver %v", txHash)

			return nil
		}
	}
}
