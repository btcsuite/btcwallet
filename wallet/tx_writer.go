// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// MaxTxLabelLength is the longest transaction label the wallet stores,
// measured in bytes.
//
// Every store enforces a limit of its own, but not the same one: the legacy
// kvdb store counts bytes while the SQL schemas constrain characters. Counting
// bytes here is the stricter reading, so a label this API accepts satisfies
// every store and no backend constraint can reject a label the wallet already
// approved. Those constraints remain as defence in depth.
const MaxTxLabelLength = 500

var (
	// ErrLabelTooLong is returned when a transaction label exceeds
	// MaxTxLabelLength. Callers can match this error with errors.Is.
	ErrLabelTooLong = errors.New("transaction label exceeds limit")

	// ErrTxNotUnconfirmed is returned when DeleteUnconfirmedTx targets a tx
	// that is confirmed or coinbase. Callers can match this error with
	// errors.Is.
	ErrTxNotUnconfirmed = errors.New("tx is not an unconfirmed transaction")
)

// TxWriter provides an interface for updating wallet txns.
type TxWriter interface {
	// LabelTx adds a label to a tx. If a label already exists, it will be
	// overwritten, and an empty label clears any existing one. Labels
	// longer than MaxTxLabelLength bytes are rejected with
	// ErrLabelTooLong.
	LabelTx(ctx context.Context, hash chainhash.Hash, label string) error

	// DeleteUnconfirmedTx removes an unconfirmed tx and every recorded tx
	// that spends it, restoring the wallet outputs they spent. It returns
	// ErrTxNotFound if the wallet has no active unconfirmed record of the
	// tx, which includes a tx an earlier event already made terminal, and
	// ErrTxNotUnconfirmed if the tx is confirmed or coinbase. A terminal tx
	// reported as not found may still be readable through GetTx. No history
	// is retained.
	DeleteUnconfirmedTx(ctx context.Context, hash chainhash.Hash) error
}

// A compile time check to ensure that Wallet implements the interface.
var _ TxWriter = (*Wallet)(nil)

// labelTxReq keeps the value label and hash joined through Store completion.
type labelTxReq struct {
	reqCtx

	hash        chainhash.Hash
	label       string
	respErrChan chan error
}

// LabelTx adds a label to a tx. If a label already exists, it will be
// overwritten, and an empty label clears any existing one. Labels longer than
// MaxTxLabelLength bytes are rejected with ErrLabelTooLong.
//
// NOTE: This method is part of the TxWriter interface.
func (w *Wallet) LabelTx(ctx context.Context,
	hash chainhash.Hash, label string) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	// Reject an oversized label here rather than letting each store report
	// its own constraint violation, which is how the same rejection reached
	// callers as three unrelated errors.
	if len(label) > MaxTxLabelLength {
		return fmt.Errorf("%w: %d bytes, limit is %d", ErrLabelTooLong,
			len(label), MaxTxLabelLength)
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := labelTxReq{
		reqCtx:      reqCtx{ctx: ctx},
		hash:        hash,
		label:       label,
		respErrChan: make(chan error, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	return <-r.respErrChan
}

// handleLabelTx updates the label under an already accepted request's
// ownership.
// The admitted caller waits for this result before reusing its inputs.
func (w *Wallet) handleLabelTx(r labelTxReq) {
	err := w.store.UpdateTx(r.ctx, db.UpdateTxParams{
		WalletID: w.id,
		Txid:     r.hash,
		Label:    &r.label,
	})
	if err != nil {
		if errors.Is(err, db.ErrTxNotFound) {
			r.respErrChan <- fmt.Errorf("update tx label: %w", ErrTxNotFound)

			return
		}

		r.respErrChan <- fmt.Errorf("update tx label: %w", err)

		return
	}

	r.respErrChan <- nil
}

// deleteUnconfirmedTxReq keeps the root hash joined through Store completion.
type deleteUnconfirmedTxReq struct {
	reqCtx

	hash        chainhash.Hash
	respErrChan chan error
}

// DeleteUnconfirmedTx removes an unconfirmed tx and every tx the wallet
// recorded as spending it, and restores the wallet outputs that branch spent.
// The removal is atomic, and no history is retained: a tx the chain later
// confirms is recorded again by synchronization.
//
// It returns ErrTxNotFound if the wallet has no active unconfirmed record of
// the tx, which includes a tx an earlier event already made terminal, and
// ErrTxNotUnconfirmed if the tx is confirmed or coinbase. A terminal tx
// reported as not found may still be readable through GetTx.
//
// NOTE: This method is part of the TxWriter interface.
func (w *Wallet) DeleteUnconfirmedTx(ctx context.Context,
	hash chainhash.Hash) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := deleteUnconfirmedTxReq{
		reqCtx:      reqCtx{ctx: ctx},
		hash:        hash,
		respErrChan: make(chan error, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	return <-r.respErrChan
}

// handleDeleteUnconfirmedTx removes the branch under an already accepted
// request's ownership and maps Store rejections to wallet identities.
func (w *Wallet) handleDeleteUnconfirmedTx(r deleteUnconfirmedTxReq) {
	err := w.store.DeleteUnminedTx(r.ctx, db.DeleteUnminedTxParams{
		WalletID: w.id,
		Txid:     r.hash,
	})

	switch {
	case err == nil:
		r.respErrChan <- nil

	case errors.Is(err, db.ErrTxNotFound):
		r.respErrChan <- fmt.Errorf("delete unconfirmed tx %v: %w", r.hash,
			ErrTxNotFound)

	// The Store's message already names the tx and its state.
	case errors.Is(err, db.ErrDeleteRequiresUnmined):
		r.respErrChan <- fmt.Errorf("%w: %s", ErrTxNotUnconfirmed,
			err.Error())

	default:
		r.respErrChan <- fmt.Errorf("delete unconfirmed tx %v: %w", r.hash,
			err)
	}
}
