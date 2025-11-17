// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// ErrUtxoLocked is returned when a UTXO is locked.
	ErrUtxoLocked = errors.New("utxo is locked")
)

// FundIntent represents the user's intent for funding a PSBT. It serves as a
// blueprint for the FundPsbt method, bundling all the parameters required to
// construct a funded transaction into a single, coherent structure.
type FundIntent struct {
	// Packet is the PSBT to be funded. It must contain the outputs to be
	// funded. If inputs are also specified, the wallet will detect this and
	// enter a "completion" mode, where it only adds a change output if
	// necessary, rather than performing full coin selection.
	Packet *psbt.Packet

	// Policy specifies the coin selection policy to use when funding the
	// PSBT. This field is only used when the `Packet` has no inputs,
	// indicating that automatic coin selection should be performed. If this
	// policy is used, the `Source` (`*ScopedAccount`) must be fully
	// specified with both `AccountName` and `KeyScope`, as the wallet will
	// not perform any searches or guesses. If the `Packet` already
	// contains inputs, this field is ignored.
	Policy *InputsPolicy

	// FeeRate specifies the desired fee rate for the transaction, expressed
	// in satoshis per kilo-virtual-byte (sat/kvb). This field is always
	// required, regardless of whether coin selection is performed.
	FeeRate btcunit.SatPerKVByte

	// ChangeSource specifies the account and key scope to use for the
	// change output. If this field is nil, the wallet will use a default
	// change source based on the account and scope of the inputs.
	ChangeSource *ScopedAccount

	// Label is an optional, human-readable label for the transaction. This
	// can be used to associate a memo with the transaction for later
	// reference.
	Label string
}

// SignPsbtParams encapsulates the arguments for signing a PSBT.
type SignPsbtParams struct {
	// Packet is the PSBT to be signed.
	Packet *psbt.Packet

	// InputTweakers is a map of input indices to a private key tweaker.
	// This allows the caller to define a specific tweaker for each input
	// index.
	//
	// NOTE: The ideal implementation would be to add a new field to
	// psbt.PInput that holds the tweaker, but that would require a change
	// to the core psbt package in btcd. To keep btcwallet generic and avoid
	// that dependency, we allow the caller (e.g. lnd) to inspect the PSBT
	// beforehand, determine the necessary tweaks (e.g. based on custom
	// fields like PsbtKeyTypeInputSignatureTweakSingle), and pass them in
	// via this map.
	InputTweakers map[int]PrivKeyTweaker
}

// SignPsbtResult encapsulates the result of a PSBT signing operation.
type SignPsbtResult struct {
	// SignedInputs contains the indices of the inputs that were
	// successfully signed.
	SignedInputs []uint32

	// Packet is the modified PSBT packet. This is the same pointer as
	// passed in the params, returned for convenience.
	Packet *psbt.Packet
}

// PsbtManager provides a cohesive, high-level interface for creating and
// managing Partially Signed Bitcoin Transactions (PSBTs). It encapsulates the
// entire workflow, from funding and decorating to signing and finalization,
// allowing users to construct complex transactions in a safe and predictable
// manner.
//
// The typical workflow for a single-signer transaction is as follows:
//
// 1. Create a bare PSBT:
// A stateless helper function, CreatePsbt, is used to construct a PSBT
// packet from a list of desired inputs and outputs.
//
//	// The user specifies their desired outputs.
//	outputs := []*wire.TxOut{{Value: 100000, PkScript: carolPkScript}}
//
//	// A bare PSBT is created, representing the transaction template.
//	barePacket, err := wallet.CreatePsbt(nil, outputs)
//
// 2. Fund the PSBT:
// The FundPsbt method is called to perform coin selection. The wallet selects
// UTXOs to cover the output value and fee, adds them as inputs, and adds a
// change output if necessary.
//
//	fundIntent := &wallet.FundIntent{
//	    Packet: barePacket,
//	    Policy: &wallet.InputsPolicy{
//	        Source: &wallet.ScopedAccount{
//	            AccountName: "default",
//	            KeyScope:    waddrmgr.KeyScopeBIP0086,
//	        },
//	        MinConfs: 1,
//	    },
//	    FeeRate: btcunit.NewSatPerKVByte(250),
//	}
//	fundedPacket, changeIndex, err := psbtManager.FundPsbt(
//		ctx, fundIntent,
//	)
//
// The `fundedPacket` now contains the necessary inputs (fully decorated)
// and a change output. The `changeIndex` indicates the index of the
// change output in the `fundedPacket.UnsignedTx.TxOut` slice, or -1 if
// no change output was added.
//
// 3. Sign the PSBT:
// The wallet signs all inputs it has the keys for.
//
//	signParams := &wallet.SignPsbtParams{Packet: barePacket}
//	result, err := psbtManager.SignPsbt(ctx, signParams)
//
// 4. Finalize the PSBT:
// The final scriptSig and/or witness for each input is constructed.
//
//	err = psbtManager.FinalizePsbt(ctx, barePacket)
//
// 5. Extract and Broadcast:
// The final, network-ready transaction is extracted and broadcast.
//
//	finalTx, err := psbt.Extract(barePacket)
//	err = broadcaster.Broadcast(ctx, finalTx, "payment")
//
// For more detailed examples, including multi-party collaborative workflows,
// see the documentation in the `wallet/docs/psbt_workflows.md` file.
type PsbtManager interface {
	// DecorateInputs enriches a PSBT's inputs with UTXO and derivation
	// information known to the wallet.
	//
	// This is useful when importing a PSBT created externally (e.g., by a
	// coordinator or another wallet) that only contains references to
	// inputs (txids/indices) but lacks the necessary witness data and key
	// derivation paths required for signing.
	//
	// If `skipUnknown` is true, the wallet will skip inputs it does not
	// recognize; otherwise, it will return an error if any input is not
	// found in the wallet's transaction store.
	DecorateInputs(ctx context.Context, packet *psbt.Packet,
		skipUnknown bool) (*psbt.Packet, error)

	// FundPsbt performs coin selection and adds the selected inputs (and a
	// change output, if necessary) to the PSBT.
	//
	// It inspects the provided `FundIntent` to determine whether to
	// perform automatic coin selection (if no inputs are present) or to
	// validate and fund a specific set of manual inputs.
	//
	// The returned PSBT is a fully funded transaction template, ready for
	// signing. The change output index is also returned (-1 if no change
	// was added).
	FundPsbt(ctx context.Context, intent *FundIntent) (*psbt.Packet,
		int32, error)

	// SignPsbt adds partial signatures to the PSBT for all inputs
	// controlled by the wallet.
	//
	// It iterates through the inputs, identifying those for which the
	// wallet possesses the private key (based on derivation information),
	// and appends a valid signature to the partial signature field.
	//
	// Note: This method is non-destructive; it adds signatures without
	// finalizing the inputs, allowing for further signing in multi-party
	// scenarios. It enforces a strict policy of one signature per input
	// per call to avoid ambiguity in complex derivation paths.
	SignPsbt(ctx context.Context, params *SignPsbtParams) (
		*SignPsbtResult, error)

	// FinalizePsbt attempts to finalize the PSBT, transitioning it from a
	// partially signed state to a complete, network-ready transaction.
	//
	// It validates that all inputs have sufficient signatures to satisfy
	// their spending scripts. If valid, it constructs the final
	// `scriptSig` and `witness` fields and removes the partial signature
	// data.
	//
	// Note: This implementation is "smart": if it detects an input owned
	// by the wallet that is not yet signed, it will attempt to sign it
	// internally before finalization.
	FinalizePsbt(ctx context.Context, packet *psbt.Packet) error

	// CombinePsbt acts as the "Combiner" role in BIP 174, merging multiple
	// Partially Signed Bitcoin Transactions (PSBTs) into a single packet.
	//
	// This is distinct from FinalizePsbt: CombinePsbt aggregates partial
	// signatures and metadata from different signers (who signed copies of
	// the same transaction in parallel), whereas FinalizePsbt uses those
	// aggregated signatures to construct the final valid network
	// transaction.
	//
	// This method is essential for collaborative workflows (e.g. Multisig,
	// CoinJoin) where no single party holds all necessary keys.
	CombinePsbt(ctx context.Context, psbts ...*psbt.Packet) (
		*psbt.Packet, error)
}

// DecorateInputs enriches a PSBT's inputs with UTXO and derivation information.
//
// It iterates through all inputs in the PSBT and:
//  1. Validates ownership: Calls `fetchAndValidateUtxo` to check if the input
//     references a UTXO owned by the wallet.
//  2. Enriches: If owned, calls `decorateInput` to add the full previous
//     transaction (`NonWitnessUtxo`) or output (`WitnessUtxo`), along with
//     BIP32 derivation paths (`Bip32Derivation` or `TaprootBip32Derivation`)
//     and script information.
func (w *Wallet) DecorateInputs(ctx context.Context, packet *psbt.Packet,
	skipUnknown bool) (*psbt.Packet, error) {

	// We'll iterate through all the inputs of the PSBT and decorate them
	// if they are owned by the wallet. The `skipUnknown` parameter
	// determines whether an error is returned if an input is not owned
	// by the wallet.
	for i, txIn := range packet.UnsignedTx.TxIn {
		// Attempt to fetch the transaction details for the current
		// input from our transaction store and validate that we own
		// the UTXO. The `fetchAndValidateUtxo` function will return an
		// `ErrNotMine` error if the UTXO is not found or not owned by
		// the wallet.
		tx, utxo, err := w.fetchAndValidateUtxo(txIn)
		if err != nil {
			// If the error is `ErrNotMine` and `skipUnknown` is
			// true, we'll simply continue to the next input, as we
			// don't own it and are not required to fail.
			if errors.Is(err, ErrNotMine) && skipUnknown {
				continue
			}

			// Otherwise, we'll return the error. This includes the
			// case where the UTXO is locked.
			return nil, err
		}

		// If we own the UTXO, we'll proceed to decorate the
		// corresponding PSBT input with detailed information from the
		// wallet.
		err = w.decorateInput(ctx, &packet.Inputs[i], tx, utxo)
		if err != nil {
			return nil, fmt.Errorf("error decorating input %d: %w",
				i, err)
		}
	}

	return packet, nil
}

// decorateInput is a helper function that decorates a single PSBT input with
// UTXO information from the wallet.
//
// NOTE: The `pInput` parameter is modified in-place by this function.
func (w *Wallet) decorateInput(ctx context.Context, pInput *psbt.PInput,
	tx *wire.MsgTx, utxo *wire.TxOut) error {

	// We'll start by extracting the address from the UTXO's pkScript.
	// This will be used to look up the managed address from the
	// database.
	addr := extractAddrFromPKScript(utxo.PkScript, w.chainParams)
	if addr == nil {
		return fmt.Errorf("%w: from pkscript %x",
			ErrUnableToExtractAddress, utxo.PkScript)
	}

	// We'll then use the address to look up the managed address from the
	// database. This will give us access to the derivation information.
	managedAddr, err := w.AddressInfo(ctx, addr)
	if err != nil {
		return fmt.Errorf("unable to get address info for %s: %w",
			addr.String(), err)
	}

	// We'll ensure that the managed address is a public key address, as
	// we can only decorate inputs for which we have the private key.
	pubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return fmt.Errorf("%w: addr %s", ErrNotPubKeyAddress,
			managedAddr.Address())
	}

	// With the managed address, we can now get the derivation information
	// for the address.
	derivation, err := derivationForManagedAddress(pubKeyAddr)
	if err != nil {
		return err
	}

	// With all the information gathered, we'll now populate the PSBT
	// input based on its address type by calling the existing, non-
	// deprecated helper functions.
	switch {
	// For SegWit v1 (Taproot) inputs, we'll use the SegWit v1 helper.
	case txscript.IsPayToTaproot(utxo.PkScript):
		addInputInfoSegWitV1(pInput, utxo, derivation)

	// For SegWit v0 inputs, we'll use the SegWit v0 helper.
	default:
		// We'll need to build the redeem script for the input.
		_, redeemScript, err := buildScriptsForManagedAddress(
			pubKeyAddr, utxo.PkScript, w.chainParams,
		)
		if err != nil {
			return err
		}

		// With the redeem script, we can now populate the PSBT
		// input.
		addInputInfoSegWitV0(
			pInput, tx, utxo, derivation, managedAddr, redeemScript,
		)
	}

	return nil
}

// fetchAndValidateUtxo fetches the transaction details for a given input,
// validates that the wallet owns the UTXO, and ensures it is not locked.
//
// This function serves as a crucial pre-check before decorating a PSBT input.
// It performs three key validation steps:
//  1. Transaction Lookup: It first attempts to fetch the full transaction
//     details from the wallet's transaction store using the input's previous
//     outpoint. If the transaction is not found, it returns an `ErrNotMine`
//     error.
//  2. Ownership Verification: If the transaction is found, it verifies that the
//     specific output index is a credit to the wallet. This ensures that the
//     wallet actually owns the UTXO. If this check fails, it also returns
//     `ErrNotMine`.
//  3. Lock Status Check: After confirming ownership, it checks if the UTXO has
//     been locked. If the UTXO is locked, it returns an `ErrUtxoLocked`
//     error.
//
// Only if all these checks pass, the function returns the full parent
// transaction (`*wire.MsgTx`) and the specific unspent transaction output
// (`*wire.TxOut`).
func (w *Wallet) fetchAndValidateUtxo(txIn *wire.TxIn) (
	*wire.MsgTx, *wire.TxOut, error) {

	// First, we'll attempt to fetch the transaction details from our
	// transaction store.
	txDetail, err := w.fetchTxDetails(&txIn.PreviousOutPoint.Hash)
	if errors.Is(err, ErrTxNotFound) {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotMine,
			txIn.PreviousOutPoint)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch tx details: %w",
			err)
	}

	// With the transaction details retrieved, we'll make an additional
	// check to ensure we actually have control of this output.
	if !findCredit(txDetail, txIn.PreviousOutPoint.Index) {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotMine,
			txIn.PreviousOutPoint)
	}

	// Now that we've confirmed we know about the UTXO, we'll check if it
	// is locked.
	if w.LockedOutpoint(txIn.PreviousOutPoint) {
		return nil, nil, fmt.Errorf("%w: %v", ErrUtxoLocked,
			txIn.PreviousOutPoint)
	}

	// Now that we've confirmed we know about the UTXO, we'll proceed to
	// gather the rest of the information required to decorate the PSBT
	// input.
	tx := &txDetail.MsgTx
	utxo := tx.TxOut[txIn.PreviousOutPoint.Index]

	return tx, utxo, nil
}

// findCredit determines whether a transaction's details contain a credit for a
// specific output index.
func findCredit(txDetail *wtxmgr.TxDetails, outputIndex uint32) bool {
	for _, cred := range txDetail.Credits {
		if cred.Index == outputIndex {
			return true
		}
	}

	return false
}
