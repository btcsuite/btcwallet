// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// ErrUtxoLocked is returned when a UTXO is locked.
	ErrUtxoLocked = errors.New("utxo is locked")

	// ErrChangeAddressNotManagedPubKey is returned when a change address is
	// not a managed public key address.
	ErrChangeAddressNotManagedPubKey = errors.New(
		"change address is not a managed pubkey address",
	)

	// ErrChangeIndexOutOfRange is returned when the change index is out of
	// range.
	ErrChangeIndexOutOfRange = errors.New("change index out of range")

	// ErrPacketOutputsMissing is returned when a PSBT is provided for
	// funding with no outputs.
	ErrPacketOutputsMissing = errors.New("psbt packet has no outputs")

	// ErrInputsAndPolicy is returned when a PSBT is provided with inputs,
	// but a coin selection policy is also specified.
	ErrInputsAndPolicy = errors.New(
		"cannot specify both psbt inputs and a coin selection policy",
	)

	// ErrNilFundIntent is returned when a nil FundIntent is provided.
	ErrNilFundIntent = errors.New("nil FundIntent")

	// ErrNoPsbtsToCombine is returned when no PSBTs are provided to
	// combine.
	ErrNoPsbtsToCombine = errors.New("no psbts to combine")

	// ErrDifferentTransactions is returned when PSBTs do not refer to the
	// same transaction.
	ErrDifferentTransactions = errors.New(
		"psbts do not refer to the same transaction",
	)

	// ErrInputCountMismatch is returned when PSBTs have different input
	// counts.
	ErrInputCountMismatch = errors.New("input count mismatch")

	// ErrOutputCountMismatch is returned when PSBTs have different output
	// counts.
	ErrOutputCountMismatch = errors.New("output count mismatch")

	// ErrUnknownAddressType is returned when an unknown address type is
	// encountered.
	ErrUnknownAddressType = errors.New("unknown address type")

	// ErrInvalidBip32PathLength is returned when a BIP32 path does not
	// have the expected length of 5.
	ErrInvalidBip32PathLength = errors.New("invalid BIP32 path length")

	// ErrUnknownBip32Purpose is returned when a BIP32 path has a purpose
	// that is not supported by the wallet.
	ErrUnknownBip32Purpose = errors.New("unknown BIP32 purpose")

	// ErrUnsupportedTaprootLeafCount is returned when a Taproot derivation
	// info contains an unsupported number of leaf hashes (e.g. > 1).
	ErrUnsupportedTaprootLeafCount = errors.New("unsupported number of " +
		"leaf hashes in Taproot derivation")

	// ErrMissingTaprootLeafScript is returned when a Taproot derivation
	// specifies a leaf hash but the corresponding Taproot leaf script is
	// missing from the PSBT.
	ErrMissingTaprootLeafScript = errors.New("specified leaf hash in " +
		"taproot BIP0032 derivation but missing taproot leaf script")

	// ErrTaprootLeafHashMismatch is returned when the calculated hash of
	// the provided Taproot leaf script does not match the leaf hash
	// specified in the derivation info.
	ErrTaprootLeafHashMismatch = errors.New("specified leaf hash in " +
		"taproot BIP0032 derivation but corresponding taproot leaf " +
		"script was not found")

	// ErrUnsupportedMultipleTaprootDerivation is returned when a Taproot
	// input has multiple derivation paths, which is not supported.
	ErrUnsupportedMultipleTaprootDerivation = errors.New(
		"unsupported multiple taproot BIP0032 derivation info found",
	)

	// ErrUnsupportedMultipleBip32Derivation is returned when a BIP32
	// input has multiple derivation paths, which is not supported.
	ErrUnsupportedMultipleBip32Derivation = errors.New(
		"unsupported multiple BIP0032 derivation info found",
	)

	// ErrAmbiguousDerivation is returned when an input has both Taproot and
	// BIP32 derivation information, which is an ambiguous state.
	ErrAmbiguousDerivation = errors.New(
		"both Taproot and BIP32 derivation info found",
	)

	// ErrInvalidTaprootMerkleRootLength is returned when the Taproot
	// Merkle Root has an invalid length.
	ErrInvalidTaprootMerkleRootLength = errors.New(
		"invalid taproot merkle root length",
	)

	// ErrInvalidBip32PathElementHardened is returned when a BIP32 path
	// element that should be hardened is not.
	ErrInvalidBip32PathElementHardened = errors.New(
		"invalid BIP32 derivation path, element must be hardened",
	)

	// ErrInvalidBip32DerivationCoinType is returned when the coin type in
	// a BIP32 derivation path does not match the wallet's chain parameters.
	ErrInvalidBip32DerivationCoinType = errors.New(
		"invalid BIP32 derivation path, coin type mismatch",
	)

	// ErrSighashMismatch is returned when merging PSBTs with conflicting
	// sighash types.
	ErrSighashMismatch = errors.New("sighash type mismatch")

	// ErrRedeemScriptMismatch is returned when merging PSBTs with
	// conflicting redeem scripts.
	ErrRedeemScriptMismatch = errors.New("redeem script mismatch")

	// ErrWitnessScriptMismatch is returned when merging PSBTs with
	// conflicting witness scripts.
	ErrWitnessScriptMismatch = errors.New("witness script mismatch")

	// ErrFinalScriptSigMismatch is returned when merging PSBTs with
	// conflicting final script sigs.
	ErrFinalScriptSigMismatch = errors.New("final script sig mismatch")

	// ErrFinalScriptWitnessMismatch is returned when merging PSBTs with
	// conflicting final script witnesses.
	ErrFinalScriptWitnessMismatch = errors.New("final script witness " +
		"mismatch")

	// ErrTaprootKeySpendSigMismatch is returned when merging PSBTs with
	// conflicting Taproot key spend signatures.
	ErrTaprootKeySpendSigMismatch = errors.New("taproot key spend sig " +
		"mismatch")

	// ErrWitnessUtxoMismatch is returned when merging PSBTs with
	// conflicting witness UTXOs.
	ErrWitnessUtxoMismatch = errors.New("witness utxo mismatch")

	// ErrNonWitnessUtxoMismatch is returned when merging PSBTs with
	// conflicting non-witness UTXOs.
	ErrNonWitnessUtxoMismatch = errors.New("non-witness utxo mismatch")

	// ErrTaprootInternalKeyMismatch is returned when merging PSBTs with
	// conflicting Taproot internal keys.
	ErrTaprootInternalKeyMismatch = errors.New("taproot internal key " +
		"mismatch")

	// ErrImportedAddrNoDerivation is returned when trying to add output
	// info for an imported address that has no derivation path.
	ErrImportedAddrNoDerivation = errors.New("change addr is an " +
		"imported addr with unknown derivation path")

	// ErrNilSignPsbtParams is returned when nil SignPsbtParams are
	// provided.
	ErrNilSignPsbtParams = errors.New("nil SignPsbtParams")

	// ErrPsbtInputIndexOutOfBounds is returned when an input index is out
	// of bounds.
	ErrPsbtInputIndexOutOfBounds = errors.New("psbt input index out of " +
		"bounds")

	// ErrInputMissingUtxoInfo is returned when an input lacks both
	// WitnessUtxo and NonWitnessUtxo.
	ErrInputMissingUtxoInfo = errors.New("input missing both " +
		"WitnessUtxo and NonWitnessUtxo")

	// ErrUnsignedTxInputIndexOutOfBounds is returned when an input index
	// is out of bounds for the unsigned transaction.
	ErrUnsignedTxInputIndexOutOfBounds = errors.New("psbt input index " +
		"out of bounds for UnsignedTx inputs")

	// ErrPrevOutIndexOutOfBounds is returned when a previous output index
	// is out of bounds for the NonWitnessUtxo.
	ErrPrevOutIndexOutOfBounds = errors.New("prevOut index out of " +
		"bounds for NonWitnessUtxo")

	// errAlreadySigned is returned when an input is already signed.
	//
	// NOTE: This error is private because it is used for internal control
	// flow within the signing loop (to skip inputs) and should not be
	// returned to the caller.
	errAlreadySigned = errors.New("input already signed")

	// errComputeRawSig is returned when the wallet cannot produce a
	// signature for the input (e.g. key not found, signing error).
	//
	// NOTE: This error is private because it is used for internal control
	// flow (skipping inputs that don't belong to this wallet) and should
	// not be exposed to the caller.
	errComputeRawSig = errors.New("cannot compute raw signature")
)

const (
	// BIP32PathLength is the expected length of a BIP32 derivation path. A
	// full path follows the structure:
	// m / purpose' / coin_type' / account' / branch / index.
	BIP32PathLength = 5
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

// FundPsbt performs coin selection and funds the PSBT.
//
// It executes the funding logic by:
//  1. Validation: Checking the `FundIntent` for consistency.
//  2. Creation: Converting the intent into a `TxIntent` and delegating to the
//     `CreateTransaction` method (which handles the underlying coin selection
//     and change calculation algorithms).
//  3. Population: Calling `populatePsbtPacket` to apply the selected inputs and
//     change output to the PSBT structure and sort it according to BIP 69.
func (w *Wallet) FundPsbt(ctx context.Context, intent *FundIntent) (
	*psbt.Packet, int32, error) {

	// Validate the funding intent before proceeding.
	err := w.validateFundIntent(intent)
	if err != nil {
		return nil, 0, err
	}

	// Create a TxIntent from the FundIntent.
	txIntent := w.createTxIntent(intent)

	// Create the transaction.
	authoredTx, err := w.CreateTransaction(ctx, txIntent)
	if err != nil {
		return nil, 0, err
	}

	// Populate the PSBT packet with the new transaction details.
	packet, changeIndex, err := w.populatePsbtPacket(
		ctx, intent.Packet, authoredTx,
	)
	if err != nil {
		return nil, 0, err
	}

	return packet, changeIndex, nil
}

// populatePsbtPacket updates the PSBT packet with the new transaction details,
// decorates the inputs, and handles the change output. It returns the modified
// packet and the index of the change output, or -1 if no change output was
// added.
func (w *Wallet) populatePsbtPacket(ctx context.Context, packet *psbt.Packet,
	authoredTx *txauthor.AuthoredTx) (*psbt.Packet, int32, error) {

	// The authored transaction contains the selected inputs and the change
	// output (if any). We'll update the PSBT packet with this new
	// unsigned transaction.
	packet.UnsignedTx = authoredTx.Tx

	// We'll also re-initialize the input and output slices to match the
	// dimensions of the new transaction. This is crucial because the
	// `authoredTx` may have a different output order than the original PSBT
	// (e.g., due to change output randomization in txauthor.AuthoredTx),
	// which would otherwise cause a misalignment between the wire outputs
	// and the PSBT's output metadata. By resetting, we ensure consistency.
	packet.Inputs = make([]psbt.PInput, len(authoredTx.Tx.TxIn))
	packet.Outputs = make([]psbt.POutput, len(authoredTx.Tx.TxOut))

	// With the new inputs in place, we'll decorate them with UTXO and
	// derivation information from the wallet. We set `skipUnknown` to
	// false because all inputs in the `authoredTx` must be known to the
	// wallet.
	_, err := w.DecorateInputs(ctx, packet, false)
	if err != nil {
		return nil, 0, err
	}

	// If a change output was created, we need to add its derivation
	// information to the corresponding PSBT output.
	var changeOutput *wire.TxOut
	if authoredTx.ChangeIndex >= 0 {
		err := w.addChangeOutputInfo(ctx, packet, authoredTx)
		if err != nil {
			return nil, 0, err
		}

		changeOutput = authoredTx.Tx.TxOut[authoredTx.ChangeIndex]
	}

	// The PSBT specification recommends that inputs and outputs are
	// sorted. This is done for privacy and standardization. We'll sort
	// the packet in place.
	err = psbt.InPlaceSort(packet)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot sort psbt: %w", err)
	}

	// After sorting, the original change index from `authoredTx` is no
	// longer valid. We need to find the new index of the change output in
	// the sorted list.
	changeIndex, err := findChangeIndex(changeOutput, packet)
	if err != nil {
		return nil, 0, err
	}

	return packet, changeIndex, nil
}

// addChangeOutputInfo is a helper function that adds the derivation information
// for a change output to a PSBT packet.
func (w *Wallet) addChangeOutputInfo(ctx context.Context, packet *psbt.Packet,
	authoredTx *txauthor.AuthoredTx) error {

	// TODO(yy): The calls to `w.ScriptForOutput` and `w.AddressInfo` both
	// involve database lookups. This could be optimized to a single
	// database call to fetch all necessary address information. However,
	// for now, this approach favors readability over micro-optimization,
	// as this path is not performance-critical.
	//
	// First, we'll get the script information for the change output.
	changeScriptInfo, err := w.ScriptForOutput(
		ctx, *authoredTx.Tx.TxOut[authoredTx.ChangeIndex],
	)
	if err != nil {
		return err
	}

	// Then, we'll get the managed address for the change output.
	changeAddr, err := w.AddressInfo(ctx, changeScriptInfo.Addr.Address())
	if err != nil {
		return err
	}

	// We'll ensure that the change address is a public key address.
	managedPubKeyAddr, ok := changeAddr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return ErrChangeAddressNotManagedPubKey
	}

	// With the managed address, we can now create the PSBT output
	// information.
	changeOutputInfo, err := createOutputInfo(
		authoredTx.Tx.TxOut[authoredTx.ChangeIndex],
		managedPubKeyAddr,
	)
	if err != nil {
		return err
	}

	// Finally, we'll add the change output information to the PSBT packet.
	packet.Outputs[authoredTx.ChangeIndex] = *changeOutputInfo

	return nil
}

// validateFundIntent performs a series of checks on a FundIntent to ensure it
// is well-formed and unambiguous. This function is called before any funding
// logic to ensure that the caller has provided a valid intent.
//
// The following checks are performed:
//  1. The intent must not be nil.
//  2. The PSBT packet must not be nil.
//  3. If the PSBT has no inputs (automatic coin selection mode), it must have
//     at least one output.
//  4. If the PSBT has inputs, a coin selection policy must not be specified
//     (mutual exclusivity).
func (w *Wallet) validateFundIntent(intent *FundIntent) error {
	// The intent must not be nil.
	if intent == nil {
		return ErrNilFundIntent
	}

	// The PSBT packet must not be nil.
	if intent.Packet == nil {
		return fmt.Errorf(
			"%w: psbt packet cannot be nil", ErrNilTxIntent,
		)
	}

	// If the PSBT has no inputs (automatic coin selection mode), it must
	// have at least one output.
	if len(intent.Packet.UnsignedTx.TxIn) == 0 &&
		len(intent.Packet.UnsignedTx.TxOut) == 0 {

		return ErrPacketOutputsMissing
	}

	// If the PSBT has inputs, a coin selection policy must not be
	// specified (mutual exclusivity).
	if len(intent.Packet.UnsignedTx.TxIn) > 0 && intent.Policy != nil {
		return ErrInputsAndPolicy
	}

	return nil
}

// findChangeIndex finds the new index of the change output after the PSBT has
// been sorted.
func findChangeIndex(changeOutput *wire.TxOut,
	packet *psbt.Packet) (int32, error) {

	if changeOutput == nil {
		return -1, nil
	}

	for i, txOut := range packet.UnsignedTx.TxOut {
		if i > math.MaxInt32 {
			return 0, ErrChangeIndexOutOfRange
		}

		if psbt.TxOutsEqual(changeOutput, txOut) {
			// The above check ensures that the conversion to int32
			// is safe.
			//
			//nolint:gosec
			return int32(i), nil
		}
	}

	return -1, nil
}

// createTxIntent creates a TxIntent from a FundIntent. This helper function
// acts as a pure adapter, translating the high-level funding request into a
// concrete transaction creation plan for the wallet's underlying `TxCreator`.
//
// It does not perform any database lookups or validation. Instead, it relies
// on the API contract that the caller must provide a fully specified
// `InputsPolicy` (with both `AccountName` and `KeyScope`) if automatic coin
// selection is desired. The underlying `TxCreator` is responsible for
// validating the existence of the specified account.
//
// The function is responsible for two main pieces of logic:
//  1. Input Source Determination: It inspects the incoming PSBT. If it has no
//     inputs, it uses the `InputsPolicy` from the intent. If it has inputs,
//     it creates an `InputsManual` source.
//  2. Change Source Mapping: It directly maps the `FundIntent.ChangeSource`
//     to `TxIntent.ChangeSource`. Any default change source determination
//     (e.g., when `FundIntent.ChangeSource` is `nil`) is delegated to the
//     underlying `TxCreator`'s `determineChangeSource` method.
func (w *Wallet) createTxIntent(intent *FundIntent) *TxIntent {
	// First, we'll copy the outputs from the PSBT packet to the TxIntent.
	outputs := make([]wire.TxOut, len(intent.Packet.UnsignedTx.TxOut))
	for i, txOut := range intent.Packet.UnsignedTx.TxOut {
		outputs[i] = *txOut
	}

	// The fee rate and label are passed through directly.
	txIntent := &TxIntent{
		Outputs: outputs,
		FeeRate: intent.FeeRate,
		Label:   intent.Label,
	}

	// Now, we'll determine the input source based on whether the PSBT
	// packet already contains inputs.
	if len(intent.Packet.UnsignedTx.TxIn) == 0 {
		// If the packet has no inputs, we'll use the policy-based input
		// source from the intent. This will trigger automatic coin
		// selection by the wallet. The caller is responsible for
		// providing a complete `ScopedAccount` with both `AccountName`
		// and `KeyScope`.
		txIntent.Inputs = intent.Policy
	} else {
		// If the packet already has inputs, we'll use a manual input
		// source. This bypasses coin selection and tells the wallet to
		// use the exact inputs provided in the PSBT.
		utxos := make(
			[]wire.OutPoint, len(intent.Packet.UnsignedTx.TxIn),
		)
		for i, txIn := range intent.Packet.UnsignedTx.TxIn {
			utxos[i] = txIn.PreviousOutPoint
		}

		txIntent.Inputs = &InputsManual{
			UTXOs: utxos,
		}
	}

	// The change source is directly mapped from the FundIntent. If it is
	// nil, the underlying `TxCreator` will determine a default.
	txIntent.ChangeSource = intent.ChangeSource

	return txIntent
}

// parseBip32Path parses a raw BIP32 derivation path (slice of uint32) into a
// strongly-typed structure containing the key scope and specific derivation
// components (Account, Branch, Index).
//
// It enforces the following wallet-specific constraints (based on BIP44/49/84
// conventions):
//  1. Path length must be exactly 5.
//  2. First 3 elements must be hardened.
//  3. Coin type must match the wallet's chain parameters.
//
// NOTE: While the underlying cryptographic derivation is defined by BIP32, the
// specific requirement for a 5-level path with hardened prefixes is strictly a
// convention of the BIP44/49/84/86 standards, not a constraint of BIP32
// itself.
//
// Returns `ErrInvalidBip32Path` if the path is invalid.
func (w *Wallet) parseBip32Path(path []uint32) (BIP32Path, error) {
	// The BIP32 path must have exactly 5 elements:
	// m / purpose' / coin_type' / account' / branch / index
	if len(path) != BIP32PathLength {
		return BIP32Path{}, fmt.Errorf("%w: %d",
			ErrInvalidBip32PathLength, len(path))
	}

	// The first 3 elements (Purpose, CoinType, Account) must be hardened.
	// We check this by verifying they are >= HardenedKeyStart.
	for i := range 3 {
		if path[i] < hdkeychain.HardenedKeyStart {
			return BIP32Path{}, fmt.Errorf("%w: element %d",
				ErrInvalidBip32PathElementHardened, i)
		}
	}

	// Helper to extract values (remove hardened flag).
	purpose := path[0] - hdkeychain.HardenedKeyStart
	coinType := path[1] - hdkeychain.HardenedKeyStart
	account := path[2] - hdkeychain.HardenedKeyStart
	branch := path[3]
	index := path[4]

	// Verify that the coin type matches the wallet's chain parameters.
	if coinType != w.chainParams.HDCoinType {
		return BIP32Path{}, fmt.Errorf("%w: expected %d, got %d",
			ErrInvalidBip32DerivationCoinType,
			w.chainParams.HDCoinType, coinType)
	}

	scope := waddrmgr.KeyScope{
		Purpose: purpose,
		Coin:    coinType,
	}

	bip32Path := BIP32Path{
		KeyScope: scope,
		DerivationPath: waddrmgr.DerivationPath{
			Account: account,
			Branch:  branch,
			Index:   index,
		},
	}

	return bip32Path, nil
}

// addressTypeFromPurpose maps a BIP purpose to a wallet address type.
func addressTypeFromPurpose(purpose uint32) (waddrmgr.AddressType, error) {
	// TODO(yy): Currently, we hardcode the supported BIP purposes.
	// A more robust solution would dynamically query the `waddrmgr` to
	// determine supported key scopes configured in the database, allowing
	// for custom purposes (e.g., LND's 1017 purpose key) to be seamlessly
	// supported without code changes here.
	switch purpose {
	case waddrmgr.KeyScopeBIP0044.Purpose:
		return waddrmgr.PubKeyHash, nil

	case waddrmgr.KeyScopeBIP0049Plus.Purpose:
		return waddrmgr.NestedWitnessPubKey, nil

	case waddrmgr.KeyScopeBIP0084.Purpose:
		return waddrmgr.WitnessPubKey, nil

	case waddrmgr.KeyScopeBIP0086.Purpose:
		return waddrmgr.TaprootPubKey, nil

	default:
		return 0, fmt.Errorf("%w: %d", ErrUnknownBip32Purpose, purpose)
	}
}

// shouldSkipInput determines whether the input at the given index should be
// skipped during the signing process.
//
// It checks for two conditions:
//  1. If the input already has a final script witness, it is considered
//     complete and is skipped.
//  2. If the input lacks any derivation information (both Taproot and BIP32),
//     it implies that the wallet does not have the key to sign it, so it is
//     skipped.
func shouldSkipInput(pInput *psbt.PInput, idx int) bool {
	// Skip if already finalized.
	if len(pInput.FinalScriptWitness) > 0 {
		log.Debugf("Skipping input %d: already has final "+
			"script witness", idx)

		return true
	}

	// Check if we have any derivation info.
	tapCount := len(pInput.TaprootBip32Derivation)
	bip32Count := len(pInput.Bip32Derivation)

	if tapCount == 0 && bip32Count == 0 {
		// No derivation info, so we can't sign this input. We skip it
		// silently, assuming it's not ours or not meant to be signed
		// by us.
		log.Debugf("Skipping input %d: no derivation info", idx)

		return true
	}

	return false
}

// shouldSkipSigningError determines whether a signing error should be skipped
// (logged and ignored) or returned as a fatal error.
//
// It handles cases typical in collaborative workflows where an input might
// belong to another signer, already be signed, or use an unknown derivation
// scheme.
func shouldSkipSigningError(err error, idx int) bool {
	// If the input is already signed, we can just skip it.
	if errors.Is(err, errAlreadySigned) {
		log.Debugf("Skipping input %d: already signed", idx)
		return true
	}

	// In a collaborative PSBT workflow, the transaction may contain inputs
	// that belong to other parties. Even if a derivation path is present
	// and valid (e.g. BIP-84), it might correspond to a different signer's
	// key (same path, different seed).
	//
	// If we encounter `errComputeRawSig`, it means we failed to produce a
	// signature. This usually happens because we don't have the private
	// key for the derived address (it's someone else's input). In this
	// case, we skip the input and log a debug message, allowing us to
	// proceed and sign the inputs that we DO own.
	if errors.Is(err, errComputeRawSig) {
		log.Debugf("Skipping input %d: %v", idx, err)
		return true
	}

	// If the derivation path has an unknown purpose, it likely belongs to
	// another signer or a scheme we don't support. We skip these as well.
	if errors.Is(err, ErrUnknownBip32Purpose) {
		log.Debugf("Skipping input %d: unknown BIP32 purpose", idx)
		return true
	}

	return false
}

// validateDerivation inspects the derivation information for the input and
// ensures it conforms to the supported signing modes.
//
// It enforces the following rules:
//  1. Only one derivation path per type is supported.
//  2. Taproot and BIP32 derivation information cannot be present
//     simultaneously. This avoids ambiguity about which signing path to take.
//
// It returns a boolean indicating whether the input is a Taproot input (true)
// or a legacy/SegWit input (false), and an error if the validation fails.
func validateDerivation(pInput *psbt.PInput, idx int) (bool, error) {
	tapCount := len(pInput.TaprootBip32Derivation)
	bip32Count := len(pInput.Bip32Derivation)

	if tapCount > 1 {
		return false, fmt.Errorf("input %d: %w", idx,
			ErrUnsupportedMultipleTaprootDerivation)
	}

	if bip32Count > 1 {
		return false, fmt.Errorf("input %d: %w", idx,
			ErrUnsupportedMultipleBip32Derivation)
	}

	if tapCount == 1 && bip32Count == 1 {
		// This is ambiguous/invalid state in the PSBT.
		return false, fmt.Errorf("input %d: %w", idx,
			ErrAmbiguousDerivation)
	}

	// If we have Taproot info, it's a Taproot input.
	return tapCount == 1, nil
}

// fetchPsbtUtxo extracts the UTXO for the given input index from the PSBT
// packet. It prioritizes the WitnessUtxo if present, otherwise falls back to
// the NonWitnessUtxo.
//
// NOTE: While psbt.InputsReadyToSign guarantees that at least one of these
// fields is set, this function performs additional checks and returns an error
// if the UTXO information is missing or the index is out of bounds, preventing
// panics on malformed packets.
func fetchPsbtUtxo(packet *psbt.Packet, idx int) (*wire.TxOut, error) {
	if idx >= len(packet.Inputs) {
		return nil, fmt.Errorf("%w: %d",
			ErrPsbtInputIndexOutOfBounds, idx)
	}

	pInput := &packet.Inputs[idx]

	if pInput.WitnessUtxo != nil {
		return pInput.WitnessUtxo, nil
	}

	if pInput.NonWitnessUtxo == nil {
		return nil, fmt.Errorf("%w: %d",
			ErrInputMissingUtxoInfo, idx)
	}

	if idx >= len(packet.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("%w: %d",
			ErrUnsignedTxInputIndexOutOfBounds, idx)
	}

	prevIdx := packet.UnsignedTx.TxIn[idx].PreviousOutPoint.Index

	if int(prevIdx) >= len(pInput.NonWitnessUtxo.TxOut) {
		return nil, fmt.Errorf("%w: input %d prevOut index %d",
			ErrPrevOutIndexOutOfBounds, idx, prevIdx)
	}

	return pInput.NonWitnessUtxo.TxOut[prevIdx], nil
}

// checkTaprootScriptSpendSig checks if a Taproot script-path signature already
// exists for the given input and derivation details. It returns
// errAlreadySigned, if a matching signature is found, otherwise nil.
func checkTaprootScriptSpendSig(pInput *psbt.PInput,
	tapDerivation *psbt.TaprootBip32Derivation) error {

	for _, sig := range pInput.TaprootScriptSpendSig {
		if bytes.Equal(
			sig.XOnlyPubKey, tapDerivation.XOnlyPubKey,
		) && bytes.Equal(
			sig.LeafHash, tapDerivation.LeafHashes[0],
		) {

			return errAlreadySigned
		}
	}

	return nil
}

// addTaprootSigToPInput adds the generated signature to the PSBT input.
//
// NOTE: This method modifies the `pInput` in-place.
func addTaprootSigToPInput(pInput *psbt.PInput, sig []byte,
	sighashType txscript.SigHashType, details TaprootSpendDetails,
	tapDerivation *psbt.TaprootBip32Derivation) {

	if details.SpendPath == KeyPathSpend {
		if sighashType != txscript.SigHashDefault {
			sig = append(sig, byte(sighashType))
		}

		pInput.TaprootKeySpendSig = sig
	} else {
		tsSig := &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: tapDerivation.XOnlyPubKey,
			LeafHash:    tapDerivation.LeafHashes[0],
			Signature:   sig,
			SigHash:     pInput.SighashType,
		}
		pInput.TaprootScriptSpendSig = append(
			pInput.TaprootScriptSpendSig, tsSig,
		)
	}
}

// addBip32SigToPInput adds the generated signature to the PSBT input for
// non-Taproot (Legacy/SegWit) inputs.
//
// NOTE: This method modifies the `pInput` in-place.
func addBip32SigToPInput(pInput *psbt.PInput, sig []byte,
	sighashType txscript.SigHashType, derivation *psbt.Bip32Derivation,
	addrType waddrmgr.AddressType) {

	// Append sighash type if needed (SegWit v0).
	if addrType == waddrmgr.NestedWitnessPubKey ||
		addrType == waddrmgr.WitnessPubKey {

		sig = append(sig, byte(sighashType))
	}

	pInput.PartialSigs = append(pInput.PartialSigs,
		&psbt.PartialSig{
			PubKey:    derivation.PubKey,
			Signature: sig,
		},
	)
}
