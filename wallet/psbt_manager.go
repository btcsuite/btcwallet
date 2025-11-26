// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
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
