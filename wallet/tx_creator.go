// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// ErrUnsupportedInputs is returned when the `Inputs` field of a
	// TxIntent is not of a supported type.
	ErrUnsupportedInputs = errors.New("unsupported inputs type")

	// ErrUtxoNotEligible is returned when a UTXO is not eligible to be
	// spent.
	ErrUtxoNotEligible = errors.New("utxo not eligible")

	// ErrDuplicateUtxo is returned when a UTXO is specified multiple times.
	ErrDuplicateUtxo = errors.New("duplicate utxo")

	// ErrAccountNotFound is returned when an account is not found.
	ErrAccountNotFound = errors.New("account not found")

	// ErrNoOutputs is returned when a transaction is created without any
	// outputs.
	ErrNoOutputs = errors.New("transaction has no outputs")

	// ErrInsaneFee is returned when a transaction is created with a fee
	// that is too high.
	ErrInsaneFee = errors.New("insane fee")

	// ErrNoChangeSource is returned when a change source is not provided.
	ErrNoChangeSource = errors.New("change source cannot be nil")

	// ErrMissingAccountName is returned when an account name is required but
	// not provided.
	ErrMissingAccountName = errors.New(
		"account name cannot be empty",
	)

	// ErrNoInputSource is returned when an input source is not provided.
	ErrNoInputSource = errors.New("input source cannot be nil")

	// ErrManualInputsEmpty is returned when manual inputs are specified but
	// the list is empty.
	ErrManualInputsEmpty = errors.New("manual inputs cannot be empty")

	// ErrUnsupportedCoinSource is returned when the `Source` field of a
	// CoinSelectionPolicy is not of a supported type.
	ErrUnsupportedCoinSource = errors.New("unsupported coin source type")

	// ErrMissingInputs is returned when a transaction is created without any
	// inputs.
	ErrMissingInputs = errors.New("transaction has no inputs")
)

// TxCreator provides an interface for creating transactions. Its primary role is
// to produce a fully-formed, unsigned transaction that can be passed to the
// Signer interface.
type TxCreator interface {
	// CreateTransaction creates a new, unsigned transaction based on the
	// provided intent. The resulting AuthoredTx will contain the unsigned
	// transaction and all the necessary metadata to sign it.
	CreateTransaction(ctx context.Context, intent *TxIntent) (
		*txauthor.AuthoredTx, error)
}

// SatPerKVByte is a type that represents a fee rate in satoshis per
// kilo-virtual-byte. This is the standard unit for fee estimation in modern
// Bitcoin transactions that use SegWit.
type SatPerKVByte btcutil.Amount

// TxIntent represents the user's intent to create a transaction. It serves as
// a blueprint for the TxCreator, bundling all the parameters required to
// construct a transaction into a single, coherent structure.
//
// A TxIntent can be used to create a transaction in four main ways:
//
// 1. Automatic Coin Selection from the Default Account:
// The simplest way to create a transaction is to specify only the outputs
// and the fee rate. By leaving the `Inputs` field as nil, the wallet will
// automatically select coins from the default account to fund the
// transaction.
//
// Example:
//
//	intent := &TxIntent{
//		Outputs: outputs,
//		FeeRate: feeRate,
//	}
//
// 2. Manual Input Selection:
// To have direct control over the inputs used, the caller can specify the
// exact UTXOs to spend. This is achieved by setting the `Inputs` field to
// an `InputsManual` struct, which contains a slice of the desired
// `wire.OutPoint`s. In this mode, all coin selection logic is bypassed; the
// wallet simply uses the provided inputs.
//
// Example:
//
//	intent := &TxIntent{
//		Outputs:      outputs,
//		Inputs:       &InputsManual{UTXOs: []wire.OutPoint{...}},
//		FeeRate:      feeRate,
//		ChangeSource: changeSource,
//	}
//
// 3. Policy-Based Coin Selection from an Account:
// To have the wallet select inputs from a specific account, the caller can
// specify a policy. This is achieved by setting the `Inputs` field to an
// `InputsPolicy` struct. This struct defines the strategy (e.g.,
// largest-first), the minimum number of confirmations, and the source of
// the coins. If the `Source` is a `ScopedAccount`, the wallet will select
// coins from that account. If the `Source` field is nil, the wallet will
// use a default source, typically the default account.
//
// Example:
//
//	intent := &TxIntent{
//		Outputs: outputs,
//		Inputs: &InputsPolicy{
//			Strategy: CoinSelectionLargest,
//			MinConfs: 1,
//			Source:   &ScopedAccount{AccountName: "default", ...},
//		},
//		FeeRate:      feeRate,
//		ChangeSource: changeSource,
//	}
//
// 4. Policy-Based Coin Selection from a specific set of UTXOs:
// For more advanced control, the caller can provide a specific list of UTXOs
// and have the coin selection algorithm choose the best subset from that
// list. This is useful for scenarios like coin control where the user wants
// to limit the potential inputs for a transaction. This is achieved by
// setting the `Source` of an `InputsPolicy` to a `CoinSourceUTXOs` struct.
//
// Example:
//
//	intent := &TxIntent{
//		Outputs: outputs,
//		Inputs: &InputsPolicy{
//			Strategy: CoinSelectionLargest,
//			MinConfs: 1,
//			Source:   &CoinSourceUTXOs{UTXOs: []wire.OutPoint{...}},
//		},
//		FeeRate:      feeRate,
//		ChangeSource: changeSource,
//	}
type TxIntent struct {
	// Outputs specifies the recipients and amounts for the transaction.
	// This field is required.
	Outputs []wire.TxOut

	// Inputs defines the source of the inputs for the transaction. This
	// must be one of the Inputs implementations (InputsManual or
	// InputsPolicy). This field is required.
	Inputs Inputs

	// ChangeSource specifies the destination for the transaction's change
	// output. If this field is nil, the wallet will use a default change
	// source based on the account and scope of the inputs.
	ChangeSource *ScopedAccount

	// FeeRate specifies the desired fee rate for the transaction,
	// expressed in satoshis per kilo-virtual-byte (sat/kvb). This field is
	// required.
	FeeRate SatPerKVByte

	// Label is an optional, human-readable label for the transaction. This
	// can be used to associate a memo with the transaction for later
	// reference.
	Label string
}

// Inputs is a sealed interface that defines the source of inputs for a
// transaction. It can either be a manually specified set of UTXOs or a policy
// for coin selection. The sealed interface pattern is used here to
// provide compile-time safety, ensuring that only the intended implementations
// can be used.
type Inputs interface {
	// isInputs is a marker method that is part of the sealed interface
	// pattern. It is unexported, so it can only be implemented by types
	// within this package. This ensures that only the intended types
	// can be used as an Inputs implementation.
	isInputs()

	// validate performs a series of checks on the input source to ensure
	// it is well-formed. This method is called before any database
	// transactions are opened, allowing for early, efficient validation.
	validate() error
}

// InputsManual implements the Inputs interface and specifies the exact UTXOs
// to be used as transaction inputs. When this is used, all automatic coin
// selection logic is bypassed.
type InputsManual struct {
	// UTXOs is a slice of outpoints to be used as the exact inputs for the
	// transaction. The wallet will validate that these UTXOs are known and
	// spendable but will not perform any further coin selection.
	UTXOs []wire.OutPoint
}

// InputsPolicy implements the Inputs interface and specifies the policy
// for coin selection by the wallet.
type InputsPolicy struct {
	// Strategy is the algorithm to use for selecting coins (e.g., largest
	// first, random). If this is nil, the wallet's default coin selection
	// strategy will be used.
	Strategy CoinSelectionStrategy

	// MinConfs is the minimum number of confirmations a UTXO must have to
	// be considered eligible for coin selection.
	MinConfs uint32

	// Source specifies the pool of UTXOs to select from. If this is nil,
	// the wallet will use a default source (e.g., the default account).
	// Otherwise, this must be one of the CoinSource implementations.
	Source CoinSource
}

// isInputs marks InputsManual as an implementation of the Inputs interface.
func (InputsManual) isInputs() {}

// validate performs validation on the manual inputs.
func (i *InputsManual) validate() error {
	if len(i.UTXOs) == 0 {
		return ErrManualInputsEmpty
	}

	// Make sure there are no duplicates in the specified UTXO list.
	seenUTXOs := make(map[wire.OutPoint]struct{})
	for _, utxo := range i.UTXOs {
		if _, ok := seenUTXOs[utxo]; ok {
			return ErrDuplicateUtxo
		}
		seenUTXOs[utxo] = struct{}{}
	}

	return nil
}

// isInputs marks InputsPolicy as an implementation of the Inputs
// interface.
func (InputsPolicy) isInputs() {}

// validate performs validation on the input policy.
func (i *InputsPolicy) validate() error {
	if i.Source == nil {
		return nil
	}

	switch source := i.Source.(type) {
	// If the source is a scoped account, it must have a non-empty
	// account name.
	case *ScopedAccount:
		if source.AccountName == "" {
			return ErrMissingAccountName
		}

	// If the source is a list of UTXOs, it must not be empty and
	// must not contain duplicates.
	case *CoinSourceUTXOs:
		if len(source.UTXOs) == 0 {
			return ErrManualInputsEmpty
		}
		seenUTXOs := make(map[wire.OutPoint]struct{})
		for _, utxo := range source.UTXOs {
			if _, ok := seenUTXOs[utxo]; ok {
				return ErrDuplicateUtxo
			}
			seenUTXOs[utxo] = struct{}{}
		}
	// Any other source type is unsupported.
	default:
		return fmt.Errorf("%w: %T",
			ErrUnsupportedCoinSource, source)
	}

	return nil
}

// A compile-time assertion to ensure that all types implementing the Inputs
// interface adhere to it.
var _ Inputs = (*InputsManual)(nil)
var _ Inputs = (*InputsPolicy)(nil)

// CoinSource is a sealed interface that defines the pool of UTXOs available
// for coin selection. The sealed interface pattern ensures that only
// the intended implementations can be used.
type CoinSource interface {
	// isCoinSource is a marker method that is part of the sealed interface
	// pattern. It is unexported, so it can only be implemented by types
	// within this package. This ensures that only the intended types
	// can be used as a CoinSource implementation.
	isCoinSource()
}

// ScopedAccount defines a wallet account within a particular key scope. It is
// used to specify the source of funds for coin selection and the
// destination for change outputs.
type ScopedAccount struct {
	// AccountName specifies the name of the account. This must be a
	// non-empty string.
	AccountName string

	// KeyScope specifies the key scope (e.g., P2WKH, P2TR).
	KeyScope waddrmgr.KeyScope
}

// CoinSourceUTXOs specifies that the wallet should select coins from a
// specific, predefined list of candidate UTXOs.
type CoinSourceUTXOs struct {
	// UTXOs is a slice of outpoints from which the coin selection
	// algorithm will choose. This list must not be empty.
	UTXOs []wire.OutPoint
}

// isCoinSource marks ScopedAccount as an implementation of the CoinSource
// interface.
func (ScopedAccount) isCoinSource() {}

// isCoinSource marks CoinSourceUTXOs as an implementation of the CoinSource
// interface.
func (CoinSourceUTXOs) isCoinSource() {}

// A compile-time assertion to ensure that all types implementing the CoinSource
// interface adhere to it.
var _ CoinSource = (*ScopedAccount)(nil)
var _ CoinSource = (*CoinSourceUTXOs)(nil)

// validateTxIntent performs a series of checks on a TxIntent to ensure it is
// well-formed. This function is called before any transaction creation logic
// to ensure that the caller has provided a valid intent. This function is for
// validation only and does not modify the TxIntent.
//
// The following checks are performed:
//   - The intent must have at least one output.
//   - Each output must not be a dust output.
//   - If a change source is specified, it must have a non-empty account name.
//   - The intent must have a valid, non-nil input source.
//   - The input source itself is validated via the `validate` method.
func validateTxIntent(intent *TxIntent) error {
	// The intent must have at least one output.
	if len(intent.Outputs) == 0 {
		return ErrNoOutputs
	}

	// Each output must not be a dust output according to the default relay
	// fee policy.
	for _, output := range intent.Outputs {
		err := txrules.CheckOutput(
			&output, txrules.DefaultRelayFeePerKb,
		)
		if err != nil {
			return err
		}
	}

	// If a change source is specified, it must have a non-empty account
	// name.
	if intent.ChangeSource != nil && intent.ChangeSource.AccountName == "" {
		return ErrMissingAccountName
	}

	// If no input source is specified, an error is returned.
	if intent.Inputs == nil {
		return ErrMissingInputs
	}

	// Validate the inputs.
	if err := intent.Inputs.validate(); err != nil {
		return err
	}

	return nil
}

// createInputSource creates a txauthor.InputSource that will be used to select
// inputs for a transaction. It acts as a dispatcher, delegating to either the
// manual or policy-based input source creator based on the type of the intent's
// Inputs field.
//
// TODO(yy): We use customized queries here to make the utxo lookups atomic
// inside a big tx that's created in `CreateTransaction`, however, we should
// instead have methods made on the `txStore`, which takes a db tx and use them
// here, as the logic will be largely overlapped with the interface methods used
// in `wallet/utxo_manager.go`.
func (w *Wallet) createInputSource(dbtx walletdb.ReadTx, intent *TxIntent) (
	txauthor.InputSource, error) {

	switch inputs := intent.Inputs.(type) {
	// If the inputs are manually specified, we create a "constant" input
	// source that will only ever return the specified UTXOs.
	case *InputsManual:
		return w.createManualInputSource(dbtx, inputs)

	// If the inputs are policy-based, we create an input source that will
	// perform coin selection.
	case *InputsPolicy:
		return w.createPolicyInputSource(dbtx, inputs, intent.FeeRate)

	// Any other type is unsupported.
	default:
		return nil, ErrUnsupportedInputs
	}
}

// createManualInputSource creates an input source from a list of manually
// specified UTXOs. It fetches the UTXOs directly from the database and ensures
// that they are eligible for spending.
func (w *Wallet) createManualInputSource(dbtx walletdb.ReadTx,
	inputs *InputsManual) (
	txauthor.InputSource, error) {

	txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

	// Create a slice to hold the eligible UTXOs.
	var eligibleSelectedUtxo []wtxmgr.Credit

	// Iterate through the manually specified UTXOs and ensure that each
	// one is eligible for spending.
	for _, outpoint := range inputs.UTXOs {
		// Fetch the UTXO from the database.
		credit, err := w.txStore.GetUtxo(txmgrNs, outpoint)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUtxoNotEligible,
				outpoint)
		}

		// TODO(yy): check for locked utxos and log a warning.
		eligibleSelectedUtxo = append(eligibleSelectedUtxo, *credit)
	}

	// Return a constant input source that will only provide the selected
	// UTXOs.
	return constantInputSource(eligibleSelectedUtxo), nil
}

// createPolicyInputSource creates an input source that will perform automatic
// coin selection based on the provided policy.
func (w *Wallet) createPolicyInputSource(dbtx walletdb.ReadTx,
	policy *InputsPolicy, feeRate SatPerKVByte) (
	txauthor.InputSource, error) {

	// Fall back to the default coin selection strategy if none is supplied.
	strategy := policy.Strategy
	if strategy == nil {
		strategy = CoinSelectionLargest
	}

	// Get the full set of eligible UTXOs based on the policy's source
	// and confirmation requirements.
	eligible, err := w.getEligibleUTXOs(
		dbtx, policy.Source, policy.MinConfs,
	)
	if err != nil {
		return nil, err
	}

	// Wrap our wtxmgr.Credit coins in a `Coin` type that implements the
	// SelectableCoin interface. This allows the coin selection strategy
	// to operate on them.
	//
	// TODO(yy): unify the types here - we should use `Utxo` instead of
	// `Credit` or `Coin`.
	wrappedEligible := make([]Coin, len(eligible))
	for i := range eligible {
		wrappedEligible[i] = Coin{
			TxOut: wire.TxOut{
				Value: int64(
					eligible[i].Amount,
				),
				PkScript: eligible[i].PkScript,
			},
			OutPoint: eligible[i].OutPoint,
		}
	}

	// Arrange the eligible coins according to the chosen strategy (e.g.,
	// sort by largest first, or shuffle for random selection).
	feeSatPerKb := btcutil.Amount(feeRate)
	arrangedCoins, err := strategy.ArrangeCoins(
		wrappedEligible, feeSatPerKb,
	)
	if err != nil {
		return nil, err
	}

	// Return an input source that will dispense the arranged coins one by
	// one as requested by the txauthor.
	return makeInputSource(arrangedCoins), nil
}

// getEligibleUTXOs returns a slice of eligible UTXOs that can be used as
// inputs for a transaction, based on the specified source and confirmation
// requirements.
func (w *Wallet) getEligibleUTXOs(dbtx walletdb.ReadTx,
	source CoinSource, minconf uint32) ([]wtxmgr.Credit, error) {

	// TODO(yy): remove this requireChainClient. The block stamp should be
	// passed in as a parameter.
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// Get the current block's height and hash. This is needed to determine
	// the number of confirmations for UTXOs.
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	// Dispatch based on the type of the coin source.
	switch source := source.(type) {
	// If the source is nil, we'll use the default account.
	case nil:
		return w.findEligibleOutputs(
			dbtx, &waddrmgr.KeyScopeBIP0086,
			waddrmgr.DefaultAccountNum, int32(minconf), bs, nil,
		)

	// If the source is a scoped account, we find all eligible outputs for
	// that specific account and key scope.
	case *ScopedAccount:
		return w.getEligibleUTXOsFromAccount(dbtx, source, minconf, bs)

	// If the source is a list of UTXOs, we validate and fetch each UTXO
	// from the provided list.
	case *CoinSourceUTXOs:
		return w.getEligibleUTXOsFromList(dbtx, source, minconf, bs)

	// Any other source type is unsupported.
	default:
		return nil, ErrUnsupportedCoinSource
	}
}

// getEligibleUTXOsFromAccount returns a slice of eligible UTXOs for a specific
// account and key scope.
func (w *Wallet) getEligibleUTXOsFromAccount(dbtx walletdb.ReadTx,
	source *ScopedAccount, minconf uint32, bs *waddrmgr.BlockStamp) (
	[]wtxmgr.Credit, error) {

	keyScope := &source.KeyScope
	account, err := w.AccountNumber(*keyScope, source.AccountName)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotFound,
			source.AccountName)
	}

	return w.findEligibleOutputs(
		dbtx, keyScope, account, int32(minconf), bs, nil,
	)
}

// getEligibleUTXOsFromList returns a slice of eligible UTXOs from a specified
// list of outpoints.
func (w *Wallet) getEligibleUTXOsFromList(dbtx walletdb.ReadTx,
	source *CoinSourceUTXOs, minconf uint32, bs *waddrmgr.BlockStamp) (
	[]wtxmgr.Credit, error) {

	// Create a slice to hold the eligible UTXOs.
	var eligible []wtxmgr.Credit

	// Get the transaction manager's namespace.
	txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

	// Iterate through the manually specified UTXOs and ensure that each
	// one is eligible for spending.
	for _, outpoint := range source.UTXOs {
		// Fetch the UTXO from the database.
		credit, err := w.txStore.GetUtxo(txmgrNs, outpoint)
		if err != nil {
			return nil, fmt.Errorf("%w: %v",
				ErrUtxoNotEligible, outpoint)
		}

		// A UTXO is only eligible if it has reached the required
		// number of confirmations.
		if !confirmed(int32(minconf), credit.Height, bs.Height) {
			// Calculate the number of confirmations for the
			// warning message.
			confs := int32(0)
			if credit.Height != -1 {
				confs = bs.Height - credit.Height + 1
			}

			log.Warnf("Skipping user-specified UTXO %v "+
				"because it has %d confs but needs %d",
				credit.OutPoint, confs, minconf)

			continue
		}

		// If the UTXO is eligible, add it to the list.
		eligible = append(eligible, *credit)
	}

	return eligible, nil
}
