// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet provides a bitcoin wallet implementation that is ready for
// use.
//
// TODO(yy): bring wrapcheck back when implementing the `Store` interface.
//
//nolint:wrapcheck
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
	// ErrManualInputsEmpty is returned when manual inputs are specified but
	// the list is empty.
	ErrManualInputsEmpty = errors.New("manual inputs cannot be empty")

	// ErrDuplicatedUtxo is returned when a UTXO is specified multiple
	// times.
	ErrDuplicatedUtxo = errors.New("duplicated utxo")

	// ErrUnsupportedTxInputs is returned when the `Inputs` field of a
	// TxIntent is not of a supported type.
	ErrUnsupportedTxInputs = errors.New("unsupported tx inputs type")

	// ErrUtxoNotEligible is returned when a UTXO is not eligible to be
	// spent.
	ErrUtxoNotEligible = errors.New("utxo not eligible to spend")

	// ErrAccountNotFound is returned when an account is not found.
	ErrAccountNotFound = errors.New("account not found")

	// ErrNoTxOutputs is returned when a transaction is created without any
	// outputs.
	ErrNoTxOutputs = errors.New("tx has no outputs")

	// ErrFeeRateTooLarge is returned when a transaction is created with a
	// fee rate that is larger than the configured max allowed fee rate.
	// The default max fee rate is 1000 sat/vb.
	ErrFeeRateTooLarge = errors.New("fee rate too large")

	// ErrMissingFeeRate is returned when a transaction is created without
	// a fee rate.
	ErrMissingFeeRate = errors.New("missing fee rate")

	// ErrMissingAccountName is returned when an account name is required
	// but not provided.
	ErrMissingAccountName = errors.New("account name cannot be empty")

	// ErrUnsupportedCoinSource is returned when the `Source` field of a
	// CoinSelectionPolicy is not of a supported type.
	ErrUnsupportedCoinSource = errors.New("unsupported coin source type")

	// ErrMissingInputs is returned when a transaction is created without
	// any inputs.
	ErrMissingInputs = errors.New("tx has no inputs")

	// ErrNilTxIntent is returned when a nil `TxIntent` is provided.
	ErrNilTxIntent = errors.New("nil TxIntent")
)

const (
	// DefaultMaxFeeRate is the default maximum fee rate in sat/kvb that
	// the wallet will consider sane. This is currently set to 1000 sat/vb
	// (1,000,000 sat/kvb).
	//
	// TODO(yy): The max fee rate should be made configurable as part of
	// the WalletController interface implementation.
	DefaultMaxFeeRate SatPerKVByte = 1000 * 1000
)

// TxCreator provides an interface for creating transactions. Its primary
// role is to produce a fully-formed, unsigned transaction that can be passed
// to the Signer interface.
type TxCreator interface {
	// CreateTransaction creates a new, unsigned transaction based on the
	// provided intent. The resulting AuthoredTx will contain the unsigned
	// transaction and all the necessary metadata to sign it.
	CreateTransaction(ctx context.Context, intent *TxIntent) (
		*txauthor.AuthoredTx, error)
}

// A compile time check to ensure that Wallet implements the interface.
var _ TxCreator = (*Wallet)(nil)

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
//			Source: &CoinSourceUTXOs{
//				UTXOs: []wire.OutPoint{...},
//			},
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
func (*InputsManual) isInputs() {}

// validate performs validation on the manual inputs.
func (i *InputsManual) validate() error {
	return validateOutPoints(i.UTXOs)
}

// isInputs marks InputsPolicy as an implementation of the Inputs
// interface.
func (*InputsPolicy) isInputs() {}

// validate performs validation on the input policy.
func (i *InputsPolicy) validate() error {
	if i.Source == nil {
		return nil
	}

	switch source := i.Source.(type) {
	// If the source is a scoped account, it must have a non-empty account
	// name.
	case *ScopedAccount:
		if source.AccountName == "" {
			return ErrMissingAccountName
		}

	// If the source is a list of UTXOs, it must not be empty and must not
	// contain duplicates.
	case *CoinSourceUTXOs:
		return validateOutPoints(source.UTXOs)

	// Any other source type is unsupported.
	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedCoinSource, source)
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

// validateOutPoints checks a slice of `wire.OutPoint`s for emptiness and
// duplicate entries. It returns `ErrManualInputsEmpty` if the slice is empty
// and `ErrDuplicatedUtxo` if any duplicates are found.
func validateOutPoints(outpoints []wire.OutPoint) error {
	if len(outpoints) == 0 {
		return ErrManualInputsEmpty
	}

	seenUTXOs := make(map[wire.OutPoint]struct{})
	for _, utxo := range outpoints {
		if _, ok := seenUTXOs[utxo]; ok {
			return ErrDuplicatedUtxo
		}

		seenUTXOs[utxo] = struct{}{}
	}

	return nil
}

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
		return ErrNoTxOutputs
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
	err := intent.Inputs.validate()
	if err != nil {
		return err
	}

	// The intent must have a non-zero fee rate.
	if intent.FeeRate == 0 {
		return ErrMissingFeeRate
	}

	// Ensure the fee rate is not "insane". This prevents users from
	// accidentally paying exorbitant fees.
	if intent.FeeRate > DefaultMaxFeeRate {
		return fmt.Errorf("%w: fee rate of %d sat/kvb is too high, "+
			"max sane fee rate is %d sat/kvb", ErrFeeRateTooLarge,
			intent.FeeRate, DefaultMaxFeeRate)
	}

	return nil
}

// CreateTransaction creates a new unsigned transaction spending unspent outputs
// to the given outputs. It is the main implementation of the TxCreator
// interface. The method will produce a valid, unsigned transaction, which can
// then be passed to the Signer interface to be signed.
func (w *Wallet) CreateTransaction(_ context.Context, intent *TxIntent) (
	*txauthor.AuthoredTx, error) {

	// Check that the intent is not nil.
	if intent == nil {
		return nil, ErrNilTxIntent
	}

	// If no input source is specified, an auto coin selection with the
	// default account will be used.
	if intent.Inputs == nil {
		log.Debug("No input source specified, using default policy " +
			"for automatic coin selection")

		intent.Inputs = &InputsPolicy{}
	}

	err := validateTxIntent(intent)
	if err != nil {
		return nil, err
	}

	// The addrMgrWithChangeSource function of the wallet creates a new
	// change address. The address manager uses OnCommit on the walletdb tx
	// to update the in-memory state of the account state. But because the
	// commit happens _after_ the account manager internal lock has been
	// released, there is a chance for the address index to be accessed
	// concurrently, even though the closure in OnCommit re-acquires the
	// lock. To avoid this issue, we surround the whole address creation
	// process with a lock.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var (
		changeSource *txauthor.ChangeSource
		inputSource  txauthor.InputSource
	)

	// We perform the core logic of creating the input and change sources
	// within a single database transaction to ensure atomicity.
	err = walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		changeKeyScope := &intent.ChangeSource.KeyScope
		accountName := intent.ChangeSource.AccountName

		// Query the account's number using the account name.
		//
		// TODO(yy): Remove this query in upcoming SQL.
		account, err := w.AccountNumber(*changeKeyScope, accountName)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrAccountNotFound,
				accountName)
		}

		// Create the change source, which is a closure that the
		// txauthor package will use to generate a new change address
		// when needed.
		//
		// TODO(yy): Refactor to ensure atomicity. The underlying
		// `GetUnusedAddress` call creates its own database
		// transaction, breaking the atomicity of this
		// `walletdb.Update` block. A new method should be added to
		// `AccountStore` that accepts an active database transaction
		// and returns an unused address. This will allow the address
		// derivation to occur within the same atomic transaction as
		// the rest of the tx creation logic. Once fixed, we can remove
		// the above `w.newAddrMtx` lock.
		_, changeSource, err = w.addrMgrWithChangeSource(
			dbtx, changeKeyScope, account,
		)
		if err != nil {
			return err
		}

		// Create the input source, which is a closure that the
		// txauthor package will use to select coins.
		inputSource, err = w.createInputSource(dbtx, intent)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// The txauthor.NewUnsignedTransaction function expects a slice of
	// *wire.TxOut, but our intent has a slice of wire.TxOut. We perform
	// the conversion here.
	//
	// TODO(yy): change the signature of `NewUnsignedTransaction` to take a
	// list of `wire.TxOut`.
	outputs := make([]*wire.TxOut, 0, len(intent.Outputs))
	for _, output := range intent.Outputs {
		outputs = append(outputs, &output)
	}

	// With the input source and change source prepared, we can now call the
	// txauthor package to perform the actual coin selection and create the
	// unsigned transaction.
	feeSatPerKb := btcutil.Amount(intent.FeeRate)

	tx, err := txauthor.NewUnsignedTransaction(
		outputs, feeSatPerKb, inputSource, changeSource,
	)
	if err != nil {
		return nil, err
	}

	// Randomize the position of the change output, if one was created. This
	// helps to improve privacy by making it harder to distinguish change
	// outputs from other outputs.
	if tx.ChangeIndex >= 0 {
		tx.RandomizeChangePosition()
	}

	return tx, nil
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
		return nil, ErrUnsupportedTxInputs
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
	eligibleSelectedUtxo := make(
		[]wtxmgr.Credit, 0, len(inputs.UTXOs),
	)

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
// requirements. A UTXO is considered ineligible if it is not found in the
// wallet's transaction store or if it does not meet the minimum confirmation
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
			waddrmgr.DefaultAccountNum, minconf, bs, nil,
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
		dbtx, keyScope, account, minconf, bs, nil,
	)
}

// getEligibleUTXOsFromList returns a slice of eligible UTXOs from a specified
// list of outpoints.
func (w *Wallet) getEligibleUTXOsFromList(dbtx walletdb.ReadTx,
	source *CoinSourceUTXOs, minconf uint32, bs *waddrmgr.BlockStamp) (
	[]wtxmgr.Credit, error) {

	// Create a slice to hold the eligible UTXOs.
	eligible := make([]wtxmgr.Credit, 0, len(source.UTXOs))

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
		if !confirmed(minconf, credit.Height, bs.Height) {
			// Calculate the number of confirmations for the
			// warning message.
			confs := calcConf(bs.Height, credit.Height)

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
