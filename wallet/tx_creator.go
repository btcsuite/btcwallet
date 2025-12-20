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
	"math/rand"
	"sort"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
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

var (
	// DefaultMaxFeeRate is the default maximum fee rate in sat/kvb that
	// the wallet will consider sane. This is currently set to 1000 sat/vb
	// (1,000,000 sat/kvb).
	//
	// TODO(yy): The max fee rate should be made configurable as part of
	// the WalletController interface implementation.
	//
	//nolint:mnd // 1M sat/kvb default max fee.
	DefaultMaxFeeRate = btcunit.NewSatPerKVByte(1_000_000)
)

// Coin represents a spendable UTXO which is available for coin selection.
type Coin struct {
	wire.TxOut
	wire.OutPoint
}

// CoinSelectionStrategy is an interface that represents a coin selection
// strategy. A coin selection strategy is responsible for ordering, shuffling or
// filtering a list of coins before they are passed to the coin selection
// algorithm.
type CoinSelectionStrategy interface {
	// ArrangeCoins takes a list of coins and arranges them according to the
	// specified coin selection strategy and fee rate.
	ArrangeCoins(eligible []Coin, feeSatPerKb btcutil.Amount) ([]Coin,
		error)
}

var (
	// CoinSelectionLargest always picks the largest available utxo to add
	// to the transaction next.
	CoinSelectionLargest CoinSelectionStrategy = &LargestFirstCoinSelector{}

	// CoinSelectionRandom randomly selects the next utxo to add to the
	// transaction. This strategy prevents the creation of ever smaller
	// utxos over time.
	CoinSelectionRandom CoinSelectionStrategy = &RandomCoinSelector{}
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
	FeeRate btcunit.SatPerKVByte

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
	if intent.FeeRate.LessThanOrEqual(btcunit.ZeroSatPerKVByte) {
		return ErrMissingFeeRate
	}

	// Ensure the fee rate is not "insane". This prevents users from
	// accidentally paying exorbitant fees.
	if intent.FeeRate.GreaterThan(DefaultMaxFeeRate) {
		return fmt.Errorf("%w: fee rate of %s is too high, "+
			"max sane fee rate is %s", ErrFeeRateTooLarge,
			intent.FeeRate, DefaultMaxFeeRate)
	}

	return nil
}

// prepareTxAuthSources creates the input and change sources required to
// author a transaction.
func (w *Wallet) prepareTxAuthSources(intent *TxIntent) (
	txauthor.InputSource, *txauthor.ChangeSource, error) {
	// Determine the change source. If not specified, a default will be
	// used.
	changeAccount := w.determineChangeSource(intent)

	var (
		changeSource *txauthor.ChangeSource
		inputSource  txauthor.InputSource
	)
	// We perform the core logic of creating the input and change sources
	// within a single database transaction to ensure atomicity.
	err := walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		changeKeyScope := &changeAccount.KeyScope
		accountName := changeAccount.AccountName

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
		return nil, nil, err
	}

	return inputSource, changeSource, nil
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

	inputSource, changeSource, err := w.prepareTxAuthSources(intent)
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
	feeSatPerKb := intent.FeeRate.Val()

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

// determineChangeSource determines the source for the transaction's change
// output. If a source is specified in the intent, it is used. Otherwise, a
// default is determined based on the input source or the wallet's default
// account. When falling back to the default account, the P2TR (Taproot) key
// scope is used.
func (w *Wallet) determineChangeSource(intent *TxIntent) *ScopedAccount {
	// If a change source is specified in the intent, use it.
	if intent.ChangeSource != nil {
		return intent.ChangeSource
	}

	// If the inputs are from a specific account, use that for change.
	if policy, ok := intent.Inputs.(*InputsPolicy); ok {
		if account, ok := policy.Source.(*ScopedAccount); ok {
			return account
		}
	}

	// Otherwise, use the default account.
	// TODO(yy): The default key scope is currently hardcoded to P2TR
	// (Taproot). This should be made configurable.
	return &ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    waddrmgr.KeyScopeBIP0086,
	}
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
	policy *InputsPolicy, feeRate btcunit.SatPerKVByte) (
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
	feeSatPerKb := feeRate.Val()

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
		if !hasMinConfs(minconf, credit.Height, bs.Height) {
			// Calculate the number of confirmations for the
			// warning message.
			confs := calcConf(credit.Height, bs.Height)

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

func makeInputSource(eligible []Coin) txauthor.InputSource {
	// Current inputs and their total value. These are closed over by the
	// returned input source and reused across multiple calls.
	currentTotal := btcutil.Amount(0)
	currentInputs := make([]*wire.TxIn, 0, len(eligible))
	currentScripts := make([][]byte, 0, len(eligible))
	currentInputValues := make([]btcutil.Amount, 0, len(eligible))

	return func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
		[]btcutil.Amount, [][]byte, error) {

		for currentTotal < target && len(eligible) != 0 {
			nextCredit := eligible[0]
			prevOut := nextCredit.TxOut
			outpoint := nextCredit.OutPoint
			eligible = eligible[1:]

			nextInput := wire.NewTxIn(&outpoint, nil, nil)
			currentTotal += btcutil.Amount(prevOut.Value)

			currentInputs = append(currentInputs, nextInput)
			currentScripts = append(
				currentScripts, prevOut.PkScript,
			)
			currentInputValues = append(
				currentInputValues,
				btcutil.Amount(prevOut.Value),
			)
		}

		return currentTotal, currentInputs, currentInputValues,
			currentScripts, nil
	}
}

// constantInputSource creates an input source function that always returns the
// static set of user-selected UTXOs.
func constantInputSource(eligible []wtxmgr.Credit) txauthor.InputSource {
	// Current inputs and their total value. These won't change over
	// different invocations as we want our inputs to remain static since
	// they're selected by the user.
	currentTotal := btcutil.Amount(0)
	currentInputs := make([]*wire.TxIn, 0, len(eligible))
	currentScripts := make([][]byte, 0, len(eligible))
	currentInputValues := make([]btcutil.Amount, 0, len(eligible))

	for _, credit := range eligible {
		nextInput := wire.NewTxIn(&credit.OutPoint, nil, nil)
		currentTotal += credit.Amount

		currentInputs = append(currentInputs, nextInput)
		currentScripts = append(currentScripts, credit.PkScript)
		currentInputValues = append(currentInputValues, credit.Amount)
	}

	return func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
		[]btcutil.Amount, [][]byte, error) {

		return currentTotal, currentInputs, currentInputValues,
			currentScripts, nil
	}
}

// findEligibleOutputs finds eligible outputs for the given key scope and
// account.
func (w *Wallet) findEligibleOutputs(dbtx walletdb.ReadTx,
	keyScope *waddrmgr.KeyScope, account uint32, minconf uint32,
	bs *waddrmgr.BlockStamp,
	allowUtxo func(utxo wtxmgr.Credit) bool) ([]wtxmgr.Credit, error) {

	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

	unspent, err := w.txStore.UnspentOutputs(txmgrNs)
	if err != nil {
		return nil, err
	}

	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependency and requesting unspent outputs for a single account.
	eligible := make([]wtxmgr.Credit, 0, len(unspent))
	for i := range unspent {
		output := &unspent[i]

		// Restrict the selected utxos if a filter function is provided.
		if allowUtxo != nil &&
			!allowUtxo(*output) {

			continue
		}

		// Only include this output if it meets the required number of
		// confirmations. Coinbase transactions must have reached
		// maturity before their outputs may be spent.
		if !hasMinConfs(minconf, output.Height, bs.Height) {
			continue
		}

		if output.FromCoinBase {
			target := w.chainParams.CoinbaseMaturity
			if !hasMinConfs(
				uint32(target), output.Height, bs.Height,
			) {

				continue
			}
		}

		// Locked unspent outputs are skipped.
		if w.LockedOutpoint(output.OutPoint) {
			continue
		}

		// Only include the output if it is associated with the passed
		// account.
		//
		// TODO: Handle multisig outputs by determining if enough of the
		// addresses are controlled.
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams)
		if err != nil || len(addrs) != 1 {
			continue
		}

		scopedMgr, addrAcct, err := w.addrStore.AddrAccount(
			addrmgrNs, addrs[0],
		)
		if err != nil {
			continue
		}

		if keyScope != nil && scopedMgr.Scope() != *keyScope {
			continue
		}

		if addrAcct != account {
			continue
		}

		eligible = append(eligible, *output)
	}

	return eligible, nil
}

// inputYieldsPositively returns a boolean indicating whether this input yields
// positively if added to a transaction. This determination is based on the
// best-case added virtual size. For edge cases this function can return true
// while the input is yielding slightly negative as part of the final
// transaction.
func inputYieldsPositively(credit *wire.TxOut,
	feeRatePerKb btcutil.Amount) bool {

	inputSize := txsizes.GetMinInputVirtualSize(credit.PkScript)
	inputFee := feeRatePerKb * btcutil.Amount(inputSize) / 1000

	return inputFee < btcutil.Amount(credit.Value)
}

// addrMgrWithChangeSource returns the address manager bucket and a change
// source that returns change addresses from said address manager. The change
// addresses will come from the specified key scope and account, unless a key
// scope is not specified. In that case, change addresses will always come from
// the P2WKH key scope.
func (w *Wallet) addrMgrWithChangeSource(dbtx walletdb.ReadWriteTx,
	changeKeyScope *waddrmgr.KeyScope, account uint32) (
	walletdb.ReadWriteBucket, *txauthor.ChangeSource, error) {

	// Determine the address type for change addresses of the given
	// account.
	if changeKeyScope == nil {
		changeKeyScope = &waddrmgr.KeyScopeBIP0086
	}

	addrType := waddrmgr.ScopeAddrMap[*changeKeyScope].InternalAddrType

	// It's possible for the account to have an address schema override, so
	// prefer that if it exists.
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	scopeMgr, err := w.addrStore.FetchScopedKeyManager(*changeKeyScope)
	if err != nil {
		return nil, nil, err
	}

	accountInfo, err := scopeMgr.AccountProperties(addrmgrNs, account)
	if err != nil {
		return nil, nil, err
	}

	if accountInfo.AddrSchema != nil {
		addrType = accountInfo.AddrSchema.InternalAddrType
	}

	// Compute the expected size of the script for the change address type.
	var scriptSize int
	switch addrType {
	case waddrmgr.PubKeyHash:
		scriptSize = txsizes.P2PKHPkScriptSize
	case waddrmgr.NestedWitnessPubKey:
		scriptSize = txsizes.NestedP2WPKHPkScriptSize
	case waddrmgr.WitnessPubKey:
		scriptSize = txsizes.P2WPKHPkScriptSize
	case waddrmgr.TaprootPubKey:
		scriptSize = txsizes.P2TRPkScriptSize
	default:
		return nil, nil, fmt.Errorf("unsupported address type: %v",
			addrType)
	}

	newChangeScript := func() ([]byte, error) {
		// Derive the change output script. As a hack to allow spending
		// from the imported account, change addresses are created from
		// account 0.
		var (
			changeAddr btcutil.Address
			err        error
		)
		if account == waddrmgr.ImportedAddrAccount {
			changeAddr, err = w.newChangeAddress(
				addrmgrNs, 0, *changeKeyScope,
			)
		} else {
			changeAddr, err = w.newChangeAddress(
				addrmgrNs, account, *changeKeyScope,
			)
		}

		if err != nil {
			return nil, err
		}

		return txscript.PayToAddrScript(changeAddr)
	}

	return addrmgrNs, &txauthor.ChangeSource{
		ScriptSize: scriptSize,
		NewScript:  newChangeScript,
	}, nil
}

// sortByAmount is a generic sortable type for sorting coins by their amount.
type sortByAmount []Coin

func (s sortByAmount) Len() int { return len(s) }
func (s sortByAmount) Less(i, j int) bool {
	return s[i].Value < s[j].Value
}
func (s sortByAmount) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// LargestFirstCoinSelector is an implementation of the CoinSelectionStrategy
// that always selects the largest coins first.
type LargestFirstCoinSelector struct{}

// ArrangeCoins takes a list of coins and arranges them according to the
// specified coin selection strategy and fee rate.
func (*LargestFirstCoinSelector) ArrangeCoins(eligible []Coin,
	_ btcutil.Amount) ([]Coin, error) {

	sort.Sort(sort.Reverse(sortByAmount(eligible)))

	return eligible, nil
}

// RandomCoinSelector is an implementation of the CoinSelectionStrategy that
// selects coins at random. This prevents the creation of ever smaller UTXOs
// over time that may never become economical to spend.
type RandomCoinSelector struct{}

// ArrangeCoins takes a list of coins and arranges them according to the
// specified coin selection strategy and fee rate.
func (*RandomCoinSelector) ArrangeCoins(eligible []Coin,
	feeSatPerKb btcutil.Amount) ([]Coin, error) {

	// Skip inputs that do not raise the total transaction output
	// value at the requested fee rate.
	positivelyYielding := make([]Coin, 0, len(eligible))
	for _, output := range eligible {

		if !inputYieldsPositively(&output.TxOut, feeSatPerKb) {
			continue
		}

		positivelyYielding = append(positivelyYielding, output)
	}

	rand.Shuffle(len(positivelyYielding), func(i, j int) {
		positivelyYielding[i], positivelyYielding[j] =
			positivelyYielding[j], positivelyYielding[i]
	})

	return positivelyYielding, nil
}
