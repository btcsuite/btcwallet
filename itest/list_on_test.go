//go:build itest

package itest

import "github.com/btcsuite/btcwallet/bwtest"

// testCase defines a single integration test case.
type testCase struct {
	// Name is the human-readable name of the test case.
	Name string

	// TestFunc executes the test case.
	TestFunc func(t *bwtest.HarnessTest)
}

// allTestCases is the full set of integration test cases.
var allTestCases = []*testCase{
	{
		Name:     "manager create wallet",
		TestFunc: testCreateWallet,
	},
	{
		Name:     "manager create duplicate",
		TestFunc: testManagerCreateDuplicate,
	},
	{
		Name:     "manager load reload",
		TestFunc: testManagerLoadReload,
	},
	{
		Name:     "manager load concurrent",
		TestFunc: testManagerLoadConcurrent,
	},
	{
		Name:     "manager load missing",
		TestFunc: testManagerLoadMissing,
	},
	{
		Name:     "manager create watchonly",
		TestFunc: testManagerCreateWatchOnly,
	},
	{
		Name:     "account manager create account",
		TestFunc: testAccountManagerCreateAccount,
	},
	{
		Name:     "account manager create account sequence",
		TestFunc: testAccountManagerCreateAccountSequence,
	},
	{
		Name:     "account manager reject account creation",
		TestFunc: testAccountManagerRejectAccountCreation,
	},
	{
		Name:     "account manager enforce account creation lifecycle",
		TestFunc: testAccountManagerEnforceAccountCreationLifecycle,
	},
	{
		Name:     "account manager reject watchonly account creation",
		TestFunc: testAccountManagerRejectWatchOnlyAccountCreation,
	},
	{
		Name:     "account manager rename derived account",
		TestFunc: testAccountManagerRenameDerivedAccount,
	},
	{
		Name:     "account manager rename default account",
		TestFunc: testAccountManagerRenameDefaultAccount,
	},
	{
		Name:     "account manager rename imported account",
		TestFunc: testAccountManagerRenameImportedAccount,
	},
	{
		Name:     "account manager reject account rename",
		TestFunc: testAccountManagerRejectAccountRename,
	},
	{
		Name:     "account manager enforce account rename lifecycle",
		TestFunc: testAccountManagerEnforceAccountRenameLifecycle,
	},
	{
		Name:     "account manager import account",
		TestFunc: testAccountManagerImportAccount,
	},
	{
		Name:     "account manager import account zero fingerprint",
		TestFunc: testAccountManagerImportAccountZeroFingerprint,
	},
	{
		Name:     "account manager preview account import",
		TestFunc: testAccountManagerPreviewAccountImport,
	},
	{
		Name:     "account manager reject account import",
		TestFunc: testAccountManagerRejectAccountImport,
	},
	{
		Name:     "account manager reject invalid import key",
		TestFunc: testAccountManagerRejectInvalidImportKey,
	},
	{
		Name:     "account manager enforce account import lifecycle",
		TestFunc: testAccountManagerEnforceAccountImportLifecycle,
	},
	{
		Name:     "controller start stop",
		TestFunc: testControllerStartStop,
	},
	{
		Name:     "controller unlock lock",
		TestFunc: testControllerUnlockLock,
	},
	{
		Name:     "controller info",
		TestFunc: testControllerInfo,
	},
	// Keep the public Signer request in the integration matrix so callers
	// cannot accidentally depend on wallet-internal database types.
	{
		Name:     "signer derive pubkey",
		TestFunc: testSignerDerivePubKey,
	},
	{
		Name:     "utxomanager list unspent",
		TestFunc: testListUnspent,
	},
	{
		Name:     "utxomanager list unspent unconfirmed",
		TestFunc: testListUnspentUnconfirmed,
	},
	{
		Name:     "utxomanager list unspent immature coinbase",
		TestFunc: testListUnspentImmatureCoinbase,
	},
	{
		Name:     "utxomanager get utxo",
		TestFunc: testGetUtxo,
	},
	{
		Name:     "utxomanager lease output",
		TestFunc: testLeaseOutput,
	},
	{
		Name:     "utxomanager release output",
		TestFunc: testReleaseOutput,
	},
	{
		Name:     "utxomanager list leased outputs",
		TestFunc: testListLeasedOutputs,
	},
	{
		Name:     "txcreator select coins",
		TestFunc: testCreateTransactionSelectCoins,
	},
	{
		Name:     "txcreator multiple outputs",
		TestFunc: testCreateTransactionMultipleOutputs,
	},
	{
		Name:     "txcreator manual inputs",
		TestFunc: testCreateTransactionManualInputs,
	},
	{
		Name:     "txcreator default account",
		TestFunc: testCreateTransactionDefaultAccount,
	},
	{
		Name:     "txcreator coin source",
		TestFunc: testCreateTransactionCoinSource,
	},
	{
		Name:     "txcreator omit change",
		TestFunc: testCreateTransactionOmitChange,
	},
	{
		Name:     "txcreator reject intent",
		TestFunc: testCreateTransactionRejectIntent,
	},
	{
		Name:     "txcreator output boundaries",
		TestFunc: testCreateTransactionOutputBoundaries,
	},
	{
		Name:     "txcreator reject inputs",
		TestFunc: testCreateTransactionRejectInputs,
	},
	{
		Name:     "txcreator wallet state",
		TestFunc: testCreateTransactionWalletState,
	},
	{
		Name:     "txpublisher check acceptance",
		TestFunc: testCheckMempoolAcceptanceAccepted,
	},
	{
		Name:     "txpublisher reject acceptance",
		TestFunc: testCheckMempoolAcceptanceRejected,
	},
	{
		Name:     "txpublisher broadcast transaction",
		TestFunc: testBroadcastTransaction,
	},
	{
		Name:     "txpublisher broadcast known",
		TestFunc: testBroadcastAlreadyKnown,
	},
	{
		Name:     "txpublisher reject broadcast",
		TestFunc: testBroadcastRejected,
	},
	{
		Name:     "txpublisher acceptance state",
		TestFunc: testCheckMempoolAcceptanceWalletState,
	},
	{
		Name:     "txpublisher broadcast state",
		TestFunc: testBroadcastWalletState,
	},
	{
		Name:     "txreader empty history",
		TestFunc: testListTxnsEmptyHistory,
	},
	{
		Name:     "txreader missing transaction",
		TestFunc: testGetTxMissing,
	},
}
