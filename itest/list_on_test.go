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
		Name:     "manager start reopen",
		TestFunc: testManagerStartReopen,
	},
	{
		Name:     "manager start concurrent",
		TestFunc: testManagerStartConcurrent,
	},
	{
		Name:     "manager create watchonly",
		TestFunc: testManagerCreateWatchOnly,
	},
	{
		Name:     "account manager query list spendable",
		TestFunc: testAccountManagerQueryListSpendable,
	},
	{
		Name:     "account manager query list watchonly",
		TestFunc: testAccountManagerQueryListWatchOnly,
	},
	{
		Name:     "account manager query scope spendable",
		TestFunc: testAccountManagerQueryScopeSpendable,
	},
	{
		Name:     "account manager query scope watchonly",
		TestFunc: testAccountManagerQueryScopeWatchOnly,
	},
	{
		Name:     "account manager query name spendable",
		TestFunc: testAccountManagerQueryNameSpendable,
	},
	{
		Name:     "account manager query name watchonly",
		TestFunc: testAccountManagerQueryNameWatchOnly,
	},
	{
		Name:     "account manager query get spendable",
		TestFunc: testAccountManagerQueryGetSpendable,
	},
	{
		Name:     "account manager query get watchonly",
		TestFunc: testAccountManagerQueryGetWatchOnly,
	},
	{
		Name:     "account manager query list empty",
		TestFunc: testAccountManagerQueryListEmpty,
	},
	{
		Name:     "account manager query missing name",
		TestFunc: testAccountManagerQueryMissingName,
	},
	{
		Name:     "account manager query missing scope",
		TestFunc: testAccountManagerQueryMissingScope,
	},
	{
		Name:     "account manager query missing account",
		TestFunc: testAccountManagerQueryMissingAccount,
	},
	{
		Name:     "account manager create account",
		TestFunc: testAccountManagerCreateAccount,
	},
	// Custom scopes must persist their schema together with the account.
	{
		Name:     "account manager create custom scope account",
		TestFunc: testAccountManagerCreateCustomScopeAccount,
	},
	{
		Name:     "account manager create exact account",
		TestFunc: testAccountManagerCreateExactAccount,
	},
	{
		Name:     "account manager fill account hole",
		TestFunc: testAccountManagerFillAccountHole,
	},
	{
		Name:     "account manager advance account cursor",
		TestFunc: testAccountManagerAdvanceAccountCursor,
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
		Name:     "controller unlock lock",
		TestFunc: testControllerUnlockLock,
	},
	{
		Name:     "controller change passphrase locked",
		TestFunc: testControllerChangePassphraseLocked,
	},
	{
		Name:     "controller change passphrase unlocked",
		TestFunc: testControllerChangePassphraseUnlocked,
	},
	{
		Name:     "controller change passphrase lifecycle",
		TestFunc: testControllerChangePassphraseLifecycle,
	},
	{
		Name:     "controller change passphrase reject locked",
		TestFunc: testControllerChangePassphraseRejectLocked,
	},
	{
		Name:     "controller change passphrase reject empty",
		TestFunc: testControllerChangePassphraseRejectEmpty,
	},
	{
		Name:     "controller change passphrase reject unlocked",
		TestFunc: testControllerChangePassphraseRejectUnlocked,
	},
	{
		Name:     "controller unlock timeout",
		TestFunc: testControllerUnlockTimeout,
	},
	{
		Name:     "controller info",
		TestFunc: testControllerInfo,
	},
	// Keep the public Signer request in the integration matrix so callers
	// cannot accidentally depend on wallet-internal database types.
	{
		Name:     "signer derive pubkey paths",
		TestFunc: testSignerDerivePubKeyPaths,
	},
	{
		Name:     "signer derive pubkey wallet state",
		TestFunc: testSignerDerivePubKeyWalletState,
	},
	{
		Name:     "signer derive pubkey reject request",
		TestFunc: testSignerDerivePubKeyRejectRequest,
	},
	{
		Name:     "signer derive pubkey watchonly",
		TestFunc: testSignerDerivePubKeyWatchOnly,
	},
	{
		Name:     "signer ecdh agreement",
		TestFunc: testSignerECDHAgreement,
	},
	{
		Name:     "signer ecdh wallet state",
		TestFunc: testSignerECDHWalletState,
	},
	{
		Name:     "signer ecdh reject account",
		TestFunc: testSignerECDHRejectAccount,
	},
	{
		Name:     "signer ecdh watchonly",
		TestFunc: testSignerECDHWatchOnly,
	},
	{
		Name:     "signer derivation durable reopen",
		TestFunc: testSignerDerivationDurableReopen,
	},
	{
		Name:     "signer derive imported xpub",
		TestFunc: testSignerDeriveImportedXPub,
	},
	// Keep raw extraction in separate UnsafeSigner cases so safe signing
	// scenarios never need private-key results as fixtures or assertions.
	{
		Name:     "unsafe signer derive privkey",
		TestFunc: testUnsafeSignerDerivePrivKey,
	},
	{
		Name:     "unsafe signer get privkey for address",
		TestFunc: testUnsafeSignerGetPrivKeyForAddress,
	},
	{
		Name:     "unsafe signer reject unknown path",
		TestFunc: testUnsafeSignerRejectUnknownPath,
	},
	{
		Name:     "unsafe signer reject foreign address",
		TestFunc: testUnsafeSignerRejectForeignAddress,
	},
	{
		Name:     "unsafe signer reject locked",
		TestFunc: testUnsafeSignerRejectLocked,
	},
	{
		Name:     "unsafe signer reject watchonly",
		TestFunc: testUnsafeSignerRejectWatchOnly,
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
	{
		Name:     "txreader received transaction",
		TestFunc: testGetTxReceived,
	},
	{
		Name:     "txreader unmined transaction",
		TestFunc: testGetTxUnmined,
	},
	{
		Name:     "txreader mined transaction",
		TestFunc: testGetTxMined,
	},
	{
		Name:     "txreader confirmation count",
		TestFunc: testGetTxConfirmations,
	},
	{
		Name:     "txreader list boundaries",
		TestFunc: testListTxnsBoundaries,
	},
	{
		Name:     "txreader reader agreement",
		TestFunc: testListTxnsAgreesWithGetTx,
	},
	{
		Name:     "txreader durable reopen",
		TestFunc: testTxReaderDurableReopen,
	},
	{
		Name:     "txwriter label transaction",
		TestFunc: testLabelTx,
	},
	{
		Name:     "txwriter replace label",
		TestFunc: testLabelTxReplace,
	},
	{
		Name:     "txwriter clear label",
		TestFunc: testLabelTxClear,
	},
	{
		Name:     "txwriter label boundaries",
		TestFunc: testLabelTxBoundaries,
	},
	{
		Name:     "txwriter reject unknown transaction",
		TestFunc: testLabelTxRejectUnknown,
	},
	{
		Name:     "txwriter reject oversize label",
		TestFunc: testLabelTxRejectOversize,
	},
	{
		Name:     "txwriter label survives reload",
		TestFunc: testLabelTxSurvivesReload,
	},
	{
		Name:     "txwriter wallet state",
		TestFunc: testLabelTxWalletState,
	},
	{
		Name:     "txwriter delete unconfirmed transaction",
		TestFunc: testDeleteUnconfirmedTx,
	},
	{
		Name:     "txwriter reject confirmed removal",
		TestFunc: testDeleteUnconfirmedTxRejectsConfirmed,
	},
	{
		Name:     "txwriter reject unknown removal",
		TestFunc: testDeleteUnconfirmedTxRejectsUnknown,
	},
	{
		Name:     "txwriter removed transaction rediscovery",
		TestFunc: testDeleteUnconfirmedTxRediscovery,
	},
}
