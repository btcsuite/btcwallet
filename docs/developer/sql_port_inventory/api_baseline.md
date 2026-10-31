# SQL Port API Baseline

In this snapshot, we record the public wallet contract that the port-first branch must preserve. The lnd side is pinned to an exact checkout, so later API checks can distinguish a btcwallet regression from unrelated lnd movement.

- btcwallet baseline: `d7d47d08558e67f6c4d6b19381b64543547aec99`
- lnd audit checkout: `31168557c3a8602d7669c1eb86eddd07d9892bc6`
- lnd btcwallet module requirement: `v0.18.0`
- generator: `./scripts/sql-port-api-baseline.sh <lnd-checkout> [btcwallet-ref] [lnd-ref]`

## `wallet.Interface`

The interface contains 59 methods. Signatures are copied from `wallet/interface.go`, not reconstructed from documentation.

| Method | Signature | Non-test lnd references |
| --- | --- | --- |
| `Start` | `Start()` | `lnwallet/btcwallet/btcwallet.go:393` |
| `Stop` | `Stop()` | `lnwallet/btcwallet/btcwallet.go:407` |
| `WaitForShutdown` | `WaitForShutdown()` | `lnwallet/btcwallet/btcwallet.go:409` |
| `SynchronizeRPC` | `SynchronizeRPC(chainClient chain.Interface)` | `lnwallet/btcwallet/btcwallet.go:397` |
| `Locked` | `Locked() bool` | none |
| `Unlock` | `Unlock(passphrase []byte, lock <-chan time.Time) error` | `lnwallet/btcwallet/btcwallet.go:321` |
| `Lock` | `Lock()` | none |
| `ChainSynced` | `ChainSynced() bool` | `lnwallet/btcwallet/btcwallet.go:1781` |
| `SyncedTo` | `SyncedTo() waddrmgr.BlockStamp` | `lnwallet/btcwallet/btcwallet.go:1384`<br>`lnwallet/btcwallet/btcwallet.go:1574`<br>`lnwallet/btcwallet/btcwallet.go:1690`<br>`lnwallet/btcwallet/btcwallet.go:1767`<br>`lnwallet/btcwallet/btcwallet.go:1845` |
| `BirthdayBlock` | `BirthdayBlock() (*waddrmgr.BlockStamp, error)` | `lnwallet/btcwallet/btcwallet.go:1832` |
| `Database` | `Database() walletdb.DB` | `keychain/btcwallet.go:151`<br>`keychain/btcwallet.go:211`<br>`keychain/btcwallet.go:286` |
| `ChainParams` | `ChainParams() *chaincfg.Params` | `lnwallet/btcwallet/btcwallet.go:1699`<br>`lnwallet/btcwallet/btcwallet.go:1720` |
| `NotificationServer` | `NotificationServer() *NotificationServer` | `lnwallet/btcwallet/btcwallet.go:1746` |
| `AddrManager` | `AddrManager() *waddrmgr.Manager` | `keychain/btcwallet.go:104`<br>`keychain/btcwallet.go:225`<br>`keychain/btcwallet.go:295`<br>`keychain/btcwallet.go:95`<br>`keychain/btcwallet.go:96`<br>`lnwallet/btcwallet/btcwallet.go:305`<br>`lnwallet/btcwallet/btcwallet.go:341`<br>`lnwallet/btcwallet/btcwallet.go:354` |
| `Accounts` | `Accounts(scope waddrmgr.KeyScope) (*AccountsResult, error)` | `lnwallet/btcwallet/btcwallet.go:618`<br>`lnwallet/btcwallet/btcwallet.go:630`<br>`lnwallet/btcwallet/btcwallet.go:639` |
| `AccountProperties` | `AccountProperties(scope waddrmgr.KeyScope, account uint32) ( *waddrmgr.AccountProperties, error, )` | none |
| `AccountPropertiesByName` | `AccountPropertiesByName(scope waddrmgr.KeyScope, name string) (*waddrmgr.AccountProperties, error)` | `lnwallet/btcwallet/btcwallet.go:558`<br>`lnwallet/btcwallet/btcwallet.go:572`<br>`lnwallet/btcwallet/btcwallet.go:590`<br>`lnwallet/btcwallet/psbt.go:636` |
| `AccountNumber` | `AccountNumber(scope waddrmgr.KeyScope, accountName string) ( uint32, error)` | `lnwallet/btcwallet/btcwallet.go:470` |
| `AccountName` | `AccountName(scope waddrmgr.KeyScope, accountNumber uint32) ( string, error)` | none |
| `AccountManagedAddresses` | `AccountManagedAddresses(scope waddrmgr.KeyScope, accountNum uint32) ([]waddrmgr.ManagedAddress, error)` | `lnwallet/btcwallet/btcwallet.go:716` |
| `RenameAccount` | `RenameAccount(scope waddrmgr.KeyScope, account uint32, newName string) error` | none |
| `ImportAccount` | `ImportAccount(name string, accountPubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32, addrType *waddrmgr.AddressType, ) (*waddrmgr.AccountProperties, error)` | `lnwallet/btcwallet/btcwallet.go:832` |
| `ImportAccountDryRun` | `ImportAccountDryRun(name string, accountPubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32, addrType *waddrmgr.AddressType, numAddrs uint32) (*waddrmgr.AccountProperties, []waddrmgr.ManagedAddress, []waddrmgr.ManagedAddress, error)` | `lnwallet/btcwallet/btcwallet.go:844` |
| `InitAccounts` | `InitAccounts(scope *waddrmgr.ScopedKeyManager, convertToWatchOnly bool, account uint32) error` | `lnwallet/btcwallet/btcwallet.go:381` |
| `AddScopeManager` | `AddScopeManager(scope waddrmgr.KeyScope, addrSchema waddrmgr.ScopeAddrSchema) ( *waddrmgr.ScopedKeyManager, error)` | `lnwallet/btcwallet/btcwallet.go:347`<br>`lnwallet/btcwallet/btcwallet.go:361` |
| `CurrentAddress` | `CurrentAddress(account uint32, scope waddrmgr.KeyScope) ( address.Address, error)` | `lnwallet/btcwallet/btcwallet.go:524` |
| `NewAddress` | `NewAddress(account uint32, scope waddrmgr.KeyScope) ( address.Address, error)` | `lnwallet/btcwallet/btcwallet.go:501` |
| `NewChangeAddress` | `NewChangeAddress(account uint32, scope waddrmgr.KeyScope) ( address.Address, error)` | `lnwallet/btcwallet/btcwallet.go:499` |
| `AddressInfo` | `AddressInfo(a address.Address) (waddrmgr.ManagedAddress, error)` | `lnwallet/btcwallet/btcwallet.go:542` |
| `HaveAddress` | `HaveAddress(a address.Address) (bool, error)` | `lnwallet/btcwallet/btcwallet.go:531` |
| `ImportPublicKey` | `ImportPublicKey(pubKey *btcec.PublicKey, addrType waddrmgr.AddressType) error` | `lnwallet/btcwallet/btcwallet.go:875` |
| `ImportTaprootScript` | `ImportTaprootScript(scope waddrmgr.KeyScope, tapscript *waddrmgr.Tapscript, bs *waddrmgr.BlockStamp, witnessVersion byte, isSecretScript bool) ( waddrmgr.ManagedAddress, error)` | `lnwallet/btcwallet/btcwallet.go:893` |
| `FetchDerivationInfo` | `FetchDerivationInfo(pkScript []byte) (*psbt.Bip32Derivation, error)` | `lnwallet/btcwallet/signer.go:62` |
| `CalculateBalance` | `CalculateBalance(requiredConfirmations int32) (btcutil.Amount, error)` | none |
| `CalculateAccountBalances` | `CalculateAccountBalances(account uint32, requiredConfirmations int32) ( Balances, error)` | none |
| `ListUnspent` | `ListUnspent(minconf, maxconf int32, accountName string) ( []*btcjson.ListUnspentResult, error)` | `lnwallet/btcwallet/btcwallet.go:1053`<br>`lnwallet/btcwallet/btcwallet.go:699` |
| `FetchOutpointInfo` | `FetchOutpointInfo(prevOut *wire.OutPoint) ( *wire.MsgTx, *wire.TxOut, int64, error)` | `lnwallet/btcwallet/signer.go:31` |
| `LockOutpoint` | `LockOutpoint(op wire.OutPoint)` | none |
| `UnlockOutpoint` | `UnlockOutpoint(op wire.OutPoint)` | none |
| `LockedOutpoint` | `LockedOutpoint(op wire.OutPoint) bool` | `lnwallet/btcwallet/btcwallet.go:1009` |
| `LeaseOutput` | `LeaseOutput(id wtxmgr.LockID, op wire.OutPoint, duration time.Duration) (time.Time, error)` | `lnwallet/btcwallet/btcwallet.go:1013` |
| `ReleaseOutput` | `ReleaseOutput(id wtxmgr.LockID, op wire.OutPoint) error` | `lnwallet/btcwallet/btcwallet.go:1034` |
| `ListLeasedOutputs` | `ListLeasedOutputs() ([]*ListLeasedOutputResult, error)` | `lnwallet/btcwallet/btcwallet.go:1025` |
| `CreateSimpleTx` | `CreateSimpleTx(coinSelectKeyScope *waddrmgr.KeyScope, account uint32, outputs []*wire.TxOut, minconf int32, satPerKb btcutil.Amount, strategy CoinSelectionStrategy, dryRun bool, optFuncs ...TxCreateOption) (*txauthor.AuthoredTx, error)` | `lnwallet/btcwallet/btcwallet.go:987` |
| `SendOutputs` | `SendOutputs(outputs []*wire.TxOut, coinSelectKeyScope *waddrmgr.KeyScope, account uint32, minconf int32, satPerKb btcutil.Amount, strategy CoinSelectionStrategy, label string) (*wire.MsgTx, error)` | `lnwallet/btcwallet/btcwallet.go:932` |
| `SendOutputsWithInput` | `SendOutputsWithInput(outputs []*wire.TxOut, coinSelectKeyScope *waddrmgr.KeyScope, account uint32, minconf int32, satPerKb btcutil.Amount, strategy CoinSelectionStrategy, label string, inputs []wire.OutPoint) (*wire.MsgTx, error)` | `lnwallet/btcwallet/btcwallet.go:926` |
| `PublishTransaction` | `PublishTransaction(tx *wire.MsgTx, label string) error` | `lnwallet/btcwallet/btcwallet.go:1155`<br>`lnwallet/btcwallet/btcwallet.go:1174`<br>`lnwallet/btcwallet/btcwallet.go:1194`<br>`lnwallet/btcwallet/btcwallet.go:1228` |
| `FundPsbt` | `FundPsbt(packet *psbt.Packet, keyScope *waddrmgr.KeyScope, minConfs int32, account uint32, feeSatPerKB btcutil.Amount, strategy CoinSelectionStrategy, optFuncs ...TxCreateOption) (int32, error)` | `lnwallet/btcwallet/psbt.go:144` |
| `FinalizePsbt` | `FinalizePsbt(keyScope *waddrmgr.KeyScope, account uint32, packet *psbt.Packet) error` | `lnwallet/btcwallet/psbt.go:607` |
| `DecorateInputs` | `DecorateInputs(packet *psbt.Packet, failOnUnknown bool) error` | `lnwallet/btcwallet/psbt.go:619` |
| `GetTransaction` | `GetTransaction(txHash chainhash.Hash) (*GetTransactionResult, error)` | `lnwallet/btcwallet/btcwallet.go:1386`<br>`lnwallet/btcwallet/btcwallet.go:1890` |
| `GetTransactions` | `GetTransactions(start *BlockIdentifier, end *BlockIdentifier, accountFilter string, txFilter <-chan struct{}) ( *GetTransactionsResult, error)` | `lnwallet/btcwallet/btcwallet.go:1580` |
| `LabelTransaction` | `LabelTransaction(hash chainhash.Hash, label string, overwrite bool) error` | `lnwallet/btcwallet/btcwallet.go:1328` |
| `RemoveDescendants` | `RemoveDescendants(tx *wire.MsgTx) error` | `lnwallet/btcwallet/btcwallet.go:1903` |
| `PrivKeyForAddress` | `PrivKeyForAddress(a address.Address) (*btcec.PrivateKey, error)` | `lnwallet/btcwallet/signer.go:223` |
| `DeriveFromKeyPath` | `DeriveFromKeyPath(scope waddrmgr.KeyScope, path waddrmgr.DerivationPath) (*btcec.PrivateKey, error)` | `lnwallet/btcwallet/signer.go:159` |
| `DeriveFromKeyPathAddAccount` | `DeriveFromKeyPathAddAccount(scope waddrmgr.KeyScope, path waddrmgr.DerivationPath) (*btcec.PrivateKey, error)` | `lnwallet/btcwallet/signer.go:194` |
| `ComputeInputScript` | `ComputeInputScript(tx *wire.MsgTx, output *wire.TxOut, inputIndex int, sigHashes *txscript.TxSigHashes, hashType txscript.SigHashType, tweaker PrivKeyTweaker) (wire.TxWitness, []byte, error)` | `lnwallet/btcwallet/signer.go:392` |
| `ScriptForOutput` | `ScriptForOutput(output *wire.TxOut) (waddrmgr.ManagedPubKeyAddress, []byte, []byte, error)` | `lnwallet/btcwallet/signer.go:71` |

## Direct interface call set

The lnd checkout directly calls 50 methods through a `wallet.Interface`. These calls are the narrowest source-compatibility gate for the SQL port.

- `AccountManagedAddresses`: `lnwallet/btcwallet/btcwallet.go:716`
- `AccountNumber`: `lnwallet/btcwallet/btcwallet.go:470`
- `AccountPropertiesByName`: `lnwallet/btcwallet/btcwallet.go:558`<br>`lnwallet/btcwallet/btcwallet.go:572`<br>`lnwallet/btcwallet/btcwallet.go:590`<br>`lnwallet/btcwallet/psbt.go:636`
- `Accounts`: `lnwallet/btcwallet/btcwallet.go:618`<br>`lnwallet/btcwallet/btcwallet.go:630`<br>`lnwallet/btcwallet/btcwallet.go:639`
- `AddScopeManager`: `lnwallet/btcwallet/btcwallet.go:347`<br>`lnwallet/btcwallet/btcwallet.go:361`
- `AddrManager`: `keychain/btcwallet.go:104`<br>`keychain/btcwallet.go:225`<br>`keychain/btcwallet.go:295`<br>`keychain/btcwallet.go:95`<br>`keychain/btcwallet.go:96`<br>`lnwallet/btcwallet/btcwallet.go:305`<br>`lnwallet/btcwallet/btcwallet.go:341`<br>`lnwallet/btcwallet/btcwallet.go:354`
- `AddressInfo`: `lnwallet/btcwallet/btcwallet.go:542`
- `BirthdayBlock`: `lnwallet/btcwallet/btcwallet.go:1832`
- `ChainParams`: `lnwallet/btcwallet/btcwallet.go:1699`<br>`lnwallet/btcwallet/btcwallet.go:1720`
- `ChainSynced`: `lnwallet/btcwallet/btcwallet.go:1781`
- `ComputeInputScript`: `lnwallet/btcwallet/signer.go:392`
- `CreateSimpleTx`: `lnwallet/btcwallet/btcwallet.go:987`
- `CurrentAddress`: `lnwallet/btcwallet/btcwallet.go:524`
- `Database`: `keychain/btcwallet.go:151`<br>`keychain/btcwallet.go:211`<br>`keychain/btcwallet.go:286`
- `DecorateInputs`: `lnwallet/btcwallet/psbt.go:619`
- `DeriveFromKeyPath`: `lnwallet/btcwallet/signer.go:159`
- `DeriveFromKeyPathAddAccount`: `lnwallet/btcwallet/signer.go:194`
- `FetchDerivationInfo`: `lnwallet/btcwallet/signer.go:62`
- `FetchOutpointInfo`: `lnwallet/btcwallet/signer.go:31`
- `FinalizePsbt`: `lnwallet/btcwallet/psbt.go:607`
- `FundPsbt`: `lnwallet/btcwallet/psbt.go:144`
- `GetTransaction`: `lnwallet/btcwallet/btcwallet.go:1386`<br>`lnwallet/btcwallet/btcwallet.go:1890`
- `GetTransactions`: `lnwallet/btcwallet/btcwallet.go:1580`
- `HaveAddress`: `lnwallet/btcwallet/btcwallet.go:531`
- `ImportAccount`: `lnwallet/btcwallet/btcwallet.go:832`
- `ImportAccountDryRun`: `lnwallet/btcwallet/btcwallet.go:844`
- `ImportPublicKey`: `lnwallet/btcwallet/btcwallet.go:875`
- `ImportTaprootScript`: `lnwallet/btcwallet/btcwallet.go:893`
- `InitAccounts`: `lnwallet/btcwallet/btcwallet.go:381`
- `LabelTransaction`: `lnwallet/btcwallet/btcwallet.go:1328`
- `LeaseOutput`: `lnwallet/btcwallet/btcwallet.go:1013`
- `ListLeasedOutputs`: `lnwallet/btcwallet/btcwallet.go:1025`
- `ListUnspent`: `lnwallet/btcwallet/btcwallet.go:1053`<br>`lnwallet/btcwallet/btcwallet.go:699`
- `LockedOutpoint`: `lnwallet/btcwallet/btcwallet.go:1009`
- `NewAddress`: `lnwallet/btcwallet/btcwallet.go:501`
- `NewChangeAddress`: `lnwallet/btcwallet/btcwallet.go:499`
- `NotificationServer`: `lnwallet/btcwallet/btcwallet.go:1746`
- `PrivKeyForAddress`: `lnwallet/btcwallet/signer.go:223`
- `PublishTransaction`: `lnwallet/btcwallet/btcwallet.go:1155`<br>`lnwallet/btcwallet/btcwallet.go:1174`<br>`lnwallet/btcwallet/btcwallet.go:1194`<br>`lnwallet/btcwallet/btcwallet.go:1228`
- `ReleaseOutput`: `lnwallet/btcwallet/btcwallet.go:1034`
- `RemoveDescendants`: `lnwallet/btcwallet/btcwallet.go:1903`
- `ScriptForOutput`: `lnwallet/btcwallet/signer.go:71`
- `SendOutputs`: `lnwallet/btcwallet/btcwallet.go:932`
- `SendOutputsWithInput`: `lnwallet/btcwallet/btcwallet.go:926`
- `Start`: `lnwallet/btcwallet/btcwallet.go:393`
- `Stop`: `lnwallet/btcwallet/btcwallet.go:407`
- `SyncedTo`: `lnwallet/btcwallet/btcwallet.go:1384`<br>`lnwallet/btcwallet/btcwallet.go:1574`<br>`lnwallet/btcwallet/btcwallet.go:1690`<br>`lnwallet/btcwallet/btcwallet.go:1767`<br>`lnwallet/btcwallet/btcwallet.go:1845`
- `SynchronizeRPC`: `lnwallet/btcwallet/btcwallet.go:397`
- `Unlock`: `lnwallet/btcwallet/btcwallet.go:321`
- `WaitForShutdown`: `lnwallet/btcwallet/btcwallet.go:409`


## Concrete wallet package methods referenced by lnd

Outside `wallet.Interface`, lnd calls 15 exported methods on concrete types from the wallet package. These are compatibility constraints too, in particular the loader and the concrete `Wallet` passed through lnd's unlock path.

| Method | Non-test Go references | `_test.go` references |
| --- | --- | --- |
| `CoinSelectionStrategy.ArrangeCoins` | `lnwallet/chanfunding/coin_select.go:79` | none |
| `Loader.CreateNewWallet` | `config_builder.go:1507`<br>`lnwallet/btcwallet/btcwallet.go:148` | `keychain/interface_test.go:53`<br>`walletunlocker/service_test.go:81` |
| `Loader.CreateNewWalletExtendedKey` | `config_builder.go:1516` | none |
| `Loader.CreateNewWatchingOnlyWallet` | `config_builder.go:1531` | none |
| `Loader.OnWalletCreated` | `lnwallet/btcwallet/btcwallet.go:243` | none |
| `Loader.OpenExistingWallet` | `lnwallet/btcwallet/btcwallet.go:159`<br>`walletunlocker/service.go:649`<br>`walletunlocker/service.go:687`<br>`walletunlocker/service.go:788` | none |
| `Loader.UnloadWallet` | `config_builder.go:1551`<br>`config_builder.go:1570`<br>`walletunlocker/service.go:668`<br>`walletunlocker/service.go:693`<br>`walletunlocker/service.go:798`<br>`walletunlocker/service.go:895` | `walletunlocker/service_test.go:85` |
| `Loader.WalletExists` | `lnwallet/btcwallet/btcwallet.go:140`<br>`walletunlocker/service.go:265`<br>`walletunlocker/service.go:286`<br>`walletunlocker/service.go:427`<br>`walletunlocker/service.go:638`<br>`walletunlocker/service.go:763` | none |
| `NotificationServer.TransactionNotifications` | `lnwallet/btcwallet/btcwallet.go:1746` | none |
| `TransactionNotificationsClient.Done` | `lnwallet/btcwallet/btcwallet.go:1676` | none |
| `Wallet.ChangePassphrases` | `walletunlocker/service.go:824` | none |
| `Wallet.Database` | `lnwallet/btcwallet/btcwallet.go:169`<br>`walletunlocker/service.go:662` | `keychain/interface_test.go:76` |
| `Wallet.ImportAccountWithScope` | `config_builder.go:1644` | none |
| `Wallet.Lock` | none | `keychain/interface_test.go:90` |
| `Wallet.Unlock` | none | `keychain/interface_test.go:60` |

## Wallet package-level identifiers referenced by lnd

Across the lnd checkout, Go files reference 25 exported package-level identifiers from `github.com/btcsuite/btcwallet/wallet`. The non-test and `_test.go` columns are kept separate because both matter, but only non-test references constrain an lnd binary build.

| Symbol | Non-test Go references | `_test.go` references |
| --- | --- | --- |
| `Block` | `lnwallet/btcwallet/btcwallet.go:1397`<br>`lnwallet/btcwallet/btcwallet.go:1420` | none |
| `Coin` | `lnwallet/chanfunding/coin_select.go:177`<br>`lnwallet/chanfunding/coin_select.go:179`<br>`lnwallet/chanfunding/coin_select.go:298`<br>`lnwallet/chanfunding/coin_select.go:301`<br>`lnwallet/chanfunding/coin_select.go:364`<br>`lnwallet/chanfunding/coin_select.go:367`<br>`lnwallet/chanfunding/coin_select.go:442`<br>`lnwallet/chanfunding/coin_select.go:72`<br>`lnwallet/chanfunding/coin_select.go:74`<br>`lnwallet/chanfunding/coin_select.go:98`<br>`lnwallet/chanfunding/interface.go:21`<br>`lnwallet/chanfunding/interface.go:26`<br>`lnwallet/chanfunding/wallet_assembler.go:302`<br>`lnwallet/chanfunding/wallet_assembler.go:307`<br>`lnwallet/chanfunding/wallet_assembler.go:355`<br>`lnwallet/chanfunding/wallet_assembler.go:356`<br>`lnwallet/chanfunding/wallet_assembler.go:403`<br>`lnwallet/chanfunding/wallet_assembler.go:570`<br>`lnwallet/chanfunding/wallet_assembler.go:571`<br>`lnwallet/chanfunding/wallet_assembler.go:573`<br>`lnwallet/chanfunding/wallet_assembler.go:59`<br>`lnwallet/wallet.go:2708`<br>`lnwallet/wallet.go:2717`<br>`lnwallet/wallet.go:2730`<br>`lnwallet/wallet.go:2745`<br>`lnwallet/wallet.go:2751` | `lnwallet/chanfunding/coin_select_test.go:109`<br>`lnwallet/chanfunding/coin_select_test.go:161`<br>`lnwallet/chanfunding/coin_select_test.go:175`<br>`lnwallet/chanfunding/coin_select_test.go:199`<br>`lnwallet/chanfunding/coin_select_test.go:217`<br>`lnwallet/chanfunding/coin_select_test.go:242`<br>`lnwallet/chanfunding/coin_select_test.go:269`<br>`lnwallet/chanfunding/coin_select_test.go:287`<br>`lnwallet/chanfunding/coin_select_test.go:491`<br>`lnwallet/chanfunding/coin_select_test.go:505`<br>`lnwallet/chanfunding/coin_select_test.go:526`<br>`lnwallet/chanfunding/coin_select_test.go:547`<br>`lnwallet/chanfunding/coin_select_test.go:565`<br>`lnwallet/chanfunding/coin_select_test.go:584`<br>`lnwallet/chanfunding/coin_select_test.go:604`<br>`lnwallet/chanfunding/coin_select_test.go:624`<br>`lnwallet/chanfunding/coin_select_test.go:67`<br>`lnwallet/chanfunding/coin_select_test.go:727`<br>`lnwallet/chanfunding/coin_select_test.go:740`<br>`lnwallet/chanfunding/coin_select_test.go:758`<br>`lnwallet/chanfunding/coin_select_test.go:776`<br>`lnwallet/chanfunding/coin_select_test.go:77`<br>`lnwallet/chanfunding/coin_select_test.go:795`<br>`lnwallet/chanfunding/coin_select_test.go:814`<br>`lnwallet/chanfunding/coin_select_test.go:831`<br>`lnwallet/chanfunding/coin_select_test.go:854`<br>`lnwallet/chanfunding/coin_select_test.go:872`<br>`lnwallet/chanfunding/coin_select_test.go:93` |
| `CoinSelectionLargest` | `config_builder.go:685`<br>`lnrpc/marshall_utils.go:211`<br>`lnwallet/test/test_interface.go:3155`<br>`lnwallet/test/test_interface.go:334` | `funding/manager_test.go:395`<br>`lnwallet/chanfunding/coin_select_test.go:316`<br>`lnwallet/chanfunding/coin_select_test.go:653`<br>`lnwallet/chanfunding/coin_select_test.go:899` |
| `CoinSelectionRandom` | `config_builder.go:688`<br>`lnrpc/marshall_utils.go:214` | none |
| `CoinSelectionStrategy` | `lnrpc/marshall_utils.go:203`<br>`lnrpc/marshall_utils.go:204`<br>`lntest/mock/walletcontroller.go:150`<br>`lntest/mock/walletcontroller.go:158`<br>`lntest/mock/walletcontroller.go:218`<br>`lnwallet/btcwallet/btcwallet.go:908`<br>`lnwallet/btcwallet/btcwallet.go:953`<br>`lnwallet/btcwallet/config.go:73`<br>`lnwallet/btcwallet/psbt.go:81`<br>`lnwallet/chanfunding/coin_select.go:177`<br>`lnwallet/chanfunding/coin_select.go:299`<br>`lnwallet/chanfunding/coin_select.go:365`<br>`lnwallet/chanfunding/coin_select.go:73`<br>`lnwallet/chanfunding/wallet_assembler.go:244`<br>`lnwallet/config.go:65`<br>`lnwallet/interface.go:359`<br>`lnwallet/interface.go:375`<br>`lnwallet/interface.go:496`<br>`lnwallet/mock.go:161`<br>`lnwallet/mock.go:169`<br>`lnwallet/mock.go:231`<br>`lnwallet/rpcwallet/rpcwallet.go:127`<br>`rpcserver.go:1133` | none |
| `DropTransactionHistory` | `walletunlocker/service.go:661` | none |
| `ErrTxLabelExists` | none | `itest/lnd_misc_test.go:814` |
| `ErrTxUnsigned` | `lnwallet/rpcwallet/rpcwallet.go:132` | none |
| `Interface` | `keychain/btcwallet.go:51`<br>`keychain/btcwallet.go:67`<br>`lnwallet/btcwallet/btcwallet.go:1647`<br>`lnwallet/btcwallet/btcwallet.go:294`<br>`lnwallet/btcwallet/btcwallet.go:90` | none |
| `ListLeasedOutputResult` | `lntest/mock/walletcontroller.go:210`<br>`lnwallet/btcwallet/btcwallet.go:1022`<br>`lnwallet/interface.go:433`<br>`lnwallet/mock.go:223` | none |
| `Loader` | `lnwallet/btcwallet/btcwallet.go:216`<br>`walletunlocker/service.go:250` | none |
| `NewBlockIdentifierFromHeight` | `lnwallet/btcwallet/btcwallet.go:1578`<br>`lnwallet/btcwallet/btcwallet.go:1579` | none |
| `NewLoader` | `lnwallet/btcwallet/btcwallet.go:247` | `keychain/interface_test.go:47`<br>`walletunlocker/service_test.go:78` |
| `NewLoaderWithDB` | `lnwallet/btcwallet/btcwallet.go:231` | none |
| `PsbtPrevOutputFetcher` | `lnwallet/btcwallet/psbt.go:178`<br>`lnwallet/rpcwallet/rpcwallet.go:272` | none |
| `TransactionNotifications` | `lnwallet/btcwallet/btcwallet.go:1695`<br>`lnwallet/btcwallet/btcwallet.go:1717` | none |
| `TransactionNotificationsClient` | `lnwallet/btcwallet/btcwallet.go:1642` | none |
| `TransactionSummary` | `lnwallet/btcwallet/btcwallet.go:1334`<br>`lnwallet/btcwallet/btcwallet.go:1398`<br>`lnwallet/btcwallet/btcwallet.go:1494` | none |
| `TransactionSummaryInput` | `lnwallet/btcwallet/btcwallet.go:1354` | `lnwallet/btcwallet/btcwallet_test.go:107`<br>`lnwallet/btcwallet/btcwallet_test.go:20`<br>`lnwallet/btcwallet/btcwallet_test.go:33`<br>`lnwallet/btcwallet/btcwallet_test.go:54`<br>`lnwallet/btcwallet/btcwallet_test.go:75`<br>`lnwallet/btcwallet/btcwallet_test.go:92` |
| `TxCreateOption` | `lnwallet/btcwallet/btcwallet.go:989`<br>`lnwallet/btcwallet/psbt.go:134` | none |
| `UseLogger` | `lnwallet/btcwallet/log.go:36` | none |
| `Wallet` | `config_builder.go:1500`<br>`config_builder.go:1608`<br>`lnwallet/btcwallet/config.go:66`<br>`walletunlocker/service.go:163`<br>`walletunlocker/service.go:50`<br>`walletunlocker/service.go:630` | `keychain/interface_test.go:33` |
| `WithCustomChangeScope` | `lnwallet/btcwallet/psbt.go:136` | none |
| `WithCustomSelectUtxos` | `lnwallet/btcwallet/btcwallet.go:985` | none |
| `WithUtxoFilter` | `lnwallet/btcwallet/psbt.go:139` | none |

## Audit boundary

The lnd scan uses Go type information, then separates `_test.go` references from other Go files. It does not claim to find reflection, generated code outside the checkout, or downstream users other than lnd. The port gate should still compile unmodified lnd against each candidate btcwallet tip.
