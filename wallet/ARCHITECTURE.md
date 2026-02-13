# Wallet Package Architecture

The `wallet` package serves as the high-level orchestrator for all core wallet functionality. It integrates key management (`waddrmgr`), transaction management (`wtxmgr`), and blockchain interaction (`chain`) to provide a unified, high-level API for wallet operations.

## Core Responsibilities

1.  **High-Level Wallet API**: Expose a clean, intuitive, and stable API for common wallet operations through a set of small, role-based interfaces.
2.  **Orchestration**: Coordinate the complex interactions between the address manager, the transaction store, and the blockchain backend.
3.  **State Management**: Manage the wallet's state, including its lock status and synchronization with the blockchain, in a robust and concurrency-safe manner.
4.  **Decoupling from Storage**: Ensure that the wallet's business logic is completely independent of the underlying database technology.

## Architectural Design: The `Wallet` Actor

Following the project's core philosophy, the `Wallet` is designed as an **actor**—a self-contained, concurrent unit that manages its own state and communicates via messages.

-   **State Ownership**: The `Wallet` actor is the sole owner of the `waddrmgr.Manager` and `wtxmgr.Store` instances. All access to these critical components **MUST** go through the `Wallet` actor's API. This serializes all state-mutating operations, ensuring data consistency without the need for complex, fine-grained locking.
-   **Command Processing**: The public methods of the `Wallet` will not perform complex logic directly. Instead, they will send a command message to the actor's internal message loop (its "mailbox") and wait for a response. This ensures that all operations are processed sequentially and safely.

## Decoupling from the Database via the Repository Pattern

A critical architectural goal is to decouple the wallet's logic from the specifics of the database backend. This is essential for achieving the goal of migrating to a SQL database.

-   **The `Store` Interface**: We will define a `Store` (or `Repository`) interface that abstracts all database operations required by `waddrmgr` and `wtxmgr`. This interface will be designed with a relational model in mind, featuring methods like `CreateTransaction`, `GetAddress`, `ListUnspentOutputs`, etc., rather than low-level `Get`/`Put` calls.
-   **Interface-Based Logic**: The `Wallet` actor and its components (`waddrmgr`, `wtxmgr`) will be refactored to depend *only* on this `Store` interface, not on `walletdb` directly.
-   **Concrete Implementations**: We will provide two concrete implementations of the `Store` interface:
    1.  **`KVStore`**: An implementation that adapts the existing `walletdb` (BoltDB) backend to the new interface.
    2.  **`SQLStore`**: The new implementation that uses a SQL database as its backend.

## Interface-Driven Design: Role-Based Interfaces

The `wallet` package exposes a set of small, role-based interfaces based on the domain objects they manage. This adheres to the Interface Segregation Principle and the Single Responsibility Principle, making the API safer, more modular, and easier to consume. A single concrete `Wallet` struct will implement all of these interfaces, but consumers of the package should depend only on the narrowest interface they need.

### `WalletController`
*Manages the wallet's operational state, lifecycle, and connection to the blockchain.*
```go
// WalletController provides an interface for managing the wallet's lifecycle and state.
type WalletController interface {
    // Start starts the goroutines necessary to manage a wallet.
    Start()

    // Stop signals all wallet goroutines to shutdown and blocks until
    // they have all exited.
    Stop()

    // Unlock unlocks the wallet with a passphrase.
    Unlock(ctx context.Context, passphrase []byte, lock <-chan time.Time) error

    // Lock locks the wallet.
    Lock()

    // Info returns a struct containing static information about the wallet.
    Info(ctx context.Context) (*WalletInfo, error)

    // Status returns the current synchronization and recovery state of the wallet.
    Status(ctx context.Context) (*SyncStatus, error)
}
```

### `AccountManager`
*Handles the creation, querying, and modification of wallet accounts and their balances.*
```go
// AccountManager provides an interface for managing wallet accounts and their balances.
type AccountManager interface {
    // ListAccounts lists all accounts for a particular key scope.
    ListAccounts(ctx context.Context, scope waddrmgr.KeyScope) (*base.AccountsResult, error)

    // GetAccountByName returns the properties for a specific account, looked up by its name.
    GetAccountByName(ctx context.Context, scope waddrmgr.KeyScope, name string) (*waddrmgr.AccountProperties, error)

    // GetAccountByNumber returns the properties for a specific account, looked up by its number.
    GetAccountByNumber(ctx context.Context, scope waddrmgr.KeyScope, number uint32) (*waddrmgr.AccountProperties, error)

    // RenameAccount renames an existing account.
    RenameAccount(ctx context.Context, scope waddrmgr.KeyScope, account uint32, newName string) error

    // ImportAccount imports a watch-only account from an extended public key.
    // If dryRun is true, the import is validated but not persisted.
    ImportAccount(ctx context.Context, name string, accountPubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32, addrType *waddrmgr.AddressType, dryRun bool) (*waddrmgr.AccountProperties, error)

    // Balance returns the wallet's total balance for a given confirmation depth and account.
    Balance(ctx context.Context, requiredConfirmations int32, accountName string) (btcutil.Amount, error)
}
```

### `AddressManager`
*For generating, importing, and inspecting addresses and scripts.*
```go
// AddressManager provides an interface for generating and inspecting wallet addresses and scripts.
type AddressManager interface {
    // NewAddress returns a new, unused address for the given account and scope. The `change`
    // parameter dictates whether a change address or a receiving address should be
    // generated.
    NewAddress(ctx context.Context, account uint32, scope waddrmgr.KeyScope, change bool) (btcutil.Address, error)

    // ListUnusedAddresses returns a list of all addresses that have not yet received funds.
    ListUnusedAddresses(ctx context.Context, account uint32, scope waddrmgr.KeyScope) ([]btcutil.Address, error)

    // AddressInfo returns detailed information about a managed address. If the
    // address is not known to the wallet, an error is returned.
    AddressInfo(ctx context.Context, a btcutil.Address) (waddrmgr.ManagedAddress, error)

    // ListAddresses lists all addresses for a given account, including their balances.
    ListAddresses(ctx context.Context, account uint32, scope waddrmgr.KeyScope) ([]AddressProperty, error)

    // ImportPublicKey imports a single public key as a watch-only address.
    ImportPublicKey(ctx context.Context, pubKey *btcec.PublicKey, addrType waddrmgr.AddressType) error

    // ImportTaprootScript imports a taproot script for tracking and spending.
    ImportTaprootScript(ctx context.Context, scope waddrmgr.KeyScope, tapscript *waddrmgr.Tapscript) (waddrmgr.ManagedAddress, error)

    // ScriptForOutput returns the address, witness program, and redeem script for a given UTXO.
    ScriptForOutput(ctx context.Context, output *wire.TxOut) (waddrmgr.ManagedPubKeyAddress, []byte, []byte, error)
}
```

### `UtxoManager`
*For querying wallet balance and managing the UTXO set.*
```go
// UtxoManager provides an interface for querying and managing the wallet's UTXO set.
type UtxoManager interface {
    // ListUnspent returns all unspent transaction outputs. An optional filter can be provided
    // to only include witness outputs.
    ListUnspent(ctx context.Context, minconf, maxconf int32, accountName string, witnessOnly bool) ([]*Utxo, error)

    // GetUtxoInfo returns the output information for a given outpoint.
    GetUtxoInfo(ctx context.Context, prevOut *wire.OutPoint) (*Utxo, error)

    // LeaseOutput locks an output for a given duration.
    LeaseOutput(ctx context.Context, id wtxmgr.LockID, op wire.OutPoint, duration time.Duration) (time.Time, error)

    // ReleaseOutput unlocks a previously leased output.
    ReleaseOutput(ctx context.Context, id wtxmgr.LockID, op wire.OutPoint) error

    // ListLeasedOutputs returns a list of all currently leased outputs.
    ListLeasedOutputs(ctx context.Context) ([]*base.ListLeasedOutputResult, error)
}
```

### `TxPublisher`
*High-level methods for building and broadcasting transactions.*
```go
// TxPublisher provides a high-level interface for creating and broadcasting transactions.
type TxPublisher interface {
    // SendOutputs funds, signs, and broadcasts a transaction paying to the
    // specified outputs. If inputs are provided, they will be used as the
    // transaction's inputs; otherwise, coin selection will be performed.
    SendOutputs(ctx context.Context, outputs []*wire.TxOut, feeRate SatPerKWeight, minConfs int32, label string, strategy base.CoinSelectionStrategy, inputs []*wire.OutPoint) (*wire.MsgTx, error)

    // CreateTransaction creates a signed transaction paying to the specified
    // outputs. The transaction is not broadcast to the network.
    CreateTransaction(ctx context.Context, outputs []*wire.TxOut, feeRate SatPerKWeight, minConfs int32, strategy base.CoinSelectionStrategy, dryRun bool) (*txauthor.AuthoredTx, error)

    // PublishTransaction broadcasts a transaction to the network.
    PublishTransaction(ctx context.Context, tx *wire.MsgTx, label string) error

    // CheckMempoolAcceptance checks if a transaction would be accepted by the
    // mempool without broadcasting.
    CheckMempoolAcceptance(ctx context.Context, tx *wire.MsgTx) error
}
```

### `PsbtManager`
*Provides a workflow for creating and signing transactions via the PSBT standard.*
```go
// PsbtManager provides an interface for managing Partially Signed Bitcoin Transactions (PSBTs).
type PsbtManager interface {
    // FundPsbt adds inputs and a change output to a PSBT to fund the specified outputs.
    FundPsbt(ctx context.Context, packet *psbt.Packet, minConfs int32, feeRate SatPerKWeight, account uint32, keyScope *waddrmgr.KeyScope, strategy base.CoinSelectionStrategy) (int32, error)

    // SignPsbt signs all unsigned inputs of a PSBT that are in the wallet.
    SignPsbt(ctx context.Context, packet *psbt.Packet) error

    // FinalizePsbt signs and finalizes a PSBT.
    FinalizePsbt(ctx context.Context, packet *psbt.Packet, account uint32, keyScope *waddrmgr.KeyScope) error

    // DecorateInputs adds UTXO and derivation information to a PSBT's inputs.
    DecorateInputs(ctx context.Context, packet *psbt.Packet, failOnUnknown bool) error
}
```

### `TxReader`
*For querying and managing the wallet's transaction history.*
```go
// TxReader provides an interface for querying transaction history.
type TxReader interface {
    // GetTxDetails returns a detailed description of a transaction
    // given its transaction hash.
    GetTxDetails(ctx context.Context, txHash *chainhash.Hash) (*TransactionDetail, error)

    // ListTxDetails returns a list of all transactions which are
    // relevant to the wallet over a given block range.
    ListTxDetails(ctx context.Context, startHeight, endHeight int32, accountFilter string) ([]*TransactionDetail, error)

    // LabelTx adds a label to a transaction.
    LabelTx(ctx context.Context, hash chainhash.Hash, label string, overwrite bool) error

    // FetchTx attempts to fetch a transaction in the wallet's database.
    FetchTx(ctx context.Context, txHash *chainhash.Hash) (*wire.MsgTx, error)

    // TODO: This is a legacy method that should be removed in favor
    // of a more robust notification system.
    // SubscribeTxes returns a TransactionSubscription client which
    // is capable of receiving async notifications as new transactions
    // related to the wallet are seen within the network, or found in
    // blocks.
    SubscribeTxes() (TransactionSubscription, error)
}
```

### `Signer`
*Provides direct access to cryptographic operations and are primarily used by higher-level protocols like Lightning.*
```go
// Signer provides an interface for low-level cryptographic operations,
// including signing and key derivation. This interface should be used with
// caution as it provides access to sensitive key material.
type Signer interface {
    // SignOutputRaw generates a raw signature for a single transaction input.
    SignOutputRaw(ctx context.Context, tx *wire.MsgTx, signDesc *input.SignDescriptor) (input.Signature, error)

    // ComputeInputScript generates the full sigScript and witness required to
    // spend a UTXO.
    ComputeInputScript(ctx context.Context, tx *wire.MsgTx, signDesc *input.SignDescriptor) (*input.Script, error)

    // SignMessage signs an arbitrary message with a key from the wallet.
    SignMessage(ctx context.Context, keyLoc KeyLocator, msg []byte, doubleHash bool) (*ecdsa.Signature, error)

    // FetchDerivationInfo returns the BIP-32 derivation path for a given
    // output script.
    FetchDerivationInfo(ctx context.Context, pkScript []byte) (*psbt.Bip32Derivation, error)

    // DerivePrivKey derives a private key from a BIP-32 derivation path.
    DerivePrivKey(ctx context.Context, path waddrmgr.DerivationPath) (*btcec.PrivateKey, error)

    // PrivKeyForAddress returns the private key for a given address.
    // DANGER: This method should be used with extreme care, as it exports
    // sensitive key material.
    PrivKeyForAddress(ctx context.Context, a btcutil.Address) (*btcec.PrivateKey, error)
}
```

## Chain and Notification Architecture

The wallet's interaction with the blockchain is managed by a new two-tiered architecture that separates low-level, stateless I/O from high-level, stateful notification management. This is composed of the `chain` and `ntfn` packages, which are detailed in their respective `ARCHITECTURE.md` files.

## Key Architectural Decisions

The new architecture is guided by several key decisions:

-   **Hybrid "Push" Notification Model**: The system is primarily asynchronous, with the `ntfn.Notifier` pushing events to clients. However, registration methods provide an immediate, synchronous check of the notifier's current state to support linear client workflows.

-   **"Subscribe-First, Sync-Later" Startup**: To eliminate race conditions, all subsystems must subscribe to the `ntfn.Notifier` *before* the `chain.Driver` is started and begins processing blocks.

-   **Dependency Inversion for Drivers**: The low-level `chain.Driver` depends on a `ChainEventReceiver` interface, which is implemented by the high-level `ntfn.Notifier`. This creates a clean, decoupled boundary.

-   **Stateless and Opaque Drivers**: All `chain.Driver` implementations must be stateless, with all stateful logic (queues, reorg tracking) pushed up to the `ntfn` layer. They must also encapsulate backend-specific complexity and return a standard set of typed, exported errors.
