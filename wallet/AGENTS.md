# Wallet AGENTS.md

This is the knowledge base for the `wallet/` core subsystem. It handles business
  logic, transaction construction, and wallet state management.

## RESPONSIBILITIES
- **Manager/Controller:** Orchestrates top-level wallet operations
  (`manager.go`, `controller.go`).
- **Syncer/State:** Handles blockchain synchronization and life-cycle state
  (`syncer.go`, `state.go`).
- **TX Creation:** Logic for creating, signing, and publishing transactions
  (`tx_creator.go`, `signer.go`, `tx_publisher.go`).
- **PSBT:** Management of Partially Signed Bitcoin Transactions
  (`psbt_manager.go`).
- **Key Manager Interface:** High-level bridge to `waddrmgr` for HD key
  derivation and address info (`address_manager.go`).

## WHERE TO LOOK
| Task                 | Core Files                                        |
|:---------------------|:--------------------------------------------------|
| Lifecycle/Start/Stop | `wallet.go`, `controller.go`, `state.go`          |
| Sending/Creating TXs | `tx_creator.go`, `signer.go`, `txauthor/`         |
| Syncing/Scanning     | `syncer.go`, `recovery.go`, `notifications.go`    |
| Balance/UTXOs        | `utxo_manager.go`, `tx_reader.go`, `tx_writer.go` |
| Compatibility        | `deprecated.go` (large legacy JSON-RPC logic)     |

## LOCAL CONVENTIONS
- **Deprecated Layer:** Avoid adding new logic to `deprecated.go`. It acts as a
  stability boundary for the legacy JSON-RPC server. New features should live in
  discrete managers or controllers.
- **Dependency Injection:** Prefer passing interfaces like `chain.Interface`
  and `db.Store` to allow mocking.
- **Concurrency:** Primary lifecycle and sensitive authentication requests are
  serialized via `requestChan` and `mainLoop`. Background tasks respect
  `lifetimeCtx` for clean shutdowns, and `walletState` uses atomic primitives
  for thread-safe status checks.
- **Notifications:** External events flow through `notifications.go`. Use the
  `Chain` interface to register for block and transaction events.

## TESTING FOCUS
- **Unit Tests:** Live alongside code. Use `setupTestDB` from `common_test.go`
  for BDB-backed tests.
- **Mocking:** Leverage `mockWalletDeps` and `createTestWalletWithMocks` for
  isolated logic testing.
- **Scrypt Speed:** Tests use `waddrmgr.FastScryptOptions` in `init()` to avoid
  timeouts.
- **Regression:** Follow Arrange, Act, Assert. Ensure tests clean up temporary
  DBs using `t.Cleanup`.

## ADJACENT SUBSYSTEMS
- `wallet/internal/db/`: The persistence layer for the wallet core.
- `waddrmgr/`: The source of truth for BIP32/BIP44 keys and addresses.
- `chain/`: Provides the client connection to the blockchain backend.
- `rpc/legacyrpc/`: Consumes `wallet/deprecated.go` to provide the legacy API.
