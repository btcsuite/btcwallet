# Wallet AGENTS.md

This is the knowledge base for the `wallet/` core subsystem. The subsystem
  contains the business logic, builds transactions, and manages the wallet
  state.

## RESPONSIBILITIES
- **Manager/Controller:** Control the top-level wallet operations
  (`manager.go`, `controller.go`).
- **Syncer/State:** Synchronize with the blockchain and keep the lifecycle
  state (`syncer.go`, `state.go`).
- **TX Creation:** Create, sign, and publish transactions (`tx_creator.go`,
  `signer.go`, `tx_publisher.go`).
- **PSBT:** Manage Partially Signed Bitcoin Transactions (`psbt_manager.go`).
- **Key Manager Interface:** Connect to `waddrmgr` for HD key derivation and
  address information (`address_manager.go`).

## WHERE TO LOOK
| Task                 | Core Files                                        |
|:---------------------|:--------------------------------------------------|
| Lifecycle/Start/Stop | `wallet.go`, `controller.go`, `state.go`          |
| Sending/Creating TXs | `tx_creator.go`, `signer.go`, `txauthor/`         |
| Syncing/Scanning     | `syncer.go`, `recovery.go`, `notifications.go`    |
| Balance/UTXOs        | `utxo_manager.go`, `tx_reader.go`, `tx_writer.go` |
| Compatibility        | `deprecated.go` (large legacy JSON-RPC logic)     |

## LOCAL CONVENTIONS
- **Deprecated Layer:** Do not add new logic to `deprecated.go`. This file is
  a stability boundary for the legacy JSON-RPC server. New features should go
  in separate managers or controllers.
- **Dependency Injection:** Prefer to pass interfaces such as
  `chain.Interface` and `db.Store`, so that tests can use mocks.
- **Concurrency:** `requestChan` and `mainLoop` serialize the primary
  lifecycle requests and the sensitive authentication requests. Background
  tasks use `lifetimeCtx` for a clean shutdown. `walletState` uses atomic
  primitives for thread-safe status checks.
- **Notifications:** External events go through `notifications.go`. Use the
  `Chain` interface to register for block and transaction events.

## TESTING FOCUS
- **Unit Tests:** Unit tests are next to the code. For BDB-backed tests, use
  `setupTestDB` from `common_test.go`.
- **Mocking:** For isolated logic tests, use `mockWalletDeps` and
  `createTestWalletWithMocks`.
- **Scrypt Speed:** Tests set `waddrmgr.FastScryptOptions` in `init()` to
  prevent timeouts.
- **Regression:** Use Arrange, Act, Assert. Use `t.Cleanup` to remove
  temporary DBs.

## ADJACENT SUBSYSTEMS
- `wallet/internal/db/`: The persistence layer for the wallet core.
- `waddrmgr/`: The source of truth for BIP32/BIP44 keys and addresses.
- `chain/`: The client connection to the blockchain backend.
- `rpc/legacyrpc/`: Uses `wallet/deprecated.go` to give the legacy API.
