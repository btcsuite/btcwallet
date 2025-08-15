# wallet

[![Build Status](https://travis-ci.org/btcsuite/btcwallet.png?branch=master)](https://travis-ci.org/btcsuite/btcwallet)[![GoDoc](https://godoc.org/github.com/btcsuite/btcwallet/wallet?status.png)](http://godoc.org/github.com/btcsuite/btcwallet/wallet)

## Overview

The `wallet` package serves as the high-level orchestrator for all core wallet functionality. It provides a unified, high-level API for wallet operations, abstracting away the underlying details of key management, transaction management, and blockchain interaction.

For a detailed overview of the package's design and architecture, please see the [architecture documentation](./ARCHITECTURE.md).

## Architecture

The package is designed around two core principles:

1.  **Actor Model**: The `Wallet` is a self-contained, concurrent unit that manages its own state and communicates via messages, ensuring thread safety without complex locking.
2.  **Interface-Driven Design**: Functionality is exposed through a set of small, role-based interfaces, allowing consumers to depend only on the features they need.

### Provided Interfaces

-   **`WalletController`**: Manages the wallet's lifecycle (Start, Stop, Lock, Unlock) and provides high-level status information.
-   **`AccountManager`**: Handles the creation, querying, and renaming of accounts, and is also responsible for querying account-specific or total wallet balances.
-   **`AddressManager`**: Manages the generation, import, and inspection of addresses and scripts.
-   **`UtxoManager`**: Manages the wallet's UTXO set, including listing unspent outputs and managing UTXO leases.
-   **`TxPublisher`**: A command-oriented interface for all "write" operations related to transactions, such as creating and broadcasting them.
-   **`TxReader`**: A query-oriented interface for all "read" operations related to transaction history.
-   **`PsbtManager`**: A dedicated interface for the multi-step PSBT workflow (Fund, Sign, Finalize).
-   **`Signer`**: A low-level interface providing direct access to cryptographic operations like signing and key derivation.

### Required Interfaces

The `wallet` package depends on the following key interfaces for its operation:

-   **`wallet.Store`**: An interface that abstracts all database operations, allowing for different backend implementations (e.g., key-value or SQL).
-   **`chain.ChainQuery`**: A read-only interface for fetching data from the blockchain.
-   **`chain.ChainIO`**: A write-only interface for broadcasting transactions.
-   **`ntfn.Notifier`**: A high-level, stateful service for receiving on-chain event notifications.

## Installation

```bash
$ go get github.com/btcsuite/btcwallet/wallet
```
