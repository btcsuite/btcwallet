# ntfn

## Overview

The `ntfn` package provides a high-level, stateful notification service for on-chain events. It is built on top of the low-level, stateless `chain` package and is responsible for all the complex logic of managing reorgs, historical dispatches, and ensuring exactly-once delivery of notifications to clients like `wallet` and `lnd`.

For a detailed overview of the package's design and architecture, please see the [architecture documentation](./ARCHITECTURE.md).

## Architecture

The `ntfn` package contains a central component, the `Notifier`, which consumes raw events from a `chain.Driver` and provides a robust, reorg-aware notification service to its clients.

### Provided Interfaces

-   **`Notifier`**: The primary public interface of the `ntfn` package. It provides a robust, reorg-aware notification service with a type-safe, battle-tested API for registering for confirmation, spend, and block epoch notifications.

### Required Interfaces

The `ntfn` package depends on the following interfaces for its operation:

-   **`chain.Driver`**: The `Notifier` takes a `chain.Driver` (which implements `ChainQuery`, `ChainIO`, etc.) as a dependency in its constructor to interact with the blockchain.
-   **`chain.ChainEventReceiver`**: The `Notifier` implements this interface to receive a raw stream of blockchain events from the `chain.Driver`.
