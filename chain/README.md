# chain

## Overview

The `chain` package is the foundational layer of `btcwallet` responsible for interacting with the Bitcoin blockchain. Its primary role is to act as a low-level, stateless I/O adapter over various blockchain backends, such as `btcd`, `bitcoind`, and `neutrino`. This ensures that the core wallet logic remains agnostic to the specific chain source being used.

For a detailed overview of the package's design and architecture, please see the [architecture documentation](./ARCHITECTURE.md).

## Architecture

The package is designed to be a stateless I/O layer. All stateful logic (such as notification queues, subscription management, and reorg tracking) is handled by a higher-level package, `ntfn`.

### Provided Interfaces

-   **`ChainQuery`**: A read-only interface for fetching data from the blockchain (e.g., `GetBlock`, `GetBestBlock`).
-   **`ChainIO`**: A write-only interface for broadcasting transactions (`SendRawTransaction`).
-   **`MempoolObserver` (Optional)**: An optional interface that a driver may implement to provide functionality specific to full nodes that have a view of the transaction mempool.

### Required Interfaces

The `chain` package's drivers depend on the following interface, which must be implemented by a consumer (such as the `ntfn` package):

-   **`ChainEventReceiver`**: An interface that the driver uses to forward raw, low-level blockchain events to a higher-level, stateful consumer.
