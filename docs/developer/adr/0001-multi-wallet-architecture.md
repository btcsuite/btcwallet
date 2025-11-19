# ADR 0001: Multi-Wallet Architecture

## 1. Context

`btcwallet` is undergoing a significant architectural change, transitioning its persistent storage from a key-value database (kvdb) to a SQL-based backend (supporting SQLite and PostgreSQL). During this transition, a fundamental design decision must be made regarding the wallet's ability to manage multiple distinct wallets and networks within a single daemon instance.

## 2. Decision

`btcwallet` will be architected to support multiple wallets, using an **"Explicit DB-per-Network via Configuration"** model.

This design prioritizes safety and clarity by encouraging users to use a separate database for each blockchain network, while retaining the flexibility to manage multiple wallets within each network.

### How It Works:

1.  **Explicit Configuration:** The `btcwallet.conf` file will feature network-specific sections, each with its own `db.dsn` (Data Source Name) setting. This makes the "DB-per-Network" model the default and most intuitive path.
    ```toml
    [mainnet]
    db.dsn = "postgres://user:pass@host/btcwallet_mainnet"
    
    [testnet]
    db.dsn = "postgres://user:pass@host/btcwallet_testnet"
    ```
2.  **Application Logic:** On startup, the daemon will read the active network flag (e.g., `--network=testnet`), select the corresponding DSN from the config, and connect to that specific database.
3.  **Network Binding & Safety Check:** To prevent accidental data corruption (e.g., pointing the testnet DSN to a mainnet database), a `meta` table in each database will bind it to a specific network upon creation. On every startup, the daemon will verify this binding. If a mismatch is detected, `btcwallet` will refuse to start and will output a clear error.
4.  **Internal Multi-Wallet Schema:** The schema *within* each database will still fully support multiple wallets (e.g., a hot and cold wallet on mainnet). This requires a `wallets` table and `wallet_id` scoping on all relevant tables. The `wallets` table itself will not need a `network` column, as this context is managed at the database level.

## 3. Arguments FOR this Decision (Pros)

### 3.1. Safest by Default
This model makes it nearly impossible for a user to accidentally mix mainnet and testnet data, preventing a catastrophic class of user errors. The network binding check provides a critical backstop.

### 3.2. Maximum Clarity for the User
The configuration is explicit and self-documenting. The physical separation of databases (e.g., `mainnet.db`, `testnet.db`) aligns with the user's mental model of these being entirely separate environments.

### 3.3. Retains Full Multi-Wallet Flexibility
The design fully supports the primary multi-wallet use case: managing multiple wallets (e.g., hot/cold, personal/business) on the *same network*. It also allows for the advanced use case of a unified database for those who explicitly configure it.

### 3.4. Superior Resource Efficiency
Compared to a "one process per wallet" model, this design remains highly efficient by sharing a single chain connection (`btcd`) among all wallets running on the same network within the single daemon instance.

## 4. Alternatives Considered

### 4.1. Alternative: Unified Database Model

A model where a single database is used for all wallets across all networks was considered. In this design, a `network` column would be added to the `wallets` table to provide logical data separation.

*   **Rationale for Rejection:** While this model simplifies user configuration to a single DSN, it was rejected because it does not provide the same level of default safety. The risk of a novice user unintentionally mixing mainnet and testnet data in a single database was deemed too high. The "Explicit DB-per-Network" model provides a safer default posture while still allowing this behavior for advanced users who opt-in via their configuration.

### 4.2. Alternative: Single-Wallet-per-Database Model

A model where each wallet gets its own database was also considered.

*   **Rationale for Rejection:** This model was rejected due to significant scalability and usability issues, particularly for PostgreSQL, where it would lead to connection limit exhaustion and require users to perform administrative database commands (`CREATE DATABASE`). It also adds significant complexity to the application, which would need to manage a connection pool for every loaded wallet.

## 5. Implementation Plan

1.  **Implement the "Explicit DB-per-Network" configuration** in `btcwallet.conf`.
2.  **Build the application logic** to select the appropriate DSN based on the active network and manage the corresponding database connection.
3.  **Implement the network binding safety check** using a `meta` table in the database schema.
4.  **Build the internal SQL schema to be fully multi-wallet aware** (using `wallet_id` scoping) to support multiple wallets within a single network database.
5.  **Provide a Migration Path for Existing Users.** A migration tool will be developed to import data from an existing single-wallet `wallet.db` (kvdb) into the new SQL database structure.
6.  **Deprecate and Remove the KVDB Backend.** Once the SQL backend is stable and the migration path is established, the legacy kvdb implementation will be removed.
