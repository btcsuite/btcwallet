# ADR 0001: Multi-Wallet Architecture

## 1. Context

`btcwallet` is moving its persistent storage from a key-value database (kvdb)
to a SQL-based backend. This is a significant architectural change. The SQL
backend supports SQLite and PostgreSQL. During this change, the project must
make a fundamental design decision: how a single daemon instance manages
multiple distinct wallets and networks.

## 2. Decision

The `btcwallet` architecture will support multiple wallets. It will use an
**"Explicit DB-per-Network via Configuration"** model.

This design gives priority to safety and clarity. It encourages users to use a
separate database for each blockchain network. It also keeps the flexibility to
manage multiple wallets within each network.

### How It Works:

1.  **Explicit Configuration:** The `btcwallet.conf` file will have
    network-specific sections. Each section has its own `db.dsn` (Data Source
    Name) setting. Thus, the "DB-per-Network" model is the default and the most
    intuitive path.
    ```toml
    [mainnet]
    db.dsn = "postgres://user:pass@host/btcwallet_mainnet"
    
    [testnet]
    db.dsn = "postgres://user:pass@host/btcwallet_testnet"
    ```
2.  **Application Logic:** On startup, the daemon will do these steps:
    *   Read the active network flag (e.g., `--network=testnet`).
    *   Select the corresponding DSN from the config.
    *   Connect to that specific database.
3.  **Network Binding & Safety Check:** A `meta` table in each database will
    bind the database to a specific network when the database is created. This
    binding prevents accidental data corruption (e.g., a testnet DSN that
    points to a mainnet database). On every startup, the daemon will verify
    this binding. If the daemon detects a mismatch, `btcwallet` will refuse to
    start and will output a clear error.
4.  **Internal Multi-Wallet Schema:** The schema *within* each database will
    still fully support multiple wallets (e.g., a hot and cold wallet on
    mainnet). This support requires a `wallets` table and `wallet_id` scoping
    on all relevant tables. The `wallets` table itself will not need a
    `network` column, because the database level manages the network context.

## 3. Arguments FOR this Decision (Pros)

### 3.1. Safest by Default
With this model, it is almost impossible for a user to mix mainnet and testnet
data by accident. Thus, the model prevents a catastrophic class of user errors.
The network binding check gives a critical backstop.

### 3.2. Maximum Clarity for the User
The configuration is explicit and self-documenting. The physical separation of
databases (e.g., `mainnet.db`, `testnet.db`) agrees with the user's mental
model: these are entirely separate environments.

### 3.3. Retains Full Multi-Wallet Flexibility
The design fully supports the primary multi-wallet use case: multiple wallets
(e.g., hot/cold, personal/business) on the *same network*. The design also
permits the advanced use case of a unified database for users who explicitly
configure it.

### 3.4. Superior Resource Efficiency
This design is more efficient than a "one process per wallet" model. All
wallets that run on the same network within the single daemon instance share a
single chain connection (`btcd`).

## 4. Alternatives Considered

### 4.1. Alternative: Unified Database Model

The project considered a model that uses a single database for all wallets
across all networks. In this design, a `network` column in the `wallets` table
would give logical data separation.

*   **Rationale for Rejection:** This model makes user configuration simpler,
    because it uses a single DSN. But the project rejected it, because it does
    not give the same level of default safety. The project decided that the
    risk was too high: a novice user could accidentally mix mainnet and
    testnet data in a single database. The "Explicit DB-per-Network" model
    gives a safer default posture. It still permits this behavior for
    advanced users who opt in through their configuration.

### 4.2. Alternative: Single-Wallet-per-Database Model

The project also considered a model that gives each wallet its own database.

*   **Rationale for Rejection:** The project rejected this model because of
    significant scalability and usability issues, particularly for PostgreSQL.
    With PostgreSQL, the model would exhaust the connection limit. It would
    also require users to run administrative database commands
    (`CREATE DATABASE`). The model also adds significant complexity to the
    application, because the application must manage a connection pool for
    each loaded wallet.

## 5. Implementation Plan

1.  **Implement the "Explicit DB-per-Network" configuration** in
    `btcwallet.conf`.
2.  **Build the application logic** to select the applicable DSN for the
    active network and to manage the corresponding database connection.
3.  **Implement the network binding safety check** with a `meta` table in the
    database schema.
4.  **Build the internal SQL schema to be fully multi-wallet aware** (with
    `wallet_id` scoping) to support multiple wallets within a single network
    database.
5.  **Provide a Migration Path for Existing Users.** The project will develop a
    migration tool. The tool will import data from an existing single-wallet
    `wallet.db` (kvdb) into the new SQL database structure.
6.  **Deprecate and Remove the KVDB Backend.** When the SQL backend is stable
    and the migration path is available, the project will remove the legacy
    kvdb implementation.
