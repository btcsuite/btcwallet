# Wallet Transactions Manager SQL Schema

This schema serves as a reference for migrating data
from a Key-Value (KV) store to a relational SQL database.

## SQL Schema Reference
```sql
// Bitcoin Wallet Transactions Schema - Aligned with btcwallet KV Store
// Based on btcwallet's transaction manager (wtxmgr) design
// Paste this into https://dbdiagram.io

// -------------------------------------------------------------------------
// TYPE: Dimension Table
// ANSWERS: What is the context (hash, time) of the block that confirmed a transaction?
// -------------------------------------------------------------------------
Table blocks {
  block_height int [pk, note: "Natural key - immutable blockchain height"]
  block_hash bytea [not null, unique]
  block_timestamp bigint [not null, note: "Unix timestamp"]
  
  Note: "Block metadata - tracks blocks containing wallet transactions"
}

// -------------------------------------------------------------------------
// TYPE: Dimension Table (Snowflake)
// ANSWERS: What are the full details (raw data, received time) of any wallet-relevant transaction?
// -------------------------------------------------------------------------
Table transactions {
  transaction_key int [pk, increment, note: "Surrogate key for space efficiency"]
  transaction_hash bytea [not null, unique]
  block_height int [null, ref: > blocks.block_height, note: "NULL for unconfirmed"]
  is_coinbase boolean [not null, default: false]
  received_timestamp bigint [not null, note: "When tx was first seen"]
  serialized_tx bytea [not null]

  Note: "Transaction records - stores complete tx data for both confirmed and unconfirmed"
}

// -------------------------------------------------------------------------
// TYPE: Dimension Table
// ANSWERS: What are the descriptive attributes (scope, name) of the user's accounts?
// -------------------------------------------------------------------------
Table accounts {
  account_id int [pk, increment]
  // ...Has been initially designed in the waddrmgr schema.

  Note: "Wallet accounts, mapping to waddrmgr.KeyScope and name"
}

// -------------------------------------------------------------------------
// TYPE: Fact Table (Transactional)
// ANSWERS: 
// What is the current spendable balance?
// Which specific UTXOs (Credits) does the wallet own?
// What is the history of a single Credit?
// -------------------------------------------------------------------------
Table credits {
  credit_key bigint [pk, increment]

  // Foreign Keys.
  account_id int [not null, ref: > accounts.account_id, note: "Which account this credit belongs to"]
  transaction_key int [not null, ref: > transactions.transaction_key]
  block_height int [null, ref: > blocks.block_height, note: "NULL if unconfirmed"]

  // Degenerate Dimensions (for query performance).
  transaction_hash bytea [
    not null,
    note: "Answers quickly: 'What is the hash of the transaction that created this Credit?' (Avoids 1-table join to dim_transaction)"
  ]
  block_hash bytea [
    null,
    note: "Answers quickly: 'What is the block hash that confirmed this Credit?' (Avoids 1-table join to dim_block)"
  ]
  output_index int [not null, note: "Output position in transaction (Part of the unique Credit identifier)"]
  
  // Spending Information (NULL if unspent).
  spender_transaction_key int [null, ref: > transactions.transaction_key]
  spender_block_height int [null, ref: > blocks.block_height]

  // Degenerate Dimensions (for query performance) (NULL if unspent).
  spender_transaction_hash bytea [
    null,
    note: "Answers quickly: 'What transaction hash spent this UTXO?' (Avoids 1-table join to dim_transaction for history display)"
  ]
  spender_block_hash bytea [
    null,
    note: "Answers quickly: 'What block hash was the spending transaction included in?' (Avoids 1-table join to dim_block)"
  ]
  spender_input_index int [
    null,
    note: "Answers quickly: 'Which input index within the spending transaction consumed this UTXO?' (Avoids 1-table join to fact_debit)"
  ]

  // Status Flags (maps to KV 'flags' byte).
  is_spent boolean [not null, default: false, note: "Bit 0 of flags byte"]
  is_change boolean [not null, default: false, note: "Bit 1 of flags byte"]
  is_confirmed boolean [not null, default: false, note: "In a block vs mempool"]
  is_locked boolean [
    not null, default: false,
    note: "Duplicates state from locked_output for fast balance queries. Set to TRUE \
           when a corresponding row exists in locked_output."
  ]

  // Timestamps
  received_timestamp bigint [not null, note: "When output was first seen"]
  spent_timestamp bigint [null, note: "When output was spent"]
  
  // Measures.
  amount bigint [not null, note: "Amount in satoshis (1 BTC = 100,000,000 sats)"]
  
  indexes {
    (account_id, is_spent, is_confirmed, is_locked, amount) [
      name: "idx_spendable_account_fast",
      note: "CRITICAL: Enables ultra-fast Index-Only Scan for account balance and coin selection. \
             N is the total number of rows in fact_credit. \
             K is the small number of UTXOs matching the WHERE criteria (spendable). \
             Without this index, complexity is O(N). \
             With this index, complexity is reduced to O(Log N + K)."
    ]
  }
  
  Note: "Credits - All transaction outputs (confirmed and unconfirmed). Maps to KV buckets: \
         'c' (confirmed) and 'mc' (unmined credits)"
}

// -------------------------------------------------------------------------
// TYPE: Fact Table (Transactional)
// ANSWERS:
// What UTXOs has the wallet spent?
// What was the amount and block context of each spending input?
// -------------------------------------------------------------------------
Table debits {
  debit_key bigint [pk, increment]
  
  // Spending Transaction (the input).
  spender_transaction_key int [not null, ref: > transactions.transaction_key]
  spender_block_height int [null, ref: > blocks.block_height]

  // Degenerate Dimensions (for query performance).
  spender_transaction_hash bytea [not null]
  spender_block_hash bytea [null]
  input_index int [not null, note: "Input position in spending transaction"]

  // Reference to Credit Being Spent.
  spent_credit_key bigint [not null, ref: > credits.credit_key]
  spent_block_height int [null, ref: > blocks.block_height]

  // Degenerate Dimensions (for query performance).
  spent_transaction_hash bytea [not null]
  spent_block_hash bytea [null]
  spent_output_index int [not null]
  
  // Flags.
  is_confirmed boolean [not null, default: false]

  // Measures.
  amount bigint [not null, note: "Amount in satoshis (1 BTC = 100,000,000 sats)"]
  
  Note: "Debits - Transaction inputs that spend wallet UTXOs. Maps to KV buckets: 'd' (confirmed) and 'mi' (unmined inputs)"
}

// -------------------------------------------------------------------------
// TYPE: Auxiliary/State Table (Semi-Fact)
// ANSWERS:
// Is a specific UTXO currently reserved?
// What is the expiration time of the lock?
// -------------------------------------------------------------------------
Table locked_outputs {
  lock_key bigint [pk, increment]
  
  // UTXO Reference.
  credit_key bigint [null, ref: > credits.credit_key]
  
  // Degenerate Dimensions (for query performance).
  transaction_hash bytea [not null]
  output_index int [not null]

  // Lock Details.
  lock_id bytea [not null, note: "Application-defined lock identifier"]
  expiry_timestamp bigint [not null, note: "Unix timestamp when lock expires"]
  
  Note: "Locked Outputs - Manually reserved UTXOs for coordination (Lightning, atomic swaps). Maps to KV bucket: 'lo'"
}

// -------------------------------------------------------------------------
// TYPE: Auxiliary/Metadata Table
// ANSWERS:
// What is the current version of the wallet?
// What is the latest blockchain height?
// -------------------------------------------------------------------------
Table wallet_metadata {
  id int [pk, default: 1]
  created_at bigint
  schema_version int
  current_block_height int [not null, note: "Cached MAX(block_height) for confirmation calculations."]
  
  Note: "Wallet metadata - creation date, schema version, and cached chain state."
}
```
