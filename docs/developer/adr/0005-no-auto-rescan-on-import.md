# ADR 0005: Explicit Rescan on Import

## Status

- **Status:** Accepted
- **Date:** 2025-12-25

## Relationships

- **Amends:** [ADR 0004](0004-targeted-rescan-vs-rewind.md) for explicit
  import recovery and wallet-wide targets.
- **Supersedes:** None.
- **Amended by:** None.
- **Superseded by:** None.

## 1. Context

When a wallet imports new keys, addresses, or accounts, the wallet needs to
scan the blockchain history. The scan discovers any existing funds that are
associated with these new credentials.

Some wallet implementations use a common pattern: they automatically trigger a
rescan immediately on import. However, this approach causes several issues:

*   **Performance Storms:** A user or application can import a batch of 100
    keys sequentially. In that case, an automatic trigger would start 100
    overlapping, redundant rescan jobs.
*   **Blocking Behavior:** If the import method waits for the scan, a simple
    database insertion becomes an operation that can take an hour.
*   **API Ambiguity:** The automatic trigger blurs the line between the import
    of wallet state and an explicit request for historical recovery.

## 2. Decision

`btcwallet` will **not** automatically trigger a blockchain rescan when keys,
addresses, or accounts are imported.

*   **Imports Do Not Start Historical Recovery:** Maintained controller import
    methods persist wallet data. For watchable addresses, these methods also
    synchronously request live notifications from the chain backend. Live
    registration does not scan historical blocks.
*   **Historical Rescans Must Be Explicit:** The caller is responsible for an
    explicit rescan request (through `Rescan(...)`) after the import is
    complete.

## 3. Rationale

### 3.1 Batch Efficiency
With this design, downstream applications (like `lnd` or custom scripts) can
batch imports efficiently. An application can import 1,000 keys in a loop. The
application can then trigger a **single** targeted rescan for the aggregate
birthday of those keys. This single scan is orders of magnitude more efficient
than 1,000 individual scans.

### 3.2 API Clarity
The separation of live registration from historical recovery makes the API
predictable.

*   `ImportXXX`: "I want to save this key and watch new activity."
*   `Rescan`: "I want to search historical blocks."

### 3.3 User Control
The user (or the calling software) keeps control over system resources. The
user may choose to import keys now. The user may then defer the heavy scan
operation until a maintenance window or until bandwidth is available.

## 4. Consequences

### Pros
*   **Performance:** The design eliminates redundant scans during bulk imports.
*   **Responsiveness:** Import RPCs stay consistently fast.
*   **Flexibility:** The design permits advanced import workflows (e.g.,
    offline imports).

### Cons
*   **Usability Pitfall:** A naive user might import a key and then not
    understand why the balance shows `0`. Documentation and RPC output must
    clearly indicate that a rescan is necessary to see funds.
*   **Client Burden:** Clients must implement the "Import -> Rescan" logic
    themselves.
