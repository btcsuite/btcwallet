# btcwallet Engineering Guide

This guide provides a comprehensive overview of the design philosophy, architectural patterns, and implementation details for `btcwallet`. It is intended for developers and contributors to the project.

# Table of Contents

- [Part 1: High-Level Design Philosophy](#part-1-high-level-design-philosophy)
  - [Introduction](#introduction)
  - [Foundational Principles: SOLID](#foundational-principles-solid)
  - [Domain-Specific Principles for Bitcoin Wallets](#domain-specific-principles-for-bitcoin-wallets)
  - [Core Philosophy on Complexity](#core-philosophy-on-complexity)
  - [Development Methodology: Test-Driven Development (TDD)](#development-methodology-test-driven-development-tdd)
- [Part 2: Architectural Patterns](#part-2-architectural-patterns)
  - [Core Philosophy: The Actor Model in Go](#core-philosophy-the-actor-model-in-go)
  - [Design Checklist: Key Architectural Patterns](#design-checklist-key-architectural-patterns)
- [Part 3: Go Implementation Guide](#part-3-go-implementation-guide)
  - [API and Package Design](#api-and-package-design)
  - [Error Handling](#error-handling)
  - [Concurrency](#concurrency)
  - [Performance and Optimization](#performance-and-optimization)
  - [Testing](#testing)
  - [Logging](#logging)
  - [References](#references)

---

# Part 1: High-Level Design Philosophy

## Introduction

This document outlines the high-level design philosophy and core principles that guide the development of `btcwallet`. Its purpose is to ensure that the resulting codebase is robust, secure, maintainable, and extensible.

Adherence to these principles is essential for any contributor. They serve as the architectural foundation and the primary reference for making design decisions, resolving ambiguities, and reviewing code. The goal is not just to build software that *works*, but to engineer a piece of critical financial infrastructure that is simple, obvious, and safe.

The principles are drawn from three sources: foundational software engineering (SOLID), domain-specific requirements of decentralized financial networks, and a core philosophy on managing complexity inspired by John Ousterhout's "A Philosophy of Software Design".

---

## Foundational Principles: SOLID

SOLID provides the bedrock for a modular and maintainable codebase.

*   **Single Responsibility Principle (SRP)**: A module should have one reason to change.
    *   **Practice**: Logic is strictly separated at the interface level. The `AccountManager` handles accounts, the `AddressManager` handles addresses, the `TxReader` and `TxWriter` handle transaction history, and the `UtxoManager` handles the UTXO set. A change in how UTXOs are leased should only touch the `UtxoManager`'s implementation, not the transaction reading logic.

*   **Open/Closed Principle (OCP)**: Modules are open for extension, closed for modification.
    *   **Practice**: The Bitcoin protocol is always evolving. The system is designed to accommodate new features (e.g., new script types, transaction formats) by adding new, isolated code rather than modifying core wallet logic.

*   **Liskov Substitution Principle (LSP)**: Subtypes must be substitutable for their base types.
    *   **Practice**: Components are programmed against interfaces. The `wallet.Wallet` depends on the `chain.Interface` abstraction, allowing different blockchain backends (e.g., `btcd`, `neutrino`) to be used interchangeably.

*   **Interface Segregation Principle (ISP)**: Clients should not depend on interfaces they don't use.
    *   **Practice**: Components expose minimal, role-focused interfaces. A component that only needs to query transaction history should depend on the simple `TxReader` interface, not the entire, complex `wallet.Wallet` object which also includes methods for signing and broadcasting.

*   **Dependency Inversion Principle (DIP)**: High-level modules depend on abstractions, not low-level details.
    *   **Practice**: The `wallet.Wallet` (high-level policy) does not depend directly on a concrete `chain.BtcdClient` (low-level mechanism). Both depend on the abstract `chain.Interface`, decoupling wallet logic from the specifics of the blockchain backend.

---

## Domain-Specific Principles for Bitcoin Wallets

These principles address the unique challenges of a secure, decentralized financial system.

**Security First, Always.**
A bug can lead to a direct, irreversible loss of funds. This is the paramount principle.
*   **Zero Trust**: Trust nothing from external sources, including the blockchain backend. All data is validated.
*   **Least Privilege**: Components only have the authority they need. The RPC server, which may use the `TxPublisher` interface, cannot access raw private keys directly as the signing logic is encapsulated within the `wallet`'s implementation.
*   **Fail-Safe Defaults**: When in doubt, fail safely. An ambiguous or unexpected state in transaction signing must result in an error, not a broadcasted transaction.

**The Network is Unreliable.**
*   **Asynchronous and Non-Blocking**: No single RPC call or blockchain request should block the entire wallet.
*   **Idempotency**: Operations are designed to handle retries without issue, which is critical during connection flaps with the backend.

**State is Sacred and Complex.**
*   **Atomicity of State Updates**: Logical updates that span multiple data items are performed in a single, atomic database transaction. For example, the `TxPublisher`'s implementation of `Broadcast` uses the internal `recordTxAndCredits` function to update both the transaction store (`wtxmgr`) and the address manager (`waddrmgr`) in one transaction, preventing state corruption.
*   **Isolate State**: The state of one wallet account is strictly isolated from all others. A failure in one account must never cascade to another.

**Everything is a Resource.**
*   **Aggressive Resource Limiting**: Strict limits are applied to RPC requests and resource-intensive operations like rescans to protect the node.

**Design for Usability: Simple by Default, Powerful when Needed.**
The system must be approachable for common use cases while providing flexibility for advanced operators.
*   **Practice**: Implement a "Normal vs. Advanced" philosophy for APIs and configuration. The default settings and primary APIs should be simple, safe, and cover 95% of use cases. Advanced, fine-grained controls should be available but kept separate to avoid overwhelming the average user.

**Prefer Mature and Boring Technology.**
For critical financial infrastructure, stability, predictability, and maintainability are more valuable than novelty.
*   **Practice**: When choosing dependencies (databases, libraries, etc.), prefer battle-tested, well-understood technologies over new, experimental ones, even if the latter promise performance benefits. The long-term cost of debugging immature technology is too high.

**Minimize Cognitive Load through Simplicity and Uniformity.**
The easier a system is to understand, the fewer bugs it will have. The primary goal of our design is to reduce the mental effort required for a developer to contribute safely.
*   **Practice**: Use consistent, uniform patterns throughout the codebase. If one component handles asynchronous results using a specific pattern (e.g., Go channels), other components should use the same pattern. Avoid introducing multiple, slightly different ways of doing the same thing. This allows developers to learn a pattern once and apply that knowledge everywhere.

---

## Core Philosophy on Complexity

The central goal of our design is to minimize complexity.

**Modules Should Be Deep.**
A module's interface must be significantly simpler than its implementation.
*   **Practice**: The `TxPublisher` interface exposes a clean `Broadcast(tx)` method. This hides the immense internal complexity of mempool acceptance checks, atomic database updates via `addTxToWallet`, and the final broadcast to the network.

**Pull Complexity Downwards.**
It is better for the implementer of a module to take on more work if it makes the interface simpler for its users.
*   **Practice**: The `chain.Service` must handle the complexity of blockchain reorganizations internally. It must present a simple, consistent view of the on-chain world to the `wallet`, even if that requires significant internal effort.

**Define Errors and Special Cases Out of Existence.**
Instead of returning errors for every edge case, design APIs so these cases are handled by the normal code path.
*   **Practice**: The internal `extractTxAddrs` function takes a transaction and returns a map of all addresses found in its outputs. If an output contains a script that cannot be parsed (a common and expected case), the function logs a warning and simply continues to the next output, omitting the unparseable one from the returned map. The function's signature does not include an `error` return type. This defines the "unparseable script" case out of existence for the caller, who receives a best-effort map and doesn't need to write special error-handling logic for this non-exceptional event.

**Prioritize Strategic over Tactical Programming.**
Adopt an investment mindset. The primary goal is a great long-term design, not just code that works *now*. Continually invest time in improving the design.
*   **Practice**: Every change should leave the design better than it was before. Resist the temptation to add small hacks to get a feature working quickly. Take the extra time to refactor and integrate the feature cleanly.

**Write Comments That Explain the "Why", Not the "How".**
Comments should capture the designer's intent and provide a higher-level, more intuitive view than the code itself.
*   **Practice**: A comment should not say `// Loop through transaction outputs`. It should say `// Identify our change output to ensure it is properly credited back to the wallet.` This explains the purpose, which cannot be gleaned from the code alone.

---

## Development Methodology: Test-Driven Development (TDD)

To ensure correctness and security, this project **recommends** a Test-Driven Development (TDD) approach. While not mandatory, TDD is a powerful methodology for building secure financial software. When practiced, it often leads to more robust, well-designed, and inherently testable code.

*   **Strengths of TDD for Security**:
    *   **Specification Before Implementation**: TDD forces a deep understanding of Bitcoin's consensus rules and standard transaction types before a single line of implementation code is written. Requirements are translated directly into testable assertions.
    *   **Adversarial Thinking by Default**: The "Red" step of the TDD cycle is the natural place to test for edge cases and invalid inputs. Tests for non-standard transactions or unexpected backend behavior are written before the "happy path" is ever implemented.
    *   **Security Regression Suite**: The resulting comprehensive test suite acts as a powerful safety net, preventing future changes from inadvertently introducing security vulnerabilities into previously correct code.

*   **Limitations and Complements**:
    TDD is not a replacement for a holistic security approach. It validates known requirements but cannot discover unknown threats. Therefore, TDD must be complemented by:
    *   **Proactive Threat Modeling**: To think about and design for potential economic and network-level attacks.
    *   **Rigorous Integration and E2E Testing**: To discover emergent bugs from the interaction between concurrently running components.
    *   **External Audits and Peer Review**: To provide an outside perspective that can catch flaws missed by the core developers.

---

# Part 2: Architectural Patterns

## Core Philosophy: The Actor Model in Go

To manage concurrency and state safely, we use the **Actor Model** as our primary architectural guide. Instead of sharing memory and protecting it with mutexes, we isolate state within independent, long-running goroutines called "actors."

An **actor** is a self-contained unit of concurrency that:
1.  **Owns its state exclusively.** No other part of the system is allowed to touch its internal data.
2.  **Runs in a dedicated goroutine.**
3.  **Communicates only via messages** sent over channels (its "mailbox").

This approach provides strong guarantees of concurrency safety and helps decouple our subsystems, making them easier to reason about, test, and maintain.

---

## Design Checklist: Key Architectural Patterns

When designing a new feature or subsystem, consider each of the following patterns. They are not overlapping; they are complementary and address different aspects of a robust system.

### Data Flow Patterns
*How do we structure the flow of work between actors?*

#### 1. Pipeline Pattern
- **What it is:** A series of actors (stages) connected by channels, where each actor performs a specific task and passes its output to the next actor in the chain.
- **Why we use it:** It allows us to break down a complex process into a set of simple, decoupled, and reusable stages.
- **Example:**
  ```go
  // Stage 1: Doubles numbers
  func doubler(in <-chan int, out chan<- int) {
      for num := range in {
          out <- num * 2
      }
      close(out)
  }
  
  // Stage 2: Adds 5 to numbers
  func adder(in <-chan int, out chan<- int) {
      for num := range in {
          out <- num + 5
      }
      close(out)
  }
  
  // Building the pipeline:
  // inputChan -> doubler -> adder -> outputChan
  ```

#### 2. Fan-Out, Fan-In Pattern
- **What it is:** A pattern to parallelize a pipeline stage. A "distributor" (Fan-Out) sends tasks to a pool of worker actors. A "collector" (Fan-In) gathers the results.
- **Why we use it:** It scales throughput for tasks that can be performed independently, preventing a single stage from becoming a bottleneck. This is our primary method for implementing a **Worker Pool**.
- **Example:**
  ```go
  func worker(id int, tasks <-chan Job, results chan<- Result) {
      for j := range tasks {
          // Process the job...
          results <- process(j)
      }
  }
  
  // Fan-Out: Start 10 workers
  tasks := make(chan Job, 100)
  results := make(chan Result, 100)
  for w := 1; w <= 10; w++ {
      go worker(w, tasks, results)
  }
  
  // Fan-In: A single goroutine collects all results
  go func() {
      for r := range results {
          fmt.Println("Completed:", r)
      }
  }()
  ```

### Resilience Patterns
*How does our actor behave when things go wrong?*

#### 3. Rate Limiting Pattern
- **What it is:** Limiting the frequency of an operation to protect a resource from overload.
- **Why we use it:** To prevent an actor from overwhelming an external API, a database, or another internal subsystem.
- **Example:**
  ```go
  import "golang.org/x/time/rate"
  
  // This actor can only process a message every 200ms.
  limiter := rate.NewLimiter(rate.Every(200*time.Millisecond), 1)
  
  func (a *MyActor) HandleMessage(ctx context.Context, msg Message) {
      if err := limiter.Wait(ctx); err != nil {
          // Context was canceled, abort.
          return
      }
      // Process the message...
  }
  ```

#### 4. Circuit Breaker Pattern
- **What it is:** A state machine that wraps calls to an external service. After a number of failures, the breaker "opens" and fails fast, avoiding calls to a service that is likely down.
- **Why we use it:** Prevents the system from wasting resources on calls that are likely to fail and avoids cascading failures.
- **Example (Conceptual):**
  ```go
  // Inside an actor's message loop
  switch state {
  case "CLOSED":
      err := callExternalAPI()
      if err != nil {
          consecutiveFailures++
          if consecutiveFailures > 5 {
              state = "OPEN"
              openTime = time.Now()
          }
      }
  case "OPEN":
      if time.Since(openTime) > 30*time.Second {
          state = "HALF_OPEN"
      } else {
          return fmt.Errorf("circuit is open")
      }
  case "HALF_OPEN":
      // Allow one trial call to see if the service has recovered.
      // ...
  }
  ```

#### 5. Retry with Exponential Backoff
- **What it is:** Re-attempting a failed operation with an increasing delay between each attempt.
- **Why we use it:** To handle transient, temporary failures (e.g., a brief network hiccup) gracefully.
- **Example:**
  ```go
  func CallWithRetry(ctx context.Context) error {
      var err error
      delay := 1 * time.Second
      for i := 0; i < 5; i++ { // Max 5 retries
          err = callExternalAPI()
          if err == nil {
              return nil // Success
          }
  
          select {
          case <-time.After(delay):
              delay *= 2 // Exponential backoff
          case <-ctx.Done():
              return ctx.Err() // Timeout or cancellation
          }
      }
      return fmt.Errorf("failed after retries: %w", err)
  }
  ```

### Operational Patterns
*How do we control and observe our system?*

#### 6. Context Propagation
- **What it is:** Passing a `context.Context` through every function call in a request's lifecycle.
- **Why we use it:** It is the single most important pattern for controlling behavior. It allows us to enforce timeouts, propagate cancellation signals, and gracefully tear down work for abandoned requests.
- **Example:**
  ```go
  // Every function that is part of a request accepts a context.
  func (a *MyActor) ProcessPayment(ctx context.Context, payment Payment) error {
      // Pass the context down to the next actor/function.
      err := a.db.Save(ctx, payment)
      if err != nil {
          return err
      }
      // ...
      return nil
  }
  
  // Inside a long-running loop, always check for cancellation.
  for {
      select {
      case <-ctx.Done():
          return ctx.Err() // Exit cleanly
      // ... do other work
      }
  }
  ```

#### 7. Health and Metrics Endpoints
- **What they are:** A pair of dedicated HTTP endpoints for service observability.
    - **`/healthz` (Health Check):** A simple endpoint that returns `200 OK` if the service is alive and able to work. The `z` is a common convention to distinguish this machine-readable endpoint from a potentially human-readable `/health` status page.
    - **`/metrics` (Metrics):** An endpoint that exposes detailed performance and health metrics in a standard format (e.g., Prometheus).
- **Why we use them:** They provide a complete picture of service health. While `/healthz` answers "is it alive?", `/metrics` answers "how is it doing?". They are essential for automated restarts, alerting, and performance analysis. Any service with a health check should also have a metrics endpoint.
- **Example (Health Check):**
  ```go
  // The actor holds a channel to receive health check queries.
  type SystemActor struct {
      healthChecks chan chan error
  }
  
  // The HTTP handler sends a request to the actor.
  func HealthCheckHandler(actor *SystemActor) http.HandlerFunc {
      return func(w http.ResponseWriter, r *http.Request) {
          resultChan := make(chan error)
          actor.healthChecks <- resultChan
  
          select {
          case err := <-resultChan:
              if err != nil {
                  http.Error(w, "unhealthy", http.StatusServiceUnavailable)
                  return
              }
              fmt.Fprintln(w, "ok")
          case <-time.After(2 * time.Second):
              http.Error(w, "timeout", http.StatusServiceUnavailable)
          }
      }
  }
  ```

---

# Part 3: Go Implementation Guide

This section provides practical, Go-specific guidance for contributors. It details the concrete patterns, conventions, and best practices for writing clean, correct, and idiomatic Go code in this project. For specific rules on code style, please see the [Code Formatting Rules](./code_formatting_rules.md).

---

## API and Package Design

Well-designed packages and APIs are the foundation of a maintainable system.

*   **Avoid Generic Package Names**: Package names like `utils`, `common`, or `helpers` are forbidden. A package name should describe its purpose, not its contents. If you are tempted to create such a package, it is a sign that the code should be better organized within the existing domain packages.

*   **Use `internal` Packages**: To reduce the public API surface of the project, any code that is not intended to be used by other projects should be placed in an `internal` package.

*   **Accept Interfaces, Return Structs**: This core Go idiom is our standard. Functions should accept simple, focused interfaces to remain flexible and easy to test. They should return concrete structs so the caller has a specific, usable type.

    ```go
    // GOOD: The function accepts a generic io.Reader interface.
    func processData(r io.Reader) (*Result, error) {
        // ... implementation ...
        return &Result{...}, nil // Returns a concrete type.
    }
    ```

*   **Clean Dependency Graph**: Dependencies must flow in one direction (e.g., from high-level policy to low-level mechanisms). Circular dependencies are forbidden and will be caught by CI.

---

## Error Handling

Robust error handling is critical.

*   **Wrap Errors for Context**: Never return a raw, unadorned error from a dependency. Always wrap it with context using `fmt.Errorf("component: could not do X: %w", err)`. This creates a traceable error chain that is invaluable for debugging.

    ```go
    // GOOD:
    if err != nil {
        return fmt.Errorf("failed to read peer message: %w", err)
    }
    ```

*   **Use Constant Sentinel Errors**: For well-known, specific error conditions, define constant sentinel errors (e.g., `var ErrPeerNotConnected = errors.New("peer not connected")`). This allows callers to reliably check for specific errors using `errors.Is`.

    ```go
    // GOOD:
    var ErrChannelNotFound = errors.New("channel not found")

    func GetChannel(...) (*Channel, error) {
        if ... {
            return nil, ErrChannelNotFound
        }
        // ...
    }
    ```

*   **Eliminate Errors by Design**: Whenever possible, follow the principle of "defining errors out of existence." For example, a function to retrieve an item from a cache should return `(value, true)` on success and `(nil, false)` on a miss, rather than returning an error for a cache miss, which is a normal and expected event.

---

## Concurrency

Concurrency is where the most subtle and dangerous bugs hide. We follow a strict set of rules to manage it safely.

#### Core Philosophy
*   **Share Memory By Communicating**: Whenever possible, prefer passing ownership of data over channels rather than sharing memory and protecting it with locks. This often leads to simpler and safer concurrent code.
*   **Never Start a Goroutine Without Knowing How It Will Stop**: Every goroutine must have a clear and predictable exit path. This is the single most important rule for preventing goroutine leaks.

    ```go
    // GOOD: Goroutine will exit when the context is cancelled.
    func worker(ctx context.Context, jobs <-chan Job) {
        for {
            select {
            case <-ctx.Done():
                return
            case job := <-jobs:
                process(job)
            }
        }
    }
    ```

#### Structured Concurrency with `context`
*   **Principle**: Every function that performs a network call, a database query, or any potentially long-running or blocking operation MUST accept a `context.Context` as its first argument.
*   **Practice**: This enables proper cancellation and deadline propagation. For managing groups of related goroutines, use a package like `golang.org/x/sync/errgroup`, which elegantly combines context management with error propagation.

#### Common Pitfalls and Best Practices
*   **Treat Slices as Unsafe for Concurrent Modification**: A slice is a header pointing to a shared underlying array. To share a slice, either pass a pointer to it (`*[]MyType`) and protect all access with a mutex, or use channels to safely pass ownership.

*   **Never Concurrently Access a Standard `map` without a Lock**: Go's built-in `map` is not safe for concurrent writes. Any `map` that could be accessed by more than one goroutine MUST be protected by a `sync.Mutex` or `sync.RWMutex`.

*   **Always Pass Synchronization Primitives by Pointer**: Primitives like `sync.Mutex` are value types (`structs`). Passing them by value creates a useless copy.
*   **Worker Pools**: Managing a fixed number of goroutines to process tasks from a queue. This helps control resource consumption and prevent system overload when dealing with a high volume of tasks.
*   **Atomic Operations**: Using the `sync/atomic` package for simple, high-performance, lock-free operations like counters and flags.
*   **Lazy Initialization**: Deferring the initialization of expensive resources until they are first needed, often using `sync.Once`, `sync.OnceValue`, or `sync.OnceValues`.
*   **Immutable Data Sharing**: Sharing data between goroutines by making it immutable. This avoids the need for locks, as the data cannot be changed.

---

## Performance and Optimization

Performance is critical, but optimizations must be driven by data, not by guesswork.

*   **Profile First**: No optimization should be attempted without a clear benchmark and profile (`pprof`) that demonstrates a bottleneck.
*   **Reduce Allocations**: The most common source of performance improvement in Go is reducing unnecessary memory allocations.
    *   **Pre-allocate Slices and Maps**: If the size is known, always use `make([]T, 0, size)` or `make(map[K]V, size)`.
        ```go
        // GOOD:
        items := make([]Item, 0, len(sourceItems))
        for _, item := range sourceItems {
            items = append(items, transform(item))
        }
        ```
    *   **Use `sync.Pool`**: For frequently used, short-lived objects like buffers, use `sync.Pool` to recycle them.
        ```go
        var bufferPool = sync.Pool{
            New: func() any { return new(bytes.Buffer) },
        }
        
        buf := bufferPool.Get().(*bytes.Buffer)
        buf.Reset()
        // ... use buffer ...
        bufferPool.Put(buf)
        ```
    *   **Avoid Interface Boxing in Hot Paths**: Be mindful that assigning a large struct to an interface can cause a heap allocation. In performance-critical code, passing a pointer can avoid this.
    *   **Zero-Copy Techniques**: Minimizing data copying by using techniques like slicing existing buffers instead of creating new ones, and using `io.Reader` and `io.Writer` interfaces to stream data efficiently.
    *   **Stack Allocations**: Writing code in a way that allows the compiler to allocate memory on the stack instead of the heap. You can use `go build -gcflags="-m"` to see which variables "escape" to the heap.
    *   **Garbage Collector Tuning**: Understanding and tuning the Go garbage collector using `GOGC` and `GOMEMLIMIT` environment variables to balance memory usage and CPU overhead.

*   **Be Mindful of the CPU Cache**:
    *   **Struct Field Alignment**: Always order the fields in a struct from largest to smallest. Use the `fieldalignment` linter to check this automatically.

#### I/O Optimization and Throughput

*   **Efficient Buffering**: Using `bufio.Reader` and `bufio.Writer` to wrap I/O operations. This reduces the number of underlying system calls by buffering reads and writes.
*   **Batching Operations**: Grouping multiple small operations (like database writes or API calls) into a single larger batch to reduce overhead and improve throughput.

#### Compiler-Level Optimization

*   **Leveraging Compiler Flags**: Using build flags like `-ldflags` to strip debug information and reduce binary size, and `-gcflags` to control compiler optimizations and view diagnostics like escape analysis.

---

## Testing

Our goal is a high degree of test coverage to ensure the code is as bug-free as possible. For a detailed guide on testing best practices, please see the [Unit Testing Guidelines](./unit_testing_guidelines.md).

*   **TDD is the Standard**: Follow a Test-Driven Development approach. Write tests for error cases and protocol violations *before* writing the happy path implementation.
*   **Prefer Table-Driven Tests**: Use table-driven tests to cover a wide range of inputs and edge cases for a given function in a clean and maintainable way.
    ```go
    // GOOD:
    testCases := []struct{
        name string
        input int
        want int
        err error
    }{
        // ... test cases ...
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            got, err := myFunction(tc.input)
            // ... assertions ...
        })
    }
    ```
*   **Unit and Integration Tests**: All new code must be accompanied by unit tests. Changes to P2P protocol logic or RPCs must also have integration tests.
*   **Benchmarking**: Any change made for performance reasons must be accompanied by a benchmark (`testing.B`) that proves the improvement.

---

## Logging

Clear and structured logging is essential for observability and debugging.

* **Use Structured Logging**: All log messages MUST be written using a structured logging library (e.g., `slog`).

*   **Log Levels**:
    
       *   `Trace`: Extremely verbose, step-by-step logging for deep debugging of a specific function or workflow. This level is intended only for development and should be disabled in production.
       *   `Debug`: For verbose information useful only to developers during active debugging.    
       *   `Info`: For routine operational events (e.g., peer connected, channel opened).
    
    *   `Error`: For internal errors that are never expected to happen during normal operation. External errors (e.g., a peer sending a malformed message) should be handled gracefully and logged at `Info` or `Debug`.
    
* **Static Messages**: The primary log message should be a static string, with all dynamic data provided as key-value pairs.

  **WRONG**: `log.Info(fmt.Sprintf("User %d connected from %s", userID, ipAddr))`
  **RIGHT**: `log.Info("User connected", "user_id", userID, "ip_addr", ipAddr)`

---

## References

*   [A Philosophy of Software Design (John Ousterhout)](https://web.stanford.edu/~ouster/cgi-bin/aposd.php)
*   [Effective Go](https://go.dev/doc/effective_go)
*   [Practical Go (Dave Cheney)](https://dave.cheney.net/practical-go)
*   [High Performance Go Workshop (Dave Cheney)](https://dave.cheney.net/high-performance-go-workshop/gophercon-2019.html)
*   [A Study of Real-World Data Races in Golang (Uber)](https://arxiv.org/abs/2204.00764)
*   [Never start a goroutine without knowing how it will stop (Dave Cheney)](https://dave.cheney.net/2016/12/22/never-start-a-goroutine-without-knowing-how-it-will-stop)
