# AGENTS.md

This file defines the standard for tests under `itest/`. It inherits the root
`AGENTS.md`.

Except for mechanically enforced repository contracts identified below, these
rules define violations and the invariants they break. They do not prescribe a
particular implementation or repair. Any design is acceptable when it avoids
the violations and preserves the named contract, ownership, and source of
truth.

## AUTHORITATIVE REFERENCES

- `docs/developer/adr/0008-integration-test-framework.md` owns the boundary
  between reusable infrastructure in `bwtest/` and scenarios in `itest/`.
- `docs/developer/unit_testing_guidelines.md` owns the repository's
  Arrange/Act/Assert and data-only table contracts.
- `itest/README.md` owns test selection, naming, and log documentation.
- `bwtest/README.md` owns the harness and wallet-convenience contracts.
- `bwtest/wait/wait.go` owns polling callback and timeout mechanics. This file
  defines only when polling violates a scenario contract.
- An existing helper is authoritative only for its documented contract. Its
  implementation is not a policy to copy into a test.

## ONE CASE, ONE CONTRACT

- A registered case violates single responsibility when it attempts to prove
  multiple unrelated public contracts.
- The subject contract is ambiguous when the registered name and test body do
  not let a reviewer identify the behavior under test and its public outcome.
- Calling another API for fixture preparation or a narrow postcondition is not
  a violation. Fully validating that API's independent contract in the same
  case is.
- A mutation and a query are separate responsibilities when the case attempts
  to validate both complete contracts. Using a narrow query only to observe a
  mutation's promised state is not a second responsibility.

## MECHANICAL CASE CONTRACTS

- The `component action` naming form enforced by `itest/main_test.go` is
  mandatory. Names contain at least two space-separated words and no
  underscores.
- A registered name and test function that use inconsistent component or
  behavior vocabulary obscure the case's subject contract.
- A case is not independent when its result depends on registration order,
  state left by another case, wall-clock timing, or another case's fixture.

## ARRANGE, ACT, AND ASSERT REMAIN DISTINCT

- `docs/developer/unit_testing_guidelines.md` requires three distinct phases,
  separated by blank lines: Arrange, Act, and Assert.
- Arrange establishes fixtures, preconditions, and required readiness. Act
  performs the isolated subject behavior. Assert checks its public outcome and
  only the narrow postconditions needed to prove that outcome.
- The contract is obscured when helpers, broad assertion bundles, defensive
  success checks, or comments hide the Act or its decisive assertions.
- An assertion bundle violates single responsibility when it silently proves
  several independent contracts rather than the named case.
- Assertions must use `require`. Stable public error contracts must use
  `require.ErrorIs` or `require.ErrorAs`; matching implementation error text
  makes the case depend on a non-contractual detail.
- A defensive nil guard after a successful API result hides an impossible
  success state unless non-nil is itself part of the asserted public contract.
- Test comments violate the repository documentation contract when a reader
  cannot determine why the case exists and what it checks. Narrating mechanics
  is not a substitute for explaining non-obvious intent, control values,
  waits, error identities, or reloads.

## TABLES CONTAIN DATA, NOT BEHAVIOR

- A table violates the data-only contract when rows contain setup, execution,
  or assertion closures instead of names, inputs, and expected results.
- Row-specific branches that materially change setup, execution, or assertions
  disguise different scenarios as one uniform table.
- Boundary variants do not violate the table contract when every row retains
  the same subject and execution structure.

## LIFECYCLE HAS ONE OWNER

- Duplicating routine wallet creation, registration, funding, synchronization,
  or cleanup policy outside its documented harness owner creates a competing
  source of truth.
- A lifecycle transition under test is obscured when the transition itself is
  hidden behind fixture setup rather than remaining the case's visible Act.
- Cleanup is invalid when a resource has no shutdown owner, more than one
  owner, or remains registered after another owner has released it.
- A failed start or partial setup must still leave every acquired wallet,
  manager, process, and goroutine under one recoverable shutdown owner.
- A fixture variation is not a violation merely because it is new. It becomes
  one when it duplicates established lifecycle policy or changes ownership
  semantics without one canonical owner.

## READINESS REPRESENTS REAL ASYNCHRONY

- Sleeps and raw retry loops violate the harness readiness boundary.
- `wait.NoError` is invalid for a synchronous result, deterministic state
  transition, or postcondition already guaranteed by a completed readiness
  boundary. It is appropriate only when independently scheduled work may make
  the condition true later.
- Callback, interval, and timeout behavior belong solely to the documented
  `bwtest/wait` contract; duplicating those mechanics here or in a scenario
  creates another policy owner.
- `AssertWalletSynced` is redundant as a routine follow-up to wallet creation
  or start. Initial synchronization must be the case's subject, or a later
  action must require current-tip state without an intervening harness
  boundary. Creation and start alone do not promise synchronization.
- A readiness check before the final side effect that can trigger asynchronous
  work does not protect behavior that depends on the later effect.
- Polling after an authoritative readiness boundary hides a broken visibility
  or atomicity guarantee. A direct read that fails after that boundary exposes
  the violated contract and must not be masked by another wait.
- Repeating a recurring readiness predicate or timeout policy in scenarios
  creates divergent definitions. A condition unique to one scenario does not
  violate this rule merely because it needs a local bounded wait.

## HELPERS AND FIXTURES MUST NOT HIDE CONTRACTS

- A helper is a violation when it hides the subject call, decisive assertions,
  or an entire multi-API scenario from the registered case.
- A helper or fixture creates competing ownership when it independently
  defines side-effecting setup, lifecycle, readiness, or cleanup policy already
  owned by the harness.
- Shared fixtures have accidental ownership when one component's test file is
  the source of another component's constants, builders, or algorithms.
- Package-level names that lose their meaning outside the originating file
  obscure ownership for every other `itest` consumer.
- Helper location, shape, and reuse count are not violations by themselves. The
  violation is an unclear domain responsibility, hidden contract, or competing
  policy owner.

## PRESERVE ONE SOURCE OF TRUTH

- A test violates the single-source-of-truth invariant when it redeclares
  authoritative production or harness configuration that can drift
  independently.
- Maintaining related facts as independent mutable values is a violation when
  one can be derived from the canonical value.
- Repeated fixture algorithms violate the invariant when their assumptions can
  diverge across consumers.
- An intentionally independent test oracle is not duplication when it verifies
  rather than copies the production decision. Its independence and protected
  contract must be clear to a reviewer.

## PUBLIC CONTRACTS DO NOT CHANGE BY BACKEND

- A backend-neutral case is invalid when success on one supported database or
  chain backend and failure on another are both accepted outcomes.
- Backend-conditioned expectations violate the public contract unless the API
  explicitly documents that backend distinction.
- Boundary coverage is incomplete when an applicable contract omits the last
  rejected value, first accepted value, accepted maximum, or first value above
  it.
- A negative mutation case is incomplete when it can pass despite a partial
  change to relevant public state.
- A durability claim is unproved when the case never crosses the supported
  close-and-reopen lifecycle or compares only a selected subset that can hide
  lost state.

## VERIFICATION MUST MATCH THE CONTRACT

- Start with the narrowest matching case, for example:

  ```bash
  make itest chain=btcd db=sqlite icase='component action'
  ```

- Verification is incomplete when a backend-neutral case is not exercised on
  every supported database and chain backend that can execute it.
- A single ordered run is insufficient evidence for a timing- or
  order-sensitive case. Non-zero `-shuffleseed` failures must retain the seed
  needed to reproduce the order.
- Failure evidence is incomplete without the relevant `itest/test-logs/`
  output and the exact chain, database, case filter, repeat count, and shuffle
  seed.
