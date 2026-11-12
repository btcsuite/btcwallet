# AGENTS.md

This file defines the standard for tests in `itest/`. The root `AGENTS.md`
also applies.

Some rules below are repository contracts that tools enforce. The other rules
define violations and the invariants that the violations break. These rules do
not prescribe an implementation or a repair. Any design is acceptable if it
has no violations and keeps the named contract, owner, and source of truth.

## AUTHORITATIVE REFERENCES

- `docs/developer/adr/0008-integration-test-framework.md` owns the boundary
  between the reusable infrastructure in `bwtest/` and the scenarios in
  `itest/`.
- `docs/developer/unit_testing_guidelines.md` owns the Arrange/Act/Assert
  contract and the data-only table contract of the repository.
- `itest/README.md` owns the documentation for test selection, naming, and
  logs.
- `bwtest/README.md` owns the contracts of the harness and of the wallet
  convenience helpers.
- `bwtest/wait/wait.go` owns the mechanics of polling callbacks and timeouts.
  This file defines only when polling violates a scenario contract.
- An existing helper is authoritative only for its documented contract. Do not
  copy its implementation into a test as a policy.

## ONE CASE, ONE CONTRACT

- A registered case violates single responsibility when it tries to prove
  more than one unrelated public contract.
- The subject contract is ambiguous when a reviewer cannot use the registered
  name and the test body to identify the behavior under test and its public
  outcome.
- A call to another API to prepare a fixture or to check a narrow
  postcondition is not a violation. A full validation of the independent
  contract of that API in the same case is a violation.
- A mutation and a query are separate responsibilities when the case tries to
  validate the full contract of each. A narrow query that only observes the
  state that a mutation promises is not a second responsibility.

## MECHANICAL CASE CONTRACTS

- `itest/main_test.go` enforces the `component action` naming form. This form
  is mandatory. A name has at least two words, separated by spaces, and no
  underscores.
- The subject contract of a case is not clear when the registered name and the
  test function use different words for the component or the behavior.
- A case is not independent when its result depends on any of these items:
  - The order of registration.
  - State that another case left.
  - Wall-clock timing.
  - The fixture of another case.

## ARRANGE, ACT, AND ASSERT REMAIN DISTINCT

- `docs/developer/unit_testing_guidelines.md` requires three distinct phases:
  Arrange, Act, and Assert. Blank lines separate the phases.
- Arrange makes the fixtures, the preconditions, and the necessary readiness.
  Act does the isolated subject behavior. Assert checks the public outcome of
  that behavior. Assert checks only the narrow postconditions that are
  necessary to prove that outcome.
- The contract is not clear when helpers, broad assertion bundles, defensive
  success checks, or comments hide the Act or its decisive assertions.
- An assertion bundle violates single responsibility when it silently proves
  more than one independent contract, and not only the named case.
- Assertions must use `require`. Stable public error contracts must use
  `require.ErrorIs` or `require.ErrorAs`. A match on the text of an
  implementation error makes the case depend on a detail that is not part of
  the contract.
- A defensive nil guard after a successful API result hides a success state
  that cannot occur. The guard is correct only if a non-nil result is part of
  the public contract that the case asserts.
- A test comment violates the documentation contract of the repository when a
  reader cannot find why the case exists and what it checks. A description of
  the mechanics does not replace an explanation of non-obvious intent, control
  values, waits, error identities, or reloads.

## TABLES CONTAIN DATA, NOT BEHAVIOR

- A table violates the data-only contract when its rows contain closures for
  setup, execution, or assertions. Rows must contain names, inputs, and
  expected results.
- Branches for specific rows that materially change the setup, execution, or
  assertions hide different scenarios in one uniform table.
- Boundary variants do not violate the table contract when every row keeps
  the same subject and the same execution structure.

## LIFECYCLE HAS ONE OWNER

- The harness owns the documented policy for routine wallet creation,
  registration, funding, synchronization, and cleanup. A copy of this policy
  outside the harness makes a competing source of truth.
- A lifecycle transition under test is not clear when fixture setup hides the
  transition. The transition must stay the visible Act of the case.
- Cleanup is not valid when a resource has no shutdown owner, has more than
  one owner, or stays registered after another owner released it.
- After a failed start or a partial setup, one recoverable shutdown owner must
  still own every wallet, manager, process, and goroutine that the test
  acquired.
- A new fixture variation is not a violation only because it is new. It is a
  violation when it copies an established lifecycle policy, or when it changes
  the ownership semantics without one canonical owner.

## READINESS REPRESENTS REAL ASYNCHRONY

- Sleeps and raw retry loops violate the readiness boundary of the harness.
- Do not use `wait.NoError` for these conditions:
  - A synchronous result.
  - A deterministic state transition.
  - A postcondition that a completed readiness boundary already guarantees.

  Use `wait.NoError` only when independently scheduled work can make the
  condition true at a later time.
- The documented `bwtest/wait` contract alone owns the callback, interval, and
  timeout behavior. A copy of these mechanics in this file or in a scenario
  makes a second policy owner.
- Do not use `AssertWalletSynced` as a routine step after wallet creation or
  start. Creation and start do not promise synchronization. Use it only in
  these conditions:
  - The initial synchronization is the subject of the case.
  - A later action needs the state at the current tip, and no harness
    boundary occurs between the two.
- A readiness check before the final side effect that can start asynchronous
  work does not protect behavior that depends on that later effect.
- Polling after an authoritative readiness boundary hides a broken visibility
  or atomicity guarantee. If a direct read fails after that boundary, the read
  shows the violated contract. Do not hide the failure with another wait.
- If scenarios repeat a recurring readiness predicate or timeout policy, the
  definitions can diverge. A condition that is unique to one scenario does not
  violate this rule only because it needs a local bounded wait.

## HELPERS AND FIXTURES MUST NOT HIDE CONTRACTS

- A helper is a violation when it hides the subject call, the decisive
  assertions, or a full multi-API scenario from the registered case.
- A helper or fixture makes competing ownership when it defines its own
  policy for side-effecting setup, lifecycle, readiness, or cleanup, and the
  harness already owns that policy.
- Shared fixtures have accidental ownership when the test file of one
  component is the source of the constants, builders, or algorithms of another
  component.
- Package-level names that lose their meaning outside their original file
  make the ownership unclear for every other consumer in `itest`.
- The location, shape, and reuse count of a helper are not violations alone.
  The violation is an unclear domain responsibility, a hidden contract, or a
  competing policy owner.

## PRESERVE ONE SOURCE OF TRUTH

- A test violates the single-source-of-truth invariant when it declares
  authoritative production or harness configuration again, and the two copies
  can drift apart.
- Related facts kept as independent mutable values are a violation when you
  can derive one fact from the canonical value.
- Repeated fixture algorithms violate the invariant when their assumptions
  can diverge across consumers.
- An intentionally independent test oracle is not duplication when it
  verifies the production decision and does not copy it. A reviewer must be
  able to see its independence and the contract that it protects.

## PUBLIC CONTRACTS DO NOT CHANGE BY BACKEND

- A backend-neutral case is not valid when it accepts success on one
  supported database or chain backend and failure on another.
- Backend-conditioned expectations violate the public contract, unless the API
  documents that backend difference.
- Boundary coverage is not complete when an applicable contract does not test
  each of these values:
  - The last rejected value.
  - The first accepted value.
  - The accepted maximum.
  - The first value above the maximum.
- A negative mutation case is not complete when it can pass after a partial
  change to the applicable public state.
- A durability claim is not proved when the case does not go through the
  supported close-and-reopen lifecycle. It is also not proved when the case
  compares only a selected subset that can hide lost state.

## VERIFICATION MUST MATCH THE CONTRACT

- First, run the narrowest matching case. For example:

  ```bash
  make itest chain=btcd db=sqlite icase='component action'
  ```

- Verification is not complete when a backend-neutral case does not run on
  every supported database and chain backend that can execute it.
- One ordered run is not sufficient evidence for a case that is sensitive to
  timing or order. For a failure with a non-zero `-shuffleseed`, keep the seed
  that reproduces the order.
- Failure evidence is not complete without these items:
  - The applicable output from `itest/test-logs/`.
  - The exact chain, database, case filter, repeat count, and shuffle seed.
