# Unit Testing Guidelines

This document outlines the best practices for writing clear, effective, and
maintainable unit tests in this project. The goal is to create a test suite
that is not a burden but a valuable asset: it should be easy to read, easy to
maintain, and give high confidence that our code works correctly.

## Guiding Principles

1.  **Clarity is paramount:** A test should be as easy to read and understand
    as possible.
2.  **One test, one concept:** Each test should verify a single, specific piece
    of behavior.
3.  **Tests should be reliable:** Tests should be deterministic and free of
    side effects.

---

## 1. When to Use Table-driven Tests

For testing variations in data inputs and outputs, the **table-driven test is
the default and most efficient pattern**. They are excellent for exercising the
same logic with a wide range of different inputs and expected outputs.

The cardinal rule is that the **structure of the "Arrange" block must be
identical for all test cases**. The test loop's body must not contain
conditional logic (like `if` or `switch` statements) to handle different setup
requirements for different test cases. Only the *data* used in the setup should
vary.

**A simple litmus test: If you find yourself writing an `if` statement inside
the test's `for` loop to change the mock setup for a specific case, the setups
are too different. You should use separate `Test` functions instead.**

#### Good Use Case: Identical Setup Structure

Testing a function like `func IsValidScriptClass(class txscript.ScriptClass) bool`.
The test cases would simply be a list of script classes and the expected
boolean result. The setup is the same for all cases.

#### Bad Use Case: Conditional Mocking in the Test Loop

Avoid using a table-driven test if the number or sequence of mock calls changes
between test cases. This forces you to add conditional logic to the test loop,
which is an anti-pattern that makes the test hard to debug.

**AVOID THIS PATTERN:**

```go
// This test combines two cases with different mock setups, forcing an 'if'
// statement into the test loop.
func TestGetThing(t *testing.T) {
    testCases := []struct {
        name string
        setupSecondMock bool // This flag is an anti-pattern
        // ... other fields
    }{
        {name: "success", setupSecondMock: true},
        {name: "not found", setupSecondMock: false},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Arrange
            mocks.mock1.On("FirstCall").Return(...)

            // ANTI-PATTERN: Conditional logic in the setup block.
            if tc.setupSecondMock {
                mocks.mock2.On("SecondCall").Return(...)
            }

            // Act and Assert...
        })
    }
}
```

**PREFERRED PATTERN:**

When setups differ, use separate, standalone functions. The clarity of a
simple, linear test body is more valuable than the conciseness of a complex,
branching one.

```go
func TestGetThingSuccess(t *testing.T) {
    // Arrange
    mocks.mock1.On("FirstCall").Return(...)
    mocks.mock2.On("SecondCall").Return(...)

    // Act and Assert...
}

func TestGetThingNotFound(t *testing.T) {
    // Arrange
    mocks.mock1.On("FirstCall").Return(...) // Only one mock is needed

    // Act and Assert...
}
```

## 2. Keep Test Case Structs for Data

A test case struct in a table-driven test should be for data only (inputs and
expected outputs). It should not contain functions or complex setup logic.
Embedding setup into the test case itself obscures the test's behavior and
makes it harder to understand each case in isolation. The setup should be
explicit and clear within the test's body.

### Good Example: Data-only Struct

The struct only contains the inputs and expected outputs for the test. The setup
is performed separately and explicitly in the test body.

```go
func TestBuildTxDetail(t *testing.T) {
    tests := []struct {
        name             string
        details          *wtxmgr.TxDetails // Input
        currentHeight    int32             // Input
        expectedTxDetail *TxDetail         // Expected Output
    }{
        // ... test cases defined here
    }

    for _, test := range tests {
        // ... test logic here
    }
}
```

### Bad Example: Struct with Setup Logic

Here, the setup logic is hidden inside a function within the test case struct.
This makes it difficult to see the overall test flow and understand what each
case is doing without inspecting the closure's implementation.

```go
// AVOID THIS PATTERN
func TestSomething(t *testing.T) {
    tests := []struct {
        name        string
        setup       func(*testing.T, *mockStore) // Setup logic in the struct
        expectedErr error
    }{
        {
            name: "some case",
            setup: func(t *testing.T, ms *mockStore) {
                // Complex, multi-step setup logic hidden here.
                ms.On("SomeCall", mock.Anything).Return(nil)
                ms.On("AnotherCall", 123).Return(errors.New("fail"))
            },
            expectedErr: nil,
        },
    }
    // ...
}
```

## 3. Structure Tests with "Arrange, Act, Assert" (AAA)

This pattern makes tests predictable and highly readable. The body of a test
function should be structured into these three distinct parts, separated by a
blank line.

1.  **Arrange:** This section sets up the world for the test. This includes
    creating mocks, inserting data into a test database, and initializing any
    objects needed for this specific test.
2.  **Act:** This section executes the single function or method under test.
3.  **Assert:** This section checks that the outcome is as expected. This
    involves asserting that the function returned the correct value, that the
    correct error was returned, or that a mock was called with the right
    parameters.

### Example

```go
func TestLabelTx_TxNotFound_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Mock the TxDetails call to return nil, simulating a tx
	// that is not known to the wallet.
	w, mocks := testWalletWithMocks(t)
	mocks.txStore.On("TxDetails", mock.Anything, TstTxHash).
		Return(nil, nil).Once()

	// Act: Attempt to label a tx that is not known to the wallet.
	err := w.LabelTx(context.Background(), *TstTxHash, "some label")

	// Assert: Check that the correct error is returned.
	require.ErrorIs(t, err, ErrTxNotFound)
	mocks.txStore.AssertExpectations(t)
}
```

## 4. A Test Should Target a Single Concept

Each test function should verify one specific piece of behavior. This makes it
obvious what is broken when a test fails and makes the test itself simpler.

For example, a complex test for `BuildTxDetail` can be broken into
three focused, standalone functions:

-   `TestBuildTxDetailMinedTxSuccess`
-   `TestBuildTxDetailUnminedTxSuccess`
-   `TestBuildTxDetailUnminedTxNoFeeSuccess`

The function names are descriptive, and if one fails, the source of the bug is
easier to identify.

## 5. Recommended Pattern for Complex Tests: Standalone Functions

When a test requires a unique or complex setup, **the recommended approach is a standalone `Test` function.**

In testing, **clarity and debuggability are more important than avoiding code
repetition.** A self-contained test where the setup, execution, and assertions
are read linearly is far easier to debug than a test that relies on
abstractions or helper functions.

**Use this pattern when:**
*   The test requires a multi-step or complex setup.
*   You are verifying a sequence of behaviors, not just a simple input/output.
*   The test setup is unique and not reused by other tests.

**Example:**
```go
// Flat naming is clear and allows for precise test execution.
func TestProcessPaymentHandlesOrchestration(t *testing.T) {
    // Arrange: The complex, unique setup is self-contained and easy to read here.
    mockNotifier := &MockNotifier{}
    mockDB := &MockDB{}
    // ... more setup ...

    // Act
    ProcessPayment(...)

    // Assert: Verify the specific sequence of calls.
    require.True(t, mockDB.WasCalledFirst)
    require.True(t, mockNotifier.WasCalledSecond)
}
```

## 7. Prefer `require` Over `assert`

The `testify` library provides both `require` and `assert` packages.

-   `require` (e.g., `require.NoError(t, err)`) **stops the test immediately**
    if the assertion fails.
-   `assert` (e.g., `assert.Equal(t, 1, 2)`) reports a failure but **allows the
    test to continue executing**.

For most setup and critical checks, `require` is the preferred choice. When an
assertion fails, the rest of the test is likely invalid and may produce noise or
panics. `assert` should be used only when checking multiple independent
conditions where seeing all failures at once is valuable.