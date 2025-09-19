package wallet

import (
	"fmt"
)

// growthFunc defines how a benchmark parameter should scale with iteration
// index. It takes an iteration index i (0-based) and returns the parameter
// value for that iteration. This allows flexible configuration of benchmark
// data sizes with different growth patterns (linear, exponential, logarithmic,
// etc.).
type growthFunc func(i int) int

// linearGrowth scales the parameter value linearly.
func linearGrowth(i int) int {
	return 5 + (i * 5)
}

// exponentialGrowth scales the parameter value exponentially.
func exponentialGrowth(i int) int {
	return 1 << i
}

// constantGrowth returns a constant value regardless of iteration.
func constantGrowth(i int) int {
	return 0
}

// benchmarkDataSize represents different test data sizes for stress testing.
type benchmarkDataSize struct {
	// numAccounts is the number of accounts to create.
	numAccounts int

	// numUTXOs is the number of UTXOs to create.
	numUTXOs int

	// maxAccounts is the maximum number of accounts in the benchmark
	// series.
	maxAccounts int

	// maxUTXOs is the maximum number of UTXOs in the benchmark series.
	maxUTXOs int
}

// name returns a dynamically generated benchmark name based on accounts and
// UTXOs. Uses dynamic padding based on maximum values for proper sorting in
// visualization tools. If numUTXOs is 0, it's omitted from the name.
func (b benchmarkDataSize) name() string {
	accountDigits := len(fmt.Sprintf("%d", b.maxAccounts))

	if b.numUTXOs == 0 {
		return fmt.Sprintf("%0*d-Accounts", accountDigits,
			b.numAccounts)
	}

	utxoDigits := len(fmt.Sprintf("%d", b.maxUTXOs))

	return fmt.Sprintf("%0*d-Accounts-%0*d-UTXOs",
		accountDigits, b.numAccounts, utxoDigits, b.numUTXOs)
}

// benchmarkConfig holds configuration for benchmark wallet setup.
type benchmarkConfig struct {
	// accountGrowth is the function to use to grow the number of accounts.
	accountGrowth growthFunc

	// utxoGrowth is the function to use to grow the number of UTXOs.
	utxoGrowth growthFunc

	// maxIterations is the maximum number of iterations to run.
	maxIterations int

	// startIndex is the index to start the benchmark at.
	startIndex int
}

// generateBenchmarkSizes creates benchmark data sizes programmatically.
func generateBenchmarkSizes(config benchmarkConfig) []benchmarkDataSize {
	var sizes []benchmarkDataSize

	// Calculate maximum values for proper padding.
	maxAccounts := config.accountGrowth(config.maxIterations)
	maxUTXOs := config.utxoGrowth(config.maxIterations)

	for i := config.startIndex; i <= config.maxIterations; i++ {
		sizes = append(sizes, benchmarkDataSize{
			numAccounts: config.accountGrowth(i),
			numUTXOs:    config.utxoGrowth(i),
			maxAccounts: maxAccounts,
			maxUTXOs:    maxUTXOs,
		})
	}

	return sizes
}
