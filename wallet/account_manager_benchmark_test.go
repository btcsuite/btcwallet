package wallet

import (
	"fmt"
)

// benchmarkDataSize represents different test data sizes for stress testing.
type benchmarkDataSize struct {
	numAccounts int
	numUTXOs    int
}

// name returns a dynamically generated benchmark name based on accounts and
// UTXOs with leading zeros for proper sorting in visualization tools.
func (b benchmarkDataSize) name() string {
	// Intentionally using leading zeros for proper sorting.
	return fmt.Sprintf("%02d-Accounts-%05d-UTXOs", b.numAccounts,
		b.numUTXOs)
}

// generateBenchmarkSizes creates benchmark data sizes programmatically.
func generateBenchmarkSizes() []benchmarkDataSize {
	var sizes []benchmarkDataSize

	// Generate UTXO sizes from 2^0 to 2^14 and account sizes from 5 to 75.
	for i := 0; i <= 14; i++ {
		numUTXOs := 1 << i
		numAccounts := 5 + (i * 5)
		sizes = append(sizes, benchmarkDataSize{
			numAccounts: numAccounts,
			numUTXOs:    numUTXOs,
		})
	}

	return sizes
}
