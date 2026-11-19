// Package bwtest provides shared Wallet benchmark data and diagnostics.
package bwtest

import (
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// StartBenchmarkProfile starts the requested diagnostic after fixture setup.
// Call the returned function immediately after the workload, before cleanup;
// cleanup also finishes a failed run before the Wallet is stopped. Empty mode
// leaves normal timing runs free of profile writes and explicit GC.
func StartBenchmarkProfile(tb testing.TB) func() {
	tb.Helper()

	mode := os.Getenv("BTCWALLET_BENCH_PROFILE")
	if mode == "" {
		// Keep identical call sites without adding probes inside the loop.
		return func() {}
	}

	dir := os.Getenv("BTCWALLET_BENCH_PROFILE_DIR")
	require.NotEmpty(tb, dir, "profile output directory is required")

	// Separate captures keep CPU-profiler allocations out of the heap delta.
	// Each diagnostic can also use its own duration.
	switch mode {
	case "cpu":
		file, err := os.Create(filepath.Clean(filepath.Join(dir, "cpu.pprof")))
		require.NoError(tb, err)

		// Register before starting so a failed start or operation still closes
		// the file. OnceFunc makes explicit stop and cleanup share ownership.
		finish := sync.OnceFunc(func() {
			pprof.StopCPUProfile()
			require.NoError(tb, file.Close())
		})
		tb.Cleanup(finish)
		require.NoError(tb, pprof.StartCPUProfile(file))

		return finish

	case "mem":
		// Both snapshots use the lifetime-constant default sampling rate;
		// subtract this baseline to remove prepared fixture allocation history.
		writeBenchmarkHeap(tb, filepath.Join(dir, "heap-before.pprof"))

		finish := sync.OnceFunc(func() {
			writeBenchmarkHeap(tb, filepath.Join(dir, "heap-after.pprof"))
		})
		tb.Cleanup(finish)

		return finish

	default:
		tb.Fatalf("unknown benchmark profile mode %q", mode)

		return nil
	}
}

// writeBenchmarkHeap captures allocations and retained heap before cleanup.
func writeBenchmarkHeap(tb testing.TB, path string) {
	tb.Helper()

	// Explicit GC completes sweeping and publishes the latest heap profile;
	// one call suffices in the pinned Go runtime. Keep sampling unchanged.
	runtime.GC()

	file, err := os.Create(filepath.Clean(path))

	require.NoError(tb, err)
	defer func() { require.NoError(tb, file.Close()) }()

	// The standard heap format retains both alloc_space and inuse_space;
	// pprof -base can therefore distinguish allocation traffic from retention.
	require.NoError(tb, pprof.WriteHeapProfile(file))
}

// BenchmarkRead measures a prepared native read after one untimed first call.
// The first b.Loop resets time and allocations; loop exit stops timing. Finish
// diagnostics here so neither fixture preparation nor shutdown enters profiles.
func BenchmarkRead(b *testing.B, read func() error) {
	b.Helper()

	// Prime the selected request on the measured Wallet before diagnostics.
	err := read()
	if err != nil {
		b.Fatalf("prepare read: %v", err)
	}

	finishProfile := StartBenchmarkProfile(b)
	b.ReportAllocs()

	// Measure completed calls, including normal database I/O, and stop on
	// operation errors without inspecting results or validating the fixture.
	for b.Loop() {
		err := read()
		if err != nil {
			b.Fatalf("read: %v", err)
		}
	}

	finishProfile()
}
