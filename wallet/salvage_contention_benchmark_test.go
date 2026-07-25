package wallet

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

const salvageContentionTimeout = 2 * time.Second

// salvageContentionStore counts one-shot writer calls and SQLite contention
// results without changing the delegated transaction behavior.
type salvageContentionStore struct {
	// Store delegates the measured transaction execution.
	walletstore.Store

	updateCalls atomic.Int64
	busyEvents  atomic.Int64
}

// UpdateOnce records writer calls and retryable SQLite contention results.
func (s *salvageContentionStore) UpdateOnce(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	s.updateCalls.Add(1)
	err := s.Store.UpdateOnce(ctx, body, reset)
	var retryable *walletstore.RetryableTransactionError
	if errors.As(err, &retryable) {
		s.busyEvents.Add(1)
	}

	return err
}

// salvageFundingBenchmarkFixture owns the common spend used by blocked and
// mixed funding measurements.
type salvageFundingBenchmarkFixture struct {
	fixture          *salvageBenchmarkFixture
	output           *wire.TxOut
	outpoint         wire.OutPoint
	startExternal    uint32
	startInternal    uint32
	notificationSink *splitChainClient
}

// newSalvageFundingBenchmarkFixture creates one repeatable SQLite funding
// workload. Authored transactions are not published, so the UTXO stays usable.
func newSalvageFundingBenchmarkFixture(
	b *testing.B) *salvageFundingBenchmarkFixture {

	b.Helper()
	fixture := newSalvageBenchmarkFixture(b)
	wallet := fixture.wallet
	wallet.chainClient = &mockChainClient{}

	receive, err := wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	if err != nil {
		b.Fatalf("allocate funding address: %v", err)
	}
	prevScript, err := txscript.PayToAddrScript(receive)
	if err != nil {
		b.Fatalf("create funding script: %v", err)
	}
	fundingTx := wire.NewMsgTx(2)
	fundingTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  chainhash.Hash{0x61},
		Index: 1,
	}})
	fundingTx.AddTxOut(wire.NewTxOut(1_000_000, prevScript))
	funding, err := wtxmgr.NewTxRecordFromMsgTx(
		fundingTx, time.Unix(1_700_000_100, 0),
	)
	if err != nil {
		b.Fatalf("create funding record: %v", err)
	}
	if err := wallet.store.UpdateOnce(
		b.Context(), func(tx walletstore.ReadWriteTx) error {
			return wallet.addRelevantTxFromStore(tx, funding, nil)
		}, nil,
	); err != nil {

		b.Fatalf("insert funding transaction: %v", err)
	}

	destination, err := txscript.PayToAddrScript(receive)
	if err != nil {
		b.Fatalf("create destination script: %v", err)
	}
	startExternal, startInternal := salvageBenchmarkAccountIndexes(
		b, wallet.store, waddrmgr.KeyScopeBIP0084,
		waddrmgr.DefaultAccountNum,
	)
	notificationSink := &splitChainClient{
		mockChainClient: &mockChainClient{},
	}
	wallet.chainClient = notificationSink

	return &salvageFundingBenchmarkFixture{
		fixture:          fixture,
		output:           wire.NewTxOut(100_000, destination),
		outpoint:         wire.OutPoint{Hash: funding.Hash, Index: 0},
		startExternal:    startExternal,
		startInternal:    startInternal,
		notificationSink: notificationSink,
	}
}

// createSimpleTx authors one transaction against the fixture's reusable UTXO.
func (f *salvageFundingBenchmarkFixture) createSimpleTx(
	strategy CoinSelectionStrategy,
	options ...TxCreateOption) (*wire.MsgTx, error) {

	authored, err := f.fixture.wallet.CreateSimpleTx(
		&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
		[]*wire.TxOut{{
			Value:    f.output.Value,
			PkScript: append([]byte(nil), f.output.PkScript...),
		}}, 0, 1_000, strategy, false, options...,
	)
	if err != nil {
		return nil, err
	}

	return authored.Tx, nil
}

// salvageBenchmarkAccountIndexes reads the durable branch indexes used to
// validate mixed-writer allocation continuity after timing stops.
func salvageBenchmarkAccountIndexes(b *testing.B, store walletstore.Store,
	scope waddrmgr.KeyScope, account uint32) (uint32, uint32) {

	b.Helper()
	var state waddrmgr.AccountState
	err := store.View(b.Context(), func(tx walletstore.ReadTx) error {
		var err error
		state, err = tx.Addr().Account(scope, account)
		return err
	}, func() {
		state = waddrmgr.AccountState{}
	})
	if err != nil {
		b.Fatalf("read benchmark account indexes: %v", err)
	}

	return state.NextExternalIndex, state.NextInternalIndex
}

// salvageDurationPercentile returns the nearest-rank latency percentile.
func salvageDurationPercentile(values []time.Duration,
	percentile int) time.Duration {

	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i] < ordered[j]
	})
	rank := (len(ordered)*percentile + 99) / 100
	if rank < 1 {
		rank = 1
	}

	return ordered[rank-1]
}

// salvageBlockedRun starts one wallet operation that announces when its
// selected external seam has blocked.
type salvageBlockedRun func(started, release chan struct{}) <-chan error

// benchmarkSalvageBlockedWrite measures an unrelated same-wallet write while
// the selected wallet seam is blocked outside a Store transaction.
func benchmarkSalvageBlockedWrite(b *testing.B, store walletstore.Store,
	prepare func() error, run salvageBlockedRun) {

	b.Helper()
	durations := make([]time.Duration, b.N)
	var busyEvents int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if prepare != nil {
			if err := prepare(); err != nil {
				b.Fatalf("prepare blocked operation: %v", err)
			}
		}

		started := make(chan struct{})
		release := make(chan struct{})
		result := run(started, release)
		select {
		case <-started:

		case <-time.After(salvageContentionTimeout):
			close(release)
			b.Fatal("wallet seam did not block")
		}

		start := time.Now()
		err := store.UpdateOnce(
			b.Context(), func(tx walletstore.ReadWriteTx) error {
				return tx.Addr().SetBirthday(
					time.Unix(1_700_001_000+int64(i), 0),
				)
			}, nil,
		)
		durations[i] = time.Since(start)
		var retryable *walletstore.RetryableTransactionError
		if errors.As(err, &retryable) {
			busyEvents++
		}
		close(release)
		if err != nil {
			b.Fatalf("unrelated SQLite write: %v", err)
		}

		select {
		case err := <-result:
			if err != nil {
				b.Fatalf("blocked wallet operation: %v", err)
			}

		case <-time.After(salvageContentionTimeout):
			b.Fatal("released wallet operation did not finish")
		}
	}
	b.StopTimer()

	b.ReportMetric(float64(salvageDurationPercentile(
		durations, 50,
	).Microseconds()), "write-p50-us")
	b.ReportMetric(float64(salvageDurationPercentile(
		durations, 100,
	).Microseconds()), "write-max-us")
	b.ReportMetric(float64(busyEvents), "sqlite-busy/run")
}

// BenchmarkSQLiteBlockedSeamContention measures same-wallet writes while each
// external, policy, or cryptographic seam is deliberately blocked.
func BenchmarkSQLiteBlockedSeamContention(b *testing.B) {
	useSalvageBenchmarkScrypt(b)

	b.Run("FilterBlocks", benchmarkSalvageFilterBlocksContention)
	b.Run("GetBlockHeader", benchmarkSalvageGetBlockHeaderContention)
	b.Run("NotifyReceived", benchmarkSalvageNotifyReceivedContention)
	b.Run("AllowUtxo", benchmarkSalvageAllowUtxoContention)
	b.Run("CoinStrategy", benchmarkSalvageCoinStrategyContention)
	b.Run("Signing", benchmarkSalvageSigningContention)
}

// benchmarkSalvageFilterBlocksContention blocks recovery filtering after its
// durable snapshot and lookahead preparation have completed.
func benchmarkSalvageFilterBlocksContention(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageBenchmarkFixture(b)
	wallet := fixture.wallet
	params := &chaincfg.TestNet3Params
	header := wire.BlockHeader{
		Version:   1,
		PrevBlock: params.GenesisBlock.BlockHash(),
		Timestamp: params.GenesisBlock.Header.Timestamp.Add(time.Minute),
		Nonce:     1,
	}
	hash := header.BlockHash()
	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: hash, Height: 1},
		Time:  header.Timestamp,
	}
	stamp := &waddrmgr.BlockStamp{
		Hash: hash, Height: 1, Timestamp: header.Timestamp,
	}
	managers := make(map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager)
	for _, manager := range wallet.Manager.ActiveScopedKeyManagers() {
		managers[manager.Scope()] = manager
	}
	client := &mockChainClient{getBlockHeader: &header}

	benchmarkSalvageBlockedWrite(
		b, wallet.store, nil,
		func(started, release chan struct{}) <-chan error {
			client.filterBlocksFunc = func(*chain.FilterBlocksRequest) (
				*chain.FilterBlocksResponse, error) {

				close(started)
				<-release
				return nil, nil
			}
			result := make(chan error, 1)
			go func() {
				_, err := wallet.prepareRecoveryStorePlan(
					client, NewRecoveryState(1),
					[]wtxmgr.BlockMeta{block},
					[]*waddrmgr.BlockStamp{stamp}, managers,
				)
				result <- err
			}()

			return result
		},
	)
}

// benchmarkSalvageGetBlockHeaderContention blocks parent-header retrieval
// during a Store-backed disconnect after its read snapshot has closed.
func benchmarkSalvageGetBlockHeaderContention(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageBenchmarkFixture(b)
	wallet := fixture.wallet
	hashes, headers := syncTestChain(&chaincfg.TestNet3Params, 1)
	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: hashes[1], Height: 1},
		Time:  headers[hashes[1]].Timestamp,
	}
	wallet.SetChainSynced(true)
	client := &mockChainClient{}
	prepare := func() error {
		return wallet.store.UpdateOnce(
			b.Context(), func(tx walletstore.ReadWriteTx) error {
				return wallet.connectBlockFromStore(tx, block)
			}, nil,
		)
	}

	benchmarkSalvageBlockedWrite(
		b, wallet.store, prepare,
		func(started, release chan struct{}) <-chan error {
			client.getBlockHeaderFunc = func(hash *chainhash.Hash) (
				*wire.BlockHeader, error) {

				close(started)
				<-release
				header := headers[*hash]
				return &header, nil
			}
			result := make(chan error, 1)
			go func() {
				_, err := wallet.disconnectBlockFromStore(client, block)
				result <- err
			}()

			return result
		},
	)
}

// benchmarkSalvageNotifyReceivedContention blocks post-commit watcher
// registration while another same-wallet write executes.
func benchmarkSalvageNotifyReceivedContention(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageFundingBenchmarkFixture(b)
	wallet := fixture.fixture.wallet

	benchmarkSalvageBlockedWrite(
		b, wallet.store, nil,
		func(started, release chan struct{}) <-chan error {
			client := &splitChainClient{
				mockChainClient: &mockChainClient{},
				started:         started,
				release:         release,
			}
			wallet.chainClient = client
			result := make(chan error, 1)
			go func() {
				_, err := fixture.createSimpleTx(CoinSelectionLargest)
				if err == nil && client.notifications.Load() != 1 {
					err = fmt.Errorf("watcher calls: got %d, want 1",
						client.notifications.Load())
				}
				result <- err
			}()

			return result
		},
	)
}

// benchmarkSalvageAllowUtxoContention blocks caller UTXO policy after the
// funding snapshot has closed.
func benchmarkSalvageAllowUtxoContention(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageFundingBenchmarkFixture(b)
	wallet := fixture.fixture.wallet

	benchmarkSalvageBlockedWrite(
		b, wallet.store, nil,
		func(started, release chan struct{}) <-chan error {
			var once sync.Once
			result := make(chan error, 1)
			go func() {
				_, err := fixture.createSimpleTx(
					CoinSelectionLargest,
					WithUtxoFilter(func(wtxmgr.Credit) bool {
						once.Do(func() { close(started) })
						<-release
						return true
					}),
				)
				result <- err
			}()

			return result
		},
	)
}

// benchmarkSalvageCoinStrategyContention blocks caller coin ordering after the
// funding snapshot has closed.
func benchmarkSalvageCoinStrategyContention(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageFundingBenchmarkFixture(b)
	wallet := fixture.fixture.wallet

	benchmarkSalvageBlockedWrite(
		b, wallet.store, nil,
		func(started, release chan struct{}) <-chan error {
			var once sync.Once
			strategy := fundingStrategyFunc(func(coins []Coin,
				_ btcutil.Amount) ([]Coin, error) {

				once.Do(func() { close(started) })
				<-release
				return coins, nil
			})
			result := make(chan error, 1)
			go func() {
				_, err := fixture.createSimpleTx(strategy)
				result <- err
			}()

			return result
		},
	)
}

// benchmarkSalvageSigningContention blocks transaction signing after all
// durable funding and key material has been detached.
func benchmarkSalvageSigningContention(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageFundingBenchmarkFixture(b)
	wallet := fixture.fixture.wallet

	benchmarkSalvageBlockedWrite(
		b, wallet.store, nil,
		func(started, release chan struct{}) <-chan error {
			var once sync.Once
			previous := activeStoreTxObserver.Swap(&storeTxObserver{
				observe: func(stage storeTxStage) {
					if stage != storeTxStageSigning {
						return
					}
					once.Do(func() { close(started) })
					<-release
				},
			})
			result := make(chan error, 1)
			go func() {
				defer activeStoreTxObserver.Store(previous)
				_, err := fixture.createSimpleTx(CoinSelectionLargest)
				result <- err
			}()

			return result
		},
	)
}

// BenchmarkSQLiteMixedWalletWriters runs equal external-key and funding
// writers against one SQLite wallet and one BIP84 account.
func BenchmarkSQLiteMixedWalletWriters(b *testing.B) {
	useSalvageBenchmarkScrypt(b)
	b.StopTimer()
	fixture := newSalvageFundingBenchmarkFixture(b)
	wallet := fixture.fixture.wallet
	store := &salvageContentionStore{Store: wallet.store}
	wallet.store = store

	externalCount := b.N / 2
	fundingCount := b.N - externalCount
	externalResults := make([]salvageBenchmarkKeyResult, externalCount)
	externalDurations := make([]time.Duration, externalCount)
	fundingDurations := make([]time.Duration, fundingCount)
	fundingErrors := make([]error, fundingCount)
	start := make(chan struct{})
	var ready sync.WaitGroup
	var workers sync.WaitGroup
	ready.Add(2)
	workers.Add(2)
	go func() {
		defer workers.Done()
		ready.Done()
		<-start
		for i := 0; i < externalCount; i++ {
			begin := time.Now()
			key, index, err := wallet.NextExternalKey(
				waddrmgr.KeyScopeBIP0084,
				waddrmgr.DefaultAccountNum,
			)
			externalDurations[i] = time.Since(begin)
			externalResults[i] = salvageBenchmarkKeyResult{
				index: index,
				err:   err,
			}
			if err == nil && key != nil {
				copy(externalResults[i].publicKey[:],
					key.SerializeCompressed())
			}
		}
	}()
	go func() {
		defer workers.Done()
		ready.Done()
		<-start
		for i := 0; i < fundingCount; i++ {
			begin := time.Now()
			_, fundingErrors[i] = fixture.createSimpleTx(
				CoinSelectionLargest,
			)
			fundingDurations[i] = time.Since(begin)
		}
	}()
	ready.Wait()

	b.ReportAllocs()
	b.ResetTimer()
	begin := time.Now()
	close(start)
	workers.Wait()
	elapsed := time.Since(begin)
	b.StopTimer()

	publicKeys := make(map[[33]byte]struct{}, externalCount)
	for i, result := range externalResults {
		if result.err != nil {
			b.Fatalf("external allocation %d: %v", i, result.err)
		}
		wantIndex := fixture.startExternal + uint32(i)
		if result.index != wantIndex {
			b.Fatalf("external index %d: got %d, want %d", i,
				result.index, wantIndex)
		}
		if _, ok := publicKeys[result.publicKey]; ok {
			b.Fatalf("duplicate external key at allocation %d", i)
		}
		publicKeys[result.publicKey] = struct{}{}
	}
	for i, err := range fundingErrors {
		if err != nil {
			b.Fatalf("funding operation %d: %v", i, err)
		}
	}
	gotNotifications := fixture.notificationSink.notifications.Load()
	if gotNotifications != int32(fundingCount) {

		b.Fatalf("watcher callbacks: got %d, want %d", gotNotifications,
			fundingCount)
	}
	afterExternal, afterInternal := salvageBenchmarkAccountIndexes(
		b, store, waddrmgr.KeyScopeBIP0084,
		waddrmgr.DefaultAccountNum,
	)
	wantExternal := fixture.startExternal + uint32(externalCount)
	if afterExternal != wantExternal {

		b.Fatalf("final external index: got %d, want %d",
			afterExternal, wantExternal)
	}
	wantInternal := fixture.startInternal + uint32(fundingCount)
	if afterInternal != wantInternal {

		b.Fatalf("final internal index: got %d, want %d",
			afterInternal, wantInternal)
	}

	durations := append(externalDurations, fundingDurations...)
	retries := store.updateCalls.Load() - int64(b.N)
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "aggregate-ops/s")
	b.ReportMetric(float64(salvageDurationPercentile(
		durations, 50,
	).Microseconds()), "latency-p50-us")
	b.ReportMetric(float64(salvageDurationPercentile(
		durations, 95,
	).Microseconds()), "latency-p95-us")
	b.ReportMetric(float64(salvageDurationPercentile(
		durations, 99,
	).Microseconds()), "latency-p99-us")
	b.ReportMetric(float64(store.busyEvents.Load()), "writer-busy/run")
	b.ReportMetric(float64(retries), "writer-retries/run")
}
