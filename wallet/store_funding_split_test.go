package wallet

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// splitFundingFixture owns one unlocked SQLite Store wallet and spendable
// P2WPKH output.
type splitFundingFixture struct {
	validation  *validationFixture
	wallet      *Wallet
	store       walletstore.Store
	outpoint    wire.OutPoint
	prevScript  []byte
	destination []byte
}

// newSplitFundingFixture creates one deterministic Store funding fixture.
func newSplitFundingFixture(t *testing.T) *splitFundingFixture {
	t.Helper()

	seed := bytes.Repeat([]byte{0x61}, hdkeychain.RecommendedSeedLen)
	validation := newValidationFixture(
		t, "sqlite", "funding-split", func(loader *Loader) (*Wallet, error) {
			return loader.CreateNewWallet(
				[]byte("public"), []byte("private"), seed,
				time.Unix(1_700_000_000, 0),
			)
		},
	)
	t.Cleanup(validation.close)
	wallet := validation.wallet
	wallet.chainClient = &mockChainClient{}
	require.NoError(t, wallet.Unlock([]byte("private"), nil))

	receive, err := wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	prevScript, err := txscript.PayToAddrScript(receive)
	require.NoError(t, err)
	fundingTx := wire.NewMsgTx(2)
	fundingTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  chainhash.Hash{0x71},
		Index: 1,
	}})
	fundingTx.AddTxOut(wire.NewTxOut(1_000_000, prevScript))
	funding, err := wtxmgr.NewTxRecordFromMsgTx(
		fundingTx, time.Unix(1_700_000_100, 0),
	)
	require.NoError(t, err)
	require.NoError(t, wallet.store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			return wallet.addRelevantTxFromStore(tx, funding, nil)
		}, nil,
	))

	destination, err := address.NewAddressWitnessPubKeyHash(
		bytes.Repeat([]byte{0x72}, 20), &chaincfg.TestNet3Params,
	)
	require.NoError(t, err)
	destinationScript, err := txscript.PayToAddrScript(destination)
	require.NoError(t, err)

	return &splitFundingFixture{
		validation:  validation,
		wallet:      wallet,
		store:       wallet.store,
		outpoint:    wire.OutPoint{Hash: funding.Hash, Index: 0},
		prevScript:  prevScript,
		destination: destinationScript,
	}
}

// output returns the standard destination used by split funding tests.
func (f *splitFundingFixture) output() *wire.TxOut {
	return wire.NewTxOut(100_000, append([]byte(nil), f.destination...))
}

// packet returns an explicit-input PSBT owned by the caller.
func (f *splitFundingFixture) packet() *psbt.Packet {
	return &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: f.outpoint,
			}},
			TxOut: []*wire.TxOut{f.output()},
		},
		Inputs:  []psbt.PInput{{}},
		Outputs: []psbt.POutput{{}},
	}
}

// serializeTx returns the canonical bytes used to detect caller mutation.
func serializeTx(t *testing.T, tx *wire.MsgTx) []byte {
	t.Helper()

	var buffer bytes.Buffer
	require.NoError(t, tx.Serialize(&buffer))

	return buffer.Bytes()
}

// serializePacket returns the canonical bytes used to detect caller mutation.
func serializePacket(t *testing.T, packet *psbt.Packet) []byte {
	t.Helper()

	var buffer bytes.Buffer
	require.NoError(t, packet.Serialize(&buffer))

	return buffer.Bytes()
}

// installStoreTxObserver installs one process-wide stage observer for a serial
// test and restores the previous observer during cleanup.
func installStoreTxObserver(t *testing.T, observe func(storeTxStage)) {
	t.Helper()

	previous := activeStoreTxObserver.Swap(&storeTxObserver{observe: observe})
	t.Cleanup(func() {
		activeStoreTxObserver.Store(previous)
	})
}

// fundingStrategyFunc adapts a test function to CoinSelectionStrategy.
type fundingStrategyFunc func([]Coin, btcutil.Amount) ([]Coin, error)

// ArrangeCoins invokes the test strategy.
func (f fundingStrategyFunc) ArrangeCoins(coins []Coin,
	feeRate btcutil.Amount) ([]Coin, error) {

	return f(coins, feeRate)
}

// splitChainClient records and optionally blocks change watcher registration.
type splitChainClient struct {
	*mockChainClient

	notifications atomic.Int32
	started       chan struct{}
	release       chan struct{}
	once          sync.Once
	notifyErr     error
}

// NotifyReceived records one post-commit watcher registration.
func (c *splitChainClient) NotifyReceived([]address.Address) error {
	if err := c.guardRPC(); err != nil {
		return err
	}
	c.notifications.Add(1)
	if c.started != nil {
		c.once.Do(func() {
			close(c.started)
		})
		<-c.release
	}

	return c.notifyErr
}

// beforeUpdateStore runs one test mutation before the next final write begins.
type beforeUpdateStore struct {
	// Store delegates the final transaction after mutation injection.
	walletstore.Store

	once sync.Once
	hook func()
}

// UpdateOnce runs the configured mutation before delegating the transaction.
func (s *beforeUpdateStore) UpdateOnce(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	s.once.Do(s.hook)
	return s.Store.UpdateOnce(ctx, body, reset)
}

// retryUpdateStore injects one known-uncommitted final write failure.
type retryUpdateStore struct {
	// Store delegates final transactions after the injected failure.
	walletstore.Store

	updates atomic.Int32
}

// UpdateOnce fails before the first body and delegates later attempts.
func (s *retryUpdateStore) UpdateOnce(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	if s.updates.Add(1) == 1 {
		return &walletstore.RetryableTransactionError{
			Err: errors.New("retry final write"),
		}
	}

	return s.Store.UpdateOnce(ctx, body, reset)
}

// failingViewStore rejects every funding or signing snapshot.
type failingViewStore struct {
	// Store supplies operations not overridden by the fixture.
	walletstore.Store
	err error
}

// View returns the configured read failure without invoking body.
func (s *failingViewStore) View(ctx context.Context,
	body func(walletstore.ReadTx) error, reset func()) error {

	_, _, _ = ctx, body, reset
	return s.err
}

// failingUpdateStore rejects every final funding write.
type failingUpdateStore struct {
	// Store supplies operations not overridden by the fixture.
	walletstore.Store
	err error
}

// UpdateOnce returns the configured write failure without invoking body.
func (s *failingUpdateStore) UpdateOnce(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	_, _, _ = ctx, body, reset
	return s.err
}

// retryingViewStore invokes a successful read body twice with reset between
// attempts to model a replaying Store implementation.
type retryingViewStore struct {
	// Store delegates the replayed transaction execution.
	walletstore.Store
}

// View replays the snapshot callback before returning its second result.
func (s *retryingViewStore) View(ctx context.Context,
	body func(walletstore.ReadTx) error, reset func()) error {

	return s.Store.View(ctx, func(tx walletstore.ReadTx) error {
		if reset != nil {
			reset()
		}
		if err := body(tx); err != nil {
			return err
		}
		if reset != nil {
			reset()
		}

		return body(tx)
	}, nil)
}

// absentAmbiguousStore reports an ambiguous commit without starting the
// selected transaction, so reconciliation must prove the plan absent.
type absentAmbiguousStore struct {
	// Store supplies operations not overridden by the fixture.
	walletstore.Store

	updates atomic.Int32
}

// UpdateOnce returns an ambiguous error while leaving durable state unchanged.
func (s *absentAmbiguousStore) UpdateOnce(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	_, _, _ = ctx, body, reset
	s.updates.Add(1)
	return walletstore.NewAmbiguousCommitError(
		errors.New("commit acknowledgement lost"),
	)
}

// failingReconcileStore fails the first read after an ambiguous final write.
type failingReconcileStore struct {
	// Store delegates operations after reconciliation failure injection.
	walletstore.Store

	err       error
	reconcile atomic.Bool
}

// UpdateOnce arms the reconciliation failure after an ambiguous result.
func (s *failingReconcileStore) UpdateOnce(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	err := s.Store.UpdateOnce(ctx, body, reset)
	var ambiguous *walletstore.AmbiguousCommitError
	if errors.As(err, &ambiguous) {
		s.reconcile.Store(true)
	}

	return err
}

// View injects the armed reconciliation failure before delegating later reads.
func (s *failingReconcileStore) View(ctx context.Context,
	body func(walletstore.ReadTx) error, reset func()) error {

	if s.reconcile.Swap(false) {
		return s.err
	}

	return s.Store.View(ctx, body, reset)
}

// storeAccountIndexes reads exact durable account indexes.
func storeAccountIndexes(t *testing.T, store walletstore.Store,
	scope waddrmgr.KeyScope, account uint32) (uint32, uint32) {

	t.Helper()
	var state waddrmgr.AccountState
	err := store.View(t.Context(), func(tx walletstore.ReadTx) error {
		var err error
		state, err = tx.Addr().Account(scope, account)
		return err
	}, func() {
		state = waddrmgr.AccountState{}
	})
	require.NoError(t, err)

	return state.NextExternalIndex, state.NextInternalIndex
}

// unrelatedSQLiteWrite requires a same-wallet write to finish while expensive
// transaction preparation is blocked.
func unrelatedSQLiteWrite(t *testing.T, store walletstore.Store) {
	t.Helper()

	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		result <- store.UpdateOnce(
			ctx, func(tx walletstore.ReadWriteTx) error {
				return tx.Addr().SetBirthday(time.Unix(1_700_000_001, 0))
			}, nil,
		)
	}()

	select {
	case err := <-result:
		require.NoError(t, err)

	case <-time.After(2 * time.Second):
		t.Fatal("unrelated SQLite write blocked by transaction preparation")
	}
}

// testSigningTransaction creates a P2PKH spend using only caller-provided key
// and previous-script material.
func testSigningTransaction(t *testing.T) (*wire.MsgTx,
	map[wire.OutPoint][]byte, map[string]*btcutil.WIF) {

	t.Helper()
	privateKey, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x73}, 32))
	wif, err := btcutil.NewWIF(privateKey, &chaincfg.TestNet3Params, true)
	require.NoError(t, err)
	addr, err := address.NewAddressPubKeyHash(
		address.Hash160(privateKey.PubKey().SerializeCompressed()),
		&chaincfg.TestNet3Params,
	)
	require.NoError(t, err)
	prevScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	outpoint := wire.OutPoint{Hash: chainhash.Hash{0x74}, Index: 1}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: outpoint})
	tx.AddTxOut(wire.NewTxOut(1_000, []byte{txscript.OP_TRUE}))

	return tx, map[wire.OutPoint][]byte{outpoint: prevScript},
		map[string]*btcutil.WIF{addr.EncodeAddress(): wif}
}

// TestStoreFundingTransactionScope verifies every instrumented expensive
// stage, callback, strategy, VM, and watcher runs after Store callback exit.
func TestStoreFundingTransactionScope(t *testing.T) {
	fixture := newSplitFundingFixture(t)
	guard := &callbackGuardStore{Store: fixture.store}
	fixture.wallet.store = guard
	client := &splitChainClient{mockChainClient: &mockChainClient{}}
	client.rpcGuard = func() error {
		if guard.active.Load() != 0 {
			return errRPCInStoreCallback
		}

		return nil
	}
	fixture.wallet.chainClient = client

	var (
		violations atomic.Int32
		crypto     atomic.Int32
		signing    atomic.Int32
		vm         atomic.Int32
	)
	installStoreTxObserver(t, func(stage storeTxStage) {
		if guard.active.Load() != 0 {
			violations.Add(1)
		}
		switch stage {
		case storeTxStageCrypto:
			crypto.Add(1)

		case storeTxStageSigning:
			signing.Add(1)

		case storeTxStageVM:
			vm.Add(1)
		}
	})
	strategy := fundingStrategyFunc(func(coins []Coin,
		_ btcutil.Amount) ([]Coin, error) {

		if guard.active.Load() != 0 {
			violations.Add(1)
		}

		return coins, nil
	})
	allow := func(wtxmgr.Credit) bool {
		if guard.active.Load() != 0 {
			violations.Add(1)
		}

		return true
	}

	_, err := fixture.wallet.CreateSimpleTx(
		&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
		[]*wire.TxOut{fixture.output()}, 0, 1_000, strategy, false,
		WithUtxoFilter(allow),
	)
	require.NoError(t, err)

	signingTx, prevScripts, keys := testSigningTransaction(t)
	_, err = fixture.wallet.SignTransaction(
		signingTx, txscript.SigHashAll, prevScripts, keys, nil,
	)
	require.NoError(t, err)

	packet := fixture.packet()
	_, err = fixture.wallet.FundPsbt(
		packet, &waddrmgr.KeyScopeBIP0084, 0,
		waddrmgr.DefaultAccountNum, 1_000, CoinSelectionLargest,
	)
	require.NoError(t, err)
	require.Zero(t, violations.Load())
	require.Positive(t, crypto.Load())
	require.Positive(t, signing.Load())
	require.Positive(t, vm.Load())
	require.Equal(t, int32(1), client.notifications.Load())
}

// TestStoreFundingPreparationDoesNotBlockWrites verifies blocked external and
// cryptographic stages hold no SQLite transaction or write lock.
func TestStoreFundingPreparationDoesNotBlockWrites(t *testing.T) {
	tests := []struct {
		name string
		run  func(
			*testing.T, *splitFundingFixture, chan struct{}, chan struct{},
		)
	}{
		{
			name: "allow UTXO",
			run: func(t *testing.T, fixture *splitFundingFixture, started,
				release chan struct{}) {

				var once sync.Once
				result := make(chan error, 1)
				go func() {
					_, err := fixture.wallet.CreateSimpleTx(
						&waddrmgr.KeyScopeBIP0084,
						waddrmgr.DefaultAccountNum,
						[]*wire.TxOut{fixture.output()}, 0, 1_000,
						CoinSelectionLargest, false,
						WithUtxoFilter(func(wtxmgr.Credit) bool {
							once.Do(func() { close(started) })
							<-release
							return true
						}),
					)
					result <- err
				}()
				require.NoError(t, <-result)
			},
		},
		{
			name: "strategy",
			run: func(t *testing.T, fixture *splitFundingFixture, started,
				release chan struct{}) {

				var once sync.Once
				strategy := fundingStrategyFunc(func(coins []Coin,
					_ btcutil.Amount) ([]Coin, error) {

					once.Do(func() { close(started) })
					<-release
					return coins, nil
				})
				result := make(chan error, 1)
				go func() {
					_, err := fixture.wallet.CreateSimpleTx(
						&waddrmgr.KeyScopeBIP0084,
						waddrmgr.DefaultAccountNum,
						[]*wire.TxOut{fixture.output()}, 0, 1_000,
						strategy, false,
					)
					result <- err
				}()
				require.NoError(t, <-result)
			},
		},
		{
			name: "signing",
			run: func(t *testing.T, fixture *splitFundingFixture, started,
				release chan struct{}) {

				var once sync.Once
				installStoreTxObserver(t, func(stage storeTxStage) {
					if stage != storeTxStageSigning {
						return
					}
					once.Do(func() { close(started) })
					<-release
				})
				tx, scripts, keys := testSigningTransaction(t)
				result := make(chan error, 1)
				go func() {
					_, err := fixture.wallet.SignTransaction(
						tx, txscript.SigHashAll, scripts, keys, nil,
					)
					result <- err
				}()
				require.NoError(t, <-result)
			},
		},
		{
			name: "NotifyReceived",
			run: func(t *testing.T, fixture *splitFundingFixture, started,
				release chan struct{}) {

				fixture.wallet.chainClient = &splitChainClient{
					mockChainClient: &mockChainClient{},
					started:         started,
					release:         release,
				}
				result := make(chan error, 1)
				go func() {
					_, err := fixture.wallet.CreateSimpleTx(
						&waddrmgr.KeyScopeBIP0084,
						waddrmgr.DefaultAccountNum,
						[]*wire.TxOut{fixture.output()}, 0, 1_000,
						CoinSelectionLargest, false,
					)
					result <- err
				}()
				require.NoError(t, <-result)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSplitFundingFixture(t)
			started := make(chan struct{})
			release := make(chan struct{})
			finished := make(chan struct{})
			go func() {
				test.run(t, fixture, started, release)
				close(finished)
			}()
			select {
			case <-started:

			case <-time.After(2 * time.Second):
				close(release)
				t.Fatal("preparation stage did not block")
			}
			unrelatedSQLiteWrite(t, fixture.store)
			close(release)
			select {
			case <-finished:

			case <-time.After(2 * time.Second):
				t.Fatal("preparation stage did not finish")
			}
		})
	}
}

// TestStoreFundingConflictsAndRetries verifies stale UTXO and index plans are
// rebuilt, while Store retries repeat only the database apply phase.
func TestStoreFundingConflictsAndRetries(t *testing.T) {
	t.Run("change index", func(t *testing.T) {
		fixture := newSplitFundingFixture(t)
		var strategyCalls atomic.Int32
		strategy := fundingStrategyFunc(func(coins []Coin,
			_ btcutil.Amount) ([]Coin, error) {

			strategyCalls.Add(1)
			return coins, nil
		})
		fixture.wallet.store = &beforeUpdateStore{
			Store: fixture.store,
			hook: func() {
				require.NoError(t, fixture.store.UpdateOnce(
					t.Context(), func(tx walletstore.ReadWriteTx) error {
						state, err := tx.Addr().Account(
							waddrmgr.KeyScopeBIP0084,
							waddrmgr.DefaultAccountNum,
						)
						if err != nil {
							return err
						}

						return tx.Addr().SetAccountIndexes(
							state.Scope, state.Account,
							state.NextExternalIndex,
							state.NextInternalIndex+1,
						)
					}, nil,
				))
			},
		}
		_, err := fixture.wallet.CreateSimpleTx(
			&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
			[]*wire.TxOut{fixture.output()}, 0, 1_000, strategy, false,
		)
		require.NoError(t, err)
		require.Equal(t, int32(2), strategyCalls.Load())
	})

	t.Run("stale UTXO", func(t *testing.T) {
		fixture := newSplitFundingFixture(t)
		client := &splitChainClient{mockChainClient: &mockChainClient{}}
		fixture.wallet.chainClient = client
		fixture.wallet.store = &beforeUpdateStore{
			Store: fixture.store,
			hook: func() {
				spender := wire.NewMsgTx(2)
				spender.AddTxIn(&wire.TxIn{
					PreviousOutPoint: fixture.outpoint,
				})
				spender.AddTxOut(wire.NewTxOut(
					900_000, []byte{txscript.OP_TRUE},
				))
				record, err := wtxmgr.NewTxRecordFromMsgTx(
					spender, time.Unix(1_700_000_200, 0),
				)
				require.NoError(t, err)
				require.NoError(t, fixture.store.UpdateOnce(
					t.Context(), func(tx walletstore.ReadWriteTx) error {
						return fixture.wallet.addRelevantTxFromStore(
							tx, record, nil,
						)
					}, nil,
				))
			},
		}
		_, err := fixture.wallet.CreateSimpleTx(
			&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
			[]*wire.TxOut{fixture.output()}, 0, 1_000,
			CoinSelectionLargest, false,
		)
		require.Error(t, err)
		require.Zero(t, client.notifications.Load())
	})

	t.Run("Store retry", func(t *testing.T) {
		fixture := newSplitFundingFixture(t)
		retryStore := &retryUpdateStore{Store: fixture.store}
		fixture.wallet.store = retryStore
		client := &splitChainClient{mockChainClient: &mockChainClient{}}
		fixture.wallet.chainClient = client
		var strategyCalls atomic.Int32
		strategy := fundingStrategyFunc(func(coins []Coin,
			_ btcutil.Amount) ([]Coin, error) {

			strategyCalls.Add(1)
			return coins, nil
		})
		_, err := fixture.wallet.CreateSimpleTx(
			&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
			[]*wire.TxOut{fixture.output()}, 0, 1_000, strategy, false,
		)
		require.NoError(t, err)
		require.Equal(t, int32(1), strategyCalls.Load())
		require.Equal(t, int32(2), retryStore.updates.Load())
		require.Equal(t, int32(1), client.notifications.Load())
	})
}

// TestStoreSigningSnapshotFailureAndRetry verifies fatal snapshot outcomes do
// not mutate the caller and read retries never repeat signing or VM work.
func TestStoreSigningSnapshotFailureAndRetry(t *testing.T) {
	t.Run("read failure", func(t *testing.T) {
		fixture := newSplitFundingFixture(t)
		tx, scripts, keys := testSigningTransaction(t)
		before := serializeTx(t, tx)
		readErr := errors.New("snapshot read failed")
		fixture.wallet.store = &failingViewStore{
			Store: fixture.store,
			err:   readErr,
		}
		_, err := fixture.wallet.SignTransaction(
			tx, txscript.SigHashAll, scripts, keys, nil,
		)
		require.ErrorIs(t, err, readErr)
		require.Equal(t, before, serializeTx(t, tx))
	})

	t.Run("read retry", func(t *testing.T) {
		fixture := newSplitFundingFixture(t)
		fixture.wallet.store = &retryingViewStore{Store: fixture.store}
		tx, scripts, keys := testSigningTransaction(t)
		var signing atomic.Int32
		installStoreTxObserver(t, func(stage storeTxStage) {
			if stage == storeTxStageSigning {
				signing.Add(1)
			}
		})
		_, err := fixture.wallet.SignTransaction(
			tx, txscript.SigHashAll, scripts, keys, nil,
		)
		require.NoError(t, err)
		require.Equal(t, int32(1), signing.Load())
	})
}

// TestStoreFundingFailuresKeepCallersAtomic verifies write failures leave exact
// caller PSBT bytes and durable change indexes unchanged.
func TestStoreFundingFailuresKeepCallersAtomic(t *testing.T) {
	fixture := newSplitFundingFixture(t)
	beforeExternal, beforeInternal := storeAccountIndexes(
		t, fixture.store, waddrmgr.KeyScopeBIP0084,
		waddrmgr.DefaultAccountNum,
	)
	packet := fixture.packet()
	beforePacket := serializePacket(t, packet)
	readErr := errors.New("funding snapshot failed")
	fixture.wallet.store = &failingViewStore{
		Store: fixture.store,
		err:   readErr,
	}
	_, err := fixture.wallet.FundPsbt(
		packet, &waddrmgr.KeyScopeBIP0084, 0,
		waddrmgr.DefaultAccountNum, 1_000, CoinSelectionLargest,
	)
	require.ErrorIs(t, err, readErr)
	require.Equal(t, beforePacket, serializePacket(t, packet))

	writeErr := errors.New("final write failed")
	fixture.wallet.store = &failingUpdateStore{
		Store: fixture.store,
		err:   writeErr,
	}

	_, err = fixture.wallet.CreateSimpleTx(
		&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
		[]*wire.TxOut{fixture.output()}, 0, 1_000,
		CoinSelectionLargest, false,
	)
	require.ErrorIs(t, err, writeErr)

	_, err = fixture.wallet.FundPsbt(
		packet, &waddrmgr.KeyScopeBIP0084, 0,
		waddrmgr.DefaultAccountNum, 1_000, CoinSelectionLargest,
	)
	require.ErrorIs(t, err, writeErr)
	require.Equal(t, beforePacket, serializePacket(t, packet))
	afterExternal, afterInternal := storeAccountIndexes(
		t, fixture.store, waddrmgr.KeyScopeBIP0084,
		waddrmgr.DefaultAccountNum,
	)
	require.Equal(t, beforeExternal, afterExternal)
	require.Equal(t, beforeInternal, afterInternal)

	rollbackErr := errors.New("rollback completed final write")
	fixture.wallet.store = &failUpdateStore{
		Store:    fixture.store,
		err:      rollbackErr,
		failNext: true,
	}
	_, err = fixture.wallet.FundPsbt(
		packet, &waddrmgr.KeyScopeBIP0084, 0,
		waddrmgr.DefaultAccountNum, 1_000, CoinSelectionLargest,
	)
	require.ErrorIs(t, err, rollbackErr)
	require.Equal(t, beforePacket, serializePacket(t, packet))
	afterExternal, afterInternal = storeAccountIndexes(
		t, fixture.store, waddrmgr.KeyScopeBIP0084,
		waddrmgr.DefaultAccountNum,
	)
	require.Equal(t, beforeExternal, afterExternal)
	require.Equal(t, beforeInternal, afterInternal)
}

// TestStoreFundingAmbiguousCommitNotification verifies watcher registration is
// withheld for rolled-back addresses and occurs once for a proven durable row.
func TestStoreFundingAmbiguousCommitNotification(t *testing.T) {
	t.Run("durable", func(t *testing.T) {
		fixture := newSplitFundingFixture(t)
		client := &splitChainClient{mockChainClient: &mockChainClient{}}
		fixture.wallet.chainClient = client
		_, beforeInternal := storeAccountIndexes(
			t, fixture.store, waddrmgr.KeyScopeBIP0084,
			waddrmgr.DefaultAccountNum,
		)
		fixture.wallet.store = &ambiguousCommitStore{
			Store:                   fixture.store,
			ambiguousNextUpdateOnce: true,
		}
		first, err := fixture.wallet.CreateSimpleTx(
			&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
			[]*wire.TxOut{fixture.output()}, 0, 1_000,
			CoinSelectionLargest, false,
		)
		require.NoError(t, err)
		require.Equal(t, int32(1), client.notifications.Load())
		require.True(t, first.ChangeIndex >= 0)
		_, afterInternal := storeAccountIndexes(
			t, fixture.store, waddrmgr.KeyScopeBIP0084,
			waddrmgr.DefaultAccountNum,
		)
		require.Equal(t, beforeInternal+1, afterInternal)

		second, err := fixture.wallet.CreateSimpleTx(
			&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
			[]*wire.TxOut{fixture.output()}, 0, 1_000,
			CoinSelectionLargest, false,
		)
		require.NoError(t, err)
		require.True(t, second.ChangeIndex >= 0)
		require.NotEqual(t,
			first.Tx.TxOut[first.ChangeIndex].PkScript,
			second.Tx.TxOut[second.ChangeIndex].PkScript,
		)
		require.Equal(t, int32(2), client.notifications.Load())
		_, afterInternal = storeAccountIndexes(
			t, fixture.store, waddrmgr.KeyScopeBIP0084,
			waddrmgr.DefaultAccountNum,
		)
		require.Equal(t, beforeInternal+2, afterInternal)
	})

	t.Run("absent", func(t *testing.T) {
		fixture := newSplitFundingFixture(t)
		client := &splitChainClient{mockChainClient: &mockChainClient{}}
		fixture.wallet.chainClient = client
		beforeExternal, beforeInternal := storeAccountIndexes(
			t, fixture.store, waddrmgr.KeyScopeBIP0084,
			waddrmgr.DefaultAccountNum,
		)
		ambiguous := &absentAmbiguousStore{Store: fixture.store}
		fixture.wallet.store = ambiguous
		var strategyCalls atomic.Int32
		strategy := fundingStrategyFunc(func(coins []Coin,
			_ btcutil.Amount) ([]Coin, error) {

			strategyCalls.Add(1)
			return coins, nil
		})
		_, err := fixture.wallet.CreateSimpleTx(
			&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
			[]*wire.TxOut{fixture.output()}, 0, 1_000,
			strategy, false,
		)
		require.Error(t, err)
		require.Equal(t, int32(maxStoreCommitAttempts),
			ambiguous.updates.Load())
		require.Equal(t, int32(1), strategyCalls.Load())
		require.Zero(t, client.notifications.Load())
		afterExternal, afterInternal := storeAccountIndexes(
			t, fixture.store, waddrmgr.KeyScopeBIP0084,
			waddrmgr.DefaultAccountNum,
		)
		require.Equal(t, beforeExternal, afterExternal)
		require.Equal(t, beforeInternal, afterInternal)

		fixture.wallet.store = fixture.store
		_, err = fixture.wallet.CreateSimpleTx(
			&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
			[]*wire.TxOut{fixture.output()}, 0, 1_000,
			CoinSelectionLargest, false,
		)
		require.NoError(t, err)
		require.Equal(t, int32(1), client.notifications.Load())
		_, afterInternal = storeAccountIndexes(
			t, fixture.store, waddrmgr.KeyScopeBIP0084,
			waddrmgr.DefaultAccountNum,
		)
		require.Equal(t, beforeInternal+1, afterInternal)
	})

	t.Run("unresolved durable", func(t *testing.T) {
		fixture := newSplitFundingFixture(t)
		beforeExternal, beforeInternal := storeAccountIndexes(
			t, fixture.store, waddrmgr.KeyScopeBIP0084,
			waddrmgr.DefaultAccountNum,
		)
		packet := fixture.packet()
		beforePacket := serializePacket(t, packet)
		reconcileErr := errors.New("reconciliation read failed")
		fixture.wallet.store = &failingReconcileStore{
			Store: &ambiguousCommitStore{
				Store:                   fixture.store,
				ambiguousNextUpdateOnce: true,
			},
			err: reconcileErr,
		}

		_, err := fixture.wallet.FundPsbt(
			packet, &waddrmgr.KeyScopeBIP0084, 0,
			waddrmgr.DefaultAccountNum, 1_000, CoinSelectionLargest,
		)
		var unresolved *UnresolvedStoreCommitError
		require.ErrorAs(t, err, &unresolved)
		require.ErrorIs(t, err, reconcileErr)
		require.Equal(t, beforePacket, serializePacket(t, packet))
		afterExternal, afterInternal := storeAccountIndexes(
			t, fixture.store, waddrmgr.KeyScopeBIP0084,
			waddrmgr.DefaultAccountNum,
		)
		require.Equal(t, beforeExternal, afterExternal)
		require.Equal(t, beforeInternal+1, afterInternal)

		fixture.wallet.store = fixture.store
		_, err = fixture.wallet.FundPsbt(
			packet, &waddrmgr.KeyScopeBIP0084, 0,
			waddrmgr.DefaultAccountNum, 1_000, CoinSelectionLargest,
		)
		require.NoError(t, err)
		_, afterInternal = storeAccountIndexes(
			t, fixture.store, waddrmgr.KeyScopeBIP0084,
			waddrmgr.DefaultAccountNum,
		)
		require.Equal(t, beforeInternal+2, afterInternal)
	})

	t.Run("watcher failure leaves durable address", func(t *testing.T) {
		fixture := newSplitFundingFixture(t)
		beforeExternal, beforeInternal := storeAccountIndexes(
			t, fixture.store, waddrmgr.KeyScopeBIP0084,
			waddrmgr.DefaultAccountNum,
		)
		notifyErr := errors.New("watcher unavailable")
		client := &splitChainClient{
			mockChainClient: &mockChainClient{},
			notifyErr:       notifyErr,
		}
		fixture.wallet.chainClient = client
		_, err := fixture.wallet.CreateSimpleTx(
			&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
			[]*wire.TxOut{fixture.output()}, 0, 1_000,
			CoinSelectionLargest, false,
		)
		require.ErrorIs(t, err, notifyErr)
		require.ErrorContains(t, err, "is durable")
		require.Equal(t, int32(1), client.notifications.Load())
		afterExternal, afterInternal := storeAccountIndexes(
			t, fixture.store, waddrmgr.KeyScopeBIP0084,
			waddrmgr.DefaultAccountNum,
		)
		require.Equal(t, beforeExternal, afterExternal)
		require.Equal(t, beforeInternal+1, afterInternal)
	})
}
