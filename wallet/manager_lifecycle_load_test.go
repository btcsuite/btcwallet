package wallet

//nolint:staticcheck // Test the temporary kvdb compatibility path.
import (
	"testing"

	kvdb "github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestManagerWalletLifecycleReplacement verifies Load joins terminal shutdown
// and publishes one shared fresh runtime for every admitted waiter.
func TestManagerWalletLifecycleReplacement(t *testing.T) {
	t.Parallel()

	// Arrange: Hold the old runtime inside terminal Vault locking and
	// acknowledge every Load after it selects that exact terminal entry.
	m, oldWallet, deps := newLifecycleTestManager(t)
	m.chainParams = &chainParams

	const callers = 3

	waitAdmissions := make(chan *walletRuntimeEntry, callers)
	m.lifecycleTestHooks = &managerLifecycleTestHooks{
		beforeTerminalWait: func(entry *walletRuntimeEntry) {
			waitAdmissions <- entry
		},
	}

	vaultEntered := make(chan struct{})
	releaseVault := make(chan struct{})
	deps.vault.On("Lock").Run(func(mock.Arguments) {
		close(vaultEntered)
		<-releaseVault
	}).Return().Once()
	deps.vault.On("Lock").Return().Once()

	data := &walletData{
		id:               oldWallet.id,
		store:            oldWallet.store,
		addressStore:     oldWallet.addrStore,
		transactionStore: oldWallet.txStore,
		vault:            oldWallet.keyVault,
	}

	m.backend = &kvdbManagerBackend{
		store:      &kvdb.Store{}, //nolint:staticcheck
		walletName: oldWallet.cfg.Name,
		walletData: data,
	}

	stopResult := make(chan error, 1)

	// Act: Begin terminal teardown and hold the current runtime before its
	// completion record can close.
	go func() {
		stopResult <- m.StopWallet(t.Context(), oldWallet)
	}()

	<-vaultEntered

	type loadResult struct {
		wallet *Wallet
		err    error
	}

	results := make(chan loadResult, callers)
	loadGate := make(chan struct{})

	// Act: Release every Load together so each must select the old entry and
	// acknowledge terminal-wait admission before teardown is released.
	for range callers {
		go func() {
			<-loadGate

			w, err := m.Load(oldWallet.cfg)
			results <- loadResult{wallet: w, err: err}
		}()
	}

	close(loadGate)

	oldEntry := m.wallets[oldWallet.cfg.Name]
	for range callers {
		require.Same(t, oldEntry, <-waitAdmissions)
	}

	// Assert: Every admitted Load remains pending and the old pointer stays
	// current while teardown has not recorded terminal completion.
	for range callers {
		select {
		case result := <-results:
			require.Failf(t, "Load completed before teardown",
				"unexpected result: %v", result.err)

		default:
		}
	}

	require.Same(t, oldWallet, oldEntry.wallet)

	// Act: Complete teardown and collect every Load result after Manager
	// revalidation and replacement publication.
	close(releaseVault)
	require.NoError(t, <-stopResult)

	first := <-results
	require.NoError(t, first.err)
	require.NotSame(t, oldWallet, first.wallet)
	fresh := first.wallet

	for range callers - 1 {
		result := <-results
		require.NoError(t, result.err)
		require.Same(t, fresh, result.wallet)
	}

	// Assert: One fresh pointer wins for every waiter and stale lifecycle
	// calls cannot select that replacement by name.
	require.Nil(t, m.wallets[fresh.cfg.Name].coordinator)
	require.ErrorIs(
		t, m.StartWallet(t.Context(), oldWallet), ErrWalletNotManaged,
	)
	require.ErrorIs(
		t, m.StopWallet(t.Context(), oldWallet), ErrWalletNotManaged,
	)

	// Arrange: Rebind the mock syncer because retained kvdb data deliberately
	// constructs the replacement without opening another backend.
	fresh.sync = deps.syncer
	fresh.state.syncer = deps.syncer
	expectLifecycleSetup(deps)
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	// Act: Run the fresh replacement through its independent lifecycle.
	startErr := m.StartWallet(t.Context(), fresh)
	stopErr := m.StopWallet(t.Context(), fresh)

	// Assert: The replacement is independently startable and stoppable.
	require.NoError(t, startErr)
	require.NoError(t, stopErr)
}
