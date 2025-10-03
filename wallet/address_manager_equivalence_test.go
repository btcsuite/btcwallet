package wallet

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// TestEquivalence_NewAndChangeAddress compares the new NewAddress API with the
// deprecated NewAddressDeprecated/NewChangeAddress APIs for multiple address
// types.
func TestEquivalence_NewAndChangeAddress(t *testing.T) {
	t.Parallel()

	// Use the same seed for both wallets to ensure they generate identical
	// address sequences, allowing us to verify API equivalence.
	seed := bytes.Repeat([]byte{0x42}, 32)

	cases := []struct {
		name     string
		addrType waddrmgr.AddressType
		scope    waddrmgr.KeyScope
	}{
		{"p2pkh", waddrmgr.PubKeyHash, waddrmgr.KeyScopeBIP0044},
		{"p2wkh", waddrmgr.WitnessPubKey, waddrmgr.KeyScopeBIP0084},
		{
			"np2wkh",
			waddrmgr.NestedWitnessPubKey,
			waddrmgr.KeyScopeBIP0049Plus,
		},
		{"p2tr", waddrmgr.TaprootPubKey, waddrmgr.KeyScopeBIP0086},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wNewWallet, cleanup := testWalletWithSeed(t, seed)
			t.Cleanup(cleanup)

			var wNew AddressManager = wNewWallet

			wOld, cleanupOld := testWalletWithSeed(t, seed)
			t.Cleanup(cleanupOld)

			gotNew, err := wNew.NewAddress(
				context.Background(),
				"default",
				tc.addrType,
				false,
			)
			require.NoError(t, err)

			gotOld, err := wOld.NewAddressDeprecated(0, tc.scope)
			require.NoError(t, err)
			require.Equal(t, gotOld.String(), gotNew.String())

			gotNewChg, err := wNew.NewAddress(
				context.Background(),
				"default",
				tc.addrType,
				true,
			)
			require.NoError(t, err)

			gotOldChg, err := wOld.NewChangeAddress(0, tc.scope)
			require.NoError(t, err)
			require.Equal(t, gotOldChg.String(), gotNewChg.String())
		})
	}
}

// TestEquivalence_GetUnusedAddress compares the sequence produced by new
// GetUnusedAddress (when marking used after each) with the deprecated
// NewAddressDeprecated sequence.
func TestEquivalence_GetUnusedAddress(t *testing.T) {
	t.Parallel()

	seed := bytes.Repeat([]byte{0x24}, 32)
	addrType := waddrmgr.WitnessPubKey
	scope := waddrmgr.KeyScopeBIP0084

	wNewWallet, cleanup := testWalletWithSeed(t, seed)
	t.Cleanup(cleanup)

	var wNew AddressManager = wNewWallet

	wOld, cleanupOld := testWalletWithSeed(t, seed)
	t.Cleanup(cleanupOld)

	// Verify that GetUnusedAddress returns the same sequence as
	// NewAddressDeprecated
	for range 5 {
		aNew, err := wNew.GetUnusedAddress(
			context.Background(),
			"default",
			addrType,
			false,
		)
		require.NoError(t, err)

		aOld, err := wOld.NewAddressDeprecated(0, scope)
		require.NoError(t, err)

		require.Equal(t, aOld.String(), aNew.String())

		// Address manager only marks addresses as used when
		// they receive funds, so we must insert a credit to
		// properly test the unused address tracking behavior.
		markAddressAsUsed := func(
			tb testing.TB, w *Wallet, addr btcutil.Address,
			amt int64,
		) {

			tb.Helper()

			pkScript, err := txscript.PayToAddrScript(addr)
			require.NoError(tb, err)

			err = walletdb.Update(
				w.db, func(tx walletdb.ReadWriteTx) error {
					txmgrNs := tx.ReadWriteBucket(
						wtxmgrNamespaceKey,
					)

					msgTx := TstTx.MsgTx()
					msgTx.TxOut = []*wire.TxOut{{
						PkScript: pkScript,
						Value:    amt,
					}}

					rec, err := wtxmgr.NewTxRecordFromMsgTx(
						msgTx, time.Now(),
					)
					if err != nil {
						return err
					}

					err = w.txStore.InsertTx(
						txmgrNs, rec, nil,
					)
					if err != nil {
						return err
					}

					err = w.txStore.AddCredit(
						txmgrNs, rec, nil, 0, false,
					)
					if err != nil {
						return err
					}

					addrmgrNs := tx.ReadWriteBucket(
						waddrmgrNamespaceKey,
					)

					return w.addrStore.MarkUsed(
						addrmgrNs, addr,
					)
				},
			)
			require.NoError(tb, err)
		}

		markAddressAsUsed(t, wNewWallet, aNew, 1000)
		markAddressAsUsed(t, wOld, aOld, 1000)
	}
}
