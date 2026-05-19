//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestCreateTxStoresWalletCredit verifies that CreateTx stores the transaction
// row and the requested wallet-owned output in one atomic write.
//
// Scenario:
//   - One wallet records a new unmined transaction with one wallet-owned
//     credited output.
//
// Setup:
//   - Create one wallet, one derived account, and one wallet-owned address.
//   - Build one transaction that pays that address.
//
// Action:
//   - Insert the transaction through CreateTx.
//
// Assertions:
//   - The transaction row exists.
//   - The credited output exists in the wallet UTXO set.
func TestCreateTxStoresWalletCredit(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-tx-credit")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000300, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	_, ok := txIDByHash(t, store, walletID, tx.TxHash())
	require.True(t, ok)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: tx.TxHash(), Index: 0,
	}))
}

// TestCreateTxCreditBareMultisigMember verifies that CreateTx records a
// bare-multisig output that the wallet partly owns: the wallet holds one
// member pubkey address, but not the full multisig output script.
//
// This is the SQL counterpart to the kvdb TestCreateTxCreditBareMultisigMember
// and locks in parity between the two backends. The publisher's ownership
// filter resolves such an output to the wallet-owned member address and passes
// it as the credit address; the store must therefore key ownership on the
// member's own script, not on the full multisig output script that no address
// row would ever match.
//
// Scenario:
//   - The wallet imports one P2PK member address (script-only on a watch-only
//     wallet, which the ADR 0012 invariant allows).
//   - A transaction pays a 1-of-2 bare-multisig output built from that member
//     plus a foreign key. The full multisig script is NOT a wallet address.
//
// Action:
//   - Insert the transaction through CreateTx with Credits[0] set to the
//     member address.
//
// Assertions:
//   - CreateTx succeeds (no ErrAddressNotFound) and the credited output exists.
//   - GetUtxo resolves the UTXO to the imported member address (imported
//     origin, raw-pubkey type) rather than the multisig output script.
//
// Without the fix, the store looks the credit up by the full multisig output
// script, finds no address row, and CreateTx fails with ErrAddressNotFound.
func TestCreateTxCreditBareMultisigMember(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	// A script-only import (no private key) requires a watch-only wallet per
	// the ADR 0012 spendable-wallet invariant.
	walletID := newWatchOnlyWallet(t, store, "wallet-bare-multisig-credit")

	scope := db.KeyScopeBIP0084
	importedName := db.DefaultImportedAccountName

	// Build a 1-of-2 bare-multisig script. memberScript is the member's own
	// P2PK script (what PayToAddrScript(memberAddr) yields), which the wallet
	// imports as an address. multiSigScript is the full on-chain output script,
	// which is deliberately never registered as a wallet address.
	memberAddr, memberScript, multiSigScript := newMultisigScript(t)
	require.NotEqual(t, memberScript, multiSigScript)

	_, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:        walletID,
			Scope:           scope,
			AddressType:     db.RawPubKey,
			PubKey:          memberAddr.ScriptAddress(),
			ScriptPubKey:    memberScript,
			EncryptedScript: RandomBytes(48),
		},
	)
	require.NoError(t, err)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: multiSigScript}},
	)

	// Credits[0] carries the resolved member address, exactly as the publisher
	// supplies it after filtering ownership by the member script.
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710004000, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: memberAddr},
	})
	require.NoError(t, err)

	outPoint := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	require.True(t, walletUtxoExists(t, store, walletID, outPoint))

	// The credit must resolve to the imported member address, not the multisig
	// output script. The account name and address type prove the resolved
	// address row is the member import.
	utxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: outPoint,
	})
	require.NoError(t, err)
	require.Equal(t, importedName, utxo.AccountName)
	require.Equal(t, db.RawPubKey, utxo.AddrType)
}

// TestCreateTxDuplicateCreditBareMultisigMemberMismatch verifies that an
// idempotent duplicate cannot change the wallet-owned member address recorded
// for a bare-multisig credit.
//
// Scenario:
//   - The wallet imports both members of a 1-of-2 bare-multisig output.
//   - The first CreateTx records the output as owned by the first member.
//   - A duplicate CreateTx call reports the same transaction and output, but
//     claims ownership through the second member.
//
// Assertions:
//   - The duplicate is rejected with ErrTxAlreadyExists because it is not an
//     exact replay of the stored ownership metadata.
func TestCreateTxDuplicateCreditBareMultisigMemberMismatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWatchOnlyWallet(
		t, store, "wallet-bare-multisig-duplicate-mismatch",
	)

	firstKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	secondKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	firstAddr, err := address.NewAddressPubKey(
		firstKey.PubKey().SerializeCompressed(),
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	secondAddr, err := address.NewAddressPubKey(
		secondKey.PubKey().SerializeCompressed(),
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	firstScript, err := txscript.PayToAddrScript(firstAddr)
	require.NoError(t, err)

	secondScript, err := txscript.PayToAddrScript(secondAddr)
	require.NoError(t, err)

	for _, member := range []struct {
		addr   *address.AddressPubKey
		script []byte
	}{
		{
			addr:   firstAddr,
			script: firstScript,
		},
		{
			addr:   secondAddr,
			script: secondScript,
		},
	} {
		_, err := store.NewImportedAddress(
			t.Context(), db.NewImportedAddressParams{
				WalletID:        walletID,
				Scope:           db.KeyScopeBIP0084,
				AddressType:     db.RawPubKey,
				PubKey:          member.addr.ScriptAddress(),
				ScriptPubKey:    member.script,
				EncryptedScript: RandomBytes(48),
			},
		)
		require.NoError(t, err)
	}

	multiSigScript, err := txscript.NewScriptBuilder().
		AddInt64(1).
		AddData(firstKey.PubKey().SerializeCompressed()).
		AddData(secondKey.PubKey().SerializeCompressed()).
		AddInt64(2).
		AddOp(txscript.OP_CHECKMULTISIG).
		Script()
	require.NoError(t, err)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: multiSigScript}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710004400, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: firstAddr},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710004401, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: secondAddr},
	})
	require.ErrorIs(t, err, db.ErrTxAlreadyExists)
}

// TestCreateTxCreditAddrMismatch verifies that CreateTx rejects a non-nil
// credit address that the credited output does not pay to, instead of
// recording a UTXO owned by an unrelated address.
//
// A non-nil Credits[index] is authoritative for ownership, so the store must
// confirm the output actually pays that address before trusting it. This is
// the SQL counterpart to the kvdb TestCreateTxCreditAddrMismatch and keeps the
// two backends consistent: kvdb validates membership via its own
// validateCreditAddr, and the SQL backends validate it through the shared
// ValidateCreditAddrMembership before the credit lookup.
//
// Scenario:
//   - The output pays a wallet-owned derived address.
//   - Credits[0] instead names an unrelated address the output never pays.
//
// Assertions:
//   - CreateTx fails with ErrInvalidParam and records nothing.
func TestCreateTxCreditAddrMismatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-credit-addr-mismatch")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	// The output pays this wallet-owned address.
	paidAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	// The credit names a different address that the output script does not
	// pay to, simulating a caller mislabeling the credited output.
	wrongKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	wrongAddr, err := address.NewAddressPubKey(
		wrongKey.PubKey().SerializeCompressed(),
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 6000, PkScript: paidAddr.ScriptPubKey}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710004200, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: wrongAddr},
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)

	// The rejected insert must not have created the transaction row or a
	// UTXO.
	_, ok := txIDByHash(t, store, walletID, tx.TxHash())
	require.False(t, ok)
	require.False(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: tx.TxHash(), Index: 0,
	}))
}

// TestCreateTxStoresConfirmedCoinbase verifies that CreateTx can record one
// coinbase transaction directly in its confirmed state when the block is
// already known.
//
// Scenario:
//   - One wallet learns about one coinbase credit together with its confirming
//     block.
//
// Setup:
//   - Create one wallet, one derived account, one wallet-owned address, and one
//     matching block fixture.
//   - Build one coinbase transaction that pays that wallet-owned address.
//
// Action:
//   - Insert the coinbase through CreateTx with the block assignment present.
//
// Assertions:
//   - The transaction row exists.
//   - The wallet-owned coinbase output exists in the current UTXO set.
func TestCreateTxStoresConfirmedCoinbase(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-confirmed-coinbase")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	block := CreateBlockFixture(t, store.Queries(), 210)
	coinbaseTx := newCoinbaseTx(addr.ScriptPubKey)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710000350, 0),
		Block:    &block,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	_, ok := txIDByHash(t, store, walletID, coinbaseTx.TxHash())
	require.True(t, ok)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: coinbaseTx.TxHash(), Index: 0,
	}))
}

// TestCreateTxRejectsInvalidParentWalletOutput verifies that CreateTx rejects a
// child that spends a wallet-owned output whose parent transaction is already
// invalid.
//
// Scenario:
//   - One wallet output exists, but its parent transaction has already been
//     marked failed.
//
// Setup:
//   - Create one wallet-owned parent credit.
//   - Rewrite the parent transaction status to failed.
//   - Build one child transaction that spends that wallet-owned output.
//
// Action:
//   - Insert the child through CreateTx.
//
// Assertions:
//   - CreateTx returns ErrTxInputInvalidParent.
//   - No child row or child spend edge is persisted.
//   - The original parent row remains stored.
func TestCreateTxRejectsInvalidParentWalletOutput(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-invalid-parent")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 50000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710000400, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	setTxStatus(t, store, walletID, parentTx.TxHash(), db.TxStatusFailed)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 49000, PkScript: []byte{0x51}}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710000410, 0),
		Status:   db.TxStatusPending,
	})
	require.ErrorIs(t, err, db.ErrTxInputInvalidParent)
	require.Empty(t, childSpendingTxIDs(t, store, walletID, parentTx.TxHash()))
	_, ok := txIDByHash(t, store, walletID, childTx.TxHash())
	require.False(t, ok)
	_, ok = txIDByHash(t, store, walletID, parentTx.TxHash())
	require.True(t, ok)
}

// TestCreateTxRejectsSecondPendingSpend verifies that CreateTx rejects a second
// pending transaction that spends the same wallet-owned output.
//
// Scenario:
//   - One wallet-owned output already has one pending child spender.
//
// Setup:
//   - Create one wallet-owned parent credit.
//   - Insert one first child transaction that spends it.
//   - Build one second child that spends the same outpoint.
//
// Action:
//   - Insert the second child through CreateTx.
//
// Assertions:
//   - CreateTx returns ErrTxInputConflict.
//   - Only the first child remains recorded as the spender.
//   - The second child row is not inserted.
func TestCreateTxRejectsSecondPendingSpend(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-second-spend-conflict")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710000500, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	spentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	firstChild := newRegularTx(
		[]wire.OutPoint{spentOutPoint},
		[]*wire.TxOut{{Value: 4000, PkScript: []byte{0x51}}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       firstChild,
		Received: time.Unix(1710000510, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	secondChild := newRegularTx(
		[]wire.OutPoint{spentOutPoint},
		[]*wire.TxOut{{Value: 3000, PkScript: []byte{0x52}}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       secondChild,
		Received: time.Unix(1710000520, 0),
		Status:   db.TxStatusPending,
	})
	require.ErrorIs(t, err, db.ErrTxInputConflict)

	childIDs := childSpendingTxIDs(t, store, walletID, parentTx.TxHash())
	require.Len(t, childIDs, 1)

	_, ok := txIDByHash(t, store, walletID, firstChild.TxHash())
	require.True(t, ok)
	_, ok = txIDByHash(t, store, walletID, secondChild.TxHash())
	require.False(t, ok)
}

// TestCreateTxSkipsDuplicateTx verifies that CreateTx inserts one wallet-
// scoped transaction row only once for an idempotent duplicate.
//
// Scenario:
//   - One wallet transaction hash is already present in the store.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//
// Action:
//   - Attempt to insert the same transaction hash again.
//
// Assertions:
//   - CreateTx treats the duplicate as a no-op.
//   - The original row remains stored once.
func TestCreateTxSkipsDuplicateTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-tx-duplicate")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000580, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000590, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	_, ok := txIDByHash(t, store, walletID, tx.TxHash())
	require.True(t, ok)
}

// TestCreateTxReplaysDuplicateCredit verifies that an idempotent duplicate
// transaction observation still records newly supplied wallet credit edges.
func TestCreateTxReplaysDuplicateCredit(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-tx-replay-credit")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)
	params := db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000580, 0),
		Status:   db.TxStatusPending,
	}

	err := store.CreateTx(t.Context(), params)
	require.NoError(t, err)

	outPoint := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	require.False(t, walletUtxoExists(t, store, walletID, outPoint))

	params.Credits = map[uint32]address.Address{0: nil}
	err = store.CreateTx(t.Context(), params)
	require.NoError(t, err)
	require.True(t, walletUtxoExists(t, store, walletID, outPoint))
}

// TestCreateTxReplayedCreditMarksExistingChildSpent verifies that replaying a
// parent credit also reconciles an already-stored child that spends it.
func TestCreateTxReplayedCreditMarksExistingChildSpent(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-tx-replay-spent")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	parentAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	childAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: parentAddr.ScriptPubKey}},
	)
	parentParams := db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710000580, 0),
		Status:   db.TxStatusPending,
	}

	err := store.CreateTx(t.Context(), parentParams)
	require.NoError(t, err)

	parentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	require.False(t, walletUtxoExists(t, store, walletID, parentOutPoint))

	childTx := newRegularTx(
		[]wire.OutPoint{parentOutPoint},
		[]*wire.TxOut{{Value: 4000, PkScript: childAddr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710000590, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)
	require.False(t, walletUtxoExists(t, store, walletID, parentOutPoint))

	parentParams.Credits = map[uint32]address.Address{0: nil}
	err = store.CreateTx(t.Context(), parentParams)
	require.NoError(t, err)
	require.True(t, walletUtxoSpent(t, store, walletID, parentOutPoint))
}

// TestCreateTxReplayedCreditConfirmedChildReplacesUnmined verifies that a
// late-discovered parent credit reconciles already-stored conflicting children
// before recording the parent spend edge.
func TestCreateTxReplayedCreditConfirmedChildReplacesUnmined(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-tx-replay-replace")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	parentAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	unminedAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	confirmedAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: parentAddr.ScriptPubKey}},
	)
	parentParams := db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710000600, 0),
		Status:   db.TxStatusPending,
	}

	err := store.CreateTx(t.Context(), parentParams)
	require.NoError(t, err)

	parentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	require.False(t, walletUtxoExists(t, store, walletID, parentOutPoint))

	unminedChild := newRegularTx(
		[]wire.OutPoint{parentOutPoint},
		[]*wire.TxOut{{Value: 4000, PkScript: unminedAddr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       unminedChild,
		Received: time.Unix(1710000610, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	confirmedChild := newRegularTx(
		[]wire.OutPoint{parentOutPoint},
		[]*wire.TxOut{{Value: 3000, PkScript: confirmedAddr.ScriptPubKey}},
	)
	confirmedBlock := CreateBlockFixture(t, store.Queries(), 262)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       confirmedChild,
		Received: time.Unix(1710000620, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	parentParams.Credits = map[uint32]address.Address{0: nil}
	err = store.CreateTx(t.Context(), parentParams)
	require.NoError(t, err)

	confirmedID, ok := txIDByHash(
		t, store, walletID, confirmedChild.TxHash(),
	)
	require.True(t, ok)
	require.Equal(
		t, []int64{confirmedID},
		childSpendingTxIDs(t, store, walletID, parentTx.TxHash()),
	)

	unminedInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     unminedChild.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusReplaced, unminedInfo.Status)

	confirmedInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     confirmedChild.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, confirmedInfo.Status)
	require.NotNil(t, confirmedInfo.Block)
	require.Equal(t, confirmedBlock.Height, confirmedInfo.Block.Height)
}

// TestCreateTxReplayedCreditSkipsReplacedChildSnapshot verifies that replaying
// a parent credit does not reattach a child spend from a stale active-child
// snapshot after that child has already been replaced.
func TestCreateTxReplayedCreditSkipsReplacedChildSnapshot(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-tx-replay-stale-child")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	parentAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	unminedAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	confirmedAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{
			{Value: 5000, PkScript: parentAddr.ScriptPubKey},
			{Value: 6000, PkScript: parentAddr.ScriptPubKey},
		},
	)
	parentParams := db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710000630, 0),
		Status:   db.TxStatusPending,
	}

	err := store.CreateTx(t.Context(), parentParams)
	require.NoError(t, err)

	firstOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	secondOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 1}
	unminedChild := newRegularTx(
		[]wire.OutPoint{firstOutPoint, secondOutPoint},
		[]*wire.TxOut{{Value: 4000, PkScript: unminedAddr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       unminedChild,
		Received: time.Unix(1710000640, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	confirmedChild := newRegularTx(
		[]wire.OutPoint{firstOutPoint},
		[]*wire.TxOut{{Value: 3000, PkScript: confirmedAddr.ScriptPubKey}},
	)
	confirmedBlock := CreateBlockFixture(t, store.Queries(), 263)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       confirmedChild,
		Received: time.Unix(1710000650, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	parentParams.Credits = map[uint32]address.Address{0: nil, 1: nil}
	err = store.CreateTx(t.Context(), parentParams)
	require.NoError(t, err)

	confirmedID, ok := txIDByHash(
		t, store, walletID, confirmedChild.TxHash(),
	)
	require.True(t, ok)
	require.Equal(
		t, []int64{confirmedID},
		childSpendingTxIDs(t, store, walletID, parentTx.TxHash()),
	)
	require.True(t, walletUtxoSpent(t, store, walletID, firstOutPoint))
	require.False(t, walletUtxoSpent(t, store, walletID, secondOutPoint))

	unminedInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     unminedChild.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusReplaced, unminedInfo.Status)
}

// TestCreateTxReplayedCreditPreplansConfirmedReplacements verifies that late
// parent-credit replay computes confirmed child replacements across all newly
// discovered credits before enforcing the single-unmined-spender rule.
func TestCreateTxReplayedCreditPreplansConfirmedReplacements(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-tx-replay-preplan")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	parentAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{
			{Value: 5000, PkScript: parentAddr.ScriptPubKey},
			{Value: 6000, PkScript: parentAddr.ScriptPubKey},
		},
	)
	parentParams := db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710000660, 0),
		Status:   db.TxStatusPending,
	}

	err := store.CreateTx(t.Context(), parentParams)
	require.NoError(t, err)

	firstOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	secondOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 1}
	staleChild := newRegularTx(
		[]wire.OutPoint{firstOutPoint, secondOutPoint},
		[]*wire.TxOut{{Value: 4000, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       staleChild,
		Received: time.Unix(1710000670, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	activeChild := newRegularTx(
		[]wire.OutPoint{firstOutPoint},
		[]*wire.TxOut{{Value: 3000, PkScript: []byte{0x52}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       activeChild,
		Received: time.Unix(1710000680, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	confirmedChild := newRegularTx(
		[]wire.OutPoint{secondOutPoint},
		[]*wire.TxOut{{Value: 2000, PkScript: []byte{0x53}}},
	)
	confirmedBlock := CreateBlockFixture(t, store.Queries(), 264)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       confirmedChild,
		Received: time.Unix(1710000690, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)

	parentParams.Credits = map[uint32]address.Address{0: nil, 1: nil}
	err = store.CreateTx(t.Context(), parentParams)
	require.NoError(t, err)

	activeID, ok := txIDByHash(t, store, walletID, activeChild.TxHash())
	require.True(t, ok)
	confirmedID, ok := txIDByHash(t, store, walletID, confirmedChild.TxHash())
	require.True(t, ok)
	require.ElementsMatch(
		t, []int64{activeID, confirmedID},
		childSpendingTxIDs(t, store, walletID, parentTx.TxHash()),
	)
	require.True(t, walletUtxoSpent(t, store, walletID, firstOutPoint))
	require.True(t, walletUtxoSpent(t, store, walletID, secondOutPoint))

	staleInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     staleChild.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusReplaced, staleInfo.Status)
}

// TestCreateTxConfirmsExistingUnminedRow verifies that CreateTx reuses one live
// unmined row when the same transaction later arrives with confirming block
// metadata.
//
// Scenario:
//   - One wallet already stores the transaction in its unmined history.
//
// Setup:
//   - Create one wallet-owned credited transaction in pending state.
//   - Create one matching confirming block fixture for the same transaction
//     hash.
//
// Action:
//   - Call CreateTx again with the same transaction hash and confirming block.
//
// Assertions:
//   - The existing row remains stored once.
//   - The transaction becomes confirmed and published.
//   - The existing label remains unchanged.
func TestCreateTxConfirmsExistingUnminedRow(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-confirm-existing-unmined")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 250)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000500, 0),
		Status:   db.TxStatusPending,
		Label:    "seed",
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000600, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Label:    "ignored",
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, info.Block)
	require.Equal(t, confirmedBlock.Height, info.Block.Height)
	require.Equal(t, db.TxStatusPublished, info.Status)
	require.Equal(t, "seed", info.Label)

	unminedTxs, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Empty(t, unminedTxs)

	confirmedTxs, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		StartHeight: confirmedBlock.Height,
		EndHeight:   confirmedBlock.Height,
	})
	require.NoError(t, err)
	require.Len(t, confirmedTxs, 1)
	require.Equal(t, tx.TxHash(), confirmedTxs[0].Hash)
}

// TestCreateTxConfirmedWinnerInvalidatesConflictBranch verifies that a newly
// confirmed transaction invalidates the conflicting unmined branch before it
// claims the shared wallet-owned input.
//
// Scenario:
//   - One wallet-owned output already has one unmined spend chain.
//   - A confirmed conflicting transaction later arrives for the same outpoint.
//
// Setup:
//   - Create one wallet-owned parent credit.
//   - Insert one unmined child and one unmined grandchild depending on it.
//   - Build one confirmed conflicting transaction spending the same parent
//     outpoint.
//
// Action:
//   - Insert the confirmed conflicting transaction through CreateTx.
//
// Assertions:
//   - The direct conflicting root becomes replaced.
//   - The descendant row becomes failed.
//   - The confirmed winner is stored.
//   - The parent outpoint remains spent instead of returning to the UTXO set.
func TestCreateTxConfirmedWinnerInvalidatesConflictBranch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-confirmed-conflict-winner")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710001500, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	spentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	firstChild := newRegularTx(
		[]wire.OutPoint{spentOutPoint},
		[]*wire.TxOut{{Value: 4000, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       firstChild,
		Received: time.Unix(1710001510, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	grandchild := newRegularTx(
		[]wire.OutPoint{{Hash: firstChild.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 3000, PkScript: []byte{0x52}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       grandchild,
		Received: time.Unix(1710001520, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	confirmedBlock := CreateBlockFixture(t, store.Queries(), 260)
	confirmedWinner := newRegularTx(
		[]wire.OutPoint{spentOutPoint},
		[]*wire.TxOut{{Value: 3500, PkScript: []byte{0x53}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       confirmedWinner,
		Received: time.Unix(1710001530, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)

	childInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     firstChild.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, childInfo.Block)
	require.Equal(t, db.TxStatusReplaced, childInfo.Status)

	grandchildInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     grandchild.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, grandchildInfo.Block)
	require.Equal(t, db.TxStatusFailed, grandchildInfo.Status)

	winnerInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     confirmedWinner.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, winnerInfo.Block)
	require.Equal(t, db.TxStatusPublished, winnerInfo.Status)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: spentOutPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestGetTxReturnsStoredPendingTx verifies that GetTx rebuilds the public
// transaction view for one stored unmined row.
//
// Scenario:
//   - One pending wallet transaction has already been inserted.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//
// Action:
//   - Retrieve the transaction through GetTx.
//
// Assertions:
//   - GetTx returns the stored hash, status, label, and nil block metadata.
func TestGetTxReturnsStoredPendingTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-tx")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000600, 0),
		Status:   db.TxStatusPending,
		Label:    "pending-note",
	})
	require.NoError(t, err)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, tx.TxHash(), info.Hash)
	require.Equal(t, db.TxStatusPending, info.Status)
	require.Equal(t, "pending-note", info.Label)
	require.Nil(t, info.Block)
}

// TestGetTxNotFound verifies that GetTx returns ErrTxNotFound when the wallet
// has no matching transaction row.
//
// Scenario:
//   - One wallet has no stored transaction for the requested hash.
//
// Setup:
//   - Create one wallet and choose one random transaction hash.
//
// Action:
//   - Query the missing hash through GetTx.
//
// Assertions:
//   - GetTx returns ErrTxNotFound.
func TestGetTxNotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-tx-missing")

	_, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     RandomHash(),
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestUpdateTxRequiresExistingConfirmedBlock verifies that UpdateTx rejects a
// state patch whose referenced block height is missing from the shared blocks
// table.
//
// Scenario:
//   - One stored pending transaction is later patched with a missing block.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//   - Build one block reference without inserting that block row.
//
// Action:
//   - Apply the confirmation patch through UpdateTx.
//
// Assertions:
//   - UpdateTx returns ErrBlockNotFound.
//   - The transaction remains unconfirmed.
func TestUpdateTxRequiresExistingConfirmedBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-confirmed-tx-missing-block")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: []byte{0x51}}},
	)
	block := db.Block{
		Hash:      RandomHash(),
		Height:    240,
		Timestamp: time.Unix(1710000560, 0),
	}

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000570, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     tx.TxHash(),
		State: &db.UpdateTxState{
			Block:  &block,
			Status: db.TxStatusPublished,
		},
	})
	require.ErrorIs(t, err, db.ErrBlockNotFound)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, info.Block)
}

// TestUpdateTxRejectsMismatchedConfirmedBlock verifies that UpdateTx rejects a
// state patch when the supplied block metadata does not match the stored block
// row for that height.
//
// Scenario:
//   - One stored pending transaction is later patched with mismatched block
//     metadata for an existing height.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//   - Insert the real block row for the target height.
//   - Build a second block reference with the same height but different hash.
//
// Action:
//   - Apply the mismatched confirmation patch through UpdateTx.
//
// Assertions:
//   - UpdateTx returns ErrBlockMismatch.
//   - The existing transaction row remains unconfirmed and pending.
func TestUpdateTxRejectsMismatchedConfirmedBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-update-tx-block-mismatch")
	queries := store.Queries()

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000550, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	block := CreateBlockFixture(t, queries, 240)
	mismatchBlock := block
	mismatchBlock.Hash = RandomHash()

	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     tx.TxHash(),
		State: &db.UpdateTxState{
			Block:  &mismatchBlock,
			Status: db.TxStatusPublished,
		},
	})
	require.ErrorIs(t, err, db.ErrBlockMismatch)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, info.Block)
	require.Equal(t, db.TxStatusPending, info.Status)
}

// TestUpdateTxUpdatesStoredLabel verifies that UpdateTx can patch the stored
// user-visible label without mutating chain-state metadata.
//
// Scenario:
//   - One pending wallet transaction already exists with an old label.
//
// Setup:
//   - Create one wallet and insert one pending transaction row with a label.
//
// Action:
//   - Patch only the label through UpdateTx.
//
// Assertions:
//   - The stored label changes.
//   - The transaction stays pending and unconfirmed.
func TestUpdateTxUpdatesStoredLabel(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-update-tx-label")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000700, 0),
		Status:   db.TxStatusPending,
		Label:    "old-label",
	})
	require.NoError(t, err)

	label := "new-label"
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     tx.TxHash(),
		Label:    &label,
	})
	require.NoError(t, err)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, "new-label", info.Label)
	require.Equal(t, db.TxStatusPending, info.Status)
}

// TestUpdateTxConfirmsStoredPendingTx verifies that UpdateTx can attach a
// confirming block to an already-stored unmined row.
//
// Scenario:
//   - One pending wallet transaction is later observed in a block.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//   - Insert one matching block row.
//
// Action:
//   - Apply a published state patch with that block through UpdateTx.
//
// Assertions:
//   - The transaction now carries the block metadata.
//   - The status becomes published.
func TestUpdateTxConfirmsStoredPendingTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-update-tx-confirm")
	queries := store.Queries()

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 6000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000710, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	block := CreateBlockFixture(t, queries, 220)
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     tx.TxHash(),
		State: &db.UpdateTxState{
			Block:  &block,
			Status: db.TxStatusPublished,
		},
	})
	require.NoError(t, err)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, info.Block)
	require.Equal(t, block.Height, info.Block.Height)
	require.Equal(t, block.Hash, info.Block.Hash)
	require.Equal(t, db.TxStatusPublished, info.Status)
}

// TestUpdateTxNotFound verifies that UpdateTx returns ErrTxNotFound when the
// wallet has no matching transaction row.
//
// Scenario:
//   - One wallet has no stored transaction for the requested hash.
//
// Setup:
//   - Create one wallet and one label patch.
//
// Action:
//   - Apply the patch to a random missing tx hash.
//
// Assertions:
//   - UpdateTx returns ErrTxNotFound.
func TestUpdateTxNotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-update-label-missing")

	label := "new-label"
	err := store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     RandomHash(),
		Label:    &label,
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestUpdateTxRejectsEmptyPatch verifies that UpdateTx rejects a request that
// does not ask to mutate any transaction field.
//
// Scenario:
//   - One wallet transaction exists, but the caller provides no label or state
//     mutation.
//
// Setup:
//   - Create one wallet and insert one pending transaction row.
//
// Action:
//   - Call UpdateTx with an empty patch.
//
// Assertions:
//   - UpdateTx returns ErrInvalidParam.
func TestUpdateTxRejectsEmptyPatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-update-empty-patch")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 6000, PkScript: []byte{0x51}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000720, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)
}

// TestListTxnsReturnsRowsWithoutBlock verifies that the no-confirming-block
// query path excludes confirmed rows while still surfacing retained invalid
// history that no longer has block metadata.
//
// Scenario:
//   - One wallet has confirmed history, active unmined history, and retained
//     invalid history without blocks.
//
// Setup:
//   - Insert one confirmed transaction, one pending transaction, and one failed
//     transaction whose block is nil.
//
// Action:
//   - Query ListTxns with UnminedOnly set.
//
// Assertions:
//   - Only unmined rows are returned.
//   - Both the active pending row and the failed history row are present.
func TestListTxnsReturnsRowsWithoutBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-txns-without-block")
	queries := store.Queries()

	confirmedBlock := CreateBlockFixture(t, queries, 200)
	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: []byte{0x51}}},
	)
	unminedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 8000, PkScript: []byte{0x52}}},
	)
	failedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 8100, PkScript: []byte{0x53}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       confirmedTx,
		Received: time.Unix(1710000800, 0),
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     confirmedTx.TxHash(),
		State: &db.UpdateTxState{
			Block:  &confirmedBlock,
			Status: db.TxStatusPublished,
		},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       unminedTx,
		Received: time.Unix(1710000810, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       failedTx,
		Received: time.Unix(1710000815, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)
	setTxStatus(t, store, walletID, failedTx.TxHash(), db.TxStatusFailed)

	infos, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, infos, 2)

	statusesByHash := make(map[chainhash.Hash]db.TxStatus, len(infos))
	for _, info := range infos {
		require.Nil(t, info.Block)
		statusesByHash[info.Hash] = info.Status
	}

	require.Equal(t, db.TxStatusPending, statusesByHash[unminedTx.TxHash()])
	require.Equal(t, db.TxStatusFailed, statusesByHash[failedTx.TxHash()])
}

// TestListTxnsReturnsConfirmedTxsByHeightRange verifies that the
// confirmed-range query path excludes unmined rows and respects the height
// bounds.
//
// Scenario:
//   - One wallet has confirmed transactions at multiple heights plus one
//     unmined row.
//
// Setup:
//   - Insert two confirmed transactions at different heights and one pending
//     transaction without a block.
//
// Action:
//   - Query ListTxns for one exact confirmed height range.
//
// Assertions:
//   - Only the matching confirmed transaction is returned.
//   - The unmined row is excluded.
func TestListTxnsReturnsConfirmedTxsByHeightRange(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-txns-confirmed")
	queries := store.Queries()

	blockOne := CreateBlockFixture(t, queries, 210)
	blockTwo := CreateBlockFixture(t, queries, 211)

	txOne := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 9000, PkScript: []byte{0x51}}},
	)
	txTwo := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 10000, PkScript: []byte{0x52}}},
	)
	unminedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 11000, PkScript: []byte{0x53}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txOne,
		Received: time.Unix(1710000900, 0),
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     txOne.TxHash(),
		State: &db.UpdateTxState{
			Block:  &blockOne,
			Status: db.TxStatusPublished,
		},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txTwo,
		Received: time.Unix(1710000910, 0),
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     txTwo.TxHash(),
		State: &db.UpdateTxState{
			Block:  &blockTwo,
			Status: db.TxStatusPublished,
		},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       unminedTx,
		Received: time.Unix(1710000920, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	infos, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		StartHeight: 211,
		EndHeight:   211,
	})
	require.NoError(t, err)
	require.Len(t, infos, 1)
	require.Equal(t, txTwo.TxHash(), infos[0].Hash)
	require.NotNil(t, infos[0].Block)
	require.Equal(t, uint32(211), infos[0].Block.Height)
}

// TestListTxnsUsesConfirmationOrder verifies that confirmed reads do not use
// row IDs as the same-block ordering tie-breaker.
//
// Scenario:
//   - One wallet sees a transaction as unmined before another transaction that
//     appears earlier in the same block.
//
// Setup:
//   - Insert the later block transaction as unmined first.
//   - Insert the earlier block transaction directly as confirmed.
//   - Confirm the older unmined row in the same block.
//
// Action:
//   - Query summary and detail transactions for that exact block height.
//
// Assertions:
//   - Both SQL reader paths return the direct confirmed transaction before the
//     older row that was confirmed later.
func TestListTxnsUsesConfirmationOrder(t *testing.T) {
	t.Parallel()

	// Arrange: Give laterBlockTx the smaller row ID, which used to make it sort
	// before earlierBlockTx after both rows were attached to the same block.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-txns-confirm-order")
	queries := store.Queries()

	const blockHeight = 222

	block := CreateBlockFixture(t, queries, blockHeight)

	laterBlockTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 17000, PkScript: []byte{0x51}}},
	)
	earlierBlockTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 18000, PkScript: []byte{0x52}}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       laterBlockTx,
		Received: time.Unix(1710000980, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       earlierBlockTx,
		Received: time.Unix(1710000990, 0),
		Block:    &block,
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       laterBlockTx,
		Received: time.Unix(1710001000, 0),
		Block:    &block,
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)

	// Act: Read the same confirmed block through summary and detail APIs.
	infos, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		StartHeight: blockHeight,
		EndHeight:   blockHeight,
	})
	require.NoError(t, err)

	details, err := store.ListTxDetails(t.Context(), db.ListTxDetailsQuery{
		WalletID:    walletID,
		StartHeight: blockHeight,
		EndHeight:   blockHeight,
	})
	require.NoError(t, err)

	// Assert: The later-confirmed old row stays after the direct confirmed row.
	wantOrder := []chainhash.Hash{
		earlierBlockTx.TxHash(),
		laterBlockTx.TxHash(),
	}
	require.Equal(t, wantOrder, txHashes(infos))
	require.Equal(t, wantOrder, txDetailHashes(details))
}

// TestGetTxDetailFindsOwnedInputAfterSpendEdgeCleared verifies that detail
// reads reconstruct historical debits after invalidation clears spent_by_tx_id.
//
// Scenario:
//   - One wallet-owned parent output is spent by an unmined child transaction.
//   - The child is invalidated, clearing the mutable spend edge while retaining
//     the child transaction row as failed history.
//
// Setup:
//   - Insert one wallet-owned parent credit and one child that spends it.
//   - Invalidate the child transaction.
//
// Action:
//   - Query the failed child through GetTxDetail.
//
// Assertions:
//   - The parent output is spendable again, proving the spend edge was cleared.
//   - The child detail still reports the wallet-owned input from its raw tx.
func TestGetTxDetailFindsOwnedInputAfterSpendEdgeCleared(t *testing.T) {
	t.Parallel()

	// Arrange: Create a wallet-owned parent credit and a child that spends it.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-detail-cleared-spend-edge")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710001010, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	spentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	childTx := newRegularTx(
		[]wire.OutPoint{spentOutPoint},
		[]*wire.TxOut{{Value: 4000, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710001020, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.InvalidateUnminedTx(t.Context(), db.InvalidateUnminedTxParams{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)

	// Act: Read the failed child detail after its spend edge has been cleared.
	detail, err := store.GetTxDetail(t.Context(), db.GetTxDetailQuery{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)

	parentUtxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: spentOutPoint,
	})
	require.NoError(t, err)

	// Assert: The current UTXO set is restored, but historical child details
	// still report the wallet-owned debit from the serialized child
	// transaction.
	require.Equal(t, btcutil.Amount(5000), parentUtxo.Amount)
	require.Equal(t, db.TxStatusFailed, detail.Status)
	require.Len(t, detail.OwnedInputs, 1)
	require.Equal(t, uint32(0), detail.OwnedInputs[0].Index)
	require.Equal(t, btcutil.Amount(5000), detail.OwnedInputs[0].Amount)
}

// TestDeleteTxRemovesLeafUnminedTx verifies that DeleteTx removes a leaf
// unmined row and restores any parent spend markers it introduced.
//
// Scenario:
//   - One unmined child transaction is the only spender of one wallet-owned
//     parent output.
//
// Setup:
//   - Create one wallet-owned parent credit and one unmined child spender.
//
// Action:
//   - Delete the child through DeleteTx.
//
// Assertions:
//   - The child row is removed.
//   - The parent output becomes spendable again.
//   - No child spend edges remain.
func TestDeleteTxRemovesLeafUnminedTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-leaf")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710001000, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4000, PkScript: []byte{0x51}}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710001010, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)
	require.Empty(t, childSpendingTxIDs(t, store, walletID, parentTx.TxHash()))
	_, ok := txIDByHash(t, store, walletID, childTx.TxHash())
	require.False(t, ok)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: parentTx.TxHash(), Index: 0,
	}))
}

// TestDeleteTxRejectsNonLeafTx verifies that DeleteTx refuses to erase an
// unmined transaction that still has direct child spenders.
//
// Scenario:
//   - One parent transaction still has one direct unmined child spender.
//
// Setup:
//   - Create one wallet-owned parent credit and one child that spends it.
//
// Action:
//   - Attempt to delete the parent through DeleteTx.
//
// Assertions:
//   - DeleteTx returns ErrDeleteRequiresLeaf.
//   - Both parent and child rows remain stored.
func TestDeleteTxRejectsNonLeafTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-non-leaf")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710001100, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4000, PkScript: addr.ScriptPubKey}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710001110, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     parentTx.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrDeleteRequiresLeaf)
	_, ok := txIDByHash(t, store, walletID, parentTx.TxHash())
	require.True(t, ok)
	_, ok = txIDByHash(t, store, walletID, childTx.TxHash())
	require.True(t, ok)
}

// TestDeleteTxRemovesParentWithFailedChild verifies that DeleteTx only treats
// still-active unmined children as leaf blockers.
//
// Scenario:
//   - One parent transaction still has one direct child row, but that child has
//     already been marked failed.
//
// Setup:
//   - Create one wallet-owned parent credit and one child that spends it.
//   - Mark the child failed to simulate an already-invalid branch.
//
// Action:
//   - Delete the parent through DeleteTx.
//
// Assertions:
//   - DeleteTx succeeds because the failed child is no longer part of the
//     active unmined graph.
//   - The parent row is removed.
func TestDeleteTxRemovesParentWithFailedChild(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-parent-failed-child")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710001115, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4000, PkScript: addr.ScriptPubKey}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710001120, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)
	setTxStatus(t, store, walletID, childTx.TxHash(), db.TxStatusFailed)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     parentTx.TxHash(),
	})
	require.NoError(t, err)

	_, ok := txIDByHash(t, store, walletID, parentTx.TxHash())
	require.False(t, ok)
}

// TestRollbackToBlockFailsCoinbaseDescendants verifies that RollbackToBlock
// marks every unmined descendant of a disconnected coinbase root as failed and
// clears the recorded spend edges they had claimed.
//
// Scenario:
//   - One confirmed coinbase credit has one unmined child spender and one
//     unmined grandchild spender beneath it.
//
// Setup:
//   - Create one wallet-owned coinbase output and confirm it in one block.
//   - Insert one child transaction that spends that output and creates one new
//     wallet-owned credit.
//   - Insert one grandchild that spends the child's wallet-owned output.
//
// Action:
//   - Roll back the block that confirmed the coinbase root.
//
// Assertions:
//   - The disconnected coinbase root becomes orphaned.
//   - Both unmined descendants become failed.
//   - The spend edges from the coinbase root and child are cleared.
func TestRollbackToBlockFailsCoinbaseDescendants(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-rollback-coinbase-descendants")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	queries := store.Queries()

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	coinbaseTx := newCoinbaseTx(addr.ScriptPubKey)

	block := CreateBlockFixture(t, queries, 300)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710001200, 0),
		Block:    &block,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: coinbaseTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710001210, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	grandchildTx := newRegularTx(
		[]wire.OutPoint{{Hash: childTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 3000, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       grandchildTx,
		Received: time.Unix(1710001220, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	require.Len(t, childSpendingTxIDs(t, store, walletID, coinbaseTx.TxHash()),
		1)
	require.Len(t, childSpendingTxIDs(t, store, walletID, childTx.TxHash()), 1)

	err = store.RollbackToBlock(t.Context(), block.Height)
	require.NoError(t, err)

	coinbaseInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusOrphaned, coinbaseInfo.Status)
	require.Nil(t, coinbaseInfo.Block)

	childInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, childInfo.Status)
	require.Nil(t, childInfo.Block)

	grandchildInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     grandchildTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, grandchildInfo.Status)
	require.Nil(t, grandchildInfo.Block)

	require.Empty(
		t, childSpendingTxIDs(t, store, walletID, coinbaseTx.TxHash()),
	)
	require.Empty(t, childSpendingTxIDs(t, store, walletID, childTx.TxHash()))
}

// TestRollbackToBlockRewindsSyncToStoredLowerBlock verifies rollback rewinds
// wallet sync references to the greatest stored block below the rollback
// boundary instead of assuming height-1 exists in sparse block tables.
func TestRollbackToBlockRewindsSyncToStoredLowerBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletName := "wallet-rollback-sparse-sync"
	walletID := newWallet(t, store, walletName)

	forkBlock := CreateBlockFixture(t, queries, 5)
	rollbackBlock := CreateBlockFixture(t, queries, 10)

	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &forkBlock,
	})
	require.NoError(t, err)

	err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &rollbackBlock,
	})
	require.NoError(t, err)

	err = store.RollbackToBlock(t.Context(), rollbackBlock.Height)
	require.NoError(t, err)

	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.NotNil(t, walletInfo.SyncedTo)
	require.Equal(t, forkBlock.Height, walletInfo.SyncedTo.Height)
	require.Equal(t, forkBlock.Hash, walletInfo.SyncedTo.Hash)
}

// TestRewindWalletLeavesOtherWalletState verifies manual rescan rewind is
// wallet-scoped. It must detach only the selected wallet's confirmed
// transactions and sync tip, leaving another wallet that shares the same Store
// at the same block height untouched.
func TestRewindWalletLeavesOtherWalletState(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	const (
		walletAName = "wallet-rewind-scoped-a"
		walletBName = "wallet-rewind-scoped-b"
	)

	walletA := newWallet(t, store, walletAName)
	walletB := newWallet(t, store, walletBName)

	rewindBlock := db.Block{
		Hash:      chainhash.Hash{100},
		Height:    100,
		Timestamp: time.Unix(1710006100, 0),
	}
	tipBlock := db.Block{
		Hash:      chainhash.Hash{101},
		Height:    101,
		Timestamp: time.Unix(1710006110, 0),
	}

	txA := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 1000}},
	)
	txB := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2000}},
	)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletA,
		Transactions: []db.CreateTxParams{{
			WalletID: walletA,
			Tx:       txA,
			Received: time.Unix(1710006120, 0),
			Block:    &tipBlock,
			Status:   db.TxStatusPublished,
		}},
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletB,
		Transactions: []db.CreateTxParams{{
			WalletID: walletB,
			Tx:       txB,
			Received: time.Unix(1710006130, 0),
			Block:    &tipBlock,
			Status:   db.TxStatusPublished,
		}},
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	err = store.RewindWallet(t.Context(), db.RewindWalletParams{
		WalletID: walletA,
		Block:    rewindBlock,
	})
	require.NoError(t, err)

	infoA, err := store.GetWallet(t.Context(), walletAName)
	require.NoError(t, err)
	require.NotNil(t, infoA.SyncedTo)
	require.Equal(t, rewindBlock.Height, infoA.SyncedTo.Height)
	require.Equal(t, rewindBlock.Hash, infoA.SyncedTo.Hash)

	infoB, err := store.GetWallet(t.Context(), walletBName)
	require.NoError(t, err)
	require.NotNil(t, infoB.SyncedTo)
	require.Equal(t, tipBlock.Height, infoB.SyncedTo.Height)
	require.Equal(t, tipBlock.Hash, infoB.SyncedTo.Hash)

	confirmedA, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletA,
		StartHeight: tipBlock.Height,
		EndHeight:   tipBlock.Height,
	})
	require.NoError(t, err)
	require.Empty(t, confirmedA)

	unminedA, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletA,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, unminedA, 1)
	require.Equal(t, txA.TxHash(), unminedA[0].Hash)
	require.Nil(t, unminedA[0].Block)
	require.Equal(t, db.TxStatusPublished, unminedA[0].Status)

	confirmedB, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletB,
		StartHeight: tipBlock.Height,
		EndHeight:   tipBlock.Height,
	})
	require.NoError(t, err)
	require.Len(t, confirmedB, 1)
	require.Equal(t, txB.TxHash(), confirmedB[0].Hash)
	require.NotNil(t, confirmedB[0].Block)
	require.Equal(t, tipBlock.Height, confirmedB[0].Block.Height)
}

// TestCreateTxReconfirmsOrphanedCoinbase verifies that CreateTx can restore an
// orphaned coinbase row to confirmed history when the same coinbase hash later
// re-enters the best chain.
//
// Scenario:
//   - One wallet already stores one orphaned coinbase transaction after
//     rollback.
//
// Setup:
//   - Create and confirm one wallet-owned coinbase transaction.
//   - Roll back the confirming block so the coinbase becomes orphaned.
//   - Create one new confirming block for the same tx hash.
//
// Action:
//   - Call CreateTx again with the same coinbase transaction and new block.
//
// Assertions:
//   - The existing row becomes confirmed and published again.
//   - The wallet-owned coinbase output returns to the current UTXO set.
func TestCreateTxReconfirmsOrphanedCoinbase(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-reconfirm-orphaned-coinbase")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	block := CreateBlockFixture(t, queries, 310)
	coinbaseTx := newCoinbaseTx(addr.ScriptPubKey)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710001540, 0),
		Block:    &block,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.RollbackToBlock(t.Context(), block.Height)
	require.NoError(t, err)

	orphanInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusOrphaned, orphanInfo.Status)
	require.Nil(t, orphanInfo.Block)

	newBlock := CreateBlockFixture(t, queries, 311)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710001550, 0),
		Block:    &newBlock,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, info.Status)
	require.NotNil(t, info.Block)
	require.Equal(t, newBlock.Height, info.Block.Height)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: coinbaseTx.TxHash(), Index: 0,
	}))
}

// TestGetUtxoReturnsCurrentWalletOutput verifies that GetUtxo returns a stored
// wallet-owned output created by an unmined transaction.
func TestGetUtxoReturnsCurrentWalletOutput(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-utxo")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 15000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710001400, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	utxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
	})

	require.NoError(t, err)
	require.Equal(t, tx.TxHash(), utxo.OutPoint.Hash)
	require.Equal(t, uint32(0), utxo.OutPoint.Index)
	require.Equal(t, btcutil.Amount(15000), utxo.Amount)
	require.Equal(t, db.UnminedHeight, utxo.Height)
}

// TestGetUtxoNotFound verifies that GetUtxo returns ErrUtxoNotFound when the
// requested outpoint is not part of the current wallet UTXO set.
func TestGetUtxoNotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-utxo-missing")

	_, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: randomOutPoint(),
	})

	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestListUTXOsReturnsCurrentWalletOutputs verifies that ListUTXOs returns the
// current wallet-owned outputs created by pending transactions.
func TestListUTXOsReturnsCurrentWalletOutputs(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-utxos")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	txOne := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 15000, PkScript: addr.ScriptPubKey}},
	)
	txTwo := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 12000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txOne,
		Received: time.Unix(1710001500, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txTwo,
		Received: time.Unix(1710001510, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	utxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
	})

	require.NoError(t, err)
	require.Len(t, utxos, 2)
	require.Equal(t, txTwo.TxHash(), utxos[0].OutPoint.Hash)
	require.Equal(t, txOne.TxHash(), utxos[1].OutPoint.Hash)
}

// TestUTXOEnrichmentFields verifies that ListUTXOs and GetUtxo populate the
// UtxoInfo enrichment fields (AccountName, AddrType, HasScript, IsLocked,
// KeyScope) from the backing account/address/lease joins. It pairs a positive
// case (an imported script address with an active lease) against a negative
// case (a derived address with neither a script nor a lease) so a regression in
// any join or row-to-UtxoInfo conversion fails the assertions.
func TestUTXOEnrichmentFields(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	// A watch-only wallet can host an imported script-only address: such an
	// address carries a persisted encrypted script (so HasScript is true)
	// but no private key, which the ADR 0012 invariant only permits on a
	// watch-only wallet.
	walletID := newWatchOnlyWallet(t, store, "wallet-utxo-enrichment")

	const derivedName = "derived"

	importedName := db.DefaultImportedAccountName
	scope := db.KeyScopeBIP0084

	// Imported script address: the encrypted script secret drives HasScript,
	// and the raw-import alias drives AccountName.
	importedScript := RandomBytes(32)
	_, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:        walletID,
			Scope:           scope,
			AddressType:     db.WitnessScript,
			PubKey:          RandomBytes(33),
			ScriptPubKey:    importedScript,
			EncryptedScript: RandomBytes(48),
		},
	)
	require.NoError(t, err)

	// Derived address: no script secret, so HasScript stays false.
	createDerivedAccount(t, store, walletID, scope, derivedName)
	derivedAddr := newDerivedAddress(
		t, store, walletID, scope, derivedName, false,
	)

	// Record one UTXO under each address.
	importedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 20000, PkScript: importedScript}},
	)
	derivedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 30000, PkScript: derivedAddr.ScriptPubKey}},
	)

	for _, tx := range []*wire.MsgTx{importedTx, derivedTx} {
		err = store.CreateTx(t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710002000, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		})
		require.NoError(t, err)
	}

	importedOutPoint := wire.OutPoint{Hash: importedTx.TxHash(), Index: 0}
	derivedOutPoint := wire.OutPoint{Hash: derivedTx.TxHash(), Index: 0}

	// Lease only the imported UTXO so IsLocked distinguishes the two rows.
	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		OutPoint: importedOutPoint,
		ID:       db.LockID{1},
		Duration: 30 * time.Minute,
	})
	require.NoError(t, err)

	// Index ListUTXOs results by outpoint so assertions don't depend on the
	// result ordering.
	utxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
	})
	require.NoError(t, err)
	require.Len(t, utxos, 2)

	byOutPoint := make(map[wire.OutPoint]db.UtxoInfo, len(utxos))
	for _, u := range utxos {
		byOutPoint[u.OutPoint] = u
	}

	imported, ok := byOutPoint[importedOutPoint]
	require.True(t, ok, "imported UTXO missing from ListUTXOs")
	require.Equal(t, importedName, imported.AccountName)
	require.Equal(t, db.WitnessScript, imported.AddrType)
	require.True(t, imported.HasScript)
	require.True(t, imported.IsLocked)
	require.Equal(t, scope, imported.KeyScope)

	filteredImported, err := store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID:    walletID,
			Scope:       &scope,
			AccountName: &importedName,
		},
	)
	require.NoError(t, err)
	require.Len(t, filteredImported, 1)
	require.Equal(t, importedOutPoint, filteredImported[0].OutPoint)

	derived, ok := byOutPoint[derivedOutPoint]
	require.True(t, ok, "derived UTXO missing from ListUTXOs")
	require.Equal(t, derivedName, derived.AccountName)
	require.Equal(t, db.WitnessPubKey, derived.AddrType)
	require.False(t, derived.HasScript)
	require.False(t, derived.IsLocked)
	require.Equal(t, scope, derived.KeyScope)

	// GetUtxo surfaces the same enriched view as ListUTXOs.
	got, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: importedOutPoint,
	})
	require.NoError(t, err)
	require.Equal(t, db.WitnessScript, got.AddrType)
	require.True(t, got.HasScript)
	require.True(t, got.IsLocked)
	require.Equal(t, scope, got.KeyScope)
}

// TestListUTXOsFiltersByAccount verifies that ListUTXOs applies the optional
// account filter without affecting the underlying wallet ownership checks.
func TestListUTXOsFiltersByAccount(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-utxos-account")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "savings")

	defaultAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	savingsAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "savings", false,
	)

	txDefault := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 16000, PkScript: defaultAddr.ScriptPubKey}},
	)
	txSavings := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 17000, PkScript: savingsAddr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txDefault,
		Received: time.Unix(1710001600, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txSavings,
		Received: time.Unix(1710001610, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	scope := db.KeyScopeBIP0084
	account := uint32(1)
	utxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
		Scope:    &scope,
		Account:  &account,
	})

	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, txSavings.TxHash(), utxos[0].OutPoint.Hash)
}

// TestAccountNumberFiltersExcludeImportedAccounts verifies that numeric account
// filters do not match imported-xpub accounts even if corrupt metadata gives
// the imported account a derived_accounts row.
func TestAccountNumberFiltersExcludeImportedAccounts(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	dbConn := store.DB()
	walletID := newWatchOnlyWallet(
		t, store, "wallet-utxo-imported-account-number",
	)

	accountName := hardwareAccountName
	CreateImportedAccount(
		t, store, walletID, db.KeyScopeBIP0084, accountName, true,
	)

	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
	accountID := GetAccountID(t, queries, scopeID, accountName)
	scriptPubKey := RandomBytes(22)
	err := createDerivedAddressRaw(
		t, queries, walletID, accountID, 0, 0, scriptPubKey,
	)
	require.NoError(t, err)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 19000, PkScript: scriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710001650, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	accountNumber := uint32(7)
	err = insertDerivedAccountNumberRaw(
		t, dbConn, accountID, scopeID, accountNumber,
	)
	require.Error(t, err)
	requireDriverConstraintError(t, err)

	unfiltered, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
	})
	require.NoError(t, err)
	require.Len(t, unfiltered, 1)
	require.Equal(t, tx.TxHash(), unfiltered[0].OutPoint.Hash)

	scope := db.KeyScopeBIP0084
	filtered, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
		Scope:    &scope,
		Account:  &accountNumber,
	})
	require.NoError(t, err)
	require.Empty(t, filtered)

	balance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID: walletID,
		Scope:    &scope,
		Account:  &accountNumber,
	})
	require.NoError(t, err)
	require.Zero(t, balance.Total)
}

// TestUTXOReadsRejectMalformedDerivedAddressShape verifies that per-row UTXO
// reads reject malformed derived address shape instead of silently reporting
// the output under the raw imported alias. Balance aggregation should exclude
// the malformed row and still count well-formed UTXOs.
func TestUTXOReadsRejectMalformedDerivedAddressShape(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-utxo-malformed-address")
	accountName := defaultAccountName
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, accountName)

	goodAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, accountName, false,
	)
	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
	accountID := GetAccountID(t, queries, scopeID, accountName)
	badScript := RandomBytes(22)
	_, err := createDerivedAddressParentRaw(
		t, queries, walletID, accountID, badScript,
	)
	require.NoError(t, err)

	goodTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 41000, PkScript: goodAddr.ScriptPubKey}},
	)
	badTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 42000, PkScript: badScript}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       goodTx,
		Received: time.Unix(1710001660, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       badTx,
		Received: time.Unix(1710001670, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: badTx.TxHash(), Index: 0},
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "address subtype invariant violated")

	_, err = store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "address subtype invariant violated")

	balance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID: walletID,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(41000), balance.Total)
	require.Zero(t, balance.Locked)
}

// TestListUTXOsFiltersByAccountName verifies that ListUTXOs filters by the
// paired (Scope, AccountName) combination. Account names are unique only
// within a scope, so the Scope is required alongside AccountName.
func TestListUTXOsFiltersByAccountName(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(
		t, store, "wallet-list-utxos-account-name",
	)
	createDerivedAccount(
		t, store, walletID, db.KeyScopeBIP0084, "default",
	)
	createDerivedAccount(
		t, store, walletID, db.KeyScopeBIP0084, "savings",
	)

	defaultAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	savingsAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "savings", false,
	)

	txDefault := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{
			{Value: 22000, PkScript: defaultAddr.ScriptPubKey},
		},
	)
	txSavings := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{
			{Value: 23000, PkScript: savingsAddr.ScriptPubKey},
		},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txDefault,
		Received: time.Unix(1710001700, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txSavings,
		Received: time.Unix(1710001710, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	scope := db.KeyScopeBIP0084
	name := "savings"
	utxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID:    walletID,
		Scope:       &scope,
		AccountName: &name,
	})

	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, txSavings.TxHash(), utxos[0].OutPoint.Hash)
}

// TestListUTXOsRejectsAccountWithoutScope verifies that the
// ListUtxosQuery validator rejects a numeric account filter that arrives
// without the matching key scope. Account numbers are allocated per scope,
// so a number-only filter would silently mix outputs across scopes.
func TestListUTXOsRejectsAccountWithoutScope(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(
		t, store, "wallet-list-utxos-account-without-scope",
	)

	account := uint32(0)
	_, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
		Account:  &account,
	})

	require.ErrorIs(
		t, err, db.ErrListUtxosQueryAccountWithoutScope,
	)
}

// TestListUTXOsRejectsNameWithoutScope verifies that AccountName-only
// filters are rejected for the same scope-uniqueness reason that
// BalanceParams enforces.
func TestListUTXOsRejectsNameWithoutScope(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(
		t, store, "wallet-list-utxos-name-without-scope",
	)

	name := defaultAccountName
	_, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID:    walletID,
		AccountName: &name,
	})

	require.ErrorIs(
		t, err, db.ErrListUtxosQueryNameWithoutScope,
	)
}

// TestListUTXOsRejectsAccountAndName verifies that callers cannot pass
// both Account and AccountName: those fields are mutually exclusive
// disambiguation handles.
func TestListUTXOsRejectsAccountAndName(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(
		t, store, "wallet-list-utxos-account-and-name",
	)

	scope := db.KeyScopeBIP0084
	account := uint32(0)
	name := defaultAccountName
	_, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID:    walletID,
		Scope:       &scope,
		Account:     &account,
		AccountName: &name,
	})

	require.ErrorIs(
		t, err, db.ErrListUtxosQueryAccountAndName,
	)
}

// TestLeaseOutputLocksCurrentUtxo verifies that LeaseOutput returns the active
// lease metadata for a current wallet-owned output.
func TestLeaseOutputLocksCurrentUtxo(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-lease-output")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 18000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710001700, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	lease, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
		ID:       db.LockID{1},
		Duration: 30 * time.Minute,
	})

	require.NoError(t, err)
	require.Equal(t, tx.TxHash(), lease.OutPoint.Hash)
	require.Equal(t, uint32(0), lease.OutPoint.Index)
	require.Equal(t, db.LockID{1}, lease.LockID)
	require.True(t, lease.Expiration.After(time.Now().UTC()))
}

// TestLeaseOutputRejectsAlreadyLeasedUtxo verifies that LeaseOutput reports
// ErrOutputAlreadyLeased when another active lock already owns the same output.
func TestLeaseOutputRejectsAlreadyLeasedUtxo(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-lease-output-conflict")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 19000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710001710, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
		ID:       db.LockID{1},
		Duration: 30 * time.Minute,
	})
	require.NoError(t, err)

	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
		ID:       db.LockID{2},
		Duration: 30 * time.Minute,
	})
	require.ErrorIs(t, err, db.ErrOutputAlreadyLeased)
}

// TestLeaseOutputRejectsNonPositiveDuration verifies that LeaseOutput rejects a
// non-positive duration before it attempts any lease write.
func TestLeaseOutputRejectsNonPositiveDuration(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-lease-output-duration")

	_, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		OutPoint: randomOutPoint(),
		ID:       db.LockID{3},
		Duration: 0,
	})

	require.ErrorIs(t, err, db.ErrInvalidParam)
}

// TestReleaseOutputUnlocksMatchingLease verifies that ReleaseOutput removes the
// active lease when the caller presents the matching lock ID.
func TestReleaseOutputUnlocksMatchingLease(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-release-output")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 20000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710001900, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	leaseID := RandomHash()
	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
		Duration: time.Minute,
	})
	require.NoError(t, err)

	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
	})

	require.NoError(t, err)

	otherID := RandomHash()
	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       otherID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
		Duration: time.Minute,
	})
	require.NoError(t, err)
}

// TestReleaseOutputRejectsWrongLockID verifies that ReleaseOutput reports the
// public unlock error when another active lock still owns the output.
func TestReleaseOutputRejectsWrongLockID(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-release-conflict")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 21000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710002000, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	leaseID := RandomHash()
	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
		Duration: time.Minute,
	})
	require.NoError(t, err)

	wrongID := RandomHash()
	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       wrongID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
	})

	require.ErrorIs(t, err, db.ErrOutputUnlockNotAllowed)
}

// TestListLeasedOutputsReturnsActiveLeases verifies that ListLeasedOutputs
// returns the currently active wallet lease set.
func TestListLeasedOutputsReturnsActiveLeases(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-leases")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 22000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710002100, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	leaseID := RandomHash()
	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
		Duration: time.Minute,
	})
	require.NoError(t, err)

	leases, err := store.ListLeasedOutputs(t.Context(), walletID)

	require.NoError(t, err)
	require.Len(t, leases, 1)
	require.Equal(t, tx.TxHash(), leases[0].OutPoint.Hash)
	require.Equal(t, db.LockID(leaseID), leases[0].LockID)
}

// TestListLeasedOutputsExcludesReleasedLease verifies that ListLeasedOutputs
// reflects a successful release immediately.
func TestListLeasedOutputsExcludesReleasedLease(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-leases-after-release")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 23000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710002200, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	leaseID := RandomHash()
	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
		Duration: time.Minute,
	})
	require.NoError(t, err)

	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
	})
	require.NoError(t, err)

	leases, err := store.ListLeasedOutputs(t.Context(), walletID)

	require.NoError(t, err)
	require.Empty(t, leases)
}

// TestBalanceReturnsTotalAndLocked verifies that Balance returns the filtered
// total UTXO value together with the locked subset covered by active leases.
func TestBalanceReturnsTotalAndLocked(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-balance")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	txOne := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 24000, PkScript: addr.ScriptPubKey}},
	)
	txTwo := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 26000, PkScript: addr.ScriptPubKey}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txOne,
		Received: time.Unix(1710002300, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       txTwo,
		Received: time.Unix(1710002310, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	leaseID := RandomHash()
	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: wire.OutPoint{Hash: txOne.TxHash(), Index: 0},
		Duration: time.Minute,
	})
	require.NoError(t, err)

	balance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID: walletID,
	})

	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(50000), balance.Total)
	require.Equal(t, btcutil.Amount(24000), balance.Locked)
}

// TestBalanceNameFilterDisambiguatesImportedXpub verifies that the account-name
// balance filter isolates imported-xpub child rows even though the imported
// account does not expose a wallet-derived account number.
func TestBalanceNameFilterDisambiguatesImportedXpub(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWatchOnlyWallet(
		t, store, "wallet-balance-name-filter",
	)

	const (
		derivedName  = defaultAccountName
		importedName = hardwareAccountName
	)

	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, derivedName)
	CreateImportedAccount(
		t, store, walletID, db.KeyScopeBIP0084, importedName, true,
	)

	derivedAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, derivedName, false,
	)
	importedScript := RandomBytes(22)
	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
	importedAccountID := GetAccountID(t, queries, scopeID, importedName)
	err := createDerivedAddressRaw(
		t, queries, walletID, importedAccountID, 0, 0,
		importedScript,
	)
	require.NoError(t, err)

	block := CreateBlockFixture(t, queries, 280)
	derivedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 11000, PkScript: derivedAddr.ScriptPubKey}},
	)
	importedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 22000, PkScript: importedScript}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       derivedTx,
		Received: time.Unix(1710002320, 0),
		Block:    &block,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       importedTx,
		Received: time.Unix(1710002330, 0),
		Block:    &block,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	scope := db.KeyScopeBIP0084
	importedBalanceName := importedName
	balance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID: walletID,
		Scope:    &scope,
		Name:     &importedBalanceName,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(22000), balance.Total)

	derivedBalanceName := derivedName
	balance, err = store.Balance(t.Context(), db.BalanceParams{
		WalletID: walletID,
		Scope:    &scope,
		Name:     &derivedBalanceName,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(11000), balance.Total)
}

// newCoinbaseTx builds a simple coinbase fixture transaction.
func newCoinbaseTx(pkScript []byte) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: ^uint32(0)}})
	tx.AddTxOut(&wire.TxOut{Value: 5000, PkScript: pkScript})

	return tx
}

// newRegularTx builds a simple fixture transaction with the provided inputs and
// outputs.
func newRegularTx(inputs []wire.OutPoint, outputs []*wire.TxOut) *wire.MsgTx {
	tx := wire.NewMsgTx(2)

	for _, prevOut := range inputs {
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: prevOut})
	}

	for _, txOut := range outputs {
		tx.AddTxOut(txOut)
	}

	return tx
}

// randomOutPoint returns one fixture outpoint backed by a random hash.
func randomOutPoint() wire.OutPoint {
	return wire.OutPoint{Hash: RandomHash(), Index: 0}
}

// newMultisigScript builds a 1-of-2 bare-multisig output script and returns the
// first member's pubkey address, that member's own P2PK script, and the full
// multisig output script. The member script is what PayToAddrScript(memberAddr)
// yields and is what a wallet would register as an address; the multisig script
// is the on-chain output script, which is never a wallet address by itself.
func newMultisigScript(t *testing.T) (*address.AddressPubKey, []byte, []byte) {
	t.Helper()

	firstKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	secondKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	memberAddr, err := address.NewAddressPubKey(
		firstKey.PubKey().SerializeCompressed(),
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	memberScript, err := txscript.PayToAddrScript(memberAddr)
	require.NoError(t, err)

	builder := txscript.NewScriptBuilder()
	builder.AddInt64(1)
	builder.AddData(firstKey.PubKey().SerializeCompressed())
	builder.AddData(secondKey.PubKey().SerializeCompressed())
	builder.AddInt64(2)
	builder.AddOp(txscript.OP_CHECKMULTISIG)

	multiSigScript, err := builder.Script()
	require.NoError(t, err)

	return memberAddr, memberScript, multiSigScript
}

// txHashes returns transaction hashes in result order.
func txHashes(infos []db.TxInfo) []chainhash.Hash {
	hashes := make([]chainhash.Hash, 0, len(infos))
	for _, info := range infos {
		hashes = append(hashes, info.Hash)
	}

	return hashes
}

// txDetailHashes returns transaction-detail hashes in result order.
func txDetailHashes(infos []db.TxDetailInfo) []chainhash.Hash {
	hashes := make([]chainhash.Hash, 0, len(infos))
	for _, info := range infos {
		hashes = append(hashes, info.Hash)
	}

	return hashes
}

// TestListOutputsToWatchBareMultisigUsesOutputScript verifies that the recovery
// watch set reports the actual on-chain output script for a bare-multisig
// output the wallet partly owns, rather than the member address's own script.
//
// A bare-multisig output is credited to one of its member pubkey addresses, so
// the stored UTXO resolves to that member address. The member's own script
// (PayToAddrScript) differs from the full multisig output script. A rescan must
// watch the output script the chain actually carries, so ListOutputsToWatch
// must derive the watch script from the funding transaction's
// TxOut[output_index].PkScript, not from the credited address row. This locks
// in parity with the kvdb backend, whose credit walk records the on-chain
// output script.
//
// Without the fix, the query returns addresses.script_pub_key (the member's
// P2PK script), so the rescan would watch a script the multisig output never
// pays, and a recovered spend would be missed.
func TestListOutputsToWatchBareMultisigUsesOutputScript(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	// A script-only import (no private key) requires a watch-only wallet per
	// the ADR 0012 spendable-wallet invariant.
	walletID := newWatchOnlyWallet(t, store, "wallet-watch-bare-multisig")

	scope := db.KeyScopeBIP0084

	// memberScript is the member's own P2PK script (registered as the wallet
	// address); multiSigScript is the full on-chain output script, which is
	// never registered as an address.
	memberAddr, memberScript, multiSigScript := newMultisigScript(t)
	require.NotEqual(t, memberScript, multiSigScript)

	_, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:        walletID,
			Scope:           scope,
			AddressType:     db.RawPubKey,
			PubKey:          memberAddr.ScriptAddress(),
			ScriptPubKey:    memberScript,
			EncryptedScript: RandomBytes(48),
		},
	)
	require.NoError(t, err)

	// The funding transaction pays the bare-multisig output; Credits[0]
	// carries the resolved member address exactly as the publisher supplies
	// it after filtering ownership by the member script.
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: multiSigScript}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710004500, 0),
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: memberAddr},
	})
	require.NoError(t, err)

	utxos, err := store.ListOutputsToWatch(t.Context(), walletID)
	require.NoError(t, err)
	require.Len(t, utxos, 1)

	outPoint := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	require.Equal(t, outPoint, utxos[0].OutPoint)

	// The watch script must be the on-chain multisig output script, not the
	// member address's own script that the UTXO row resolves to.
	require.Equal(t, multiSigScript, utxos[0].PkScript)
	require.NotEqual(t, memberScript, utxos[0].PkScript)
}

// TestApplyTxBatchChildBeforeParent verifies that ApplyTxBatch records the
// parent->child spend edge even when the child transaction is listed before
// the in-batch parent whose output it spends. Each transaction claims its spent
// parent inputs by updating the parent credit's UTXO row, so a child applied
// before its parent would update no row and, finding no conflicting spend,
// silently drop the spend edge while still succeeding. ApplyTxBatch must apply
// the batch parents-first so the parent credit ends up marked spent regardless
// of caller order.
func TestApplyTxBatchChildBeforeParent(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-apply-tx-batch-child-first")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	parentAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	childAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	// The parent spends an external input and credits the wallet at output 0.
	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: parentAddr.ScriptPubKey}},
	)

	// The child spends the parent's wallet-owned output and credits the wallet
	// at its own output 0.
	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 6000, PkScript: childAddr.ScriptPubKey}},
	)

	// Deliberately list the child before its in-batch parent. A caller-order
	// apply would record the child first, drop its spend of the not-yet-stored
	// parent output, and leave the parent credit unspent.
	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{
			{
				WalletID: walletID,
				Tx:       childTx,
				Received: time.Unix(1710000180, 0),
				Status:   db.TxStatusPending,
				Credits:  map[uint32]address.Address{0: nil},
			},
			{
				WalletID: walletID,
				Tx:       parentTx,
				Received: time.Unix(1710000181, 0),
				Status:   db.TxStatusPending,
				Credits:  map[uint32]address.Address{0: nil},
			},
		},
	})
	require.NoError(t, err)

	// Both transactions are recorded.
	_, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     parentTx.TxHash(),
	})
	require.NoError(t, err)
	_, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)

	// The child's own credit is recorded as a wallet UTXO.
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: childTx.TxHash(), Index: 0,
	}))

	// The parent credit must be marked spent: the in-batch child's spend edge
	// was recorded even though the child was applied first. Without the
	// parents-first ordering this edge is silently dropped and the assertion
	// fails.
	require.True(t, walletUtxoSpent(t, store, walletID, wire.OutPoint{
		Hash: parentTx.TxHash(), Index: 0,
	}))
}

// TestApplyTxBatchResolvesCreditCandidates verifies ApplyTxBatch resolves
// notification credit candidates inside the batch write transaction before it
// records transaction credits.
func TestApplyTxBatchResolvesCreditCandidates(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWatchOnlyWallet(
		t, store, "wallet-apply-tx-batch-candidates",
	)

	memberAddr, memberScript, multiSigScript := newMultisigScript(t)
	_, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:        walletID,
			Scope:           db.KeyScopeBIP0084,
			AddressType:     db.RawPubKey,
			PubKey:          memberAddr.ScriptAddress(),
			ScriptPubKey:    memberScript,
			EncryptedScript: RandomBytes(48),
		},
	)
	require.NoError(t, err)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: multiSigScript}},
	)

	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000190, 0),
			Status:   db.TxStatusPending,
			CreditCandidates: map[uint32][]address.Address{
				0: {memberAddr},
			},
		}},
	})
	require.NoError(t, err)

	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: tx.TxHash(), Index: 0,
	}))
}

// TestApplyScanBatchChildBeforeParent verifies that ApplyScanBatch records the
// parent->child spend edge even when the child transaction is listed before the
// in-batch parent whose output it spends.
func TestApplyScanBatchChildBeforeParent(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-apply-scan-batch-child-first")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	parentAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	childAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: parentAddr.ScriptPubKey}},
	)
	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 6000, PkScript: childAddr.ScriptPubKey}},
	)
	block := NewBlockFixture(211)

	err := store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{
			{
				WalletID: walletID,
				Tx:       childTx,
				Received: time.Unix(1710000180, 0),
				Block:    &block,
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: nil},
			},
			{
				WalletID: walletID,
				Tx:       parentTx,
				Received: time.Unix(1710000181, 0),
				Block:    &block,
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: nil},
			},
		},
		SyncedBlocks: []db.Block{block},
	})
	require.NoError(t, err)

	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: childTx.TxHash(), Index: 0,
	}))
	require.True(t, walletUtxoSpent(t, store, walletID, wire.OutPoint{
		Hash: parentTx.TxHash(), Index: 0,
	}))
}

// TestApplyTxBatchStoresTxAndSyncTip verifies that a runtime batch can persist
// transaction history and advance the wallet sync tip atomically.
func TestApplyTxBatchStoresTxAndSyncTip(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-apply-tx-batch"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)
	syncedTo := NewBlockFixture(212)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000150, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		}},
		SyncedTo: &syncedTo,
	})
	require.NoError(t, err)

	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, txInfo.Status)
	require.Nil(t, txInfo.Block)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: tx.TxHash(), Index: 0,
	}))

	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.NotNil(t, walletInfo.SyncedTo)
	require.Equal(t, syncedTo.Hash, walletInfo.SyncedTo.Hash)
	require.Equal(t, syncedTo.Height, walletInfo.SyncedTo.Height)
	require.Equal(t, syncedTo.Timestamp.Unix(),
		walletInfo.SyncedTo.Timestamp.Unix())
}

// TestApplyTxBatchRejectsStaleDuplicateTx verifies that a duplicate batch
// observation is not skipped when the existing row is terminal history. A blind
// ErrTxAlreadyExists skip would leave the failed row in place while reporting a
// successful batch application.
func TestApplyTxBatchRejectsStaleDuplicateTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-apply-tx-batch-stale")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: RandomBytes(22)}},
	)
	params := db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000155, 0),
		Status:   db.TxStatusPending,
	}

	err := store.CreateTx(t.Context(), params)
	require.NoError(t, err)
	setTxStatus(t, store, walletID, tx.TxHash(), db.TxStatusFailed)

	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID:     walletID,
		Transactions: []db.CreateTxParams{params},
	})
	require.ErrorIs(t, err, db.ErrTxAlreadyExists)
}

// TestApplyTxBatchConfirmsTxInSameBlock verifies that a batch can record a
// transaction confirmed in the very block the same batch introduces as the new
// sync tip. The confirming block row does not exist before the batch, so the
// batch must create the sync-tip block before recording the confirmed
// transaction; otherwise the confirmed insert fails with ErrBlockNotFound.
func TestApplyTxBatchConfirmsTxInSameBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-apply-tx-batch-confirmed"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)

	// The confirming block is also the batch's new sync tip. It is not
	// inserted ahead of time, so the batch itself must create it before the
	// confirmed transaction is recorded.
	block := NewBlockFixture(213)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000160, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		}},
		SyncedTo: &block,
	})
	require.NoError(t, err)

	// The transaction is recorded as confirmed in the batch's block and its
	// credited output is in the wallet UTXO set.
	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, txInfo.Status)
	require.NotNil(t, txInfo.Block)
	require.Equal(t, block.Height, txInfo.Block.Height)
	require.Equal(t, block.Hash, txInfo.Block.Hash)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: tx.TxHash(), Index: 0,
	}))

	// The sync tip advanced to the same block.
	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.NotNil(t, walletInfo.SyncedTo)
	require.Equal(t, block.Height, walletInfo.SyncedTo.Height)
	require.Equal(t, block.Hash, walletInfo.SyncedTo.Hash)
}

// TestApplyTxBatchConfirmsTxBeforeSyncTip verifies that a batch can record a
// transaction confirmed before the same batch's final synced block. The
// transaction's confirming block row does not exist before the batch, so the
// batch must create it independently of the synced-to block.
func TestApplyTxBatchConfirmsTxBeforeSyncTip(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-apply-tx-batch-confirm-before-tip"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)

	block := NewBlockFixture(212)
	syncedTo := NewBlockFixture(213)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000160, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		}},
		SyncedTo: &syncedTo,
	})
	require.NoError(t, err)

	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, txInfo.Status)
	require.NotNil(t, txInfo.Block)
	require.Equal(t, block.Height, txInfo.Block.Height)
	require.Equal(t, block.Hash, txInfo.Block.Hash)

	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.NotNil(t, walletInfo.SyncedTo)
	require.Equal(t, syncedTo.Height, walletInfo.SyncedTo.Height)
	require.Equal(t, syncedTo.Hash, walletInfo.SyncedTo.Hash)
}

// TestApplyTxBatchConfirmsExistingTx verifies that ApplyTxBatch reconciles a
// pending transaction when the same transaction is later observed confirmed.
func TestApplyTxBatchConfirmsExistingTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-apply-tx-batch-confirm-existing"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000161, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		}},
	})
	require.NoError(t, err)

	block := NewBlockFixture(216)
	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000162, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		}},
		SyncedTo: &block,
	})
	require.NoError(t, err)

	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, txInfo.Status)
	require.NotNil(t, txInfo.Block)
	require.Equal(t, block.Height, txInfo.Block.Height)
	require.Equal(t, block.Hash, txInfo.Block.Hash)

	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.NotNil(t, walletInfo.SyncedTo)
	require.Equal(t, block.Height, walletInfo.SyncedTo.Height)
	require.Equal(t, block.Hash, walletInfo.SyncedTo.Hash)
}

// TestApplyTxBatchDuplicateUnminedKeepsConfirmed verifies that an unmined batch
// notification for an already-confirmed transaction is a no-op, matching the
// legacy kvdb behavior for rescan observations.
func TestApplyTxBatchDuplicateUnminedKeepsConfirmed(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-apply-tx-batch-unmined-dupe")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: RandomBytes(22)}},
	)
	block := NewBlockFixture(217)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000163, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
		}},
		SyncedTo: &block,
	})
	require.NoError(t, err)

	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000164, 0),
			Status:   db.TxStatusPending,
		}},
	})
	require.NoError(t, err)

	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, txInfo.Status)
	require.NotNil(t, txInfo.Block)
	require.Equal(t, block.Height, txInfo.Block.Height)
	require.Equal(t, block.Hash, txInfo.Block.Hash)
}

// TestApplyTxBatchDuplicateConfirmedChecksTimestamp verifies that an otherwise
// idempotent confirmed duplicate still validates the caller's block timestamp.
func TestApplyTxBatchDuplicateConfirmedChecksTimestamp(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-apply-tx-batch-ts-dupe")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: RandomBytes(22)}},
	)
	block := NewBlockFixture(218)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000165, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
		}},
		SyncedTo: &block,
	})
	require.NoError(t, err)

	mismatchedBlock := block
	mismatchedBlock.Timestamp = block.Timestamp.Add(time.Second)
	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000166, 0),
			Block:    &mismatchedBlock,
			Status:   db.TxStatusPublished,
		}},
	})
	require.ErrorIs(t, err, db.ErrBlockMismatch)
}

// TestApplyTxBatchRejectsDuplicateStateMismatch verifies that a non-idempotent
// duplicate does not let the batch advance the sync tip.
func TestApplyTxBatchRejectsDuplicateStateMismatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-apply-tx-batch-duplicate-mismatch"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)

	firstBlock := NewBlockFixture(217)
	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000163, 0),
			Block:    &firstBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		}},
		SyncedTo: &firstBlock,
	})
	require.NoError(t, err)

	secondBlock := NewBlockFixture(218)
	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000164, 0),
			Block:    &secondBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		}},
		SyncedTo: &secondBlock,
	})
	require.ErrorIs(t, err, db.ErrTxAlreadyExists)

	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, txInfo.Status)
	require.NotNil(t, txInfo.Block)
	require.Equal(t, firstBlock.Height, txInfo.Block.Height)
	require.Equal(t, firstBlock.Hash, txInfo.Block.Hash)

	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.NotNil(t, walletInfo.SyncedTo)
	require.Equal(t, firstBlock.Height, walletInfo.SyncedTo.Height)
	require.Equal(t, firstBlock.Hash, walletInfo.SyncedTo.Hash)
}

// TestApplyTxBatchRejectsDuplicateLabelMismatch verifies that a duplicate batch
// transaction must match the stored label before it can be treated as an
// idempotent replay. The rejected duplicate must not advance the batch sync
// tip.
func TestApplyTxBatchRejectsDuplicateLabelMismatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-apply-tx-batch-duplicate-label"
	walletID := newWallet(t, store, walletName)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: RandomBytes(22)}},
	)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000165, 0),
			Status:   db.TxStatusPending,
			Label:    "original",
		}},
	})
	require.NoError(t, err)

	block := NewBlockFixture(219)
	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000166, 0),
			Status:   db.TxStatusPending,
			Label:    "mutated",
		}},
		SyncedTo: &block,
	})
	require.ErrorIs(t, err, db.ErrTxAlreadyExists)

	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, "original", txInfo.Label)
	require.Equal(t, db.TxStatusPending, txInfo.Status)
	require.Nil(t, txInfo.Block)

	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.Nil(t, walletInfo.SyncedTo)
}

// TestApplyTxBatchRejectsMismatchedWalletID verifies that a batch is rejected
// when any transaction is owned by a wallet other than the batch wallet, and
// that the rejection commits nothing: the sync tip is not advanced and no
// transaction row is written.
func TestApplyTxBatchRejectsMismatchedWalletID(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-apply-tx-batch-mismatch"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)
	syncedTo := NewBlockFixture(214)

	// The batch targets walletID, but the lone transaction claims a different
	// wallet. The whole batch must be rejected before any write.
	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID + 99,
			Tx:       tx,
			Received: time.Unix(1710000170, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		}},
		SyncedTo: &syncedTo,
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)

	// The sync tip was not advanced: the wallet is still unsynced.
	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.Nil(t, walletInfo.SyncedTo)

	// No transaction row was written for either wallet.
	_, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestApplyTxBatchRejectsNilTx verifies that a multi-transaction batch with one
// nil Tx is rejected with ErrInvalidParam rather than panicking. ApplyTxBatch
// reorders the batch parents-first before applying it, and that sort
// dereferences each transaction's Tx, so a nil member must be caught up front;
// the rejection must also commit nothing.
func TestApplyTxBatchRejectsNilTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-apply-tx-batch-nil-tx"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)
	syncedTo := NewBlockFixture(215)

	// The batch carries a valid transaction and a second one with a nil Tx.
	// The parents-first sort runs before per-tx request validation, so the nil
	// member must be rejected by the up-front guard rather than panicking.
	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{
			{
				WalletID: walletID,
				Tx:       tx,
				Received: time.Unix(1710000210, 0),
				Status:   db.TxStatusPending,
				Credits:  map[uint32]address.Address{0: nil},
			},
			{
				WalletID: walletID,
				Tx:       nil,
				Received: time.Unix(1710000211, 0),
				Status:   db.TxStatusPending,
			},
		},
		SyncedTo: &syncedTo,
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)

	// The sync tip was not advanced and the valid transaction was not written:
	// the whole batch is rejected before any write.
	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.Nil(t, walletInfo.SyncedTo)

	_, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestApplyScanBatchConfirmsTxInNewBlock verifies that a scan batch can record
// relevant transactions confirmed in blocks the same batch newly connects. The
// confirming block rows do not exist before the batch, so the batch must
// connect the synced blocks before recording the confirmed transactions;
// otherwise the confirmed inserts fail with ErrBlockNotFound.
func TestApplyScanBatchConfirmsTxInNewBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-apply-scan-batch-confirmed"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addrEarly := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	addrLate := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	// Two newly discovered synced blocks, neither inserted ahead of time.
	earlyBlock := NewBlockFixture(220)
	lateBlock := NewBlockFixture(221)

	// One relevant transaction confirmed in each newly synced block.
	earlyTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 6000, PkScript: addrEarly.ScriptPubKey}},
	)
	lateTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 9000, PkScript: addrLate.ScriptPubKey}},
	)

	err := store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       earlyTx,
			Received: time.Unix(1710000400, 0),
			Block:    &earlyBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		}, {
			WalletID: walletID,
			Tx:       lateTx,
			Received: time.Unix(1710000500, 0),
			Block:    &lateBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		}},
		SyncedBlocks: []db.Block{earlyBlock, lateBlock},
	})
	require.NoError(t, err)

	// Both transactions are recorded as confirmed in their respective newly
	// connected blocks, with their credited outputs in the UTXO set.
	earlyInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     earlyTx.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, earlyInfo.Block)
	require.Equal(t, earlyBlock.Height, earlyInfo.Block.Height)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: earlyTx.TxHash(), Index: 0,
	}))

	lateInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     lateTx.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, lateInfo.Block)
	require.Equal(t, lateBlock.Height, lateInfo.Block.Height)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: lateTx.TxHash(), Index: 0,
	}))

	// The sync tip advanced to the final synced block.
	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.NotNil(t, walletInfo.SyncedTo)
	require.Equal(t, lateBlock.Height, walletInfo.SyncedTo.Height)
	require.Equal(t, lateBlock.Hash, walletInfo.SyncedTo.Hash)
}

// TestApplyScanBatchRejectsMismatchedWalletID verifies that a scan batch is
// rejected when any transaction is owned by a wallet other than the batch
// wallet, and that the rejection commits nothing: the synced block is not
// connected, the sync tip is not advanced, and no transaction row is written.
func TestApplyScanBatchRejectsMismatchedWalletID(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-apply-scan-batch-mismatch"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)
	syncedBlock := NewBlockFixture(222)

	// The batch targets walletID and carries a synced block, but the lone
	// transaction claims a different wallet. The whole batch must be rejected
	// before any synced-block or transaction write.
	err := store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID + 99,
			Tx:       tx,
			Received: time.Unix(1710000600, 0),
			Block:    &syncedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		}},
		SyncedBlocks: []db.Block{syncedBlock},
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)

	// The synced block was not connected: the wallet sync tip is unchanged.
	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.Nil(t, walletInfo.SyncedTo)

	// No transaction row was written for either wallet.
	_, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestApplyTxBatchConfirmed verifies that a runtime batch can record a
// transaction confirmed in a block that did not exist before the batch, even
// when the batch carries no sync-tip update (SyncedTo is nil). This is the
// standalone relevant-tx notification path: applyBatchTransaction must ensure
// the confirming block row exists before CreateTxWithOps validates it,
// otherwise the confirmed insert fails with ErrBlockNotFound. The wallet sync
// tip must not advance, because only the sync-tip update path may move it.
func TestApplyTxBatchConfirmed(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletName := "wallet-apply-tx-batch-confirmed-no-tip"
	walletID := newWallet(t, store, walletName)
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)

	// The confirming block does not exist before the batch and the batch
	// carries no sync-tip update, so the transaction path itself must create
	// the block row.
	block := NewBlockFixture(214)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: walletID,
		Transactions: []db.CreateTxParams{{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000170, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		}},
	})
	require.NoError(t, err)

	// The transaction is recorded as confirmed in the batch's block with its
	// credited output in the wallet UTXO set.
	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, txInfo.Status)
	require.NotNil(t, txInfo.Block)
	require.Equal(t, block.Height, txInfo.Block.Height)
	require.Equal(t, block.Hash, txInfo.Block.Hash)
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: tx.TxHash(), Index: 0,
	}))

	// The wallet sync tip must not have advanced: a standalone confirmed
	// notification ensures only the tx's own block row, never the sync tip.
	walletInfo, err := store.GetWallet(t.Context(), walletName)
	require.NoError(t, err)
	require.Nil(t, walletInfo.SyncedTo)
}

// TestApplyTxBatchDuplicate verifies that a duplicate batch transaction whose
// stored row shape matches the new observation does not silently skip while
// leaving wallet-owned edges unrecorded. CreateTxWithOps returns
// ErrTxAlreadyExists before writing credits or marking wallet-input spends, so
// a duplicate that newly carries a credit or a wallet-input spend must replay
// those edges. An exact duplicate that already has every edge may still be
// skipped without error.
func TestApplyTxBatchDuplicate(t *testing.T) {
	t.Parallel()

	t.Run("later credit is recorded", func(t *testing.T) {
		t.Parallel()

		// Arrange: Insert the tx row first with no credits, so the wallet
		// owns no output for it yet.
		store := NewTestStore(t)
		walletID := newWallet(t, store, "wallet-dup-later-credit")
		createDerivedAccount(
			t, store, walletID, db.KeyScopeBIP0084, "default",
		)

		addr := newDerivedAddress(
			t, store, walletID, db.KeyScopeBIP0084, "default", false,
		)
		tx := newRegularTx(
			[]wire.OutPoint{randomOutPoint()},
			[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
		)

		err := store.CreateTx(t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000180, 0),
			Status:   db.TxStatusPending,
		})
		require.NoError(t, err)

		creditOutPoint := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
		require.False(
			t, walletUtxoExists(t, store, walletID, creditOutPoint),
		)

		// Act: Re-observe the same tx through a batch that now carries the
		// wallet credit. The stored row shape matches, so the old skip path
		// would drop the credit.
		err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
			WalletID: walletID,
			Transactions: []db.CreateTxParams{{
				WalletID: walletID,
				Tx:       tx,
				Received: time.Unix(1710000180, 0),
				Status:   db.TxStatusPending,
				Credits:  map[uint32]address.Address{0: nil},
			}},
		})
		require.NoError(t, err)

		// Assert: The duplicate batch recorded the previously missing credit.
		require.True(
			t, walletUtxoExists(t, store, walletID, creditOutPoint),
		)
	})

	t.Run("later wallet-input spend is recorded", func(t *testing.T) {
		t.Parallel()

		// Arrange: Record the child tx first while the parent output it
		// spends is not yet wallet-owned, so no spend edge is created.
		store := NewTestStore(t)
		walletID := newWallet(t, store, "wallet-dup-later-spend")
		createDerivedAccount(
			t, store, walletID, db.KeyScopeBIP0084, "default",
		)

		addr := newDerivedAddress(
			t, store, walletID, db.KeyScopeBIP0084, "default", false,
		)

		// Build the parent funding tx first so its hash is known, then have
		// the child spend the parent's output 0. The parent is not recorded
		// yet, so when the child is created its input is not wallet-owned and
		// no spend edge is written.
		parentTx := newRegularTx(
			[]wire.OutPoint{randomOutPoint()},
			[]*wire.TxOut{{Value: 9000, PkScript: addr.ScriptPubKey}},
		)
		parentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
		childTx := newRegularTx(
			[]wire.OutPoint{parentOutPoint},
			[]*wire.TxOut{{Value: 4000, PkScript: RandomBytes(22)}},
		)
		childParams := db.CreateTxParams{
			WalletID: walletID,
			Tx:       childTx,
			Received: time.Unix(1710000190, 0),
			Status:   db.TxStatusPending,
		}
		err := store.CreateTx(t.Context(), childParams)
		require.NoError(t, err)

		// Now record the parent funding tx with a wallet credit at output 0.
		err = store.CreateTx(t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       parentTx,
			Received: time.Unix(1710000191, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		})
		require.NoError(t, err)
		require.True(t, walletUtxoSpent(t, store, walletID, parentOutPoint))

		// Creating the parent credit reconciles the already-stored child. Clear
		// the edge directly to model a partially replayed duplicate where the
		// child row exists but its spend edge is still missing.
		clearUtxosSpentByTxID(t, store, walletID, childTx.TxHash())
		require.False(t, walletUtxoSpent(t, store, walletID, parentOutPoint))

		// Act: Re-observe the child through a batch. The stored row matches,
		// so the old skip path would leave the now-wallet-owned parent
		// unspent.
		err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
			WalletID:     walletID,
			Transactions: []db.CreateTxParams{childParams},
		})
		require.NoError(t, err)

		// Assert: The parent output is now spent by the child. A competing
		// transaction spending the same parent output must therefore be
		// rejected as a conflict, which only holds once the spend edge from
		// the replayed child exists.
		conflictTx := newRegularTx(
			[]wire.OutPoint{parentOutPoint},
			[]*wire.TxOut{{Value: 3000, PkScript: RandomBytes(22)}},
		)
		err = store.CreateTx(t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       conflictTx,
			Received: time.Unix(1710000192, 0),
			Status:   db.TxStatusPending,
		})
		require.ErrorIs(t, err, db.ErrTxInputConflict)
	})

	t.Run("exact duplicate may skip", func(t *testing.T) {
		t.Parallel()

		// Arrange: Record the tx with its wallet credit already present.
		store := NewTestStore(t)
		walletID := newWallet(t, store, "wallet-dup-exact")
		createDerivedAccount(
			t, store, walletID, db.KeyScopeBIP0084, "default",
		)

		addr := newDerivedAddress(
			t, store, walletID, db.KeyScopeBIP0084, "default", false,
		)
		tx := newRegularTx(
			[]wire.OutPoint{randomOutPoint()},
			[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
		)
		params := db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000200, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		}
		err := store.CreateTx(t.Context(), params)
		require.NoError(t, err)

		creditOutPoint := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
		require.True(
			t, walletUtxoExists(t, store, walletID, creditOutPoint),
		)

		// Act: Re-observe the identical tx through a batch.
		err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
			WalletID:     walletID,
			Transactions: []db.CreateTxParams{params},
		})

		// Assert: The exact duplicate is accepted and the credit is still
		// present exactly once.
		require.NoError(t, err)
		require.True(
			t, walletUtxoExists(t, store, walletID, creditOutPoint),
		)
	})
}
