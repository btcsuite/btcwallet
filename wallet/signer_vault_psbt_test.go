package wallet

import (
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

var (
	// lndKeyScope is lnd's custom key scope, purpose 1017, on the test
	// network.
	lndKeyScope = waddrmgr.KeyScope{Purpose: 1017, Coin: 1}

	// testnetP2WKHScope and testnetP2TRScope are the BIP-84 and BIP-86
	// scopes with the test network coin type, which PSBT paths require.
	testnetP2WKHScope = waddrmgr.KeyScope{Purpose: 84, Coin: 1}
	testnetP2TRScope  = waddrmgr.KeyScope{Purpose: 86, Coin: 1}
)

// sqlPsbtAccountNumber is the BIP44 number of the spendable accounts the SQL
// PSBT tests create. It is above every scope's default account and the
// watch-only accounts the tests import, so it never collides with them.
const sqlPsbtAccountNumber = 6

// sqlPsbtAccount creates a spendable SQL account in scope, with addrType for
// both branches, and returns its BIP44 number. The explicit schema and account
// number also serve a custom scope, such as lnd's purpose-1017 scope, whose
// key families have both.
func sqlPsbtAccount(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	addrType waddrmgr.AddressType, name string) uint32 {

	t.Helper()

	number := AccountNumber(sqlPsbtAccountNumber)
	params := NewAccountParams{
		Scope:         scope,
		Name:          name,
		AccountNumber: &number,
		AddrSchema: &waddrmgr.ScopeAddrSchema{
			ExternalAddrType: addrType,
			InternalAddrType: addrType,
		},
	}

	info, err := w.NewAccount(t.Context(), params)
	require.NoError(t, err)
	require.NotNil(t, info.AccountNumber)

	return uint32(*info.AccountNumber)
}

// sqlPsbtBaseKey returns the wallet's public key at account/0/index in scope
// and the BIP32 path a PSBT record names it by.
func sqlPsbtBaseKey(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	account, index uint32) (*btcec.PublicKey, []uint32) {

	t.Helper()

	key, err := w.DerivePubKey(t.Context(), DerivePubKeyParams{
		Account: NewAccountSelectorByNumber(
			scope, AccountNumber(account),
		),
		Index: index,
	})
	require.NoError(t, err)

	return key, []uint32{
		hdkeychain.HardenedKeyStart + scope.Purpose,
		hdkeychain.HardenedKeyStart + scope.Coin,
		hdkeychain.HardenedKeyStart + account,
		0, index,
	}
}

// sqlPsbtHardenedKey creates a spendable SQL account in scope and returns its
// public key at the hardened index account/0/0' and the BIP32 path a PSBT
// record names it by. The key is read through DerivePrivKey, so callers must
// do this before they remove the unsafe vault.
func sqlPsbtHardenedKey(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	addrType waddrmgr.AddressType, name string) (*btcec.PublicKey,
	[]uint32) {

	t.Helper()

	const hardened = hdkeychain.HardenedKeyStart

	account := sqlPsbtAccount(t, w, scope, addrType, name)
	priv, err := w.DerivePrivKey(t.Context(), BIP32Path{
		KeyScope: scope,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: account,
			Index:           hardened,
		},
	})
	require.NoError(t, err)

	pub := priv.PubKey()
	priv.Zero()

	return pub, []uint32{
		hardened + scope.Purpose, hardened + scope.Coin,
		hardened + account, 0, hardened,
	}
}

// TestSQLSignPsbtTweakedHardenedKeys verifies SQL SignPsbt end to end with no
// unsafe vault attached, for lnd-shaped inputs that an account XPub cannot
// serve: keys at a hardened index under a revocation tweak, in a P2WSH script
// of lnd's purpose-1017 scope and on the BIP-86 Taproot key path with a script
// root. The record check, and the Taproot base key read while the input is
// planned, read each key through the vault, and the vault applies the tweak,
// then the BIP-341 tweak on the key path. Each record names the tweaked key
// and spends its input.
func TestSQLSignPsbtTweakedHardenedKeys(t *testing.T) {
	t.Parallel()

	// Arrange: Read hardened keys of an lnd-scope and a BIP-86 account,
	// then drop the unsafe vault.
	w := createSQLiteWallet(t, createTestChain(t))
	ecdsaPub, ecdsaPath := sqlPsbtHardenedKey(
		t, w, lndKeyScope, waddrmgr.WitnessPubKey, "hardened",
	)
	tapPub, tapPath := sqlPsbtHardenedKey(
		t, w, testnetP2TRScope, waddrmgr.TaprootPubKey,
		"hardened taproot",
	)
	w.unsafeVault = nil

	tweak := lndRevocationTweak(t)
	ecdsaKey := testTweakedKey(t, tweak, ecdsaPub).SerializeCompressed()
	tapKey := testTweakedKey(t, tweak, tapPub)
	root := sha256.Sum256([]byte("script root"))

	// Arrange: Pay the tweaked ECDSA key in a P2WSH script and the tweaked
	// Taproot key under the script root.
	witnessScript := testScript(t, ecdsaKey, txscript.OP_CHECKSIG)
	tapScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootOutputKey(tapKey, root[:]),
	)
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 2}})
	tx.AddTxOut(wire.NewTxOut(1_500, []byte{txscript.OP_TRUE}))
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	packet.Inputs[0].WitnessUtxo = wire.NewTxOut(
		1_000, testP2WSHScript(t, witnessScript),
	)
	packet.Inputs[0].WitnessScript = witnessScript
	packet.Inputs[0].SighashType = txscript.SigHashAll
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey: ecdsaPub.SerializeCompressed(), Bip32Path: ecdsaPath,
	}}
	tapIn := &packet.Inputs[1]
	tapIn.WitnessUtxo = wire.NewTxOut(1_000, tapScript)
	tapIn.TaprootMerkleRoot = root[:]
	tapIn.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
		XOnlyPubKey: schnorr.SerializePubKey(tapPub),
		Bip32Path:   tapPath,
	}}

	// Act: Sign the packet.
	result, err := w.SignPsbt(t.Context(), &SignPsbtParams{
		Packet:      packet,
		InputTweaks: map[int]KeyTweak{0: tweak, 1: tweak},
	})

	// Assert: Both inputs are signed, the ECDSA record names the tweaked
	// key, and both spend their outputs.
	require.NoError(t, err)
	require.Equal(t, []uint32{0, 1}, result.SignedInputs)

	sigs := packet.Inputs[0].PartialSigs
	require.Len(t, sigs, 1)
	require.Equal(t, ecdsaKey, sigs[0].PubKey)
	requireInputSpends(t, packet, 0, nil, wire.TxWitness{
		sigs[0].Signature, witnessScript,
	})
	requireInputSpends(t, packet, 1, nil, wire.TxWitness{
		packet.Inputs[1].TaprootKeySpendSig,
	})
}

// sqlPsbtWatchAccount imports a watch-only account in scope, with addrType
// for both branches, and returns its BIP44 number.
func sqlPsbtWatchAccount(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	addrType waddrmgr.AddressType) uint32 {

	t.Helper()

	xpub, _ := importAccountTestKey(t, scope.Purpose)
	info, err := w.ImportAccount(t.Context(), ImportAccountParams{
		Name: "watch only", Scope: &scope, XPub: xpub,
		AddrSchema: &waddrmgr.ScopeAddrSchema{
			ExternalAddrType: addrType,
			InternalAddrType: addrType,
		},
	}, false)
	require.NoError(t, err)
	require.NotNil(t, info.AccountNumber)

	return uint32(*info.AccountNumber)
}

// TestSQLSignPsbtSkipsWatchOnlyAccount verifies that a collaborator's inputs
// are skipped when their derivations name local watch-only accounts. A tweaked
// Taproot input is skipped too, although planning reads its base key before
// any record check. The wallet still signs its own input.
func TestSQLSignPsbtSkipsWatchOnlyAccount(t *testing.T) {
	t.Parallel()

	// Arrange: Import watch-only BIP-84 and BIP-86 accounts, and create a
	// spendable BIP-84 account.
	w := createSQLiteWallet(t, createTestChain(t))
	scope := testnetP2WKHScope
	watchECDSA := sqlPsbtWatchAccount(t, w, scope, waddrmgr.WitnessPubKey)
	watchTaproot := sqlPsbtWatchAccount(
		t, w, testnetP2TRScope, waddrmgr.TaprootPubKey,
	)
	_, watchPath := sqlPsbtBaseKey(t, w, scope, watchECDSA, 0)
	_, watchTapPath := sqlPsbtBaseKey(
		t, w, testnetP2TRScope, watchTaproot, 0,
	)
	account := sqlPsbtAccount(
		t, w, scope, waddrmgr.WitnessPubKey, "spendable",
	)
	local, path := sqlPsbtBaseKey(t, w, scope, account, 0)
	foreign, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	foreignPub := foreign.PubKey()
	foreign.Zero()

	tweak, err := NewAddTweak([32]byte{31: 7})
	require.NoError(t, err)

	w.unsafeVault = nil

	// Arrange: Spend the collaborator's P2WKH and tweaked Taproot outputs
	// under the watch-only paths, and the wallet's own P2WKH output.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 2}})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 3}})
	tx.AddTxOut(wire.NewTxOut(2_500, []byte{txscript.OP_TRUE}))
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	packet.Inputs[0].WitnessUtxo = wire.NewTxOut(
		1_000, testP2WPKHScript(t, foreignPub),
	)
	packet.Inputs[0].SighashType = txscript.SigHashAll
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey: foreignPub.SerializeCompressed(), Bip32Path: watchPath,
	}}
	tapIn := &packet.Inputs[1]
	tapIn.WitnessUtxo = testBip86Output(
		t, testTweakedKey(t, tweak, foreignPub),
	)
	tapIn.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
		XOnlyPubKey: schnorr.SerializePubKey(foreignPub),
		Bip32Path:   watchTapPath,
	}}
	packet.Inputs[2].WitnessUtxo = wire.NewTxOut(
		1_000, testP2WPKHScript(t, local),
	)
	packet.Inputs[2].SighashType = txscript.SigHashAll
	packet.Inputs[2].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey: local.SerializeCompressed(), Bip32Path: path,
	}}

	// Act: Sign the packet.
	result, err := w.SignPsbt(t.Context(), &SignPsbtParams{
		Packet:      packet,
		InputTweaks: map[int]KeyTweak{1: tweak},
	})

	// Assert: Only the wallet's own input is signed, and it spends.
	require.NoError(t, err)
	require.Equal(t, []uint32{2}, result.SignedInputs)
	require.Empty(t, packet.Inputs[0].PartialSigs)
	require.Empty(t, packet.Inputs[1].TaprootKeySpendSig)

	sigs := packet.Inputs[2].PartialSigs
	require.Len(t, sigs, 1)
	requireInputSpends(t, packet, 2, nil, wire.TxWitness{
		sigs[0].Signature, local.SerializeCompressed(),
	})
}
