package wallet

import (
	"bytes"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
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

// sqlPsbtAccount creates a spendable SQL account in a custom scope and returns
// its BIP44 number. A custom scope needs an explicit schema and account
// number, as lnd's key families have.
func sqlPsbtAccount(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	name string) uint32 {

	t.Helper()

	addrType := waddrmgr.WitnessPubKey
	if scope.Purpose == 86 {
		addrType = waddrmgr.TaprootPubKey
	}

	number := AccountNumber(6)
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

// TestSQLSignPsbtEcdsaEffectiveKey verifies SQL SignPsbt for lnd-shaped ECDSA
// inputs. For BIP-84 and lnd's purpose-1017 scope, P2WKH, P2WSH and nested
// outputs pay the wallet key under no tweak and lnd's single, revocation and
// combined tweaks. The vault signs, the record names the tweaked key and
// spends the input, the base derivation is kept, a second pass changes
// nothing, and no private key is decrypted for Wallet code.
func TestSQLSignPsbtEcdsaEffectiveKey(t *testing.T) {
	t.Parallel()

	// Arrange: Create one wallet with accounts in both scopes.
	w, spy := newSQLSignerWallet(t)
	accounts := map[waddrmgr.KeyScope]uint32{
		testnetP2WKHScope: sqlPsbtAccount(
			t, w, testnetP2WKHScope, "psbt",
		),
		lndKeyScope: sqlPsbtAccount(t, w, lndKeyScope, "lnd"),
	}
	decrypts := spy.privateDecrypts.Load()

	forms := []struct {
		name   string
		form   testEcdsaForm
		nested bool
	}{
		{name: "p2wpkh", form: testKeyHashForm},
		{name: "p2wsh", form: testWitnessScriptForm},
		{name: "np2wpkh", form: testKeyHashForm, nested: true},
	}

	for scope, account := range accounts {
		basePub, path := sqlPsbtBaseKey(t, w, scope, account, 0)

		for _, form := range forms {
			for _, tc := range testLndTweaks(t, basePub) {
				name := form.name + " " + tc.name

				// Arrange: Pay the tweaked key in the form.
				key := testTweakedKey(t, tc.tweak, basePub).
					SerializeCompressed()

				var pkScript, witnessScript []byte
				if form.form == testKeyHashForm {
					pkScript = testScript(
						t, txscript.OP_0, address.Hash160(key),
					)
				} else {
					witnessScript = testScript(
						t, key, txscript.OP_CHECKSIG,
					)
					pkScript = testP2WSHScript(t, witnessScript)
				}

				var redeemScript, sigScript []byte
				if form.nested {
					redeemScript = pkScript
					pkScript = testP2SHScript(t, redeemScript)
					sigScript = testScript(t, redeemScript)
				}

				packet, _, _ := testAuthPacket(
					t, &wire.TxOut{Value: 1000, PkScript: pkScript},
					txscript.SigHashAll,
				)
				packet.Inputs[0].RedeemScript = redeemScript
				packet.Inputs[0].WitnessScript = witnessScript
				packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
					PubKey:    basePub.SerializeCompressed(),
					Bip32Path: path,
				}}
				derivations := clonePacket(packet).Inputs[0].
					Bip32Derivation

				params := &SignPsbtParams{
					Packet:      packet,
					InputTweaks: map[int]KeyTweak{0: tc.tweak},
				}

				// Act: Sign the packet twice.
				first, err := w.SignPsbt(t.Context(), params)
				require.NoError(t, err, name)

				signed := clonePacket(packet)

				second, err := w.SignPsbt(t.Context(), params)
				require.NoError(t, err, name)

				// Assert: One record under the tweaked key spends
				// the input, and the second pass is a no-op.
				require.Equal(t, []uint32{0}, first.SignedInputs, name)

				records := packet.Inputs[0].PartialSigs
				require.Len(t, records, 1, name)
				require.Equal(t, key, records[0].PubKey, name)

				sig := records[0].Signature

				witness := wire.TxWitness{sig, key}
				if form.form == testWitnessScriptForm {
					witness = wire.TxWitness{sig, witnessScript}
				}

				requireInputSpends(t, packet, 0, sigScript, witness)
				require.Equal(
					t, derivations, packet.Inputs[0].Bip32Derivation,
				)
				require.Empty(t, second.SignedInputs, name)
				require.Equal(t, signed, packet, name)
			}
		}
	}

	require.Equal(t, decrypts, spy.privateDecrypts.Load())
}

// sqlParityIndices returns indices of account keys in scope with an even and
// an odd Y coordinate.
func sqlParityIndices(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	account uint32) (uint32, uint32) {

	t.Helper()

	var even, odd *uint32
	for index := uint32(0); even == nil || odd == nil; index++ {
		require.Less(t, index, uint32(64))

		key, _ := sqlPsbtBaseKey(t, w, scope, account, index)
		if key.SerializeCompressed()[0] == 0x03 {
			if odd == nil {
				odd = &index
			}

			continue
		}

		if even == nil {
			even = &index
		}
	}

	return *even, *odd
}

// TestSQLSignPsbtTaprootEffectiveKey verifies SQL SignPsbt for Taproot inputs
// with base keys of both Y parities, under no tweak and lnd's tweaks. Key-path
// outputs commit to the tweaked internal key with and without a script root,
// and script-path outputs check the tweaked key in a leaf. The vault applies
// the Lightning tweak, then the BIP-341 tweak on the key path only, and every
// record spends its input once.
func TestSQLSignPsbtTaprootEffectiveKey(t *testing.T) {
	t.Parallel()

	// Arrange: Create a BIP-86 account and find keys of both parities.
	w, spy := newSQLSignerWallet(t)
	account := sqlPsbtAccount(t, w, testnetP2TRScope, "taproot")
	even, odd := sqlParityIndices(t, w, testnetP2TRScope, account)
	decrypts := spy.privateDecrypts.Load()

	tests := []struct {
		name       string
		index      uint32
		scriptPath bool
		merkleRoot []byte
		sigHash    txscript.SigHashType
	}{
		{name: "key path even", index: even},
		{name: "key path odd", index: odd},
		{
			name: "key path odd with root", index: odd,
			merkleRoot: bytes.Repeat([]byte{0x05}, 32),
		},
		{
			name: "key path odd sighash all", index: odd,
			sigHash: txscript.SigHashAll,
		},
		{name: "script path even", index: even, scriptPath: true},
		{
			name: "script path odd sighash all", index: odd,
			scriptPath: true, sigHash: txscript.SigHashAll,
		},
	}

	for _, tc := range tests {
		basePub, path := sqlPsbtBaseKey(
			t, w, testnetP2TRScope, account, tc.index,
		)

		for _, tw := range testLndTweaks(t, basePub) {
			name := tc.name + " " + tw.name

			// Arrange: Pay the tweaked key on the requested path.
			key := testTweakedKey(t, tw.tweak, basePub)
			xOnlyKey := schnorr.SerializePubKey(key)

			var (
				utxo       *wire.TxOut
				leafScript *psbt.TaprootTapLeafScript
				script     []byte
			)
			if tc.scriptPath {
				script = testScript(t, xOnlyKey, txscript.OP_CHECKSIG)
				utxo, _, leafScript = testOneLeafOutput(
					t, testAuthKeys(), txscript.BaseLeafVersion,
					script,
				)
			} else {
				pkScript, err := txscript.PayToTaprootScript(
					txscript.ComputeTaprootOutputKey(
						key, tc.merkleRoot,
					),
				)
				require.NoError(t, err)

				utxo = &wire.TxOut{Value: 1000, PkScript: pkScript}
			}

			packet := testTaprootSignPacket(t, utxo, leafScript)
			packet.Inputs[0].TaprootMerkleRoot = tc.merkleRoot
			packet.Inputs[0].SighashType = tc.sigHash

			derivation := packet.Inputs[0].TaprootBip32Derivation[0]
			derivation.XOnlyPubKey = schnorr.SerializePubKey(basePub)
			derivation.Bip32Path = path

			params := &SignPsbtParams{
				Packet:      packet,
				InputTweaks: map[int]KeyTweak{0: tw.tweak},
			}

			// Act: Sign the packet twice.
			first, err := w.SignPsbt(t.Context(), params)
			require.NoError(t, err, name)

			signed := clonePacket(packet)

			second, err := w.SignPsbt(t.Context(), params)
			require.NoError(t, err, name)

			// Assert: The record spends the input under the tweaked
			// key, and the second pass is a no-op.
			require.Equal(t, []uint32{0}, first.SignedInputs, name)

			pIn := packet.Inputs[0]
			witness := wire.TxWitness{pIn.TaprootKeySpendSig}

			if tc.scriptPath {
				records := pIn.TaprootScriptSpendSig
				require.Len(t, records, 1, name)
				require.Equal(t, xOnlyKey, records[0].XOnlyPubKey)

				sig := records[0].Signature
				if tc.sigHash != txscript.SigHashDefault {
					sig = append(slices.Clone(sig), byte(tc.sigHash))
				}

				witness = wire.TxWitness{
					sig, script, leafScript.ControlBlock,
				}
			}

			requireInputSpends(t, packet, 0, nil, witness)
			require.Empty(t, second.SignedInputs, name)
			require.Equal(t, signed, packet, name)
		}
	}

	require.Equal(t, decrypts, spy.privateDecrypts.Load())
}

// TestSQLSignPsbtRejectsRecordMismatch verifies that a PSBT record naming a
// key other than the wallet's key under the tweak fails with
// ErrSigningKeyMismatch, and that the vault is never asked to sign. The
// record's path is the wallet's, so only the key comparison can refuse it.
func TestSQLSignPsbtRejectsRecordMismatch(t *testing.T) {
	t.Parallel()

	// Arrange: Name a foreign key under the wallet's path in a P2WSH
	// script that checks that foreign key.
	w, spy := newSQLSignerWallet(t)
	account := sqlPsbtAccount(t, w, testnetP2WKHScope, "psbt")
	_, path := sqlPsbtBaseKey(t, w, testnetP2WKHScope, account, 0)

	foreign, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	key := foreign.PubKey().SerializeCompressed()
	witnessScript := testScript(t, key, txscript.OP_CHECKSIG)
	packet, _, _ := testAuthPacket(
		t, &wire.TxOut{
			Value: 1000, PkScript: testP2WSHScript(t, witnessScript),
		}, txscript.SigHashAll,
	)
	packet.Inputs[0].WitnessScript = witnessScript
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey:    key,
		Bip32Path: path,
	}}

	// Act: Sign the packet.
	_, err = w.SignPsbt(t.Context(), &SignPsbtParams{Packet: packet})

	// Assert: The mismatch fails before any vault request.
	require.ErrorIs(t, err, ErrSigningKeyMismatch)
	require.Zero(t, spy.signDigests.Load())
	require.Empty(t, packet.Inputs[0].PartialSigs)
}

// TestSQLSignPsbtSkipsWatchOnlyAccount verifies that an input whose account
// the wallet does not have is skipped as another signer's input on SQL, as on
// the legacy path, without a vault signature.
func TestSQLSignPsbtSkipsWatchOnlyAccount(t *testing.T) {
	t.Parallel()

	// Arrange: Name a key at an account number the wallet lacks.
	w, spy := newSQLSignerWallet(t)
	foreign, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	key := foreign.PubKey().SerializeCompressed()
	packet, _, _ := testAuthPacket(
		t, &wire.TxOut{
			Value:    1000,
			PkScript: testScript(t, txscript.OP_0, address.Hash160(key)),
		}, txscript.SigHashAll,
	)
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey: key,
		Bip32Path: []uint32{
			hdkeychain.HardenedKeyStart + 84,
			hdkeychain.HardenedKeyStart + 1,
			hdkeychain.HardenedKeyStart + 77,
			0, 0,
		},
	}}

	// Act: Sign the packet.
	result, err := w.SignPsbt(t.Context(), &SignPsbtParams{Packet: packet})

	// Assert: The input is skipped and nothing is signed.
	require.NoError(t, err)
	require.Empty(t, result.SignedInputs)
	require.Zero(t, spy.signDigests.Load())
}
