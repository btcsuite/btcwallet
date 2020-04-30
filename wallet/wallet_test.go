package wallet

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"

	"github.com/btcsuite/btcutil"
)

var (
	TstSerializedTx, _ = hex.DecodeString("010000000114d9ff358894c486b4ae11c2a8cf7851b1df64c53d2e511278eff17c22fb7373000000008c493046022100995447baec31ee9f6d4ec0e05cb2a44f6b817a99d5f6de167d1c75354a946410022100c9ffc23b64d770b0e01e7ff4d25fbc2f1ca8091053078a247905c39fce3760b601410458b8e267add3c1e374cf40f1de02b59213a82e1d84c2b94096e22e2f09387009c96debe1d0bcb2356ffdcf65d2a83d4b34e72c62eccd8490dbf2110167783b2bffffffff0280969800000000001976a914479ed307831d0ac19ebc5f63de7d5f1a430ddb9d88ac38bfaa00000000001976a914dadf9e3484f28b385ddeaa6c575c0c0d18e9788a88ac00000000")
	TstTx, _           = btcutil.NewTxFromBytes(TstSerializedTx)
	TstTxHash          = TstTx.Hash()
)

// TestLocateBirthdayBlock ensures we can properly map a block in the chain to a
//timestamp.
func TestLocateBirthdayBlock(t *testing.T) {
	t.Parallel()

	// We'll use test chains of 30 blocks with a duration between two
	// consecutive blocks being slightly greater than the largest margin
	// allowed by locateBirthdayBlock. Doing so lets us test the method more
	// effectively as there is only one block within the chain that can map
	// to a timestamp (this does not apply to the first and last blocks,
	// which can map to many timestamps beyond either end of chain).
	const (
		numBlocks     = 30
		blockInterval = birthdayBlockDelta + 1
	)

	genesisTimestamp := chainParams.GenesisBlock.Header.Timestamp

	testCases := []struct {
		name           string
		birthday       time.Time
		birthdayHeight int32
	}{
		{
			name:           "left-right-left-left",
			birthday:       genesisTimestamp.Add(8 * blockInterval),
			birthdayHeight: 8,
		},
		{
			name:           "right-right-right-left",
			birthday:       genesisTimestamp.Add(27 * blockInterval),
			birthdayHeight: 27,
		},
		{
			name:           "before start height",
			birthday:       genesisTimestamp.Add(-blockInterval),
			birthdayHeight: 0,
		},
		{
			name:           "start height",
			birthday:       genesisTimestamp,
			birthdayHeight: 0,
		},
		{
			name:           "end height",
			birthday:       genesisTimestamp.Add(numBlocks * blockInterval),
			birthdayHeight: numBlocks - 1,
		},
		{
			name:           "after end height",
			birthday:       genesisTimestamp.Add(2 * numBlocks * blockInterval),
			birthdayHeight: numBlocks - 1,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			chainConn := createMockChainConn(
				chainParams.GenesisBlock, numBlocks, blockInterval,
			)
			birthdayBlock, err := locateBirthdayBlock(
				chainConn, testCase.birthday,
			)
			if err != nil {
				t.Fatalf("unable to locate birthday block: %v",
					err)
			}
			if birthdayBlock.Height != testCase.birthdayHeight {
				t.Fatalf("expected birthday block with height "+
					"%d, got %d", testCase.birthdayHeight,
					birthdayBlock.Height)
			}
		})
		if !success {
			break
		}
	}
}

// TestLabelTransaction tests labelling of transactions with invalid labels,
// and failure to label a transaction when it already has a label.
func TestLabelTransaction(t *testing.T) {
	tests := []struct {
		name string

		// Whether the transaction should be known to the wallet.
		txKnown bool

		// Whether the test should write an existing label to disk.
		existingLabel bool

		// The overwrite parameter to call label transaction with.
		overwrite bool

		// The error we expect to be returned.
		expectedErr error
	}{
		{
			name:          "existing label, not overwrite",
			txKnown:       true,
			existingLabel: true,
			overwrite:     false,
			expectedErr:   ErrTxLabelExists,
		},
		{
			name:          "existing label, overwritten",
			txKnown:       true,
			existingLabel: true,
			overwrite:     true,
			expectedErr:   nil,
		},
		{
			name:          "no prexisting label, ok",
			txKnown:       true,
			existingLabel: false,
			overwrite:     false,
			expectedErr:   nil,
		},
		{
			name:          "transaction unknown",
			txKnown:       false,
			existingLabel: false,
			overwrite:     false,
			expectedErr:   ErrUnknownTransaction,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			w, cleanup := testWallet(t)
			defer cleanup()

			// If the transaction should be known to the store, we
			// write txdetail to disk.
			if test.txKnown {
				rec, err := wtxmgr.NewTxRecord(
					TstSerializedTx, time.Now(),
				)
				if err != nil {
					t.Fatal(err)
				}

				err = walletdb.Update(w.db,
					func(tx walletdb.ReadWriteTx) error {

						ns := tx.ReadWriteBucket(
							wtxmgrNamespaceKey,
						)

						return w.TxStore.InsertTx(
							ns, rec, nil,
						)
					})
				if err != nil {
					t.Fatalf("could not insert tx: %v", err)
				}
			}

			// If we want to setup an existing label for the purpose
			// of the test, write one to disk.
			if test.existingLabel {
				err := w.LabelTransaction(
					*TstTxHash, "existing label", false,
				)
				if err != nil {
					t.Fatalf("could not write label: %v",
						err)
				}
			}

			newLabel := "new label"
			err := w.LabelTransaction(
				*TstTxHash, newLabel, test.overwrite,
			)
			if err != test.expectedErr {
				t.Fatalf("expected: %v, got: %v",
					test.expectedErr, err)
			}
		})
	}
}
