package wallet

import (
	"fmt"

	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// ImportPrivateKey imports a private key to the wallet and writes the new
// wallet to disk.
//
// NOTE: If a block stamp is not provided, then the wallet's birthday will be
// set to the genesis block of the corresponding chain.
func (w *Wallet) ImportPrivateKey(scope waddrmgr.KeyScope, wif *btcutil.WIF,
	bs *waddrmgr.BlockStamp, rescan bool) (string, error) {

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return "", err
	}

	// The starting block for the key is the genesis block unless otherwise
	// specified.
	if bs == nil {
		bs = &waddrmgr.BlockStamp{
			Hash:      *w.chainParams.GenesisHash,
			Height:    0,
			Timestamp: w.chainParams.GenesisBlock.Header.Timestamp,
		}
	} else if bs.Timestamp.IsZero() {
		// Only update the new birthday time from default value if we
		// actually have timestamp info in the header.
		header, err := w.chainClient.GetBlockHeader(&bs.Hash)
		if err == nil {
			bs.Timestamp = header.Timestamp
		}
	}

	// Attempt to import private key into wallet.
	var addr btcutil.Address
	var props *waddrmgr.AccountProperties
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		maddr, err := manager.ImportPrivateKey(addrmgrNs, wif, bs)
		if err != nil {
			return err
		}
		addr = maddr.Address()
		props, err = manager.AccountProperties(
			addrmgrNs, waddrmgr.ImportedAddrAccount,
		)
		if err != nil {
			return err
		}

		// We'll only update our birthday with the new one if it is
		// before our current one. Otherwise, if we do, we can
		// potentially miss detecting relevant chain events that
		// occurred between them while rescanning.
		birthdayBlock, _, err := w.Manager.BirthdayBlock(addrmgrNs)
		if err != nil {
			return err
		}
		if bs.Height >= birthdayBlock.Height {
			return nil
		}

		err = w.Manager.SetBirthday(addrmgrNs, bs.Timestamp)
		if err != nil {
			return err
		}

		// To ensure this birthday block is correct, we'll mark it as
		// unverified to prompt a sanity check at the next restart to
		// ensure it is correct as it was provided by the caller.
		return w.Manager.SetBirthdayBlock(addrmgrNs, *bs, false)
	})
	if err != nil {
		return "", err
	}

	// Rescan blockchain for transactions with txout scripts paying to the
	// imported address.
	if rescan {
		job := &RescanJob{
			Addrs:      []btcutil.Address{addr},
			OutPoints:  nil,
			BlockStamp: *bs,
		}

		// Submit rescan job and log when the import has completed.
		// Do not block on finishing the rescan.  The rescan success
		// or failure is logged elsewhere, and the channel is not
		// required to be read, so discard the return value.
		_ = w.SubmitRescan(job)
	} else {
		err := w.chainClient.NotifyReceived([]btcutil.Address{addr})
		if err != nil {
			return "", fmt.Errorf("Failed to subscribe for address ntfns for "+
				"address %s: %s", addr.EncodeAddress(), err)
		}
	}

	addrStr := addr.EncodeAddress()
	log.Infof("Imported payment address %s", addrStr)

	w.NtfnServer.notifyAccountProperties(props)

	// Return the payment address string of the imported private key.
	return addrStr, nil
}
