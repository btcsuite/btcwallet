// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"github.com/roasbeef/btcwallet/chain"
	"github.com/roasbeef/btcwallet/waddrmgr"
	"github.com/roasbeef/btcwallet/walletdb"
	"github.com/roasbeef/btcwallet/wtxmgr"
)

// RescanProgressMsg reports the current progress made by a rescan for a
// set of wallet addresses.
type RescanProgressMsg struct {
	Addresses    []btcutil.Address
	Notification *chain.RescanProgress
}

// RescanFinishedMsg reports the addresses that were rescanned when a
// rescanfinished message was received rescanning a batch of addresses.
type RescanFinishedMsg struct {
	Addresses    []btcutil.Address
	Notification *chain.RescanFinished
}

// RescanJob is a job to be processed by the RescanManager.  The job includes
// a set of wallet addresses, a starting height to begin the rescan, and
// outpoints spendable by the addresses thought to be unspent.  After the
// rescan completes, the error result of the rescan RPC is sent on the Err
// channel.
type RescanJob struct {
	InitialSync bool
	Addrs       []btcutil.Address
	OutPoints   []*wire.OutPoint
	BlockStamp  waddrmgr.BlockStamp
	err         chan error
}

// rescanBatch is a collection of one or more RescanJobs that were merged
// together before a rescan is performed.
type rescanBatch struct {
	initialSync bool
	addrs       []btcutil.Address
	outpoints   []*wire.OutPoint
	bs          waddrmgr.BlockStamp
	errChans    []chan error
}

// SubmitRescan submits a RescanJob to the RescanManager.  A channel is
// returned with the final error of the rescan.  The channel is buffered
// and does not need to be read to prevent a deadlock.
func (w *Wallet) SubmitRescan(job *RescanJob) <-chan error {
	errChan := make(chan error, 1)
	job.err = errChan
	w.rescanAddJob <- job
	return errChan
}

// batch creates the rescanBatch for a single rescan job.
func (job *RescanJob) batch() *rescanBatch {
	return &rescanBatch{
		initialSync: job.InitialSync,
		addrs:       job.Addrs,
		outpoints:   job.OutPoints,
		bs:          job.BlockStamp,
		errChans:    []chan error{job.err},
	}
}

// merge merges the work from k into j, setting the starting height to
// the minimum of the two jobs.  This method does not check for
// duplicate addresses or outpoints.
func (b *rescanBatch) merge(job *RescanJob) {
	if job.InitialSync {
		b.initialSync = true
	}
	b.addrs = append(b.addrs, job.Addrs...)
	b.outpoints = append(b.outpoints, job.OutPoints...)
	if job.BlockStamp.Height < b.bs.Height {
		b.bs = job.BlockStamp
	}
	b.errChans = append(b.errChans, job.err)
}

// done iterates through all error channels, duplicating sending the error
// to inform callers that the rescan finished (or could not complete due
// to an error).
func (b *rescanBatch) done(err error) {
	for _, c := range b.errChans {
		c <- err
	}
}

// rescanBatchHandler handles incoming rescan request, serializing rescan
// submissions, and possibly batching many waiting requests together so they
// can be handled by a single rescan after the current one completes.
func (w *Wallet) rescanBatchHandler() {
	var curBatch, nextBatch *rescanBatch
	quit := w.quitChan()

out:
	for {
		select {
		case job := <-w.rescanAddJob:
			if curBatch == nil {
				// Set current batch as this job and send
				// request.
				curBatch = job.batch()
				w.rescanBatch <- curBatch
			} else {
				// Create next batch if it doesn't exist, or
				// merge the job.
				if nextBatch == nil {
					nextBatch = job.batch()
				} else {
					nextBatch.merge(job)
				}
			}

		case n := <-w.rescanNotifications:
			switch n := n.(type) {
			case *chain.RescanProgress:
				w.rescanProgress <- &RescanProgressMsg{
					Addresses:    curBatch.addrs,
					Notification: n,
				}

			case *chain.RescanFinished:
				if curBatch == nil {
					log.Warnf("Received rescan finished " +
						"notification but no rescan " +
						"currently running")
					continue
				}
				w.rescanFinished <- &RescanFinishedMsg{
					Addresses:    curBatch.addrs,
					Notification: n,
				}

				curBatch, nextBatch = nextBatch, nil

				if curBatch != nil {
					w.rescanBatch <- curBatch
				}

			default:
				// Unexpected message
				panic(n)
			}

		case <-quit:
			break out
		}
	}

	w.wg.Done()
}

// rescanProgressHandler handles notifications for partially and fully completed
// rescans by marking each rescanned address as partially or fully synced.
func (w *Wallet) rescanProgressHandler() {
	quit := w.quitChan()
out:
	for {
		// These can't be processed out of order since both chans are
		// unbuffured and are sent from same context (the batch
		// handler).
		select {
		case msg := <-w.rescanProgress:
			n := msg.Notification
			log.Infof("Rescanned through block %v (height %d)",
				n.Hash, n.Height)

			client := w.ChainClient()
			// Since btcd rescans don't send blockconnected
			// notifications, we need to cycle through all of the
			// rescanned blocks and write the hashes to the
			// database. Neutrino rescans do send the notifications,
			// which means this loop won't actually cycle.
			//
			// TODO(aakselrod): There's a race conditon here, which
			// happens when a reorg occurs between the
			// rescanProgress notification and the last GetBlockHash
			// call. The solution when using btcd is to make btcd
			// send blockconnected notifications with each block
			// the way Neutrino does, and get rid of the loop. The
			// other alternative is to check the final hash and,
			// if it doesn't match the original hash returned by
			// the notification, to roll back and restart the
			// rescan.
			log.Infof("Catching up block hashes to height %d, this"+
				" might take a while", n.Height)
			err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				startBlock := w.Manager.SyncedTo()
				for i := startBlock.Height + 1; i <= n.Height; i++ {
					hash, err := client.GetBlockHash(int64(i))
					if err != nil {
						return err
					}
					bs := waddrmgr.BlockStamp{
						Height: i,
						Hash:   *hash,
					}
					err = w.Manager.SetSyncedTo(ns, &bs)
					if err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				log.Errorf("Failed to update address manager "+
					"sync state for hash %v (height %d): %v",
					n.Hash, n.Height, err)
			}
			log.Info("Done catching up block hashes")

		case msg := <-w.rescanFinished:
			n := msg.Notification
			addrs := msg.Addresses
			noun := pickNoun(len(addrs), "address", "addresses")
			log.Infof("Finished rescan for %d %s (synced to block "+
				"%s, height %d)", len(addrs), noun, n.Hash,
				n.Height)

			client := w.ChainClient()
			// Since btcd rescans don't send blockconnected
			// notifications, we need to cycle through all of the
			// rescanned blocks and write the hashes to the
			// database. Neutrino rescans do send the notifications,
			// which means this loop won't actually cycle.
			//
			// TODO(aakselrod): There's a race conditon here, which
			// happens when a reorg occurs between the
			// rescanFinished notification and the last GetBlockHash
			// call. The solution when using btcd is to make btcd
			// send blockconnected notifications with each block
			// the way Neutrino does, and get rid of the loop. The
			// other alternative is to check the final hash and,
			// if it doesn't match the original hash returned by
			// the notification, to roll back and restart the
			// rescan.
			log.Infof("Catching up block hashes to height %d, this"+
				" might take a while", n.Height)
			err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				startBlock := w.Manager.SyncedTo()
				for i := startBlock.Height + 1; i <= n.Height; i++ {
					hash, err := client.GetBlockHash(int64(i))
					if err != nil {
						return err
					}
					bs := waddrmgr.BlockStamp{
						Height: i,
						Hash:   *hash,
					}
					err = w.Manager.SetSyncedTo(ns, &bs)
					if err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				log.Errorf("Failed to update address manager "+
					"sync state for hash %v (height %d): %v",
					n.Hash, n.Height, err)
				continue
			}

			w.SetChainSynced(true)
			log.Info("Done catching up block hashes")
			go w.resendUnminedTxs()

		case <-quit:
			break out
		}
	}
	w.wg.Done()
}

// rescanRPCHandler reads batch jobs sent by rescanBatchHandler and sends the
// RPC requests to perform a rescan.  New jobs are not read until a rescan
// finishes.
func (w *Wallet) rescanRPCHandler() {
	chainClient, err := w.requireChainClient()
	if err != nil {
		log.Errorf("rescanRPCHandler called without an RPC client")
		w.wg.Done()
		return
	}

	quit := w.quitChan()

out:
	for {
		select {
		case batch := <-w.rescanBatch:
			// Log the newly-started rescan.
			numAddrs := len(batch.addrs)
			noun := pickNoun(numAddrs, "address", "addresses")
			log.Infof("Started rescan from block %v (height %d) for %d %s",
				batch.bs.Hash, batch.bs.Height, numAddrs, noun)

			err := chainClient.Rescan(&batch.bs.Hash, batch.addrs,
				batch.outpoints)
			if err != nil {
				log.Errorf("Rescan for %d %s failed: %v", numAddrs,
					noun, err)
			}
			batch.done(err)
		case <-quit:
			break out
		}
	}

	w.wg.Done()
}

// Rescan begins a rescan for all active addresses and unspent outputs of
// a wallet.  This is intended to be used to sync a wallet back up to the
// current best block in the main chain, and is considered an initial sync
// rescan.
func (w *Wallet) Rescan(addrs []btcutil.Address, unspent []wtxmgr.Credit) error {
	outpoints := make([]*wire.OutPoint, len(unspent))
	for i, output := range unspent {
		outpoints[i] = &output.OutPoint
	}

	job := &RescanJob{
		InitialSync: true,
		Addrs:       addrs,
		OutPoints:   outpoints,
		BlockStamp:  w.Manager.SyncedTo(),
	}

	// Submit merged job and block until rescan completes.
	return <-w.SubmitRescan(job)
}
