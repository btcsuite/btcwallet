/*
 * Copyright (c) 2013, 2014 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/legacy/keystore"
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
	Addresses      []btcutil.Address
	Notification   *chain.RescanFinished
	WasInitialSync bool
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
	BlockStamp  keystore.BlockStamp
	err         chan error
}

// rescanBatch is a collection of one or more RescanJobs that were merged
// together before a rescan is performed.
type rescanBatch struct {
	initialSync bool
	addrs       []btcutil.Address
	outpoints   []*wire.OutPoint
	bs          keystore.BlockStamp
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
					Addresses:      curBatch.addrs,
					Notification:   n,
					WasInitialSync: curBatch.initialSync,
				}

				curBatch, nextBatch = nextBatch, nil

				if curBatch != nil {
					w.rescanBatch <- curBatch
				}

			default:
				// Unexpected message
				panic(n)
			}

		case <-w.quit:
			break out
		}
	}

	close(w.rescanBatch)
	w.wg.Done()
}

// rescanProgressHandler handles notifications for paritally and fully completed
// rescans by marking each rescanned address as partially or fully synced and
// writing the keystore back to disk.
func (w *Wallet) rescanProgressHandler() {
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

			// TODO(jrick): save partial syncs should also include
			// the block hash.
			for _, addr := range msg.Addresses {
				err := w.KeyStore.SetSyncStatus(addr,
					keystore.PartialSync(n.Height))
				if err != nil {
					log.Errorf("Error marking address %v "+
						"partially synced: %v", addr, err)
				}
			}
			w.KeyStore.MarkDirty()
			err := w.KeyStore.WriteIfDirty()
			if err != nil {
				log.Errorf("Could not write partial rescan "+
					"progress to keystore: %v", err)
			}

		case msg := <-w.rescanFinished:
			n := msg.Notification
			addrs := msg.Addresses
			noun := pickNoun(len(addrs), "address", "addresses")
			if msg.WasInitialSync {
				w.ResendUnminedTxs()

				bs := keystore.BlockStamp{
					Hash:   n.Hash,
					Height: n.Height,
				}
				w.KeyStore.SetSyncedWith(&bs)
				w.notifyConnectedBlock(bs)

				// Mark wallet as synced to chain so connected
				// and disconnected block notifications are
				// processed.
				close(w.chainSynced)
			}
			log.Infof("Finished rescan for %d %s (synced to block "+
				"%s, height %d)", len(addrs), noun, n.Hash,
				n.Height)

			for _, addr := range addrs {
				err := w.KeyStore.SetSyncStatus(addr,
					keystore.FullSync{})
				if err != nil {
					log.Errorf("Error marking address %v "+
						"fully synced: %v", addr, err)
				}
			}
			w.KeyStore.MarkDirty()
			err := w.KeyStore.WriteIfDirty()
			if err != nil {
				log.Errorf("Could not write finished rescan "+
					"progress to keystore: %v", err)
			}

		case <-w.quit:
			break out
		}
	}
	w.wg.Done()
}

// rescanRPCHandler reads batch jobs sent by rescanBatchHandler and sends the
// RPC requests to perform a rescan.  New jobs are not read until a rescan
// finishes.
func (w *Wallet) rescanRPCHandler() {
	for batch := range w.rescanBatch {
		// Log the newly-started rescan.
		numAddrs := len(batch.addrs)
		noun := pickNoun(numAddrs, "address", "addresses")
		log.Infof("Started rescan from block %v (height %d) for %d %s",
			batch.bs.Hash, batch.bs.Height, numAddrs, noun)

		err := w.chainSvr.Rescan(batch.bs.Hash, batch.addrs,
			batch.outpoints)
		if err != nil {
			log.Errorf("Rescan for %d %s failed: %v", numAddrs,
				noun, err)
		}
		batch.done(err)
	}
	w.wg.Done()
}

// RescanActiveAddresses begins a rescan for all active addresses of a
// wallet.  This is intended to be used to sync a wallet back up to the
// current best block in the main chain, and is considered an intial sync
// rescan.
func (w *Wallet) RescanActiveAddresses() (err error) {
	// Determine the block necesary to start the rescan for all active
	// addresses.
	hash, height := w.KeyStore.SyncedTo()
	if hash == nil {
		// TODO: fix our "synced to block" handling (either in
		// keystore or txstore, or elsewhere) so this *always*
		// returns the block hash.  Looking it up by height is
		// asking for problems.
		hash, err = w.chainSvr.GetBlockHash(int64(height))
		if err != nil {
			return
		}
	}

	actives := w.KeyStore.SortedActiveAddresses()
	addrs := make([]btcutil.Address, len(actives))
	for i, addr := range actives {
		addrs[i] = addr.Address()
	}

	unspents, err := w.TxStore.UnspentOutputs()
	if err != nil {
		return
	}
	outpoints := make([]*wire.OutPoint, len(unspents))
	for i, output := range unspents {
		outpoints[i] = output.OutPoint()
	}

	job := &RescanJob{
		InitialSync: true,
		Addrs:       addrs,
		OutPoints:   outpoints,
		BlockStamp:  keystore.BlockStamp{Hash: hash, Height: height},
	}

	// Submit merged job and block until rescan completes.
	return <-w.SubmitRescan(job)
}
