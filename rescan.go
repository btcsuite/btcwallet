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
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
)

// RescanMsg is the interface type for messages sent to the
// RescanManager's message channel.
type RescanMsg interface {
	ImplementsRescanMsg()
}

// RescanStartedMsg reports the job being processed for a new
// rescan.
type RescanStartedMsg RescanJob

// ImplementsRescanMsg is implemented to satisify the RescanMsg
// interface.
func (r *RescanStartedMsg) ImplementsRescanMsg() {}

// RescanProgressMsg reports the current progress made by a rescan
// for a set of account's addresses.
type RescanProgressMsg struct {
	Addresses map[*Account][]btcutil.Address
	Height    int32
}

// ImplementsRescanMsg is implemented to satisify the RescanMsg
// interface.
func (r *RescanProgressMsg) ImplementsRescanMsg() {}

// RescanFinishedMsg reports the set of account's addresses of a
// possibly-finished rescan, or an error if the rescan failed.
type RescanFinishedMsg struct {
	Addresses map[*Account][]btcutil.Address
	Error     error
}

// ImplementsRescanMsg is implemented to satisify the RescanMsg
// interface.
func (r *RescanFinishedMsg) ImplementsRescanMsg() {}

// RescanManager manages a set of current and to be processed account's
// addresses, batching waiting jobs together to minimize the total time
// needed to rescan many separate jobs.  Rescan requests are processed
// one at a time, and the next batch does not run until the current
// has finished.
type RescanManager struct {
	addJob          chan *RescanJob
	sendJob         chan *RescanJob
	status          chan interface{} // rescanProgress and rescanFinished
	msgs            chan RescanMsg
	jobCompleteChan chan chan struct{}
}

// NewRescanManager creates a new RescanManger.  If msgChan is non-nil,
// rescan messages are sent to the channel for additional processing by
// the caller.
func NewRescanManager(msgChan chan RescanMsg) *RescanManager {
	return &RescanManager{
		addJob:          make(chan *RescanJob, 1),
		sendJob:         make(chan *RescanJob, 1),
		status:          make(chan interface{}, 1),
		msgs:            msgChan,
		jobCompleteChan: make(chan chan struct{}, 1),
	}
}

// Start starts the goroutines to run the RescanManager.
func (m *RescanManager) Start() {
	go m.jobHandler()
	go m.rpcHandler()
}

type rescanBatch struct {
	addrs     map[*Account][]btcutil.Address
	outpoints map[btcwire.OutPoint]struct{}
	height    int32
	complete  chan struct{}
}

func newRescanBatch() *rescanBatch {
	return &rescanBatch{
		addrs:     map[*Account][]btcutil.Address{},
		outpoints: map[btcwire.OutPoint]struct{}{},
		height:    -1,
		complete:  make(chan struct{}),
	}
}

func (b *rescanBatch) done() {
	close(b.complete)
}

func (b *rescanBatch) empty() bool {
	return len(b.addrs) == 0
}

func (b *rescanBatch) job() *RescanJob {
	// Create slice of outpoints from the batch's set.
	outpoints := make([]*btcwire.OutPoint, 0, len(b.outpoints))
	for outpoint := range b.outpoints {
		opCopy := outpoint
		outpoints = append(outpoints, &opCopy)
	}

	return &RescanJob{
		Addresses:   b.addrs,
		OutPoints:   outpoints,
		StartHeight: b.height,
	}
}

func (b *rescanBatch) merge(job *RescanJob) {
	for acct, addr := range job.Addresses {
		b.addrs[acct] = append(b.addrs[acct], addr...)
	}
	for _, op := range job.OutPoints {
		b.outpoints[*op] = struct{}{}
	}
	if b.height == -1 || job.StartHeight < b.height {
		b.height = job.StartHeight
	}
}

// jobHandler runs the RescanManager's for-select loop to manage rescan jobs
// and dispatch requests.
func (m *RescanManager) jobHandler() {
	curBatch := newRescanBatch()
	nextBatch := newRescanBatch()

	for {
		select {
		case job := <-m.addJob:
			if curBatch.empty() {
				// Set current batch as this job and send
				// request.
				curBatch.merge(job)
				m.sendJob <- job

				// Send the channel that is closed when the
				// current batch completes.
				m.jobCompleteChan <- curBatch.complete

				// Notify listener of a newly-started rescan.
				if m.msgs != nil {
					m.msgs <- (*RescanStartedMsg)(job)
				}
			} else {
				// Add job to waiting batch.
				nextBatch.merge(job)

				// Send the channel that is closed when the
				// waiting batch completes.
				m.jobCompleteChan <- nextBatch.complete
			}

		case status := <-m.status:
			switch s := status.(type) {
			case rescanProgress:
				if m.msgs != nil {
					m.msgs <- &RescanProgressMsg{
						Addresses: curBatch.addrs,
						Height:    int32(s),
					}
				}

			case rescanFinished:
				if m.msgs != nil {
					m.msgs <- &RescanFinishedMsg{
						Addresses: curBatch.addrs,
						Error:     s.error,
					}
				}
				curBatch.done()

				curBatch, nextBatch = nextBatch, newRescanBatch()

				if !curBatch.empty() {
					job := curBatch.job()
					m.sendJob <- job
					if m.msgs != nil {
						m.msgs <- (*RescanStartedMsg)(job)
					}
				}

			default:
				// Unexpected status message
				panic(s)
			}
		}
	}
}

// rpcHandler reads jobs sent by the jobHandler and sends the rpc requests
// to perform the rescan.  New jobs are not read until a rescan finishes.
// The jobHandler is notified when the processing the rescan finishes.
func (m *RescanManager) rpcHandler() {
	for job := range m.sendJob {
		var addrs []btcutil.Address
		for _, accountAddrs := range job.Addresses {
			addrs = append(addrs, accountAddrs...)
		}
		client, err := accessClient()
		if err != nil {
			m.MarkFinished(rescanFinished{err})
			return
		}
		err = client.Rescan(job.StartHeight, addrs, job.OutPoints)
		if err != nil {
			m.MarkFinished(rescanFinished{err})
		}
	}
}

// RescanJob is a job to be processed by the RescanManager.  The job includes
// a set of account's addresses, a starting height to begin the rescan, and
// outpoints spendable by the addresses thought to be unspent.
type RescanJob struct {
	Addresses   map[*Account][]btcutil.Address
	OutPoints   []*btcwire.OutPoint
	StartHeight int32
}

// Merge merges the work from k into j, setting the starting height to
// the minimum of the two jobs.  This method does not check for
// duplicate addresses or outpoints.
func (j *RescanJob) Merge(k *RescanJob) {
	for acct, addrs := range k.Addresses {
		j.Addresses[acct] = append(j.Addresses[acct], addrs...)
	}
	for _, op := range k.OutPoints {
		j.OutPoints = append(j.OutPoints, op)
	}
	if k.StartHeight < j.StartHeight {
		j.StartHeight = k.StartHeight
	}
}

// SubmitJob submits a RescanJob to the RescanManager.  A channel is returned
// that is closed once the rescan request for the job completes.
func (m *RescanManager) SubmitJob(job *RescanJob) <-chan struct{} {
	m.addJob <- job
	return <-m.jobCompleteChan
}

// MarkProgress messages the RescanManager with the height of the block
// last processed by a running rescan.
func (m *RescanManager) MarkProgress(height rescanProgress) {
	m.status <- height
}

// MarkFinished messages the RescanManager that the currently running rescan
// finished, or errored prematurely.
func (m *RescanManager) MarkFinished(finished rescanFinished) {
	m.status <- finished
}
