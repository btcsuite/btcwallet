package chain

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	rescanv2 "github.com/lightninglabs/neutrino/rescan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxDur is the max duration a test has to execute successfully.
var maxDur = 5 * time.Second

type rescanMode struct {
	name           string
	useActorRescan bool
}

var rescanModes = []rescanMode{
	{name: "legacy"},
	{name: "actor", useActorRescan: true},
}

func TestNewNeutrinoClientUseActorRescanFlag(t *testing.T) {
	client := NewNeutrinoClient(
		&chaincfg.MainNetParams, nil, true,
	)
	require.True(t, client.UseActorRescan)

	client = NewNeutrinoClient(
		&chaincfg.MainNetParams, nil, false,
	)
	require.False(t, client.UseActorRescan)
}

func testRescanAddr(t *testing.T, label string) btcutil.Address {
	t.Helper()

	hash := chainhash.HashB([]byte(label))
	addr, err := btcutil.NewAddressPubKeyHash(
		hash[:20], &chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	return addr
}

func testRescanStartHash(t *testing.T, nc *NeutrinoClient) chainhash.Hash {
	t.Helper()

	if nc.UseActorRescan {
		chainSource, err := nc.newRescanChainSource()
		require.NoError(t, err)

		header, err := chainSource.GetBlockHeaderByHeight(0)
		require.NoError(t, err)

		return header.BlockHash()
	}

	return new(wire.BlockHeader).BlockHash()
}

// TestNeutrinoClientSequentialStartStop ensures that the client
// can sequentially Start and Stop without errors or races.
func TestNeutrinoClientSequentialStartStop(t *testing.T) {
	for _, mode := range rescanModes {
		t.Run(mode.name, func(t *testing.T) {
			var (
				nc           = newMockNeutrinoClient(mode.useActorRescan)
				wantRestarts = 50
			)

			callStartStop := func() <-chan struct{} {
				done := make(chan struct{})

				go func() {
					defer close(done)

					err := nc.Start(t.Context())
					require.NoError(t, err)
					nc.Stop()
					nc.WaitForShutdown()
				}()

				return done
			}

			timeout := time.After(maxDur)
			for i := 0; i < wantRestarts; i++ {
				select {
				case <-timeout:
					t.Fatal("timed out")
				case <-callStartStop():
				}
			}
		})
	}
}

// TestNeutrinoClientNotifyReceived verifies that a call to NotifyReceived sets
// the client into the scanning state and that subsequent calls while scanning
// will call Update on the client's Rescanner.
func TestNeutrinoClientNotifyReceived(t *testing.T) {
	for _, mode := range rescanModes {
		t.Run(mode.name, func(t *testing.T) {
			var (
				nc                      = newMockNeutrinoClient(mode.useActorRescan)
				wantNotifyReceivedCalls = 50
				wantUpdateCalls         = wantNotifyReceivedCalls - 1
				addrs                   = []btcutil.Address{
					testRescanAddr(t, mode.name),
				}
			)

			err := nc.Start(t.Context())
			require.NoError(t, err)
			t.Cleanup(func() {
				nc.Stop()
				nc.WaitForShutdown()
			})

			executeCalls := func(n int) <-chan error {
				done := make(chan error, 1)

				go func() {
					defer close(done)

					for i := 0; i < n; i++ {
						err := nc.NotifyReceived(addrs)
						if err != nil {
							done <- err
							return
						}
					}

					done <- nil
				}()

				return done
			}

			timeout := time.After(maxDur)
			select {
			case <-timeout:
				t.Fatal("timed out")
			case err := <-executeCalls(wantNotifyReceivedCalls):
				require.NoError(t, err)
			}

			if !mode.useActorRescan {
				mockRescan := nc.rescan.(*mockRescanner)
				gotUpdateCalls := mockRescan.updateArgs.Len()
				require.Equal(t, wantUpdateCalls, gotUpdateCalls)
				return
			}

			require.NotNil(t, nc.rescanActor)

			state, err := nc.rescanActor.CurrentState()
			require.NoError(t, err)

			cur, ok := state.(*rescanv2.StateCurrent)
			require.True(t, ok, "expected StateCurrent, got %T", state)
			require.Len(
				t, cur.Watch.Addrs,
				wantNotifyReceivedCalls*len(addrs),
			)
		})
	}
}

// TestNeutrinoClientNotifyReceivedRescan verifies concurrent calls to
// NotifyBlocks, NotifyReceived and Rescan do not result in a data race
// and that there is no panic on replacing the rescan goroutine single instance.
//
// Each successful method call writes a success message to a buffered channel.
// The channel is buffered so that no concurrent reader is needed.  The buffer
// size is exactly the number of goroutines launched because each goroutine
// must finish successfully or else this test will fail.  Each message is read
// out of the channel to verify the number of messages received is the number
// expected (i.e., wantMsgs == gotMsgs).
func TestNeutrinoClientNotifyReceivedRescan(t *testing.T) {
	for _, mode := range rescanModes {
		t.Run(mode.name, func(t *testing.T) {
			var (
				addrs     []btcutil.Address
				nc        = newMockNeutrinoClient(mode.useActorRescan)
				wantMsgs  = 100
				gotMsgs   = 0
				msgCh     = make(chan string, wantMsgs)
				errCh     = make(chan error, wantMsgs)
				msgPrefix = "successfully called"

				sendMsg = func(s string) {
					msgCh <- fmt.Sprintf("%s %s", msgPrefix, s)
				}
				sendErr = func(err error) {
					errCh <- err
				}
			)

			startHash := testRescanStartHash(t, nc)
			callRescan := func(wg *sync.WaitGroup) {
				defer wg.Done()

				err := nc.Rescan(&startHash, addrs, nil)
				if err != nil {
					sendErr(fmt.Errorf("rescan: %w", err))
					return
				}

				sendMsg("rescan")
			}

			callNotifyReceived := func(wg *sync.WaitGroup) {
				defer wg.Done()

				err := nc.NotifyReceived(addrs)
				if err != nil {
					sendErr(fmt.Errorf("notify received: %w", err))
					return
				}

				sendMsg("notify received")
			}

			callNotifyBlocks := func(wg *sync.WaitGroup) {
				defer wg.Done()

				err := nc.NotifyBlocks()
				if err != nil {
					sendErr(fmt.Errorf("notify blocks: %w", err))
					return
				}

				sendMsg("notify blocks")
			}

			executeCalls := func(n int) <-chan error {
				done := make(chan error, 1)

				go func() {
					var wg sync.WaitGroup
					wg.Add(n)
					for i := 0; i < n; i++ {
						if i%3 == 0 {
							go callRescan(&wg)
							continue
						}

						if i%10 == 0 {
							go callNotifyBlocks(&wg)
							continue
						}

						go callNotifyReceived(&wg)
					}

					wg.Wait()
					close(msgCh)
					close(errCh)

					for str := range msgCh {
						assert.Contains(t, str, msgPrefix)
						gotMsgs++
					}

					var firstErr error
					for err := range errCh {
						if firstErr == nil {
							firstErr = err
						}
					}

					done <- firstErr
					close(done)
				}()

				return done
			}

			err := nc.Start(t.Context())
			require.NoError(t, err)
			t.Cleanup(func() {
				nc.Stop()
				nc.WaitForShutdown()
			})

			timeout := time.After(maxDur)
			select {
			case <-timeout:
				t.Fatal("timed out")
			case err := <-executeCalls(wantMsgs):
				require.NoError(t, err)
				require.Equal(t, wantMsgs, gotMsgs)
			}
		})
	}
}

// TestNeutrinoClientStopWithActiveRescan ensures both backends can stop cleanly
// after the client has started an active notification/rescan pipeline.
func TestNeutrinoClientStopWithActiveRescan(t *testing.T) {
	for _, mode := range rescanModes {
		t.Run(mode.name, func(t *testing.T) {
			nc := newMockNeutrinoClient(mode.useActorRescan)

			err := nc.Start(t.Context())
			require.NoError(t, err)

			addrs := []btcutil.Address{
				testRescanAddr(t, mode.name+"-stop"),
			}
			err = nc.NotifyReceived(addrs)
			require.NoError(t, err)

			done := make(chan struct{})
			go func() {
				defer close(done)
				nc.Stop()
				nc.WaitForShutdown()
			}()

			select {
			case <-time.After(maxDur):
				t.Fatal("timed out")
			case <-done:
			}

			nc.clientMtx.Lock()
			defer nc.clientMtx.Unlock()

			require.False(t, nc.started)
			require.Nil(t, nc.rescanActor)
			require.Nil(t, nc.rescan)
		})
	}
}
