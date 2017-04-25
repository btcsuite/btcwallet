package spvchain_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aakselrod/btctestlog"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpctest"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcrpcclient"
	"github.com/btcsuite/btcwallet/spvsvc/spvchain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
)

const (
	logLevel      = btclog.TraceLvl
	syncTimeout   = 30 * time.Second
	syncUpdate    = time.Second
	numTestBlocks = 50
)

func TestSetup(t *testing.T) {
	// Create a btcd SimNet node and generate 500 blocks
	h1, err := rpctest.New(&chaincfg.SimNetParams, nil, nil)
	if err != nil {
		t.Fatalf("Couldn't create harness: %s", err)
	}
	defer h1.TearDown()
	err = h1.SetUp(false, 0)
	if err != nil {
		t.Fatalf("Couldn't set up harness: %s", err)
	}
	_, err = h1.Node.Generate(500)
	if err != nil {
		t.Fatalf("Couldn't generate blocks: %s", err)
	}

	// Create a second btcd SimNet node
	h2, err := rpctest.New(&chaincfg.SimNetParams, nil, nil)
	if err != nil {
		t.Fatalf("Couldn't create harness: %s", err)
	}
	defer h2.TearDown()
	err = h2.SetUp(false, 0)
	if err != nil {
		t.Fatalf("Couldn't set up harness: %s", err)
	}

	// Create a third btcd SimNet node and generate 900 blocks
	h3, err := rpctest.New(&chaincfg.SimNetParams, nil, nil)
	if err != nil {
		t.Fatalf("Couldn't create harness: %s", err)
	}
	defer h3.TearDown()
	err = h3.SetUp(false, 0)
	if err != nil {
		t.Fatalf("Couldn't set up harness: %s", err)
	}
	_, err = h3.Node.Generate(900)
	if err != nil {
		t.Fatalf("Couldn't generate blocks: %s", err)
	}

	// Connect, sync, and disconnect h1 and h2
	err = csd([]*rpctest.Harness{h1, h2})
	if err != nil {
		t.Fatalf("Couldn't connect/sync/disconnect h1 and h2: %s", err)
	}

	// Generate 300 blocks on the first node and 350 on the second
	_, err = h1.Node.Generate(300)
	if err != nil {
		t.Fatalf("Couldn't generate blocks: %s", err)
	}
	_, err = h2.Node.Generate(350)
	if err != nil {
		t.Fatalf("Couldn't generate blocks: %s", err)
	}

	// Now we have a node with 800 blocks (h1), 850 blocks (h2), and
	// 900 blocks (h3). The chains of nodes h1 and h2 match up to block
	// 500. By default, a synchronizing wallet connected to all three
	// should synchronize to h3. However, we're going to take checkpoints
	// from h1 at 111, 333, 555, and 777, and add those to the
	// synchronizing wallet's chain parameters so that it should
	// disconnect from h3 at block 111, and from h2 at block 555, and
	// then synchronize to block 800 from h1. Order of connection is
	// unfortunately not guaranteed, so the reorg may not happen with every
	// test.

	// Copy parameters and insert checkpoints
	modParams := chaincfg.SimNetParams
	for _, height := range []int64{111, 333, 555, 777} {
		hash, err := h1.Node.GetBlockHash(height)
		if err != nil {
			t.Fatalf("Couldn't get block hash for height %d: %s",
				height, err)
		}
		modParams.Checkpoints = append(modParams.Checkpoints,
			chaincfg.Checkpoint{
				Hash:   hash,
				Height: int32(height),
			})
	}

	// Create a temporary directory, initialize an empty walletdb with an
	// SPV chain namespace, and create a configuration for the ChainService.
	tempDir, err := ioutil.TempDir("", "spvchain")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %s", err)
	}
	defer os.RemoveAll(tempDir)
	db, err := walletdb.Create("bdb", tempDir+"/weks.db")
	defer db.Close()
	if err != nil {
		t.Fatalf("Error opening DB: %s\n", err)
	}
	ns, err := db.Namespace([]byte("weks"))
	if err != nil {
		t.Fatalf("Error geting namespace: %s\n", err)
	}
	config := spvchain.Config{
		DataDir:     tempDir,
		Namespace:   ns,
		ChainParams: modParams,
		AddPeers: []string{
			h3.P2PAddress(),
			h2.P2PAddress(),
			h1.P2PAddress(),
		},
	}

	spvchain.Services = 0
	spvchain.MaxPeers = 3
	spvchain.BanDuration = 5 * time.Second
	spvchain.RequiredServices = wire.SFNodeNetwork
	spvchain.WaitForMoreCFHeaders = time.Second
	logger, err := btctestlog.NewTestLogger(t)
	if err != nil {
		t.Fatalf("Could not set up logger: %s", err)
	}
	chainLogger := btclog.NewSubsystemLogger(logger, "CHAIN: ")
	chainLogger.SetLevel(logLevel)
	spvchain.UseLogger(chainLogger)
	rpcLogger := btclog.NewSubsystemLogger(logger, "RPCC: ")
	rpcLogger.SetLevel(logLevel)
	btcrpcclient.UseLogger(rpcLogger)
	svc, err := spvchain.NewChainService(config)
	if err != nil {
		t.Fatalf("Error creating ChainService: %s", err)
	}
	svc.Start()
	defer svc.Stop()

	// Make sure the client synchronizes with the correct node
	err = waitForSync(t, svc, h1)
	if err != nil {
		t.Fatalf("Couldn't sync ChainService: %s", err)
	}

	// Generate 125 blocks on h1 to make sure it reorgs the other nodes.
	// Ensure the ChainService instance stays caught up.
	h1.Node.Generate(125)
	err = waitForSync(t, svc, h1)
	if err != nil {
		t.Fatalf("Couldn't sync ChainService: %s", err)
	}

	// Connect/sync/disconnect h2 to make it reorg to the h1 chain.
	err = csd([]*rpctest.Harness{h1, h2})
	if err != nil {
		t.Fatalf("Couldn't sync h2 to h1: %s", err)
	}

	// Generate 3 blocks on h1, one at a time, to make sure the
	// ChainService instance stays caught up.
	for i := 0; i < 3; i++ {
		h1.Node.Generate(1)
		err = waitForSync(t, svc, h1)
		if err != nil {
			t.Fatalf("Couldn't sync ChainService: %s", err)
		}
	}

	// Generate 5 blocks on h2 and wait for ChainService to sync to the
	// newly-best chain on h2.
	h2.Node.Generate(5)
	err = waitForSync(t, svc, h2)
	if err != nil {
		t.Fatalf("Couldn't sync ChainService: %s", err)
	}

	// Generate 7 blocks on h1 and wait for ChainService to sync to the
	// newly-best chain on h1.
	h1.Node.Generate(7)
	err = waitForSync(t, svc, h1)
	if err != nil {
		t.Fatalf("Couldn't sync ChainService: %s", err)
	}

	// Test that we can get blocks and cfilters via P2P and decide which are
	// valid and which aren't.
	err = testRandomBlocks(t, svc, h1)
	if err != nil {
		t.Fatalf("Testing blocks and cfilters failed: %s", err)
	}
}

// csd does a connect-sync-disconnect between nodes in order to support
// reorg testing. It brings up and tears down a temporary node, otherwise the
// nodes try to reconnect to each other which results in unintended reorgs.
func csd(harnesses []*rpctest.Harness) error {
	hTemp, err := rpctest.New(&chaincfg.SimNetParams, nil, nil)
	if err != nil {
		return err
	}
	// Tear down node at the end of the function.
	defer hTemp.TearDown()
	err = hTemp.SetUp(false, 0)
	if err != nil {
		return err
	}
	for _, harness := range harnesses {
		err = rpctest.ConnectNode(hTemp, harness)
		if err != nil {
			return err
		}
	}
	return rpctest.JoinNodes(harnesses, rpctest.Blocks)
}

// waitForSync waits for the ChainService to sync to the current chain state.
func waitForSync(t *testing.T, svc *spvchain.ChainService,
	correctSyncNode *rpctest.Harness) error {
	knownBestHash, knownBestHeight, err :=
		correctSyncNode.Node.GetBestBlock()
	if err != nil {
		return err
	}
	if logLevel != btclog.Off {
		t.Logf("Syncing to %d (%s)", knownBestHeight, knownBestHash)
	}
	var haveBest *waddrmgr.BlockStamp
	haveBest, err = svc.BestSnapshot()
	if err != nil {
		return fmt.Errorf("Couldn't get best snapshot from "+
			"ChainService: %s", err)
	}
	var total time.Duration
	for haveBest.Hash != *knownBestHash {
		if total > syncTimeout {
			return fmt.Errorf("Timed out after %v waiting for "+
				"header synchronization.", syncTimeout)
		}
		if haveBest.Height > knownBestHeight {
			return fmt.Errorf("Synchronized to the wrong chain.")
		}
		time.Sleep(syncUpdate)
		total += syncUpdate
		haveBest, err = svc.BestSnapshot()
		if err != nil {
			return fmt.Errorf("Couldn't get best snapshot from "+
				"ChainService: %s", err)
		}
		if logLevel != btclog.Off {
			t.Logf("Synced to %d (%s)", haveBest.Height,
				haveBest.Hash)
		}
	}
	// Check if we're current.
	if !svc.IsCurrent() {
		return fmt.Errorf("ChainService doesn't see itself as current!")
	}
	// Check if we have all of the cfheaders.
	knownBasicHeader, err := correctSyncNode.Node.GetCFilterHeader(
		knownBestHash, false)
	if err != nil {
		return fmt.Errorf("Couldn't get latest basic header from "+
			"%s: %s", correctSyncNode.P2PAddress(), err)
	}
	knownExtHeader, err := correctSyncNode.Node.GetCFilterHeader(
		knownBestHash, true)
	if err != nil {
		return fmt.Errorf("Couldn't get latest extended header from "+
			"%s: %s", correctSyncNode.P2PAddress(), err)
	}
	haveBasicHeader := &chainhash.Hash{}
	haveExtHeader := &chainhash.Hash{}
	for (*knownBasicHeader.HeaderHashes[0] != *haveBasicHeader) &&
		(*knownExtHeader.HeaderHashes[0] != *haveExtHeader) {
		if total > syncTimeout {
			return fmt.Errorf("Timed out after %v waiting for "+
				"cfheaders synchronization.", syncTimeout)
		}
		haveBasicHeader, _ = svc.GetBasicHeader(*knownBestHash)
		haveExtHeader, _ = svc.GetExtHeader(*knownBestHash)
		time.Sleep(syncUpdate)
		total += syncUpdate
	}
	if logLevel != btclog.Off {
		t.Logf("Synced cfheaders to %d (%s)", haveBest.Height,
			haveBest.Hash)
	}
	// At this point, we know the latest cfheader is stored in the
	// ChainService database. We now compare each cfheader the
	// harness knows about to what's stored in the ChainService
	// database to see if we've missed anything or messed anything
	// up.
	for i := int32(0); i <= haveBest.Height; i++ {
		head, _, err := svc.GetBlockByHeight(uint32(i))
		if err != nil {
			return fmt.Errorf("Couldn't read block by "+
				"height: %s", err)
		}
		hash := head.BlockHash()
		haveBasicHeader, err = svc.GetBasicHeader(hash)
		if err != nil {
			return fmt.Errorf("Couldn't get basic header "+
				"for %d (%s) from DB", i, hash)
		}
		haveExtHeader, err = svc.GetExtHeader(hash)
		if err != nil {
			return fmt.Errorf("Couldn't get extended "+
				"header for %d (%s) from DB", i, hash)
		}
		knownBasicHeader, err =
			correctSyncNode.Node.GetCFilterHeader(&hash,
				false)
		if err != nil {
			return fmt.Errorf("Couldn't get basic header "+
				"for %d (%s) from node %s", i, hash,
				correctSyncNode.P2PAddress())
		}
		knownExtHeader, err =
			correctSyncNode.Node.GetCFilterHeader(&hash,
				true)
		if err != nil {
			return fmt.Errorf("Couldn't get extended "+
				"header for %d (%s) from node %s", i,
				hash, correctSyncNode.P2PAddress())
		}
		if *haveBasicHeader !=
			*knownBasicHeader.HeaderHashes[0] {
			return fmt.Errorf("Basic header for %d (%s) "+
				"doesn't match node %s. DB: %s, node: "+
				"%s", i, hash,
				correctSyncNode.P2PAddress(),
				haveBasicHeader,
				knownBasicHeader.HeaderHashes[0])
		}
		if *haveExtHeader !=
			*knownExtHeader.HeaderHashes[0] {
			return fmt.Errorf("Extended header for %d (%s)"+
				" doesn't match node %s. DB: %s, node:"+
				" %s", i, hash,
				correctSyncNode.P2PAddress(),
				haveExtHeader,
				knownExtHeader.HeaderHashes[0])
		}
	}
	return nil
}

// testRandomBlocks goes through numTestBlocks random blocks and ensures we
// can correctly get filters from them. We don't go through *all* the blocks
// because it can be a little slow, but we'll improve that soon-ish hopefully
// to the point where we can do it.
// TODO: Improve concurrency on framework side.
func testRandomBlocks(t *testing.T, svc *spvchain.ChainService,
	correctSyncNode *rpctest.Harness) error {
	var haveBest *waddrmgr.BlockStamp
	haveBest, err := svc.BestSnapshot()
	if err != nil {
		return fmt.Errorf("Couldn't get best snapshot from "+
			"ChainService: %s", err)
	}
	// Keep track of an error channel
	errChan := make(chan error)
	var lastErr error
	go func() {
		for err := range errChan {
			if err != nil {
				t.Errorf("%s", err)
				lastErr = fmt.Errorf("Couldn't validate all " +
					"blocks, filters, and filter headers.")
			}
		}
	}()
	// Test getting numTestBlocks random blocks and filters.
	var wg sync.WaitGroup
	heights := rand.Perm(int(haveBest.Height))
	for i := 0; i < numTestBlocks; i++ {
		wg.Add(1)
		height := uint32(heights[i])
		go func() {
			defer wg.Done()
			// Get block header from database.
			blockHeader, blockHeight, err := svc.GetBlockByHeight(height)
			if err != nil {
				errChan <- fmt.Errorf("Couldn't get block "+
					"header by height %d: %s", height, err)
				return
			}
			if blockHeight != height {
				errChan <- fmt.Errorf("Block height retrieved from DB "+
					"doesn't match expected height. Want: %d, "+
					"have: %d", height, blockHeight)
				return
			}
			blockHash := blockHeader.BlockHash()
			// Get block via RPC.
			wantBlock, err := correctSyncNode.Node.GetBlock(&blockHash)
			if err != nil {
				errChan <- fmt.Errorf("Couldn't get block %d (%s) by RPC",
					height, blockHash)
				return
			}
			// Get block from network.
			haveBlock := svc.GetBlockFromNetwork(blockHash)
			if haveBlock == nil {
				errChan <- fmt.Errorf("Couldn't get block %d (%s) from"+
					"network", height, blockHash)
				return
			}
			// Check that network and RPC blocks match.
			if !reflect.DeepEqual(*haveBlock.MsgBlock(), *wantBlock) {
				errChan <- fmt.Errorf("Block from network doesn't match "+
					"block from RPC. Want: %s, RPC: %s, network: "+
					"%s", blockHash, wantBlock.BlockHash(),
					haveBlock.MsgBlock().BlockHash())
				return
			}
			// Check that block height matches what we have.
			if int32(blockHeight) != haveBlock.Height() {
				errChan <- fmt.Errorf("Block height from network doesn't "+
					"match expected height. Want: %s, network: %s",
					blockHeight, haveBlock.Height())
				return
			}
			// Get basic cfilter from network.
			haveFilter := svc.GetCFilter(blockHash, false)
			if haveFilter == nil {
				errChan <- fmt.Errorf("Couldn't get basic "+
					"filter for block %d", height)
				return
			}
			// Get basic cfilter from RPC.
			wantFilter, err := correctSyncNode.Node.GetCFilter(&blockHash,
				false)
			if err != nil {
				errChan <- fmt.Errorf("Couldn't get basic filter for "+
					"block %d via RPC: %s", height, err)
				return
			}
			// Check that network and RPC cfilters match.
			if !bytes.Equal(haveFilter.NBytes(), wantFilter.Data) {
				errChan <- fmt.Errorf("Basic filter from P2P network/DB"+
					" doesn't match RPC value for block %d", height)
				return
			}
			// Calculate basic filter from block.
			calcFilter, err := spvchain.BuildBasicFilter(
				haveBlock.MsgBlock())
			if err != nil {
				errChan <- fmt.Errorf("Couldn't build basic filter for "+
					"block %d (%s): %s", height, blockHash, err)
				return
			}
			// Check that the network value matches the calculated value
			// from the block.
			if !reflect.DeepEqual(*haveFilter, *calcFilter) {
				errChan <- fmt.Errorf("Basic filter from P2P network/DB "+
					"doesn't match calculated value for block %d",
					height)
				return
			}
			// Get previous basic filter header from the database.
			prevHeader, err := svc.GetBasicHeader(blockHeader.PrevBlock)
			if err != nil {
				errChan <- fmt.Errorf("Couldn't get basic filter header "+
					"for block %d (%s) from DB: %s", height-1,
					blockHeader.PrevBlock, err)
				return
			}
			// Get current basic filter header from the database.
			curHeader, err := svc.GetBasicHeader(blockHash)
			if err != nil {
				errChan <- fmt.Errorf("Couldn't get basic filter header "+
					"for block %d (%s) from DB: %s", height-1,
					blockHash, err)
				return
			}
			// Check that the filter and header line up.
			calcHeader := spvchain.MakeHeaderForFilter(calcFilter,
				*prevHeader)
			if !bytes.Equal(curHeader[:], calcHeader[:]) {
				errChan <- fmt.Errorf("Filter header doesn't match. Want: "+
					"%s, got: %s", curHeader, calcHeader)
				return
			}
			// Get extended cfilter from network
			haveFilter = svc.GetCFilter(blockHash, true)
			if haveFilter == nil {
				errChan <- fmt.Errorf("Couldn't get extended "+
					"filter for block %d", height)
				return
			}
			// Get extended cfilter from RPC
			wantFilter, err = correctSyncNode.Node.GetCFilter(&blockHash,
				true)
			if err != nil {
				errChan <- fmt.Errorf("Couldn't get extended filter for "+
					"block %d via RPC: %s", height, err)
				return
			}
			// Check that network and RPC cfilters match
			if !bytes.Equal(haveFilter.NBytes(), wantFilter.Data) {
				errChan <- fmt.Errorf("Extended filter from P2P network/DB"+
					" doesn't match RPC value for block %d", height)
				return
			}
			// Calculate extended filter from block
			calcFilter, err = spvchain.BuildExtFilter(
				haveBlock.MsgBlock())
			if err != nil {
				errChan <- fmt.Errorf("Couldn't build extended filter for "+
					"block %d (%s): %s", height, blockHash, err)
				return
			}
			// Check that the network value matches the calculated value
			// from the block.
			if !reflect.DeepEqual(*haveFilter, *calcFilter) {
				errChan <- fmt.Errorf("Extended filter from P2P network/DB"+
					" doesn't match calculated value for block %d",
					height)
				return
			}
			// Get previous extended filter header from the database.
			prevHeader, err = svc.GetExtHeader(blockHeader.PrevBlock)
			if err != nil {
				errChan <- fmt.Errorf("Couldn't get extended filter header"+
					" for block %d (%s) from DB: %s", height-1,
					blockHeader.PrevBlock, err)
				return
			}
			// Get current basic filter header from the database.
			curHeader, err = svc.GetExtHeader(blockHash)
			if err != nil {
				errChan <- fmt.Errorf("Couldn't get extended filter header"+
					" for block %d (%s) from DB: %s", height-1,
					blockHash, err)
				return
			}
			// Check that the filter and header line up.
			calcHeader = spvchain.MakeHeaderForFilter(calcFilter,
				*prevHeader)
			if !bytes.Equal(curHeader[:], calcHeader[:]) {
				errChan <- fmt.Errorf("Filter header doesn't match. Want: "+
					"%s, got: %s", curHeader, calcHeader)
				return
			}
		}()
	}
	// Wait for all queries to finish.
	wg.Wait()
	if logLevel != btclog.Off {
		t.Logf("Finished checking %d blocks and their cfilters",
			numTestBlocks)
	}
	// Close the error channel to make the error monitoring goroutine
	// finish.
	close(errChan)
	return lastErr
}
