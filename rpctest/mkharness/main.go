// mkharness brings up a simnet node and wallet, prints the commands, and waits
// for a keypress to terminate them.

package main

import (
	"bufio"
	"fmt"
	"os"
	//"strings"
	//"time"

	"github.com/decred/dcrd/chaincfg"
	//"github.com/decred/dcrrpcclient"
	//"github.com/decred/dcrutil"
	//"github.com/decred/dcrwallet/rpc/legacyrpc"
	"github.com/decred/dcrwallet/rpctest"
)

func main() {
	var err error
	var primaryHarness *rpctest.Harness
	primaryHarness, err = rpctest.NewHarness(&chaincfg.SimNetParams, nil, nil)
	if err != nil {
		fmt.Println("Unable to create primary harness: ", err)
		os.Exit(1)
	}

	// Initialize the primary mining node with a chain of length 41,
	// providing 25 mature coinbases to allow spending from for testing
	// purposes (CoinbaseMaturity=16 for simnet).
	if err = primaryHarness.SetUp(true, 25); err != nil {
		fmt.Println("Unable to setup test chain: ", err)
		err = primaryHarness.TearDown()
		os.Exit(1)
	}

	fmt.Printf("Node command:\n\t%s\n", primaryHarness.FullNodeCommand())
	fmt.Printf("Wallet command:\n\t%s\n", primaryHarness.FullWalletCommand())

	cn := primaryHarness.RPCConfig()
	nodeCertFile := primaryHarness.RPCCertFile()
	fmt.Println("Command for node's dcrctl:")
	fmt.Printf("\tdcrctl -u %s -P %s -s %s -c %s\n", cn.User, cn.Pass,
		cn.Host, nodeCertFile)

	cw := primaryHarness.RPCWalletConfig()
	walletCertFile := primaryHarness.RPCWalletCertFile()
	fmt.Println("Command for wallet's dcrctl:")
	fmt.Printf("\tdcrctl -u %s -P %s -s %s -c %s --wallet\n", cw.User, cw.Pass,
		cw.Host, walletCertFile)

	fmt.Print("Press Enter to terminate harness.")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	// Clean up the primary harness created above. This includes removing
	// all temporary directories, and shutting down any created processes.
	if err := primaryHarness.TearDown(); err != nil {
		fmt.Println("Unable to teardown test chain: ", err)
		os.Exit(1)
	}

	os.Exit(0)

}
