// Package rpctest contains tests for dcrwallet's RPC server and a harness used
// to facilitate the tests by setting up a temporary Simnet node and wallet. The
// RPC client implementation in dcrrpcclient is used exclusively to test the RPC
// server. A single test function, TestMain, is executed by go test, and is
// responsible for setting up test harnesses and running the individual RPC test
// functions.
//
// A Harness, as defined in rpcharness.go, manages a SimNet node and a wallet
// that connects to the node. (*Harness).SetUp does the following:
//   1. Start a new dcrd process with a fresh SimNet chain.
//   2. Create a new temporary wallet connected to the running node.
//   3. Get a new address from the wallet for mining subsidy.
//   4. Restart dcrd with miningaddr set.
//   5. Generate a number of blocks so that testing starts with a spendable
//      balance.
//
// Multiple harnesses may be run concurrently. Temporary folders are created for
// each harness, and cleaned up on shutdown.
//
// The default settings for a harness wallet are:
//    1. Stake mining enabled (--enablestakemining).
//    2. Zero max ticket price.
//    3. High balance to maintain (2000000 DCR).
// Thus, a harness wallet will automatically vote on owned tickets, but not
// automatically purchase tickets.
package rpctest
