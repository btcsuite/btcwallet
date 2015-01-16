/*
 * Copyright (c) 2014 Conformal Systems LLC <info@conformal.com>
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

package votingpool_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcnet"
	"github.com/conformal/btcwallet/votingpool"
	"github.com/conformal/btcwallet/waddrmgr"
	"github.com/conformal/btcwallet/walletdb"
	_ "github.com/conformal/btcwallet/walletdb/bdb"
)

func Example_basic() {
	// This example demonstrates how to create a voting pool, create a
	// series, get a deposit address from a series and lastly how to
	// replace a series.

	// Create a new wallet DB.
	dir, err := ioutil.TempDir("", "pool_test")
	if err != nil {
		fmt.Printf("Failed to create db dir: %v\n", err)
		return
	}
	db, err := walletdb.Create("bdb", filepath.Join(dir, "wallet.db"))
	if err != nil {
		fmt.Printf("Failed to create wallet DB: %v\n", err)
		return
	}
	defer os.RemoveAll(dir)
	defer db.Close()

	// Create a new walletdb namespace for the address manager.
	mgrNamespace, err := db.Namespace([]byte("waddrmgr"))
	if err != nil {
		fmt.Printf("Failed to create addr manager DB namespace: %v\n", err)
		return
	}

	// Create the address manager
	mgr, err := waddrmgr.Create(mgrNamespace, seed, pubPassphrase, privPassphrase,
		&btcnet.MainNetParams, nil)
	if err != nil {
		fmt.Printf("Failed to create addr manager: %v\n", err)
		return
	}
	defer mgr.Close()

	// Create a walletdb for votingpools.
	vpNamespace, err := db.Namespace([]byte("votingpool"))
	if err != nil {
		fmt.Printf("Failed to create VotingPool DB namespace: %v\n", err)
		return
	}

	// Create the voting pool.
	pool, err := votingpool.Create(vpNamespace, mgr, []byte{0x00})
	if err != nil {
		fmt.Printf("Voting Pool creation failed: %v\n", err)
		return
	}

	// Create a 2-of-3 series.
	apiVersion := uint32(1)
	seriesID := uint32(1)
	requiredSignatures := uint32(2)
	pubKeys := []string{
		"xpub661MyMwAqRbcFDDrR5jY7LqsRioFDwg3cLjc7tML3RRcfYyhXqqgCH5SqMSQdpQ1Xh8EtVwcfm8psD8zXKPcRaCVSY4GCqbb3aMEs27GitE",
		"xpub661MyMwAqRbcGsxyD8hTmJFtpmwoZhy4NBBVxzvFU8tDXD2ME49A6JjQCYgbpSUpHGP1q4S2S1Pxv2EqTjwfERS5pc9Q2yeLkPFzSgRpjs9",
		"xpub661MyMwAqRbcEbc4uYVXvQQpH9L3YuZLZ1gxCmj59yAhNy33vXxbXadmRpx5YZEupNSqWRrR7PqU6duS2FiVCGEiugBEa5zuEAjsyLJjKCh",
	}
	err = pool.CreateSeries(apiVersion, seriesID, requiredSignatures, pubKeys)
	if err != nil {
		fmt.Printf("Cannot create series: %v\n", err)
		return
	}

	// Create a deposit address.
	branch := uint32(0) // The change branch
	index := uint32(1)
	addr, err := pool.DepositScriptAddress(seriesID, branch, index)
	if err != nil {
		fmt.Printf("DepositScriptAddress failed for series: %d, branch: %d, index: %d\n",
			seriesID, branch, index)
		return
	}
	fmt.Println("Generated deposit address:", addr.EncodeAddress())

	// Replace the existing series with a 3-of-5 series.
	pubKeys = []string{
		"xpub661MyMwAqRbcFQfXKHwz8ZbTtePwAKu8pmGYyVrWEM96DYUTWDYipMnHrFcemZHn13jcRMfsNU3UWQUudiaE7mhkWCHGFRMavF167DQM4Va",
		"xpub661MyMwAqRbcGnTEXx3ehjx8EiqQGnL4uhwZw3ZxvZAa2E6E4YVAp63UoVtvm2vMDDF8BdPpcarcf7PWcEKvzHhxzAYw1zG23C2egeh82AR",
		"xpub661MyMwAqRbcG83KwFyr1RVrNUmqVwYxV6nzxbqoRTNc8fRnWxq1yQiTBifTHhevcEM9ucZ1TqFS7Kv17Gd81cesv6RDrrvYS9SLPjPXhV5",
		"xpub661MyMwAqRbcFGJbLPhMjtpC1XntFpg6jjQWjr6yXN8b9wfS1RiU5EhJt5L7qoFuidYawc3XJoLjT2PcjVpXryS3hn1WmSPCyvQDNuKsfgM",
		"xpub661MyMwAqRbcGJDX4GYocn7qCzvMJwNisxpzkYZAakcvXtWV6CanXuz9xdfe5kTptFMJ4hDt2iTiT11zyN14u8R5zLvoZ1gnEVqNLxp1r3v",
		"xpub661MyMwAqRbcG13FtwvZVaA15pTerP4JdAGvytPykqDr2fKXePqw3wLhCALPAixsE176jFkc2ac9K3tnF4KwaTRKUqFF5apWD6XL9LHCu7E",
	}
	requiredSignatures = 3
	err = pool.ReplaceSeries(apiVersion, seriesID, requiredSignatures, pubKeys)
	if err != nil {
		fmt.Printf("Cannot replace series: %v\n", err)
		return
	}

	// Output:
	// Generated deposit address: 3QTzpc9d3tTbNLJLB7xwt87nWM38boAhAw
}
