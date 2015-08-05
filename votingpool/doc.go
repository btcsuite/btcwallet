/*
 * Copyright (c) 2014 The btcsuite developers
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

/*
Package votingpool provides voting pool functionality for btcwallet.

Overview

The purpose of the voting pool package is to make it possible to store
bitcoins using m-of-n multisig transactions. A pool can have multiple
series, each of them with a set of pubkeys (one for each of the members
in that pool's series) and the minimum number of required signatures (m)
needed to spend the pool's coins. Each member will hold a private key
matching one of the series' public keys, and at least m members will
need to be in agreement when spending the pool's coins.

More details about voting pools as well as some of its use cases can
be found at http://opentransactions.org/wiki/index.php?title=Category:Voting_Pools

This package depends on the waddrmgr and walletdb packages.

Creating a voting pool

A voting pool is created via the Create function. This function
accepts a database namespace which will be used to store all
information related to that pool under a bucket whose key is the
pool's ID.

Loading an existing pool

An existing voting pool is loaded via the Load function, which accepts
the database name used when creating the pool as well as the poolID.

Creating a series

A series can be created via the CreateSeries method, which accepts a
version number, a series identifier, a number of required signatures
(m in m-of-n multisig), and a set of public keys.

Deposit Addresses

A deposit address can be created via the DepositScriptAddress
method, which returns a series-specific P2SH address from the multi-sig
script constructed with the index-th child of the series' public keys and
sorted according to the given branch. The procedure to construct multi-sig
deposit addresses is described in detail at
http://opentransactions.org/wiki/index.php/Deposit_Address_(voting_pools)

Replacing a series

A series can be replaced via the ReplaceSeries method. It accepts
the same parameters as the CreateSeries method.

Empowering a series

For security reasons, most private keys will be maintained offline and
only brought online when they're needed. In order to bring a key online,
one must use the EmpowerSeries method, which takes just the series ID
and a raw private key matching one of the series' public keys.

Starting withdrawals

When withdrawing coins from the pool, we employ a deterministic process
in order to minimise the cost of coordinating transaction signing. For
this to work, members of the pool have to perform an out-of-band consensus
process (<http://opentransactions.org/wiki/index.php/Consensus_Process_(voting_pools)>)
to define the following parameters, that should be passed to the
StartWithdrawal method:

	roundID: the unique identifier of a given consensus round
	requests: a list with outputs requested by users of the voting pool
	startAddress: the seriesID, branch and indes where we should start looking for inputs
	lastSeriesID: the ID of the last series where we should take inputs from
	changeStart: the first change address to use
	dustThreshold: the minimum amount of satoshis an input needs to be considered eligible

StartWithdrawal will then select all eligible inputs in the given address
range (following the algorithim at <http://opentransactions.org/wiki/index.php/Input_Selection_Algorithm_(voting_pools)>)
and use them to construct transactions (<http://opentransactions.org/wiki/index.php/Category:Transaction_Construction_Algorithm_(voting_pools)>)
that fulfill the output requests. It returns a WithdrawalStatus containing
the state of every requested output, the raw signatures for the constructed
transactions, the network fees included in those transactions and the input
range to use in the next withdrawal.

Signing and broadcasting withdrawal transactions

The raw signatures returned by StartWithdrawal are exchanged by the pool
members and passed on to their wallets via the Pool.UpdateWithdrawal method,
which takes the ID of the consensus round, a list of raw signatures and a
wtxmgr.Store. The given list of signatures is merged with the existing one, and
then any transactions that can be signed (i.e. those for which we have the
minimum required raw signatures for each input) are broadcast. The merged list
of signatures is then returned so that it can be passed on to other pool members.

*/
package votingpool
