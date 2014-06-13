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

/*
Package votingpool provides voting pool functionality for btcwallet.

Overview

The purpose of the voting pool package is to make it possible to store
bitcoins using m-of-n multisig transactions. Each member of the pool
holds one of the n private keys needed to create a transaction and can
only create transactions that can spend the bitcoins if m - 1 other
members of the pool agree to it.

This package depends on the waddrmgr package, and in particular
instances of the waddrgmgr.Manager structure.

Creating a voting pool

A voting pool is created via the Create function. This function
accepts a database namespace which will be used to store all
information about the pool as well as a poolID.

Loading an existing pool

An existing voting pool is loaded via the Load function, which accepts
the database name used when creating the pool as well as the poolID.

Creating a series

A series can be created via the CreateSeries method, which accepts a
version number, a series identifier, a number of required signatures
(m in m-of-n multisig, and a set of public keys.

Deposit Addresses

A deposit address can be created via the DepositScriptAddress
method, which based on a seriesID a branch number and an index
creates a pay-to-script-hash address, where the script is a multisig
script. The public keys used as inputs for generating the address are
generated from the public keys passed to CreateSeries. In [1] the
generated public keys correspend to the lowest level or the
'address_index' in the hierarchy.

Replacing a series

A series can be replaced via the ReplaceSeries method. It accepts
the same parameters as the CreateSeries method.


Documentation

[1] https://github.com/justusranvier/bips/blob/master/bip-draft-Hierarchy%20for%20Non-Colored%20Voting%20Pool%20Deterministic%20Multisig%20Wallets.mediawiki


*/
package votingpool
