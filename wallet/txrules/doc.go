// Copyright (c) 2015 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package txrules provides functions that are help establish whether or not
a transaction abides by non-consensus rules for things like the daemon and
stake pool.

Dust and Fee Per KB Calculation

Please refer to mempool.go in dcrd for more information about the importance
of these function.

Pool Fees

The pool fee is calculated from the percentage given according to the
following formula:

           ps(v+z)
    f = --------------
             s+v

    where f = absolute pool fee as an amount
          p = proportion (e.g. 0.5000 = 50.00%)
          s = subsidy (adjusted two difficulty periods into the future)
          v = price of the ticket
          z = the ticket fees

    This can be derived from the known relation that
    ps = (f * (v+z)/(v+s)) obtained from the knowledge
    that the outputs of the vote are the amounts
    of the stake ticket plus subsidy (v+s) scaled by
    the proportional input of the stake pool fee
    f/(v+z).

f is then adjusted for the fact that at least one subsidy reduction is
likely to occur before it can vote on a block.

*/
package txrules
