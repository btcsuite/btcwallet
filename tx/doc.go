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

// Package tx provides an implementation of a transaction store for a
// bitcoin wallet.  Its primary purpose is to save transactions with
// outputs spendable with wallet keys and transactions that are signed by
// wallet keys in memory, handle spend tracking for newly-inserted
// transactions, report the spendable balance from each unspent
// transaction output, and finally to provide a means to serialize the
// entire data structure to an io.Writer and deserialize from an io.Reader
// (both of which are usually an os.File).
//               
// Transaction outputs which are spendable by wallet keys are called
// credits (because they credit to a wallet's total spendable balance)
// and are modeled using the Credit structure.  Transaction inputs which
// spend previously-inserted credits are called debits (because they debit
// from the wallet's spendable balance) and are modeled using the Debit
// structure.
//                      
// Besides just saving transactions, bidirectional spend tracking is also
// performed on each credit and debit.  Unlike packages such as btcdb,
// which only mark whether a transaction output is spent or unspent, this
// package always records which transaction is responsible for debiting
// (spending) any credit.  Each debit also points back to the transaction
// credit it spends.
//
// A significant amount of internal bookkeeping is used to improve the
// performance of inserting transactions and querying commonly-needed
// data.  Most notably, all unspent credits may be iterated over without
// including (and ignoring) spent credits.  Another trick is to record
// the total spendable amount delta as a result of all transactions within
// a block, which is the total value of all credits (both spent and
// unspent) minus the total value debited from previous transactions, for
// every transaction in that block.  This allows for the calculation of a
// wallet's balance for any arbitrary number of confirmations without
// needing to iterate over every unspent credit.
//
// Finally, this package records transaction insertion history (such as
// the date a transaction was first received) and is able to create the
// JSON reply structure for RPC calls such as listtransactions for any
// saved transaction.
//
// To use the transaction store, a transaction must be first inserted
// with InsertTx.  After an insert, credits and debits may be attached to
// the returned transaction record using the AddCredit and AddDebits
// methods.
//
// Example use:
//
//	// Create a new transaction store to hold two transactions.
//	s := tx.NewStore()
//
//	// Insert a transaction belonging to some imaginary block at
//	// height 123.
//	b123 := &tx.Block{Height: 123, Time: time.Now()}
//	r1, err := s.InsertTx(txA, b123)
//	if err != nil {
//		// handle error
//	}
//
//	// Mark output 0 as being a non-change credit to this wallet.
//	c1o0, err := r1.AddCredit(0, false)
//	if err != nil {
//		// handle error
//	}
//
//	// c1o0 (credit 1 output 0) is inserted unspent.
//	fmt.Println(c1o0.Spent())      // Prints "false"
//	fmt.Println(s.Balance(1, 123)) // Prints amount of txA output 0.
//
//	// Insert a second transaction at some imaginary block height
//	// 321.
//	b321 := &tx.Block{Height: 321, Time: time.Now()}
//	r2, err := s.InsertTx(txB, b321)
//	if err != nil {
//		// handle error
//	}
//
//	// Mark r2 as debiting from record 1's 0th credit.
//	d2, err := r2.AddDebits([]*tx.Credit{c1o0})
//	if err != nil {
//		// handle error
//	}
//
//	// Spend tracking and the balances are updated accordingly.
//	fmt.Println(c1o0.Spent())      // Prints "true"
//	fmt.Println(s.Balance(1, 321)) // Prints "0 BTC"
//	fmt.Println(d2.InputAmount())  // Prints amount of txA output 0.
package tx
