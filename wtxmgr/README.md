wtxmgr
======

Package wtxmgr provides storage and spend tracking of wallet transactions and
their relevant input and outputs.

## Feature overview

- Storage for relevant wallet transactions
- Ability to mark outputs as controlled by wallet
- Unspent transaction output index
- Balance tracking
- Automatic spend tracking for transaction inserts and removals
- Double spend detection and correction after blockchain reorgs
- Scalable design:
  - Utilizes similar prefixes to allow cursor iteration over relevant transaction
    inputs and outputs
  - Programmatically detectable errors, including encapsulation of errors from
    packages it relies on
  - Operates under its own walletdb namespace
    
## Documentation

[![GoDoc](https://godoc.org/github.com/decred/dcrwallet/wtxmgr?status.png)]
(http://godoc.org/github.com/decred/dcrwallet/wtxmgr)

Full `go doc` style documentation for the project can be viewed online without
installing this package by using the GoDoc site here:
http://godoc.org/github.com/decred/dcrwallet/wtxmgr

You can also view the documentation locally once the package is installed with
the `godoc` tool by running `godoc -http=":6060"` and pointing your browser to
http://localhost:6060/pkg/github.com/decred/dcrwallet/wtxmgr

## Installation

```bash
$ go get github.com/decred/dcrwallet/wtxmgr
```

Package wtxmgr is licensed under the [copyfree](http://copyfree.org) ISC
License.
