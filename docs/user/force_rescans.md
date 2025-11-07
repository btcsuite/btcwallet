# Rebuilding transaction history

It is unlikely, but possible and unfortunate, that transaction history in the
wallet database may not represent reality.  This may be due to a programming
mistake or the transaction database becoming corrupted.  Thankfully, all
transactions are publicly recorded on the blockchain, and transactions
necessary for a fully functional wallet can be recovered.  This process is
called rescanning, and the following guide will demonstrate how to force such a
rescan.

Rescans are automatically performed each time the wallet syncs to the network.
These are used to "catch up" the wallet to the newest best block in the block
chain.  For example, the following log messages at startup indicate that an
out-of-sync wallet started a rescan for all addresses and unspent outputs since
some block.

```
13:45:03 2015-04-13 [INF] WLLT: Started rescan from block 00000000001703b1a9dfd4865d587cd3f3cbb2f8e6ce9b44668e78ad8d4a7377 (height 205921) for 1 address
...
13:45:49 2015-04-13 [INF] WLLT: Finished rescan for 1 address (synced to block 0000000005cecab1013ecb1275a3e0c9623c4a497a57b6b6bf0fc1525aca1fbf, height 335146)
```

During the rescan, relevant transactions from previously unseen blocks are added
to the wallet database and spend tracking is updated accordingly.  After the
rescan at startup finishes, a wallet is marked in sync with the chain.

When wallet is started without any transaction history, a rescan is performed
for all blocks since the creation date of the wallet's first address.  There are
two situations when this holds true:

1. The wallet is newly created or was recreated from the seed
2. The transaction history is explicitly deleted

The second case is how a forced rescan is performed.

btcwallet will not drop transaction history by itself, as this is something that
should not be necessary under normal wallet operation.  However, a tool,
`dropwtxmgr`, is provided in the `cmd/dropwtxmgr` directory which may be used to
drop the wallet transaction manager (wtxmgr) history from a wallet database.
The tool may already be installed in your PATH, but if not, installing it is easy:

```
$ cd $GOPATH/src/github.com/btcsuite/btcwallet/cmd/dropwtxmgr
$ go get
```

Dropping transaction history given the default database location can be
performed by stopping wallet (to release the database) and running the tool,
answering yes to the prompt:

```
$ dropwtxmgr
Database path: /home/username/.btcwallet/mainnet/wallet.db
Drop all btcwallet transaction history? [y/N] y
Dropping wtxmgr namespace
```

If the wallet database is in another location or transaction history for a
different network (e.g. testnet or simnet) must be dropped, the full database
path may be specified:

```
$ dropwtxmgr --db ~/.btcwallet/testnet/wallet.db
Database path: /home/username/.btcwallet/testnet/wallet.db
Drop all btcwallet transaction history? [y/N] y
Dropping wtxmgr namespace
```

After dropping transaction history, btcwallet may be restarted and a full rescan
will be triggered to sync the wallet:

```
$ btcwallet
14:05:31 2015-04-13 [INF] BTCW: No recorded transaction history -- needs full rescan
...
14:05:31 2015-04-13 [INF] WLLT: Started rescan from block 000000000000e37b0f99af2e434834123b5459e31e17937169ce81ed0cc4d61c (height 193191) for 1 address
...
14:07:06 2015-04-13 [INF] WLLT: Finished rescan for 1 address (synced to block 00000000049041b5bd7f8ac86c8f1d32065053aefbe8c31e25ed03ef015a725a, height 335482)

```
