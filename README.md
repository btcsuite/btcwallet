btcwallet
=========

btcwallet is a daemon handling bitcoin wallet functions.  It relies on
a running btcd instance for asynchronous blockchain queries and
notifications over websockets.

In addition to the HTTP server run by btcd to provide RPC and
websocket connections, btcwallet requires an HTTP server of its own to
provide websocket connections to wallet frontends.  Websockets allow for
asynchronous queries, replies, and notifications.

This project is currently under active development is not production
ready yet.

## Usage

Frontends wishing to use btcwallet must connect to the websocket
`/wallet`.  Messages sent to btcwallet over this websocket are
expected to follow the standard [Bitcoin JSON
API](https://en.bitcoin.it/wiki/Original_Bitcoin_client/API_Calls_list)
and replies follow the same API.  The btcd package `btcjson` provides
types and functions for creating messages that this API.  However, due
to taking a synchronous protocol like RPC and using it asynchronously,
it is recommend for frontends to use the JSON `id` field as a sequence
number so replies can be mapped back to the messages they originated
from.

## Installation

btcwallet can be installed with the go get command:

```bash
go get github.com/conformal/btcwallet
```

## Running

To run btcwallet, you must have btcd installed and running.  By
default btcd will run its HTTP server for RPC and websocket
connections on port 8332.  However, bitcoind frontends expecting
wallet functionality may require to poll on port 8332, requiring the
btcd component in a btcwallet+btcd replacement stack to run on an
alternate port.  For this reason, btcwallet by default connects to
btcd on port 8334 and runs its own HTTP server on 8332.  When using
both btcd and btcwallet, it is recommend to run btcd on the
non-standard port 8334 using the `-r` command line flag.

Assumming btcd is running on port 8334, btcwallet can be
started by running:

```bash
btcwallet -f /path/to/wallet
```

## GPG Verification Key

All official release tags are signed by Conformal so users can ensure the code
has not been tampered with and is coming from Conformal.  To verify the
signature perform the following:

- Download the public key from the Conformal website at
  https://opensource.conformal.com/GIT-GPG-KEY-conformal.txt

- Import the public key into your GPG keyring:
  ```bash
  gpg --import GIT-GPG-KEY-conformal.txt
  ```

- Verify the release tag with the following command where `TAG_NAME` is a
  placeholder for the specific tag:
  ```bash
  git tag -v TAG_NAME
  ```

## What works
- New addresses can be queried if they are in the wallet file address pool
- Unknown commands are sent to btcd
- Unhandled btcd notifications (i.e. new blockchain height) are sent to each
  connected frontend
- btcd replies are routed back to the correct frontend who initiated the request

## TODO
- Create a new wallet if one is not available
- Update UTXO database based on btcd notifications
- Require authentication before wallet functionality can be accessed
- Support TLS
- Documentation
- Code cleanup
- Optimize
- Much much more.  Stay tuned.

## License

btcwallet is licensed under the liberal ISC License.
