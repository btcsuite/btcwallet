btcwallet
=========

btcwallet is a daemon handling bitcoin wallet functions.  It relies on
a running btcd instance for asynchronous blockchain queries and
notifications over websockets.

Full btcd installation instructions can be found
[here](https://github.com/conformal/btcd).

btcwallet runs as a daemon and provides no user interface for a
wallet.  A btcwallet frontend, such as
[btcgui](https://github.com/conformal/btcgui), is required to use
btcwallet.

In addition to the HTTP server run by btcd to provide HTTP and
websocket RPC, btcwallet requires an HTTP server of its own to provide
websocket connections to wallet frontends.  Websockets allow for
asynchronous queries, replies, and notifications between btcd and
btcwallet, as well as between btcwallet and any number of frontends.

This project is currently under active development is not production
ready yet.  Because of this, support for using the main Bitcoin is
currently disabled, and testnet must be used instead.

## Installation

### Windows - MSI Available

Install the btcd suite MSI here:

https://github.com/conformal/btcd/releases

### Linux/BSD/POSIX - Build from Source

- Install Go according to the installation instructions here:
  http://golang.org/doc/install

- Run the following commands to obtain btcwallet, all dependencies, and install it:
  ```bash
  $ go get -u -v github.com/conformal/btcd/...
  $ go get -u -v github.com/conformal/btcwallet/...
  ```

- btcd and btcwallet will now be installed in either ```$GOROOT/bin``` or
  ```$GOPATH/bin``` depending on your configuration.  If you did not already
  add to your system path during the installation, we recommend you do so now.

## Updating

### Windows

Install a newer btcd suite MSI here:

https://github.com/conformal/btcd/releases

### Linux/BSD/POSIX - Build from Source

- Run the following commands to update btcwallet, all dependencies, and install it:
  ```bash
  $ go get -u -v github.com/conformal/btcd/...
  $ go get -u -v github.com/conformal/btcwallet/...
  ```

## Getting Started

### Windows (Installed from MSI)

Open Btcd (Testnet) and Btcwallet from the Btcd Suite menu in the
Start Menu.

### Linux/BSD/POSIX/Source

- Run the following commands to start btcd and btcwallet:
  ```bash
  $ btcd --testnet -u rpcuser -P rpcpass
  $ btcwallet -u rpcuser -P rpcpass
  ```

## Frontend Usage

Frontends wishing to use btcwallet must connect to the websocket
`/wallet`.  Messages sent to btcwallet over this websocket are
expected to follow the standard [Bitcoin JSON
API](https://en.bitcoin.it/wiki/Original_Bitcoin_client/API_Calls_list)
and replies follow the same API.  The btcd package `btcjson` provides
types and functions for creating messages that this API.  However, due
to taking a synchronous protocol like HTTP and using it asynchronously
with websockets, it is recommend for frontends to use the JSON `id`
field as a sequence number so replies can be mapped back to the
messages they originated from.

## TODO

- Require authentication before wallet functionality can be accessed
- Serve websocket connections over TLS
- Rescan the blockchain for missed transactions
- Documentation (specifically the websocket API additions)
- Code cleanup
- Optimize
- Much much more.  Stay tuned.

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

## License

btcwallet is licensed under the liberal ISC License.
