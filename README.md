btcwallet
=========

[![Build Status](https://travis-ci.org/conformal/btcwallet.png?branch=master)]
(https://travis-ci.org/conformal/btcwallet)

btcwallet is a daemon handling bitcoin wallet functionality for a
single user.  It acts as both an RPC client to btcd and an RPC server
for wallet clients and legacy RPC applications.

The wallet file format is based on
[Armory](https://github.com/etotheipi/BitcoinArmory) and provides a
deterministic wallet where all future generated private keys can be
recovered from a previous wallet backup.  Unencrypted wallets are
unsupported and are never written to disk.  This design decision has
the consequence of generating new wallets on the fly impossible: a
client is required to provide a wallet encryption passphrase.

btcwallet is not an SPV client and requires connecting to a local or
remote btcd instance for asynchronous blockchain queries and
notifications over websockets.  Full btcd installation instructions
can be found [here](https://github.com/conformal/btcd).

As a daemon, btcwallet provides no user interface and an additional
graphical or command line client is required for normal, personal
wallet usage.  Conformal has written
[btcgui](https://github.com/conformal/btcgui) as a graphical client
to btcwallet.

This project is currently under active development is not production
ready yet.  Support for creating and using wallets the main Bitcoin
network is currently disabled by default.

## Installation

### Windows - MSI Available

Install the btcd suite MSI here:

https://opensource.conformal.com/packages/windows/btcdsuite/

### Linux/BSD/POSIX - Build from Source

- Install Go according to the installation instructions here:
  http://golang.org/doc/install

- Run the following commands to obtain and install btcwallet and all
  dependencies:
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

https://opensource.conformal.com/packages/windows/btcdsuite/

### Linux/BSD/POSIX - Build from Source

- Run the following commands to update btcwallet, all dependencies, and install it:

```bash
$ go get -u -v github.com/conformal/btcd/...
$ go get -u -v github.com/conformal/btcwallet/...
```

## Getting Started

The follow instructions detail how to get started with btcwallet
connecting to a localhost btcd.

### Windows (Installed from MSI)

Open ```Btcd Suite``` from the ```Btcd Suite``` menu in the Start
Menu.  This will also open btcgui, which can be closed if you only
want btcd and btcwallet running.

### Linux/BSD/POSIX/Source

- Run the following command to start btcd:

```bash
$ btcd --testnet -u rpcuser -P rpcpass
```

- Run the following command to start btcwallet:

```bash
$ btcwallet -u rpcuser -P rpcpass
```

If everything appears to be working, it is recommended at this point to
copy the sample btcd and btcwallet configurations and update with your
RPC username and password.

```bash
$ cp $GOPATH/src/github.com/conformal/btcd/sample-btcd.conf ~/.btcd/btcd.conf
$ cp $GOPATH/src/github.com/conformal/btcwallet/sample-btcwallet.conf ~/.btcwallet/btcwallet.conf
$ $EDITOR ~/.btcd/btcd.conf
$ $EDITOR ~/.btcwallet/btcwallet.conf
```

## Client Usage

Clients wishing to use btcwallet must connect to the `ws` endpoint
over a websocket connection.  Messages sent to btcwallet over this
websocket are expected to follow the standard Bitcoin JSON API
(partially documented
[here](https://en.bitcoin.it/wiki/Original_Bitcoin_client/API_Calls_list)).
Websocket connections also enable additional API extensions and
JSON-RPC notifications (currently undocumented).  The btcd packages
`btcjson` and `btcws` provide types and functions for creating and
JSON (un)marshaling these requests and notifications.

## Issue Tracker

The [integrated github issue tracker](https://github.com/conformal/btcwallet/issues)
is used for this project.

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
