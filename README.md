btcwallet
=========

[![Build Status](https://travis-ci.org/btcsuite/btcwallet.png?branch=master)]
(https://travis-ci.org/btcsuite/btcwallet)

btcwallet is a daemon handling bitcoin wallet functionality for a
single user.  It acts as both an RPC client to btcd and an RPC server
for wallet clients and legacy RPC applications.

Public and private keys are derived using the heirarchical
deterministic format described by
[BIP0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
Unencrypted private keys are not supported and are never written to
disk.  btcwallet uses the
`m/44'/<coin type>'/<account>'/<branch>/<address index>`
HD path for all derived addresses, as described by
[BIP0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Due to the sensitive nature of public data in a BIP0032 wallet,
btcwallet provides the option of encrypting not just private keys, but
public data as well.  This is intended to thwart privacy risks where a
wallet file is compromised without exposing all current and future
addresses (public keys) managed by the wallet. While access to this
information would not allow an attacker to spend or steal coins, it
does mean they could track all transactions involving your addresses
and therefore know your exact balance.  In a future release, public data
encryption will extend to transactions as well.

btcwallet is not an SPV client and requires connecting to a local or
remote btcd instance for asynchronous blockchain queries and
notifications over websockets.  Full btcd installation instructions
can be found [here](https://github.com/btcsuite/btcd).  An alternative
SPV mode that is compatible with btcd and Bitcoin Core is planned for
a future release.

No release-ready graphical frontends currently exist, however the
proof-of-concept [btcgui](https://github.com/btcsuite/btcgui) project
shows some of the possibilities of btcwallet.  In the coming months a
new stable RPC API is planned, at which point a high quality graphical
frontend can be finished.

Mainnet support is currently disabled by default.  Use of btcwallet on
mainnet requires passing the `--mainnet` flag on the command line or
adding `mainnet=1` to the configuration file.  Mainnet will be enabled
by default in a future release after further database changes and
testing.

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
$ go get -u -v github.com/btcsuite/btcd/...
$ go get -u -v github.com/btcsuite/btcwallet/...
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
$ go get -u -v github.com/btcsuite/btcd/...
$ go get -u -v github.com/btcsuite/btcwallet/...
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

- Run the following command to create a wallet:

```bash
$ btcwallet -u rpcuser -P rpcpass --create
```

- Run the following command to start btcwallet:

```bash
$ btcwallet -u rpcuser -P rpcpass
```

If everything appears to be working, it is recommended at this point to
copy the sample btcd and btcwallet configurations and update with your
RPC username and password.

```bash
$ cp $GOPATH/src/github.com/btcsuite/btcd/sample-btcd.conf ~/.btcd/btcd.conf
$ cp $GOPATH/src/github.com/btcsuite/btcwallet/sample-btcwallet.conf ~/.btcwallet/btcwallet.conf
$ $EDITOR ~/.btcd/btcd.conf
$ $EDITOR ~/.btcwallet/btcwallet.conf
```

## Client Usage

Clients wishing to use btcwallet are recommended to connect to the
`ws` endpoint over a websocket connection.  Messages sent to btcwallet
over this websocket are expected to follow the standard Bitcoin JSON
API (partially documented
[here](https://en.bitcoin.it/wiki/Original_Bitcoin_client/API_Calls_list)).
Websocket connections also enable additional API extensions and
JSON-RPC notifications (currently undocumented).  The btcd packages
`btcjson` and `btcws` provide types and functions for creating and
JSON (un)marshaling these requests and notifications.

## Issue Tracker

The [integrated github issue tracker](https://github.com/btcsuite/btcwallet/issues)
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
