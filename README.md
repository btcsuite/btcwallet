dcrwallet
=========

dcrwallet is a daemon handling decred wallet functionality for a
single user.  It acts as both an RPC client to dcrd and an RPC server
for wallet clients and legacy RPC applications.

Public and private keys are derived using the heirarchical
deterministic format described by
[BIP0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
Unencrypted private keys are not supported and are never written to
disk.  dcrwallet uses the
`m/44'/<coin type>'/<account>'/<branch>/<address index>`
HD path for all derived addresses, as described by
[BIP0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Due to the sensitive nature of public data in a BIP0032 wallet,
dcrwallet provides the option of encrypting not just private keys, but
public data as well.  This is intended to thwart privacy risks where a
wallet file is compromised without exposing all current and future
addresses (public keys) managed by the wallet. While access to this
information would not allow an attacker to spend or steal coins, it
does mean they could track all transactions involving your addresses
and therefore know your exact balance.  In a future release, public data
encryption will extend to transactions as well.

dcrwallet is not an SPV client and requires connecting to a local or
remote dcrd instance for asynchronous blockchain queries and
notifications over websockets.  Full dcrd installation instructions
can be found [here](https://github.com/decred/dcrd).  An alternative
SPV mode that is compatible with dcrd is planned for a future release.

Mainnet support is currently disabled by default.  Use of dcrwallet on
mainnet requires passing the `--mainnet` flag on the command line or
adding `mainnet=1` to the configuration file.  Mainnet will be enabled
by default in a future release after further database changes and
testing.

## Installation

### Linux/BSD/POSIX - Build from Source

- Install Go according to the installation instructions here:
  http://golang.org/doc/install

- Run the following commands to obtain and install dcrwallet and all
  dependencies:
```bash
$ go get -u -v github.com/decred/dcrd/...
$ go get -u -v github.com/decred/dcrwallet/...
```

- dcrd and dcrwallet will now be installed in either ```$GOROOT/bin``` or
  ```$GOPATH/bin``` depending on your configuration.  If you did not already
  add to your system path during the installation, we recommend you do so now.

## Updating

### Linux/BSD/POSIX - Build from Source

- Run the following commands to update dcrwallet, all dependencies, and install it:

```bash
$ go get -u -v github.com/decred/dcrd/...
$ go get -u -v github.com/decred/dcrwallet/...
```

## Getting Started

The follow instructions detail how to get started with dcrwallet
connecting to a localhost dcrd.

### Linux/BSD/POSIX/Source

- Run the following command to start dcrd:

```bash
$ dcrd --testnet -u rpcuser -P rpcpass
```

- Run the following command to create a wallet:

```bash
$ dcrwallet -u rpcuser -P rpcpass --create
```

- Run the following command to start dcrwallet:

```bash
$ dcrwallet -u rpcuser -P rpcpass
```

If everything appears to be working, it is recommended at this point to
copy the sample dcrd and dcrwallet configurations and update with your
RPC username and password.

```bash
$ cp $GOPATH/src/github.com/decred/dcrd/sample-dcrd.conf ~/.dcrd/dcrd.conf
$ cp $GOPATH/src/github.com/decred/dcrwallet/sample-dcrwallet.conf ~/.dcrwallet/dcrwallet.conf
$ $EDITOR ~/.dcrd/dcrd.conf
$ $EDITOR ~/.dcrwallet/dcrwallet.conf
```

## Client Usage

Clients wishing to use dcrwallet are recommended to connect to the
`ws` endpoint over a websocket connection.
Websocket connections also enable additional API extensions and
JSON-RPC notifications (currently undocumented).  The dcrd packages
`dcrjson` and `dcrws` provide types and functions for creating and
JSON (un)marshaling these requests and notifications.

## Issue Tracker

The [integrated github issue tracker](https://github.com/decred/dcrwallet/issues)
is used for this project.

## License

dcrwallet is licensed under the liberal ISC License.
