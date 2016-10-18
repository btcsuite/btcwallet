btcwallet
=========

[![Build Status](https://travis-ci.org/btcsuite/btcwallet.png?branch=master)](https://travis-ci.org/btcsuite/btcwallet)
[![Build status](https://ci.appveyor.com/api/projects/status/88nxvckdj8upqr36/branch/master?svg=true)](https://ci.appveyor.com/project/jrick/btcwallet/branch/master)

btcwallet is a daemon handling bitcoin wallet functionality for a
single user.  It acts as both an RPC client to btcd and an RPC server
for wallet clients and legacy RPC applications.

Public and private keys are derived using the hierarchical
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

Wallet clients can use one of two RPC servers:

  1. A legacy JSON-RPC server mostly compatible with Bitcoin Core

     The JSON-RPC server exists to ease the migration of wallet applications
     from Core, but complete compatibility is not guaranteed.  Some portions of
     the API (and especially accounts) have to work differently due to other
     design decisions (mostly due to BIP0044).  However, if you find a
     compatibility issue and feel that it could be reasonably supported, please
     report an issue.  This server is enabled by default.

  2. An experimental gRPC server

     The gRPC server uses a new API built for btcwallet, but the API is not
     stabilized and the server is feature gated behind a config option
     (`--experimentalrpclisten`).  If you don't mind applications breaking due
     to API changes, don't want to deal with issues of the legacy API, or need
     notifications for changes to the wallet, this is the RPC server to use.
     The gRPC server is documented [here](./rpc/documentation/README.md).

## Installation and updating

### Windows - MSIs Available

Install the latest MSIs available here:

https://github.com/jadeblaquiere/btcd/releases

https://github.com/jadeblaquiere/btcwallet/releases

### Windows/Linux/BSD/POSIX - Build from source

Building or updating from source requires the following build dependencies:

- **Go 1.5 or 1.6**

  Installation instructions can be found here: http://golang.org/doc/install.
  It is recommended to add `$GOPATH/bin` to your `PATH` at this point.

  **Note:** If you are using Go 1.5, you must manually enable the vendor
    experiment by setting the `GO15VENDOREXPERIMENT` environment variable to
    `1`.  This step is not required for Go 1.6.

- **Glide**

  Glide is used to manage project dependencies and provide reproducible builds.
  To install:

  `go get -u github.com/Masterminds/glide`

Unfortunately, the use of `glide` prevents a handy tool such as `go get` from
automatically downloading, building, and installing the source in a single
command.  Instead, the latest project and dependency sources must be first
obtained manually with `git` and `glide`, and then `go` is used to build and
install the project.

**Getting the source**:

For a first time installation, the project and dependency sources can be
obtained manually with `git` and `glide` (create directories as needed):

```
git clone https://github.com/btcsuite/btcwallet $GOPATH/src/github.com/btcsuite/btcwallet
cd $GOPATH/src/github.com/btcsuite/btcwallet
glide install
```

To update an existing source tree, pull the latest changes and install the
matching dependencies:

```
cd $GOPATH/src/github.com/btcsuite/btcwallet
git pull
glide install
```

**Building/Installing**:

The `go` tool is used to build or install (to `GOPATH`) the project.  Some
example build instructions are provided below (all must run from the `btcwallet`
project directory).

To build and install `btcwallet` and all helper commands (in the `cmd`
directory) to `$GOPATH/bin/`, as well as installing all compiled packages to
`$GOPATH/pkg/` (**use this if you are unsure which command to run**):

```
go install . ./cmd/...
```

To build a `btcwallet` executable and install it to `$GOPATH/bin/`:

```
go install
```

To build a `btcwallet` executable and place it in the current directory:

```
go build
```

## Getting Started

The following instructions detail how to get started with btcwallet connecting
to a localhost btcd.  Commands should be run in `cmd.exe` or PowerShell on
Windows, or any terminal emulator on *nix.

- Run the following command to start btcd:

```
btcd -u rpcuser -P rpcpass
```

- Run the following command to create a wallet:

```
btcwallet -u rpcuser -P rpcpass --create
```

- Run the following command to start btcwallet:

```
btcwallet -u rpcuser -P rpcpass
```

If everything appears to be working, it is recommended at this point to
copy the sample btcd and btcwallet configurations and update with your
RPC username and password.

PowerShell (Installed from MSI):
```
PS> cp "$env:ProgramFiles\Btcd Suite\Btcd\sample-btcd.conf" $env:LOCALAPPDATA\Btcd\btcd.conf
PS> cp "$env:ProgramFiles\Btcd Suite\Btcwallet\sample-btcwallet.conf" $env:LOCALAPPDATA\Btcwallet\btcwallet.conf
PS> $editor $env:LOCALAPPDATA\Btcd\btcd.conf
PS> $editor $env:LOCALAPPDATA\Btcwallet\btcwallet.conf
```

PowerShell (Installed from source):
```
PS> cp $env:GOPATH\src\github.com\btcsuite\btcd\sample-btcd.conf $env:LOCALAPPDATA\Btcd\btcd.conf
PS> cp $env:GOPATH\src\github.com\btcsuite\btcwallet\sample-btcwallet.conf $env:LOCALAPPDATA\Btcwallet\btcwallet.conf
PS> $editor $env:LOCALAPPDATA\Btcd\btcd.conf
PS> $editor $env:LOCALAPPDATA\Btcwallet\btcwallet.conf
```

Linux/BSD/POSIX (Installed from source):
```bash
$ cp $GOPATH/src/github.com/jadeblaquiere/btcd/sample-btcd.conf ~/.btcd/btcd.conf
$ cp $GOPATH/src/github.com/jadeblaquiere/btcwallet/sample-btcwallet.conf ~/.btcwallet/btcwallet.conf
$ $EDITOR ~/.btcd/btcd.conf
$ $EDITOR ~/.btcwallet/btcwallet.conf
```

## Issue Tracker

The [integrated github issue tracker](https://github.com/jadeblaquiere/btcwallet/issues)
is used for this project.

## GPG Verification Key

All official release tags are signed by Conformal so users can ensure the code
has not been tampered with and is coming from the btcsuite developers.  To
verify the signature perform the following:

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
