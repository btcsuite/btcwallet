# Offline wallets

Cold wallets may be monitored using a watching only wallet. A watching only 
wallet is created using an extended public key for an account.

An extended key for your cold wallet can be retrieved using the 'getmasterpubkey'
command in the legacy API. Without any argument it will return the default 
account extended public key. Other accounts may be retrieved by supplying the 
account as an argument.

A wallet is then created using the public key, by the following command:

```
dcrwallet --create --createwatchingonly
```

This wallet can safely be connected to an online daemon and used to monitor the 
cold wallet. It can be used to get new addresses and supply a UTXO list with 
the command 'listunspent'.

Cold wallets are typically used in the following configuration:
1. Online computer computer with both a hot wallet used to handle funds and a 
    watch only wallet configured to watch an account from the cold wallet.
2. Offline computer with a cold wallet.

When a portion of the cold wallet is needed to be spent, the user can produce 
a list of UTXOs to spend by fetching them from the watching only wallet. A 
transaction can be created using these UTXOs, and the funds transferred to the 
hot wallet so they can be spent somewhere online without posing a danger of 
losing other funds from the cold wallet.

A tool has been created to help easily move offline funds on *nix machines. 
This tool is located in cmd/movefunds and can be installed as follows, 
granted that dcrd and dcrwallet are installed and vendored dependencies 
are up to date with glide:

```
cd $GOPATH/src/github.com/dcrwallet/cmd/movefunds
go install
```

You may also have to install jq on the cold wallet machine. For debian-based 
builds, you can use apt-get or build yourself.

```
sudo apt-get install jq
```

To move coins from the cold wallet without having to connect to the network, 
the following procedure can be done:

1. On the machine with the watching only wallet, call 'listunspent' and pipe 
    the output to unspent.json (dcrctl --wallet listunspent > unspent.json). 
	Next, run:
	```
	dcrctl --wallet accountaddressindex myAccountName 0
	dcrctl --wallet accountaddressindex myAccountName 1
	```
	Where myAccountName is the name of the account you're using in the 
	cold wallet. Write the output of these commands down somewhere.
	
2. Open unspent.json and remove any outputs you do not want to spend.

3. Open a terminal and change directory to where unspent.json is. Then, copy 
    config.json from $GOPATH/src/github.com/dcrwallet/cmd/movefunds to 
	this directory.
	```
	cp $GOPATH/src/github.com/dcrwallet/cmd/movefunds/config.json config.json
	```
    Edit config.json according to the network you're sending the funds on. 
    Fill in a recipient address there.

4. Run movefunds. It will generate sign.sh. Transfer sign.sh to the cold 
    wallet machine.

5. Start an unsynced daemon on the offline cold wallet machine. This is 
    achieved simply by adding the argument --connect=127.0.0.1:12345 to the 
	command to start the daemon. Because there is no local peer at port 
	12345, the daemon will sit idle at the genesis block.
	
6. Connect dcrwallet on the cold machine. Synchronize the addresses on this 
    wallet using the command and the responses you got at step 1:
	```
	dcrctl --wallet accountsyncaddressindex myAccountName 0 <response1>
	dcrctl --wallet accountsyncaddressindex myAccountName 1 <response2>
	```
	Your cold wallet address manager will now be in sync with your hot 
	wallet.
	
7. Run sign.sh on the cold wallet machine and pipe the output to a file:
    ```
	./sign.sh > rawtx.txt
    ```
	Transfer the raw hex of the transaction to the hot wallet machine.
	
8. Send the raw transaction on the hot wallet machine.
    ```
	dcrctl sendrawtransaction $(cat rawtx.txt)
    ```