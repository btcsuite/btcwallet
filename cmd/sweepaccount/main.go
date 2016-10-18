// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/jadeblaquiere/ctcd/btcjson"
	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcd/txscript"
	"github.com/jadeblaquiere/ctcd/wire"
	"github.com/jadeblaquiere/ctcrpcclient"
	"github.com/jadeblaquiere/ctcutil"
	"github.com/jadeblaquiere/ctcwallet/internal/cfgutil"
	"github.com/jadeblaquiere/ctcwallet/netparams"
	"github.com/jadeblaquiere/ctcwallet/wallet/txauthor"
	"github.com/jadeblaquiere/ctcwallet/wallet/txrules"
	"github.com/btcsuite/golangcrypto/ssh/terminal"
	"github.com/jessevdk/go-flags"
)

var (
	walletDataDirectory = btcutil.AppDataDir("btcwallet", false)
	newlineBytes        = []byte{'\n'}
)

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Stderr.Write(newlineBytes)
	os.Exit(1)
}

func errContext(err error, context string) error {
	return fmt.Errorf("%s: %v", context, err)
}

// Flags.
var opts = struct {
	TestNet3              bool                `long:"testnet" description:"Use the test bitcoin network (version 3)"`
	SimNet                bool                `long:"simnet" description:"Use the simulation bitcoin network"`
	RPCConnect            string              `short:"c" long:"connect" description:"Hostname[:port] of wallet RPC server"`
	RPCUsername           string              `short:"u" long:"rpcuser" description:"Wallet RPC username"`
	RPCCertificateFile    string              `long:"cafile" description:"Wallet RPC TLS certificate"`
	FeeRate               *cfgutil.AmountFlag `long:"feerate" description:"Transaction fee per kilobyte"`
	SourceAccount         string              `long:"sourceacct" description:"Account to sweep outputs from"`
	DestinationAccount    string              `long:"destacct" description:"Account to send sweeped outputs to"`
	RequiredConfirmations int64               `long:"minconf" description:"Required confirmations to include an output"`
}{
	TestNet3:              false,
	SimNet:                false,
	RPCConnect:            "localhost",
	RPCUsername:           "",
	RPCCertificateFile:    filepath.Join(walletDataDirectory, "rpc.cert"),
	FeeRate:               cfgutil.NewAmountFlag(txrules.DefaultRelayFeePerKb),
	SourceAccount:         "imported",
	DestinationAccount:    "default",
	RequiredConfirmations: 1,
}

// Parse and validate flags.
func init() {
	// Unset localhost defaults if certificate file can not be found.
	certFileExists, err := cfgutil.FileExists(opts.RPCCertificateFile)
	if err != nil {
		fatalf("%v", err)
	}
	if !certFileExists {
		opts.RPCConnect = ""
		opts.RPCCertificateFile = ""
	}

	_, err = flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	if opts.TestNet3 && opts.SimNet {
		fatalf("Multiple bitcoin networks may not be used simultaneously")
	}
	var activeNet = &netparams.MainNetParams
	if opts.TestNet3 {
		activeNet = &netparams.TestNet3Params
	} else if opts.SimNet {
		activeNet = &netparams.SimNetParams
	}

	if opts.RPCConnect == "" {
		fatalf("RPC hostname[:port] is required")
	}
	rpcConnect, err := cfgutil.NormalizeAddress(opts.RPCConnect, activeNet.RPCServerPort)
	if err != nil {
		fatalf("Invalid RPC network address `%v`: %v", opts.RPCConnect, err)
	}
	opts.RPCConnect = rpcConnect

	if opts.RPCUsername == "" {
		fatalf("RPC username is required")
	}

	certFileExists, err = cfgutil.FileExists(opts.RPCCertificateFile)
	if err != nil {
		fatalf("%v", err)
	}
	if !certFileExists {
		fatalf("RPC certificate file `%s` not found", opts.RPCCertificateFile)
	}

	if opts.FeeRate.Amount > 1e6 {
		fatalf("Fee rate `%v/kB` is exceptionally high", opts.FeeRate.Amount)
	}
	if opts.FeeRate.Amount < 1e2 {
		fatalf("Fee rate `%v/kB` is exceptionally low", opts.FeeRate.Amount)
	}
	if opts.SourceAccount == opts.DestinationAccount {
		fatalf("Source and destination accounts should not be equal")
	}
	if opts.RequiredConfirmations < 0 {
		fatalf("Required confirmations must be non-negative")
	}
}

// noInputValue describes an error returned by the input source when no inputs
// were selected because each previous output value was zero.  Callers of
// txauthor.NewUnsignedTransaction need not report these errors to the user.
type noInputValue struct {
}

func (noInputValue) Error() string { return "no input value" }

// makeInputSource creates an InputSource that creates inputs for every unspent
// output with non-zero output values.  The target amount is ignored since every
// output is consumed.  The InputSource does not return any previous output
// scripts as they are not needed for creating the unsinged transaction and are
// looked up again by the wallet during the call to signrawtransaction.
func makeInputSource(outputs []btcjson.ListUnspentResult) txauthor.InputSource {
	var (
		totalInputValue btcutil.Amount
		inputs          = make([]*wire.TxIn, 0, len(outputs))
		sourceErr       error
	)
	for _, output := range outputs {
		outputAmount, err := btcutil.NewAmount(output.Amount)
		if err != nil {
			sourceErr = fmt.Errorf(
				"invalid amount `%v` in listunspent result",
				output.Amount)
			break
		}
		if outputAmount == 0 {
			continue
		}
		if !saneOutputValue(outputAmount) {
			sourceErr = fmt.Errorf(
				"impossible output amount `%v` in listunspent result",
				outputAmount)
			break
		}
		totalInputValue += outputAmount

		previousOutPoint, err := parseOutPoint(&output)
		if err != nil {
			sourceErr = fmt.Errorf(
				"invalid data in listunspent result: %v",
				err)
			break
		}

		inputs = append(inputs, wire.NewTxIn(&previousOutPoint, nil))
	}

	if sourceErr == nil && totalInputValue == 0 {
		sourceErr = noInputValue{}
	}

	return func(btcutil.Amount) (btcutil.Amount, []*wire.TxIn, [][]byte, error) {
		return totalInputValue, inputs, nil, sourceErr
	}
}

// makeDestinationScriptSource creates a ChangeSource which is used to receive
// all correlated previous input value.  A non-change address is created by this
// function.
func makeDestinationScriptSource(rpcClient *btcrpcclient.Client, accountName string) txauthor.ChangeSource {
	return func() ([]byte, error) {
		destinationAddress, err := rpcClient.GetNewAddress(accountName)
		if err != nil {
			return nil, err
		}
		return txscript.PayToAddrScript(destinationAddress)
	}
}

func main() {
	err := sweep()
	if err != nil {
		fatalf("%v", err)
	}
}

func sweep() error {
	rpcPassword, err := promptSecret("Wallet RPC password")
	if err != nil {
		return errContext(err, "failed to read RPC password")
	}

	// Open RPC client.
	rpcCertificate, err := ioutil.ReadFile(opts.RPCCertificateFile)
	if err != nil {
		return errContext(err, "failed to read RPC certificate")
	}
	rpcClient, err := btcrpcclient.New(&btcrpcclient.ConnConfig{
		Host:         opts.RPCConnect,
		User:         opts.RPCUsername,
		Pass:         rpcPassword,
		Certificates: rpcCertificate,
		HTTPPostMode: true,
	}, nil)
	if err != nil {
		return errContext(err, "failed to create RPC client")
	}
	defer rpcClient.Shutdown()

	// Fetch all unspent outputs, ignore those not from the source
	// account, and group by their destination address.  Each grouping of
	// outputs will be used as inputs for a single transaction sending to a
	// new destination account address.
	unspentOutputs, err := rpcClient.ListUnspent()
	if err != nil {
		return errContext(err, "failed to fetch unspent outputs")
	}
	sourceOutputs := make(map[string][]btcjson.ListUnspentResult)
	for _, unspentOutput := range unspentOutputs {
		if !unspentOutput.Spendable {
			continue
		}
		if unspentOutput.Confirmations < opts.RequiredConfirmations {
			continue
		}
		if unspentOutput.Account != opts.SourceAccount {
			continue
		}
		sourceAddressOutputs := sourceOutputs[unspentOutput.Address]
		sourceOutputs[unspentOutput.Address] = append(sourceAddressOutputs, unspentOutput)
	}

	var privatePassphrase string
	if len(sourceOutputs) != 0 {
		privatePassphrase, err = promptSecret("Wallet private passphrase")
		if err != nil {
			return errContext(err, "failed to read private passphrase")
		}
	}

	var totalSwept btcutil.Amount
	var numErrors int
	var reportError = func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, format, args...)
		os.Stderr.Write(newlineBytes)
		numErrors++
	}
	for _, previousOutputs := range sourceOutputs {
		inputSource := makeInputSource(previousOutputs)
		destinationSource := makeDestinationScriptSource(rpcClient, opts.DestinationAccount)
		tx, err := txauthor.NewUnsignedTransaction(nil, opts.FeeRate.Amount,
			inputSource, destinationSource)
		if err != nil {
			if err != (noInputValue{}) {
				reportError("Failed to create unsigned transaction: %v", err)
			}
			continue
		}

		// Unlock the wallet, sign the transaction, and immediately lock.
		err = rpcClient.WalletPassphrase(privatePassphrase, 60)
		if err != nil {
			reportError("Failed to unlock wallet: %v", err)
			continue
		}
		signedTransaction, complete, err := rpcClient.SignRawTransaction(tx.Tx)
		_ = rpcClient.WalletLock()
		if err != nil {
			reportError("Failed to sign transaction: %v", err)
			continue
		}
		if !complete {
			reportError("Failed to sign every input")
			continue
		}

		// Publish the signed sweep transaction.
		txHash, err := rpcClient.SendRawTransaction(signedTransaction, false)
		if err != nil {
			reportError("Failed to publish transaction: %v", err)
			continue
		}

		outputAmount := btcutil.Amount(tx.Tx.TxOut[0].Value)
		fmt.Printf("Swept %v to destination account with transaction %v\n",
			outputAmount, txHash)
		totalSwept += outputAmount
	}

	numPublished := len(sourceOutputs) - numErrors
	transactionNoun := pickNoun(numErrors, "transaction", "transactions")
	if numPublished != 0 {
		fmt.Printf("Swept %v to destination account across %d %s\n",
			totalSwept, numPublished, transactionNoun)
	}
	if numErrors > 0 {
		return fmt.Errorf("Failed to publish %d %s", numErrors, transactionNoun)
	}

	return nil
}

func promptSecret(what string) (string, error) {
	fmt.Printf("%s: ", what)
	fd := int(os.Stdin.Fd())
	input, err := terminal.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(input), nil
}

func saneOutputValue(amount btcutil.Amount) bool {
	return amount >= 0 && amount <= btcutil.MaxSatoshi
}

func parseOutPoint(input *btcjson.ListUnspentResult) (wire.OutPoint, error) {
	txHash, err := chainhash.NewHashFromStr(input.TxID)
	if err != nil {
		return wire.OutPoint{}, err
	}
	return wire.OutPoint{Hash: *txHash, Index: input.Vout}, nil
}

func pickNoun(n int, singularForm, pluralForm string) string {
	if n == 1 {
		return singularForm
	}
	return pluralForm
}
