module github.com/btcsuite/btcwallet/wallet/txauthor

go 1.12

require (
	github.com/btcsuite/btcd v0.22.0-beta.0.20220111222628-c5e6d3cf5f56
	github.com/btcsuite/btcd/btcutil v1.0.0
	github.com/btcsuite/btcwallet/wallet/txrules v1.0.0
	github.com/btcsuite/btcwallet/wallet/txsizes v1.0.0
)

replace github.com/btcsuite/btcwallet/wallet/txrules => ../txrules

replace github.com/btcsuite/btcwallet/wallet/txsizes => ../txsizes
