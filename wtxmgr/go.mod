module github.com/btcsuite/btcwallet/wtxmgr

require (
	github.com/btcsuite/btcd v0.24.3-0.20250318170759-4f4ea81776d6
	github.com/btcsuite/btcd/btcutil v1.1.6
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/btcsuite/btclog v1.0.0
	github.com/btcsuite/btcwallet v0.0.0
	github.com/btcsuite/btcwallet/walletdb v1.5.1
	github.com/lightningnetwork/lnd/clock v1.0.1
	github.com/mattn/go-sqlite3 v1.14.32
	github.com/stretchr/testify v1.11.1
)

replace github.com/btcsuite/btcwallet => ../

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.5 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.etcd.io/bbolt v1.3.11 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

go 1.24.6
