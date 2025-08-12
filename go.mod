module github.com/btcsuite/btcwallet

require (
	github.com/btcsuite/btcd v0.24.3-0.20250318170759-4f4ea81776d6
	github.com/btcsuite/btcd/btcec/v2 v2.3.4
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/btcsuite/btcd/btcutil/psbt v1.1.8
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/btcsuite/btcwallet/wallet/txauthor v1.3.5
	github.com/btcsuite/btcwallet/wallet/txrules v1.2.2
	github.com/btcsuite/btcwallet/wallet/txsizes v1.2.5
	github.com/btcsuite/btcwallet/walletdb v1.5.1
	github.com/btcsuite/btcwallet/wtxmgr v1.5.6
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0
	github.com/golang/protobuf v1.5.4
	github.com/jessevdk/go-flags v1.4.0
	github.com/jrick/logrotate v1.0.0
	github.com/lightninglabs/gozmq v0.0.0-20191113021534-d20a764486bf
	github.com/lightninglabs/neutrino v0.16.0
	github.com/lightninglabs/neutrino/cache v1.1.2
	github.com/lightningnetwork/lnd/fn/v2 v2.0.2
	github.com/lightningnetwork/lnd/ticker v1.0.0
	github.com/lightningnetwork/lnd/tlv v1.0.2
	github.com/stretchr/testify v1.10.0
	golang.org/x/crypto v0.37.0
	golang.org/x/net v0.38.0
	golang.org/x/sync v0.15.0
	golang.org/x/term v0.31.0
	google.golang.org/grpc v1.73.0
)

require (
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/decred/dcrd/lru v1.1.2 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/lightningnetwork/lnd/clock v1.0.1 // indirect
	github.com/lightningnetwork/lnd/queue v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	go.etcd.io/bbolt v1.3.11 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250603155806-513f23925822 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

go 1.23.0
