module github.com/btcsuite/btcwallet

require (
	github.com/btcsuite/btcd v0.24.3-0.20250318170759-4f4ea81776d6
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/btcsuite/btcd/btcutil v1.1.6
	github.com/btcsuite/btcd/btcutil/psbt v1.1.10
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/btcsuite/btclog v1.0.0
	github.com/btcsuite/btcwallet/wallet/txauthor v1.3.5
	github.com/btcsuite/btcwallet/wallet/txrules v1.2.2
	github.com/btcsuite/btcwallet/wallet/txsizes v1.2.5
	github.com/btcsuite/btcwallet/walletdb v1.5.1
	github.com/btcsuite/btcwallet/wtxmgr v1.5.6
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/golang/protobuf v1.5.4
	github.com/jessevdk/go-flags v1.6.1
	github.com/jrick/logrotate v1.1.2
	github.com/lightninglabs/gozmq v0.0.0-20191113021534-d20a764486bf
	github.com/lightninglabs/neutrino v0.16.1
	github.com/lightninglabs/neutrino/cache v1.1.2
	github.com/lightningnetwork/lnd/fn/v2 v2.0.8
	github.com/lightningnetwork/lnd/ticker v1.1.1
	github.com/lightningnetwork/lnd/tlv v1.3.2
	github.com/stretchr/testify v1.10.0
	golang.org/x/crypto v0.41.0
	golang.org/x/net v0.43.0
	golang.org/x/sync v0.16.0
	golang.org/x/term v0.34.0
	google.golang.org/grpc v1.73.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/lru v1.1.2 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/lightningnetwork/lnd/clock v1.0.1 // indirect
	github.com/lightningnetwork/lnd/queue v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	go.etcd.io/bbolt v1.3.11 // indirect
	go.opentelemetry.io/otel v1.36.0 // indirect
	golang.org/x/exp v0.0.0-20240909161429-701f63a606c0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250603155806-513f23925822 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// If you change this please run `make lint` to see where else it needs to be
// updated as well.
go 1.24.6

// We use a replace directive here for our internal wtxmgr module. This ensures
// that we can freely move between tagged releases and development commits of
// this module without needing to constantly update the go.mod file.
replace github.com/btcsuite/btcwallet/wtxmgr => ./wtxmgr
