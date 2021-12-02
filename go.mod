module github.com/btcsuite/btcwallet

require (
	github.com/btcsuite/btcd v0.22.0-beta.0.20211130143938-780cc0889fd2
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/btcsuite/btcutil/psbt v1.0.3-0.20201208143702-a53e38424cce
	github.com/btcsuite/btcwallet/wallet/txauthor v1.1.0
	github.com/btcsuite/btcwallet/wallet/txrules v1.1.0
	github.com/btcsuite/btcwallet/wallet/txsizes v1.1.0
	github.com/btcsuite/btcwallet/walletdb v1.4.0
	github.com/btcsuite/btcwallet/wtxmgr v1.3.1-0.20211201210108-79de92f527dc
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792
	github.com/davecgh/go-spew v1.1.1
	github.com/golang/protobuf v1.4.2
	github.com/jessevdk/go-flags v1.4.0
	github.com/jrick/logrotate v1.0.0
	github.com/kkdai/bstream v0.0.0-20181106074824-b3251f7901ec // indirect
	github.com/lightninglabs/gozmq v0.0.0-20191113021534-d20a764486bf
	github.com/lightninglabs/neutrino v0.13.0
	github.com/lightningnetwork/lnd/ticker v1.0.0
	github.com/stretchr/testify v1.5.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20200813134508-3edf25e44fcc
	google.golang.org/genproto v0.0.0-20190201180003-4b09977fb922 // indirect
	google.golang.org/grpc v1.18.0
)

go 1.16
