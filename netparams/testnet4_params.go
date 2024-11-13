package netparams

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"math/big"
	"time"
)

const Testnet4 wire.BitcoinNet = 0x1c163f28

var TestNet4ChainParams = chaincfg.Params{
	Name:        "testnet4",
	Net:         Testnet4,
	DefaultPort: "48333",
	DNSSeeds: []chaincfg.DNSSeed{
		{"seed.testnet4.bitcoin.sprovoost.nl", true},
		{"seed.testnet4.wiz.biz", true},
	},

	//// Chain parameters
	GenesisBlock:             &testNet4GenesisBlock,
	GenesisHash:              testNet4GenesisHash,
	PowLimit:                 testNet3PowLimit,
	PowLimitBits:             0x1d00ffff,
	BIP0034Height:            1,
	BIP0065Height:            1,
	BIP0066Height:            1,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []chaincfg.Checkpoint{},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 1512, // 75% of MinerConfirmationWindow
	MinerConfirmationWindow:       2016,
	Deployments: [chaincfg.DefinedDeployments]chaincfg.ConsensusDeployment{
		chaincfg.DeploymentTestDummy: {
			BitNumber: 28,
			DeploymentStarter: chaincfg.NewMedianTimeDeploymentStarter(
				time.Unix(1199145601, 0), // January 1, 2008 UTC
			),
			DeploymentEnder: chaincfg.NewMedianTimeDeploymentEnder(
				time.Unix(1230767999, 0), // December 31, 2008 UTC
			),
		},
		chaincfg.DeploymentTaproot: {
			BitNumber:           2,
			DeploymentStarter:   alwaysOkStarter,
			DeploymentEnder:     alwaysOkStarter,
			MinActivationHeight: 0,
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "tb", // always tb for test net

	// Address encoding magics
	PubKeyHashAddrID:        0x6f, // starts with m or n
	ScriptHashAddrID:        0xc4, // starts with 2
	WitnessPubKeyHashAddrID: 0x03, // starts with QW
	WitnessScriptHashAddrID: 0x28, // starts with T7n
	PrivateKeyID:            0xef, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}

// testNet3GenesisHash is the hash of the first block in the block chain for the
// test network (version 3).
var testNet4GenesisHash, _ = chainhash.NewHashFromStr("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043")

// testNet3GenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test network (version 3).  It is the same as the merkle root
// for the main network.
var testNet4GenesisMerkleRoot, _ = chainhash.NewHashFromStr("7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e")

// testNet3GenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var testNet4GenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{}, // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: *testNet4GenesisMerkleRoot,
		Timestamp:  time.Unix(1714777860, 0),
		Bits:       0x1d00ffff, // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      393743547,  // 393743547
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the main network, regression test network, and test network (version 3).
var genesisCoinbaseTx = wire.MsgTx{
	Version: 1,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0xffffffff,
			},
			SignatureScript: sigScript,
			Sequence:        0xffffffff,
		},
	},
	TxOut: []*wire.TxOut{
		{
			Value:    0x12a05f200,
			PkScript: scriptPubKey,
		},
	},
	LockTime: 0,
}

// create genesis block for testnet4

var sigScript, _ = hex.DecodeString("04ffff001d01044c4c30332f4d61792f323032342030303030303030303030303030303030303030303165626435386332343439373062336161396437383362623030313031316662653865613865393865303065")
var scriptPubKey, _ = hex.DecodeString("21000000000000000000000000000000000000000000000000000000000000000000ac")

var testNet3PowLimit = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 224), big.NewInt(1))

var alwaysOkStarter = &alwaysStarted{}

type alwaysStarted struct {
}

func (a *alwaysStarted) HasStarted(*wire.BlockHeader) (bool, error) {
	return true, nil
}
func (a *alwaysStarted) HasEnded(*wire.BlockHeader) (bool, error) {
	return true, nil
}
