package chain

import (
	"time"

	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"github.com/roasbeef/btcwallet/waddrmgr"
	"github.com/roasbeef/btcwallet/wtxmgr"
)

// Interface allows more than one backing blockchain source, such as a
// btcd RPC chain server, or an SPV library, as long as we write a driver for
// it.
type Interface interface {
	Start() error
	Stop()
	WaitForShutdown()
	GetBestBlock() (*chainhash.Hash, int32, error)
	GetBlock(*chainhash.Hash) (*wire.MsgBlock, error)
	GetBlockHash(int64) (*chainhash.Hash, error)
	BlockStamp() (*waddrmgr.BlockStamp, error)
	SendRawTransaction(*wire.MsgTx, bool) (*chainhash.Hash, error)
	Rescan(*chainhash.Hash, []btcutil.Address, []*wire.OutPoint) error
	NotifyReceived([]btcutil.Address) error
	NotifyBlocks() error
	Notifications() <-chan interface{}
}

// Notification types.  These are defined here and processed from from reading
// a notificationChan to avoid handling these notifications directly in
// btcrpcclient callbacks, which isn't very Go-like and doesn't allow
// blocking client calls.
type (
	// ClientConnected is a notification for when a client connection is
	// opened or reestablished to the chain server.
	ClientConnected struct{}

	// BlockConnected is a notification for a newly-attached block to the
	// best chain.
	BlockConnected wtxmgr.BlockMeta

	// FilteredBlockConnected is an alternate notification that contains
	// both block and relevant transaction information in one struct, which
	// allows atomic updates.
	FilteredBlockConnected struct {
		Block       *wtxmgr.BlockMeta
		RelevantTxs []*wtxmgr.TxRecord
	}

	// BlockDisconnected is a notifcation that the block described by the
	// BlockStamp was reorganized out of the best chain.
	BlockDisconnected wtxmgr.BlockMeta

	// RelevantTx is a notification for a transaction which spends wallet
	// inputs or pays to a watched address.
	RelevantTx struct {
		TxRecord *wtxmgr.TxRecord
		Block    *wtxmgr.BlockMeta // nil if unmined
	}

	// RescanProgress is a notification describing the current status
	// of an in-progress rescan.
	RescanProgress struct {
		Hash   *chainhash.Hash
		Height int32
		Time   time.Time
	}

	// RescanFinished is a notification that a previous rescan request
	// has finished.
	RescanFinished struct {
		Hash   *chainhash.Hash
		Height int32
		Time   time.Time
	}
)
