package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/neutrino"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/blockntfns"
	"github.com/lightninglabs/neutrino/headerfs"
	"github.com/stretchr/testify/require"
)

var errWalletNeutrinoNotImplemented = errors.New("not implemented")

type walletNeutrinoMode struct {
	name           string
	useActorRescan bool
}

var walletNeutrinoModes = []walletNeutrinoMode{
	{name: "legacy"},
	{name: "actor", useActorRescan: true},
}

type walletNeutrinoChainSource struct {
	heights map[chainhash.Hash]uint32
	headers map[uint32]*wire.BlockHeader
	best    headerfs.BlockStamp
	params  chaincfg.Params
}

func newWalletNeutrinoChainSource(bestHeight uint32,
	params chaincfg.Params) *walletNeutrinoChainSource {

	headers := make(map[uint32]*wire.BlockHeader, bestHeight+1)
	heights := make(map[chainhash.Hash]uint32, bestHeight+1)

	var prevHash chainhash.Hash
	for height := uint32(0); height <= bestHeight; height++ {
		header := params.GenesisBlock.Header
		if height != 0 {
			header = wire.BlockHeader{
				Version:    int32(height + 1),
				PrevBlock:  prevHash,
				Timestamp:  time.Unix(int64(height), 0),
				Bits:       uint32(height + 1),
				Nonce:      height,
				MerkleRoot: chainhash.Hash{byte(height + 1)},
			}
		}

		hash := header.BlockHash()
		headerCopy := header
		headers[height] = &headerCopy
		heights[hash] = height
		prevHash = hash
	}

	bestHeader := headers[bestHeight]

	return &walletNeutrinoChainSource{
		heights: heights,
		headers: headers,
		best: headerfs.BlockStamp{
			Hash:      bestHeader.BlockHash(),
			Height:    int32(bestHeight),
			Timestamp: bestHeader.Timestamp,
		},
		params: params,
	}
}

func (m *walletNeutrinoChainSource) ChainParams() chaincfg.Params {
	return m.params
}

func (m *walletNeutrinoChainSource) BestBlock() (*headerfs.BlockStamp, error) {
	best := m.best
	return &best, nil
}

func (m *walletNeutrinoChainSource) GetBlockHeaderByHeight(
	height uint32) (*wire.BlockHeader, error) {

	header, ok := m.headers[height]
	if !ok {
		return nil, fmt.Errorf("unknown height %d", height)
	}

	headerCopy := *header
	return &headerCopy, nil
}

func (m *walletNeutrinoChainSource) GetBlockHeader(
	hash *chainhash.Hash) (*wire.BlockHeader, uint32, error) {

	height, ok := m.heights[*hash]
	if !ok {
		return nil, 0, fmt.Errorf("unknown hash %v", hash)
	}

	header := m.headers[height]
	headerCopy := *header
	return &headerCopy, height, nil
}

func (m *walletNeutrinoChainSource) GetBlock(chainhash.Hash,
	...neutrino.QueryOption) (*btcutil.Block, error) {

	return nil, errWalletNeutrinoNotImplemented
}

func (m *walletNeutrinoChainSource) GetFilterHeaderByHeight(
	uint32) (*chainhash.Hash, error) {

	zero := chainhash.Hash{}
	return &zero, nil
}

func (m *walletNeutrinoChainSource) GetCFilter(chainhash.Hash,
	wire.FilterType, ...neutrino.QueryOption) (*gcs.Filter, error) {

	return nil, nil
}

func (m *walletNeutrinoChainSource) Subscribe(
	uint32) (*blockntfns.Subscription, error) {

	ntfns := make(chan blockntfns.BlockNtfn)
	var once sync.Once

	return &blockntfns.Subscription{
		Notifications: ntfns,
		Cancel: func() {
			once.Do(func() {
				close(ntfns)
			})
		},
	}, nil
}

func (m *walletNeutrinoChainSource) IsCurrent() bool {
	return true
}

var _ neutrino.ChainSource = (*walletNeutrinoChainSource)(nil)

type walletNeutrinoService struct {
	source  *walletNeutrinoChainSource
	sentMtx sync.Mutex
	sentTxs []*wire.MsgTx
}

func (m *walletNeutrinoService) Start(context.Context) error {
	return nil
}

func (m *walletNeutrinoService) GetBlock(chainhash.Hash,
	...neutrino.QueryOption) (*btcutil.Block, error) {

	return nil, errWalletNeutrinoNotImplemented
}

func (m *walletNeutrinoService) GetBlockHeight(
	hash *chainhash.Hash) (int32, error) {

	_, height, err := m.source.GetBlockHeader(hash)
	return int32(height), err
}

func (m *walletNeutrinoService) BestBlock() (*headerfs.BlockStamp, error) {
	return m.source.BestBlock()
}

func (m *walletNeutrinoService) GetBlockHash(height int64) (
	*chainhash.Hash, error) {

	header, err := m.source.GetBlockHeaderByHeight(uint32(height))
	if err != nil {
		return nil, err
	}

	hash := header.BlockHash()
	return &hash, nil
}

func (m *walletNeutrinoService) GetBlockHeader(
	hash *chainhash.Hash) (*wire.BlockHeader, error) {

	header, _, err := m.source.GetBlockHeader(hash)
	return header, err
}

func (m *walletNeutrinoService) IsCurrent() bool {
	return m.source.IsCurrent()
}

func (m *walletNeutrinoService) SendTransaction(tx *wire.MsgTx) error {
	m.sentMtx.Lock()
	defer m.sentMtx.Unlock()

	m.sentTxs = append(m.sentTxs, tx.Copy())
	return nil
}

func (m *walletNeutrinoService) GetCFilter(chainhash.Hash,
	wire.FilterType, ...neutrino.QueryOption) (*gcs.Filter, error) {

	return nil, nil
}

func (m *walletNeutrinoService) GetUtxo(
	...neutrino.RescanOption) (*neutrino.SpendReport, error) {

	return nil, errWalletNeutrinoNotImplemented
}

func (m *walletNeutrinoService) BanPeer(string, banman.Reason) error {
	return errWalletNeutrinoNotImplemented
}

func (m *walletNeutrinoService) IsBanned(string) bool {
	return false
}

func (m *walletNeutrinoService) AddPeer(*neutrino.ServerPeer) {}

func (m *walletNeutrinoService) AddBytesSent(uint64) {}

func (m *walletNeutrinoService) AddBytesReceived(uint64) {}

func (m *walletNeutrinoService) NetTotals() (uint64, uint64) {
	return 0, 0
}

func (m *walletNeutrinoService) UpdatePeerHeights(*chainhash.Hash, int32,
	*neutrino.ServerPeer) {
}

func (m *walletNeutrinoService) ChainParams() chaincfg.Params {
	return m.source.params
}

func (m *walletNeutrinoService) Stop() error {
	return nil
}

func (m *walletNeutrinoService) PeerByAddr(string) *neutrino.ServerPeer {
	return nil
}

func (m *walletNeutrinoService) sentTransactions() []*wire.MsgTx {
	m.sentMtx.Lock()
	defer m.sentMtx.Unlock()

	sent := make([]*wire.MsgTx, len(m.sentTxs))
	copy(sent, m.sentTxs)
	return sent
}

var _ chain.NeutrinoChainService = (*walletNeutrinoService)(nil)

func newWalletWithNeutrinoBackend(t *testing.T, mode walletNeutrinoMode,
	withRescanManager bool) (*Wallet, *chain.NeutrinoClient,
	*walletNeutrinoService) {

	t.Helper()

	w, cleanup := testWallet(t)
	t.Cleanup(cleanup)

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := w.Manager.SetBirthday(
			ns, chaincfg.TestNet3Params.GenesisBlock.Header.Timestamp,
		)
		if err != nil {
			return err
		}

		return w.Manager.SetBirthdayBlock(ns, waddrmgr.BlockStamp{
			Hash:      *chaincfg.TestNet3Params.GenesisHash,
			Height:    0,
			Timestamp: chaincfg.TestNet3Params.GenesisBlock.Header.Timestamp,
		}, true)
	})
	require.NoError(t, err)

	source := newWalletNeutrinoChainSource(
		0, chaincfg.TestNet3Params,
	)
	service := &walletNeutrinoService{source: source}
	client := chain.NewNeutrinoClientWithChainSource(
		&chaincfg.TestNet3Params, service, source,
		mode.useActorRescan,
	)

	require.NoError(t, client.Start(t.Context()))
	w.chainClient = client

	if withRescanManager {
		w.wg.Add(2)
		go w.rescanBatchHandler()
		go w.rescanRPCHandler()
	}

	t.Cleanup(func() {
		w.quitMu.Lock()
		select {
		case <-w.quit:
		default:
			close(w.quit)
		}
		w.quitMu.Unlock()
		client.Stop()
		client.WaitForShutdown()
		w.WaitForShutdown()
	})

	return w, client, service
}

func requireWalletHasAddress(t *testing.T, w *Wallet, addr btcutil.Address) {
	t.Helper()

	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		_, err := w.Manager.Address(ns, addr)
		return err
	})
	require.NoError(t, err)
}

func newTestWIF(t *testing.T) *btcutil.WIF {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	wif, err := btcutil.NewWIF(
		privKey, &chaincfg.TestNet3Params, true,
	)
	require.NoError(t, err)

	return wif
}

func newTestTaprootScript(t *testing.T) (*waddrmgr.Tapscript, btcutil.Address) {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	outputKey := txscript.ComputeTaprootKeyNoScript(privKey.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), &chaincfg.TestNet3Params,
	)
	require.NoError(t, err)

	return &waddrmgr.Tapscript{
		Type:          waddrmgr.TaprootFullKeyOnly,
		FullOutputKey: outputKey,
	}, addr
}

func addWalletNeutrinoUtxo(t *testing.T, w *Wallet, incomingTx *wire.MsgTx) {
	t.Helper()

	var b bytes.Buffer
	require.NoError(t, incomingTx.Serialize(&b))

	rec, err := wtxmgr.NewTxRecord(b.Bytes(), time.Now())
	require.NoError(t, err)

	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   *chaincfg.TestNet3Params.GenesisHash,
			Height: 0,
		},
		Time: chaincfg.TestNet3Params.GenesisBlock.Header.Timestamp,
	}

	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		err = w.TxStore.InsertTx(ns, rec, block)
		if err != nil {
			return err
		}

		for i := range incomingTx.TxOut {
			err = w.TxStore.AddCredit(
				ns, rec, block, uint32(i), false,
			)
			if err != nil {
				return err
			}
		}

		return nil
	})
	require.NoError(t, err)
}

func TestWalletAddressesWithNeutrinoRescanBackends(t *testing.T) {
	for _, mode := range walletNeutrinoModes {
		t.Run(mode.name, func(t *testing.T) {
			w, _, _ := newWalletWithNeutrinoBackend(t, mode, false)

			addr, err := w.NewAddress(
				waddrmgr.DefaultAccountNum,
				waddrmgr.KeyScopeBIP0084,
			)
			require.NoError(t, err)
			require.NotNil(t, addr)

			changeAddr, err := w.NewChangeAddress(
				waddrmgr.DefaultAccountNum,
				waddrmgr.KeyScopeBIP0084,
			)
			require.NoError(t, err)
			require.NotNil(t, changeAddr)
			require.NotEqual(
				t, addr.EncodeAddress(),
				changeAddr.EncodeAddress(),
			)
		})
	}
}

func TestWalletRescanWithNeutrinoRescanBackends(t *testing.T) {
	for _, mode := range walletNeutrinoModes {
		t.Run(mode.name, func(t *testing.T) {
			w, _, _ := newWalletWithNeutrinoBackend(t, mode, true)

			addr, err := w.NewAddress(
				waddrmgr.DefaultAccountNum,
				waddrmgr.KeyScopeBIP0084,
			)
			require.NoError(t, err)

			startStamp := &waddrmgr.BlockStamp{
				Hash:      *chaincfg.TestNet3Params.GenesisHash,
				Height:    0,
				Timestamp: chaincfg.TestNet3Params.GenesisBlock.Header.Timestamp,
			}

			err = w.rescanWithTarget(
				[]btcutil.Address{addr}, nil, startStamp,
			)
			require.NoError(t, err)
		})
	}
}

func TestWalletImportNotifyPathsWithNeutrinoRescanBackends(t *testing.T) {
	for _, mode := range walletNeutrinoModes {
		t.Run(mode.name, func(t *testing.T) {
			w, _, _ := newWalletWithNeutrinoBackend(t, mode, false)

			pubWIF := newTestWIF(t)
			pubAddr, err := btcutil.NewAddressWitnessPubKeyHash(
				btcutil.Hash160(
					pubWIF.PrivKey.PubKey().SerializeCompressed(),
				),
				&chaincfg.TestNet3Params,
			)
			require.NoError(t, err)

			err = w.ImportPublicKey(
				pubWIF.PrivKey.PubKey(), waddrmgr.WitnessPubKey,
			)
			require.NoError(t, err)
			requireWalletHasAddress(t, w, pubAddr)

			privWIF := newTestWIF(t)
			addrStr, err := w.ImportPrivateKey(
				waddrmgr.KeyScopeBIP0084, privWIF, nil, false,
			)
			require.NoError(t, err)

			addr, err := btcutil.DecodeAddress(
				addrStr, &chaincfg.TestNet3Params,
			)
			require.NoError(t, err)
			requireWalletHasAddress(t, w, addr)
		})
	}
}

func TestWalletImportRescanPathWithNeutrinoRescanBackends(t *testing.T) {
	for _, mode := range walletNeutrinoModes {
		t.Run(mode.name, func(t *testing.T) {
			w, _, _ := newWalletWithNeutrinoBackend(t, mode, true)

			privWIF := newTestWIF(t)
			addrStr, err := w.ImportPrivateKey(
				waddrmgr.KeyScopeBIP0084, privWIF, nil, true,
			)
			require.NoError(t, err)

			addr, err := btcutil.DecodeAddress(
				addrStr, &chaincfg.TestNet3Params,
			)
			require.NoError(t, err)
			requireWalletHasAddress(t, w, addr)
		})
	}
}

func TestWalletImportTaprootScriptWithNeutrinoRescanBackends(t *testing.T) {
	for _, mode := range walletNeutrinoModes {
		t.Run(mode.name, func(t *testing.T) {
			w, _, _ := newWalletWithNeutrinoBackend(t, mode, false)

			tapscript, expectedAddr := newTestTaprootScript(t)
			addr, err := w.ImportTaprootScript(
				waddrmgr.KeyScopeBIP0086, tapscript, nil, 1, false,
			)
			require.NoError(t, err)
			require.Equal(
				t, expectedAddr.EncodeAddress(),
				addr.Address().EncodeAddress(),
			)
			requireWalletHasAddress(t, w, expectedAddr)
		})
	}
}

func TestWalletPublishTransactionWithNeutrinoRescanBackends(t *testing.T) {
	for _, mode := range walletNeutrinoModes {
		t.Run(mode.name, func(t *testing.T) {
			w, _, service := newWalletWithNeutrinoBackend(
				t, mode, false,
			)

			addr, err := w.NewAddress(
				waddrmgr.DefaultAccountNum,
				waddrmgr.KeyScopeBIP0084,
			)
			require.NoError(t, err)

			pkScript, err := txscript.PayToAddrScript(addr)
			require.NoError(t, err)

			tx := wire.NewMsgTx(2)
			tx.AddTxIn(&wire.TxIn{})
			tx.AddTxOut(&wire.TxOut{
				Value:    1000,
				PkScript: pkScript,
			})

			err = w.PublishTransaction(tx, "wallet-neutrino-test")
			require.NoError(t, err)

			sent := service.sentTransactions()
			require.Len(t, sent, 1)
			require.Equal(t, tx.TxHash(), sent[0].TxHash())

			txHash := tx.TxHash()
			err = walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
				txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)
				details, err := w.TxStore.TxDetails(txmgrNs, &txHash)
				require.NoError(t, err)
				require.NotNil(t, details)
				return nil
			})
			require.NoError(t, err)
		})
	}
}

func TestWalletTxToOutputsWithNeutrinoRescanBackends(t *testing.T) {
	for _, mode := range walletNeutrinoModes {
		t.Run(mode.name, func(t *testing.T) {
			w, _, _ := newWalletWithNeutrinoBackend(t, mode, false)

			addr, err := w.CurrentAddress(
				waddrmgr.DefaultAccountNum,
				waddrmgr.KeyScopeBIP0049Plus,
			)
			require.NoError(t, err)

			pkScript, err := txscript.PayToAddrScript(addr)
			require.NoError(t, err)

			addWalletNeutrinoUtxo(t, w, &wire.MsgTx{
				TxIn: []*wire.TxIn{{}},
				TxOut: []*wire.TxOut{
					wire.NewTxOut(100000, pkScript),
				},
			})

			txOuts := []*wire.TxOut{
				{
					PkScript: pkScript,
					Value:    10000,
				},
				{
					PkScript: pkScript,
					Value:    20000,
				},
			}

			dryRunTx, err := w.txToOutputs(
				txOuts, nil, nil, waddrmgr.DefaultAccountNum, 1,
				1000, CoinSelectionLargest, true, nil,
				alwaysAllowUtxo,
			)
			require.NoError(t, err)
			require.GreaterOrEqual(t, dryRunTx.ChangeIndex, 0)

			addresses, err := w.AccountAddresses(
				waddrmgr.DefaultAccountNum,
			)
			require.NoError(t, err)
			require.Len(t, addresses, 1)

			tx, err := w.txToOutputs(
				txOuts, nil, nil, waddrmgr.DefaultAccountNum, 1,
				1000, CoinSelectionLargest, false, nil,
				alwaysAllowUtxo,
			)
			require.NoError(t, err)
			require.GreaterOrEqual(t, tx.ChangeIndex, 0)
			require.NoError(
				t, validateMsgTx(
					tx.Tx, tx.PrevScripts, tx.PrevInputValues,
				),
			)

			addresses, err = w.AccountAddresses(
				waddrmgr.DefaultAccountNum,
			)
			require.NoError(t, err)
			require.Len(t, addresses, 2)
			require.Equal(
				t,
				dryRunTx.Tx.TxOut[dryRunTx.ChangeIndex].PkScript,
				tx.Tx.TxOut[tx.ChangeIndex].PkScript,
			)

			_, changeAddrs, _, err := txscript.ExtractPkScriptAddrs(
				tx.Tx.TxOut[tx.ChangeIndex].PkScript, w.chainParams,
			)
			require.NoError(t, err)
			require.Len(t, changeAddrs, 1)
			requireWalletHasAddress(t, w, changeAddrs[0])
		})
	}
}
