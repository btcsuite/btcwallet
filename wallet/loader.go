package wallet

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrutil/hdkeychain"
	"github.com/decred/dcrwallet/internal/prompt"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/walletdb"
	"github.com/decred/dcrwallet/wstakemgr"
	"github.com/decred/dcrwallet/wtxmgr"
)

const (
	walletDbName = "wallet.db"
)

var (
	// ErrLoaded describes the error condition of attempting to load or
	// create a wallet when the loader has already done so.
	ErrLoaded = errors.New("wallet already loaded")

	// ErrExists describes the error condition of attempting to create a new
	// wallet when one exists already.
	ErrExists = errors.New("wallet already exists")
)

// Loader implements the creating of new and opening of existing wallets, while
// providing a callback system for other subsystems to handle the loading of a
// wallet.  This is primarely intended for use by the RPC servers, to enable
// methods and services which require the wallet when the wallet is loaded by
// another subsystem.
//
// Loader is safe for concurrent access.
type Loader struct {
	callbacks   []func(*Wallet, walletdb.DB)
	chainParams *chaincfg.Params
	dbDirPath   string
	wallet      *Wallet
	db          walletdb.DB
	mu          sync.Mutex

	stakeOptions  *StakeOptions
	autoRepair    bool
	unsafeMainNet bool
}

type StakeOptions struct {
	VoteBits           uint16
	StakeMiningEnabled bool
	BalanceToMaintain  float64
	RollbackTest       bool
	PruneTickets       bool
	AddressReuse       bool
	TicketAddress      string
	TicketMaxPrice     float64
}

// NewLoader constructs a Loader.
func NewLoader(chainParams *chaincfg.Params, dbDirPath string, stakeOptions *StakeOptions, autoRepair bool, unsafeMainNet bool) *Loader {
	return &Loader{
		chainParams:  chainParams,
		dbDirPath:    dbDirPath,
		stakeOptions: stakeOptions,
		autoRepair:   autoRepair,
	}
}

// onLoaded executes each added callback and prevents loader from loading any
// additional wallets.  Requires mutex to be locked.
func (l *Loader) onLoaded(w *Wallet, db walletdb.DB) {
	for _, fn := range l.callbacks {
		fn(w, db)
	}

	l.wallet = w
	l.db = db
	l.callbacks = nil // not needed anymore
}

// RunAfterLoad adds a function to be executed when the loader creates or opens
// a wallet.  Functions are executed in a single goroutine in the order they are
// added.
func (l *Loader) RunAfterLoad(fn func(*Wallet, walletdb.DB)) {
	l.mu.Lock()
	if l.wallet != nil {
		w := l.wallet
		db := l.db
		l.mu.Unlock()
		fn(w, db)
	} else {
		l.callbacks = append(l.callbacks, fn)
		l.mu.Unlock()
	}
}

// CreateNewWallet creates a new wallet using the provided public and private
// passphrases.  The seed is optional.  If non-nil, addresses are derived from
// this seed.  If nil, a secure random seed is generated.
func (l *Loader) CreateNewWallet(pubPassphrase, privPassphrase, seed []byte) (*Wallet, error) {
	defer l.mu.Unlock()
	l.mu.Lock()

	if l.wallet != nil {
		return nil, ErrLoaded
	}

	dbPath := filepath.Join(l.dbDirPath, walletDbName)
	exists, err := fileExists(dbPath)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrExists
	}

	// Create the wallet database backed by bolt db.
	err = os.MkdirAll(l.dbDirPath, 0700)
	if err != nil {
		return nil, err
	}
	db, err := walletdb.Create("bdb", dbPath)
	if err != nil {
		return nil, err
	}

	// If a seed was provided, ensure that it is of valid length. Otherwise,
	// we generate a random seed for the wallet with the recommended seed
	// length.
	if seed != nil {
		if len(seed) < hdkeychain.MinSeedBytes ||
			len(seed) > hdkeychain.MaxSeedBytes {

			return nil, hdkeychain.ErrInvalidSeedLen
		}
	} else {
		hdSeed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
		if err != nil {
			return nil, err
		}
		seed = hdSeed
	}

	// Create the address manager.
	addrMgrNamespace, err := db.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	addrMgr, err := waddrmgr.Create(addrMgrNamespace, seed, pubPassphrase,
		privPassphrase, l.chainParams, nil, l.unsafeMainNet)
	if err != nil {
		return nil, err
	}

	// Create empty transaction manager.
	txMgrNamespace, err := db.Namespace(wtxmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	_, err = wtxmgr.Create(txMgrNamespace, l.chainParams)
	if err != nil {
		return nil, err
	}

	// Create empty stake manager.
	stakeMgrNamespace, err := db.Namespace([]byte("wstakemgr"))
	if err != nil {
		return nil, err
	}
	_, err = wstakemgr.Create(stakeMgrNamespace, addrMgr, l.chainParams)
	if err != nil {
		return nil, err
	}

	// Open the newly-created wallet.
	so := l.stakeOptions
	w, err := Open(pubPassphrase, l.chainParams, db, addrMgrNamespace,
		txMgrNamespace, stakeMgrNamespace, nil, so.VoteBits,
		so.StakeMiningEnabled, so.BalanceToMaintain, so.AddressReuse,
		so.RollbackTest, so.PruneTickets, so.TicketAddress,
		so.TicketMaxPrice, l.autoRepair)
	if err != nil {
		return nil, err
	}

	l.onLoaded(w, db)
	return w, nil
}

var errNoConsole = errors.New("db upgrade requires console access for additional input")

func noConsole() ([]byte, error) {
	return nil, errNoConsole
}

// OpenExistingWallet opens the wallet from the loader's wallet database path
// and the public passphrase.  If the loader is being called by a context where
// standard input prompts may be used during wallet upgrades, setting
// canConsolePrompt will enables these prompts.
func (l *Loader) OpenExistingWallet(pubPassphrase []byte, canConsolePrompt bool) (*Wallet, error) {
	defer l.mu.Unlock()
	l.mu.Lock()

	if l.wallet != nil {
		return nil, ErrLoaded
	}

	// Ensure that the network directory exists.
	if err := checkCreateDir(l.dbDirPath); err != nil {
		return nil, err
	}

	// Open the database using the boltdb backend.
	dbPath := filepath.Join(l.dbDirPath, walletDbName)
	db, err := walletdb.Open("bdb", dbPath)
	if err != nil {
		log.Errorf("Failed to open database: %v", err)
		return nil, err
	}

	addrMgrNS, err := db.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	txMgrNS, err := db.Namespace(wtxmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	stkMgrNS, err := db.Namespace([]byte("wstakemgr"))
	if err != nil {
		return nil, err
	}
	var cbs *waddrmgr.OpenCallbacks
	if canConsolePrompt {
		cbs = &waddrmgr.OpenCallbacks{
			ObtainSeed:        prompt.ProvideSeed,
			ObtainPrivatePass: prompt.ProvidePrivPassphrase,
		}
	} else {
		cbs = &waddrmgr.OpenCallbacks{
			ObtainSeed:        noConsole,
			ObtainPrivatePass: noConsole,
		}
	}
	so := l.stakeOptions
	w, err := Open(pubPassphrase, l.chainParams, db, addrMgrNS, txMgrNS,
		stkMgrNS, cbs, so.VoteBits, so.StakeMiningEnabled,
		so.BalanceToMaintain, so.AddressReuse, so.RollbackTest,
		so.PruneTickets, so.TicketAddress, so.TicketMaxPrice,
		l.autoRepair)
	if err != nil {
		return nil, err
	}
	w.Start()

	l.onLoaded(w, db)
	return w, nil
}

// WalletExists returns whether a file exists at the loader's database path.
// This may return an error for unexpected I/O failures.
func (l *Loader) WalletExists() (bool, error) {
	dbPath := filepath.Join(l.dbDirPath, walletDbName)
	return fileExists(dbPath)
}

// LoadedWallet returns the loaded wallet, if any, and a bool for whether the
// wallet has been loaded or not.  If true, the wallet pointer should be safe to
// dereference.
func (l *Loader) LoadedWallet() (*Wallet, bool) {
	l.mu.Lock()
	w := l.wallet
	l.mu.Unlock()
	return w, w != nil
}

func fileExists(filePath string) (bool, error) {
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
