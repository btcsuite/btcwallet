package kvdb

import (
	"context"
	"errors"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// accountSecretReader is the narrow slice of *waddrmgr.ScopedKeyManager that
// GetAccountSecret needs. The scoped-manager methods exporting encrypted
// account material live on the concrete type rather than on AccountStore, so
// kvdb asserts to this local interface instead of widening AccountStore.
type accountSecretReader interface {
	// AccountSecret returns the stored encrypted account private key
	// ciphertext, nil when the account is watch-only or imported.
	AccountSecret(ns walletdb.ReadBucket, account uint32) ([]byte, error)
}

// checkContext reports the context's cancellation state. Secret reads consult
// it on both sides of the walletdb view so a canceled request never receives
// key material.
func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()

	default:
		return nil
	}
}

// GetAccountSecret retrieves encrypted account-level signing material from the
// legacy address manager, resolved by BIP44 account number within the scope.
func (s *Store) GetAccountSecret(ctx context.Context,
	query db.GetAccountSecretQuery) (*db.AccountSecret, error) {

	// Honor cancellation before entering walletdb so a canceled signing
	// request never reads secret material.
	err := checkContext(ctx)
	if err != nil {
		return nil, err
	}

	scope := waddrmgr.KeyScope{
		Purpose: query.Scope.Purpose,
		Coin:    query.Scope.Coin,
	}

	var secret *db.AccountSecret

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return db.ErrAccountNotFound
		}

		var err error

		secret, err = s.buildAccountSecret(ns, scope, query)

		return err
	})
	if err != nil {
		return nil, err
	}

	// Re-check after the read: the context may have been canceled while the
	// lookup ran, and a canceled request must not receive secret material.
	err = checkContext(ctx)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// buildAccountSecret resolves the query's account within the given namespace
// and scope and assembles its encrypted secret material. It is the read body
// of GetAccountSecret, factored out so the exported method stays thin.
func (s *Store) buildAccountSecret(ns walletdb.ReadBucket,
	scope waddrmgr.KeyScope,
	query db.GetAccountSecretQuery) (*db.AccountSecret, error) {

	scopedMgr, err := s.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	reader, ok := scopedMgr.(accountSecretReader)
	if !ok {
		return nil, errScopedAccountSecretUnsupported
	}

	encPriv, err := reader.AccountSecret(ns, query.AccountNumber)
	if err != nil {
		return nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	return &db.AccountSecret{
		EncryptedPrivateKey: encPriv,
	}, nil
}

// errScopedAccountSecretUnsupported is returned when a mocked or alternate
// scoped manager does not expose kvdb's encrypted-account-secret reader.
var errScopedAccountSecretUnsupported = errors.New(
	"kvdb: scoped account secret export unsupported",
)

// compile-time guard: the concrete waddrmgr scoped manager satisfies the
// narrow reader interface GetAccountSecret asserts to.
var _ accountSecretReader = (*waddrmgr.ScopedKeyManager)(nil)
