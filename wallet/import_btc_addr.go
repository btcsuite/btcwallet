package wallet

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stroomnetwork/btcwallet/waddrmgr"
	"github.com/stroomnetwork/frost/crypto"
)

func (w *Wallet) GenerateAndImportKeyWithCheck(btcAddr, ethAddr string) (*btcec.PublicKey, error) {

	key, importedAddress, err := w.generateKeyFromEthAddressAndImport(ethAddr)
	if err != nil {
		return nil, err
	}

	if importedAddress != nil {
		if btcAddr != "" && importedAddress.Address().EncodeAddress() != btcAddr {
			return nil, fmt.Errorf("address mismatch: %s != %s",
				importedAddress.Address().EncodeAddress(), btcAddr)
		}

	}

	return key, nil
}

func (w *Wallet) GenerateKeyFromEthAddressAndImport(ethAddr string) (*btcec.PublicKey, error) {
	key, _, err := w.generateKeyFromEthAddressAndImport(ethAddr)
	return key, err
}

func (w *Wallet) generateKeyFromEthAddressAndImport(ethAddr string) (*btcec.PublicKey, waddrmgr.ManagedAddress, error) {

	lc, err := w.lcFromEthAddr(ethAddr)
	if err != nil {
		return nil, nil, err
	}

	pubKey := lc.GetCombinedPubKey()
	importedAddress, err := w.ImportPublicKeyReturnAddress(pubKey, waddrmgr.TaprootPubKey)
	if err != nil {
		return nil, nil, err
	}

	if importedAddress == nil {
		return nil, nil, fmt.Errorf("imported address is nil")
	}

	err = w.AddressMapStorage.SetEthAddress(importedAddress.Address().EncodeAddress(), ethAddr)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, importedAddress, nil
}

func (w *Wallet) lcFromEthAddr(ethAddrStr string) (*crypto.LinearCombination, error) {
	ethAddr := common.HexToAddress(ethAddrStr)

	uint256Ty, _ := abi.NewType("uint256", "uint256", nil)
	addressTy, _ := abi.NewType("address", "address", nil)

	arguments := abi.Arguments{
		{
			Type: uint256Ty,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: addressTy,
		},
	}

	if w.Pk1 == nil {
		return nil, fmt.Errorf("missing pk1")
	}
	if w.Pk2 == nil {
		return nil, fmt.Errorf("missing pk2")
	}

	b1, _ := arguments.Pack(
		w.Pk1.X(),
		w.Pk1.Y(),
		ethAddr,
	)
	h1 := crypto.Sha256(b1)
	c1FromAddr, _ := crypto.PrivKeyFromBytes(h1[:])

	b2, _ := arguments.Pack(
		w.Pk2.X(),
		w.Pk2.Y(),
		ethAddr,
	)
	h2 := crypto.Sha256(b2)
	c2FromAddr, _ := crypto.PrivKeyFromBytes(h2[:])

	lc, err := crypto.NewLinearCombination(
		[]*btcec.PublicKey{w.Pk1, w.Pk2},
		[]*btcec.PrivateKey{c1FromAddr, c2FromAddr},
		crypto.PrivKeyFromInt(0),
	)
	if err != nil {
		return nil, err
	}

	return lc, nil
}

func (w *Wallet) GetSignerPublicKeys() (*btcec.PublicKey, *btcec.PublicKey, error) {

	if w.Pk1 == nil {
		return nil, nil, fmt.Errorf("missing pk1")
	}

	if w.Pk2 == nil {
		return nil, nil, fmt.Errorf("missing pk2")
	}

	return w.Pk1, w.Pk2, nil
}
