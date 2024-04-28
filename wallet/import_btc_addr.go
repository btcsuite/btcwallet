package wallet

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stroomnetwork/btcwallet/waddrmgr"
	"github.com/stroomnetwork/frost/crypto"
)

func (w *Wallet) ImportBtcAddressWithEthAddr(btcAddr, ethAddr string) (*btcec.PublicKey, error) {

	lc, err := w.lcFromEthAddr(ethAddr)
	if err != nil {
		return nil, err
	}

	pubKey := lc.GetCombinedPubKey()
	importedAddress, err := w.ImportPublicKeyReturnAddress(pubKey, waddrmgr.TaprootPubKey)
	if err != nil {
		return nil, err
	}

	if importedAddress != nil {
		address := importedAddress.Address().EncodeAddress()
		if btcAddr != "" && address != btcAddr {
			return nil, fmt.Errorf("address mismatch: %s != %s", importedAddress, btcAddr)
		}
		w.btcAddrToLc[address] = lc
		w.btcAddrToEthAddr[address] = ethAddr
	}

	return pubKey, nil
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

	pk1, pk2, err := w.GetSignerPublicKeys()
	if err != nil {
		return nil, err
	}

	b1, _ := arguments.Pack(
		pk1.X(),
		pk1.Y(),
		ethAddr,
	)
	h1 := crypto.Sha256(b1)
	c1FromAddr, _ := crypto.PrivkeyFromBytes(h1[:])

	b2, _ := arguments.Pack(
		pk2.X(),
		pk2.Y(),
		ethAddr,
	)
	h2 := crypto.Sha256(b2)
	c2FromAddr, _ := crypto.PrivkeyFromBytes(h2[:])

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
