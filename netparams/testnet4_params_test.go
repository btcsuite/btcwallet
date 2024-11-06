package netparams

import (
	"github.com/stretchr/testify/require"
	"testing"
)

// verify that the testnet4 params are correct (genesis block)
// https://mempool.space/testnet4/block/00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043
func Test_testnet4_params(t *testing.T) {
	require.Equal(t, testNet4GenesisBlock.BlockHash().String(),
		"00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043")
	require.Equal(t, testNet4GenesisBlock.Header.MerkleRoot.String(),
		"7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e")
}
