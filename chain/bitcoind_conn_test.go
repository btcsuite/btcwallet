package chain

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// TestParseCurrentNet tests that parseCurrentNet correctly identifies standard
// networks, custom signet networks, and preserves compatibility behavior for
// older backends that do not expose signet_challenge.
func TestParseCurrentNet(t *testing.T) {
	t.Parallel()

	customChallengeHex := "01020304"
	customChallenge, err := hex.DecodeString(customChallengeHex)
	require.NoError(t, err)

	customSignetParams := chaincfg.CustomSignetParams(customChallenge, nil)
	defaultSignetChallengeHex := hex.EncodeToString(chaincfg.DefaultSignetChallenge)

	tests := []struct {
		name         string
		genesisHash  *chainhash.Hash
		chainInfo    *getBlockChainInfoResult
		expectedNet  wire.BitcoinNet
		wantNet      wire.BitcoinNet
		wantErr      bool
		errSubstring string
	}{
		{
			name:        "mainnet",
			genesisHash: chaincfg.MainNetParams.GenesisHash,
			expectedNet: chaincfg.MainNetParams.Net,
			wantNet:     chaincfg.MainNetParams.Net,
		},
		{
			name:        "testnet3",
			genesisHash: chaincfg.TestNet3Params.GenesisHash,
			expectedNet: chaincfg.TestNet3Params.Net,
			wantNet:     chaincfg.TestNet3Params.Net,
		},
		{
			name:        "testnet4",
			genesisHash: chaincfg.TestNet4Params.GenesisHash,
			expectedNet: chaincfg.TestNet4Params.Net,
			wantNet:     chaincfg.TestNet4Params.Net,
		},
		{
			name:        "regtest",
			genesisHash: chaincfg.RegressionNetParams.GenesisHash,
			expectedNet: chaincfg.RegressionNetParams.Net,
			wantNet:     chaincfg.RegressionNetParams.Net,
		},
		{
			name:         "unknown network",
			genesisHash:  &chainhash.Hash{0x01, 0x02},
			expectedNet:  chaincfg.MainNetParams.Net,
			wantErr:      true,
			errSubstring: "unknown network with genesis hash",
		},
		{
			name:        "signet with default challenge",
			genesisHash: chaincfg.SigNetParams.GenesisHash,
			chainInfo: &getBlockChainInfoResult{
				SignetChallenge: defaultSignetChallengeHex,
			},
			expectedNet: chaincfg.SigNetParams.Net,
			wantNet:     chaincfg.SigNetParams.Net,
		},
		{
			name:        "signet with custom challenge matching expected",
			genesisHash: chaincfg.SigNetParams.GenesisHash,
			chainInfo: &getBlockChainInfoResult{
				SignetChallenge: customChallengeHex,
			},
			expectedNet: customSignetParams.Net,
			wantNet:     customSignetParams.Net,
		},
		{
			name:        "signet with custom challenge returns derived net",
			genesisHash: chaincfg.SigNetParams.GenesisHash,
			chainInfo: &getBlockChainInfoResult{
				SignetChallenge: customChallengeHex,
			},
			expectedNet: chaincfg.SigNetParams.Net,
			wantNet:     customSignetParams.Net,
		},
		{
			name:        "signet older backend without challenge expected default",
			genesisHash: chaincfg.SigNetParams.GenesisHash,
			chainInfo: &getBlockChainInfoResult{
				SignetChallenge: "",
			},
			expectedNet: chaincfg.SigNetParams.Net,
			wantNet:     chaincfg.SigNetParams.Net,
		},
		{
			name:        "signet older backend nil chainInfo expected default",
			genesisHash: chaincfg.SigNetParams.GenesisHash,
			chainInfo:   nil,
			expectedNet: chaincfg.SigNetParams.Net,
			wantNet:     chaincfg.SigNetParams.Net,
		},
		{
			name:        "signet older backend without challenge expected custom",
			genesisHash: chaincfg.SigNetParams.GenesisHash,
			chainInfo: &getBlockChainInfoResult{
				SignetChallenge: "",
			},
			expectedNet:  customSignetParams.Net,
			wantErr:      true,
			errSubstring: "backend bitcoind does not expose signet_challenge to verify custom signet",
		},
		{
			name:        "signet with invalid hex challenge",
			genesisHash: chaincfg.SigNetParams.GenesisHash,
			chainInfo: &getBlockChainInfoResult{
				SignetChallenge: "invalid-hex!",
			},
			expectedNet:  chaincfg.SigNetParams.Net,
			wantErr:      true,
			errSubstring: "unable to decode backend signet challenge",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotNet, err := parseCurrentNet(
				tc.genesisHash, tc.chainInfo, tc.expectedNet,
			)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errSubstring != "" {
					require.Contains(t, err.Error(), tc.errSubstring)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantNet, gotNet)
		})
	}
}

// TestBitcoindConnSignetVerification tests NewBitcoindConn and getBlockChainInfo
// against a mock JSON-RPC server verifying custom signet challenges, default
// signet, network mismatch detection, and warmup handling.
func TestBitcoindConnSignetVerification(t *testing.T) {
	customChallengeHex := "512102000000000000000000000000000000000000000000000000000000000000000151ae"
	customChallenge, err := hex.DecodeString(customChallengeHex)
	require.NoError(t, err)

	customSignetParams := chaincfg.CustomSignetParams(customChallenge, nil)
	defaultSignetChallengeHex := hex.EncodeToString(chaincfg.DefaultSignetChallenge)

	tests := []struct {
		name            string
		configuredNet   *chaincfg.Params
		serverChallenge string
		omitChallenge   bool
		warmupCount     int32
		expectedErr     string
	}{
		{
			name:            "default signet configured and server default signet",
			configuredNet:   &chaincfg.SigNetParams,
			serverChallenge: defaultSignetChallengeHex,
		},
		{
			name:            "custom signet configured and server custom signet",
			configuredNet:   &customSignetParams,
			serverChallenge: customChallengeHex,
		},
		{
			name:            "default signet configured and server custom signet mismatch",
			configuredNet:   &chaincfg.SigNetParams,
			serverChallenge: customChallengeHex,
			expectedErr:     "expected network",
		},
		{
			name:            "custom signet configured and server default signet mismatch",
			configuredNet:   &customSignetParams,
			serverChallenge: defaultSignetChallengeHex,
			expectedErr:     "expected network",
		},
		{
			name:          "older server no challenge with default signet",
			configuredNet: &chaincfg.SigNetParams,
			omitChallenge: true,
		},
		{
			name:          "older server no challenge with custom signet",
			configuredNet: &customSignetParams,
			omitChallenge: true,
			expectedErr:   "backend bitcoind does not expose signet_challenge to verify custom signet",
		},
		{
			name:            "warmup retry succeeds",
			configuredNet:   &customSignetParams,
			serverChallenge: customChallengeHex,
			warmupCount:     1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var warmupRem int32 = tc.warmupCount

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Method string `json:"method"`
					ID     any    `json:"id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}

				w.Header().Set("Content-Type", "application/json")

				switch req.Method {
				case "getblockhash":
					resp := map[string]any{
						"result": chaincfg.SigNetParams.GenesisHash.String(),
						"error":  nil,
						"id":     req.ID,
					}
					_ = json.NewEncoder(w).Encode(resp)

				case "getblockchaininfo":
					if atomic.AddInt32(&warmupRem, -1) >= 0 {
						resp := map[string]any{
							"result": nil,
							"error": map[string]any{
								"code":    -28,
								"message": "Loading block index...",
							},
							"id": req.ID,
						}
						_ = json.NewEncoder(w).Encode(resp)
						return
					}

					infoResult := map[string]any{
						"chain":  "signet",
						"blocks": 100,
						"pruned": false,
					}
					if !tc.omitChallenge {
						infoResult["signet_challenge"] = tc.serverChallenge
					}

					resp := map[string]any{
						"result": infoResult,
						"error":  nil,
						"id":     req.ID,
					}
					_ = json.NewEncoder(w).Encode(resp)

				case "getnetworkinfo":
					resp := map[string]any{
						"result": map[string]any{
							"version": 250000,
						},
						"error": nil,
						"id":    req.ID,
					}
					_ = json.NewEncoder(w).Encode(resp)

				default:
					http.Error(w, "unsupported method", http.StatusNotFound)
				}
			}))
			defer server.Close()

			cfg := &BitcoindConfig{
				ChainParams: tc.configuredNet,
				Host:        server.Listener.Addr().String(),
				User:        "user",
				Pass:        "pass",
				PollingConfig: &PollingConfig{
					BlockPollingInterval: time.Millisecond * 100,
					TxPollingInterval:    time.Millisecond * 100,
				},
			}

			// We test the connection creation.
			conn, err := NewBitcoindConn(cfg)
			if tc.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, conn)
		})
	}
}

// TestGetBlockChainInfoResult verifies that getBlockChainInfo correctly parses
// both typed btcjson.GetBlockChainInfoResult fields and the signet_challenge field.
func TestGetBlockChainInfoResult(t *testing.T) {
	t.Parallel()

	const challengeHex = "512103ad5e0eda410756f455e54823d088286f3999f432e42d661f2748e1b3437f51cb21035288a2e741636167664751842c78737f05bd36005a847aeb20f730ecb00b77bf52ae"

	rawJSON := []byte(`{
		"chain": "signet",
		"blocks": 150000,
		"headers": 150000,
		"bestblockhash": "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
		"pruned": true,
		"pruneheight": 100000,
		"signet_challenge": "` + challengeHex + `"
	}`)

	var info getBlockChainInfoResult
	err := json.Unmarshal(rawJSON, &info)
	require.NoError(t, err)

	require.Equal(t, "signet", info.Chain)
	require.Equal(t, int32(150000), info.Blocks)
	require.True(t, info.Pruned)
	require.Equal(t, int32(100000), info.PruneHeight)
	require.Equal(t, challengeHex, info.SignetChallenge)
}
