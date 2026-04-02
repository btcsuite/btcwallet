package main

import (
	"os"
	"testing"
	"time"

	"github.com/lightninglabs/neutrino"
	"github.com/stretchr/testify/require"
)

func runLoadConfigForTest(t *testing.T, args ...string) (*config, error) {
	t.Helper()

	oldArgs := os.Args
	oldActiveNet := activeNet
	oldMaxPeers := neutrino.MaxPeers
	oldBanDuration := neutrino.BanDuration
	oldBanThreshold := neutrino.BanThreshold

	t.Cleanup(func() {
		os.Args = oldArgs
		activeNet = oldActiveNet
		neutrino.MaxPeers = oldMaxPeers
		neutrino.BanDuration = oldBanDuration
		neutrino.BanThreshold = oldBanThreshold

		if logRotator != nil {
			logRotator.Close()
			logRotator = nil
		}
		if logRotatorPipe != nil {
			_ = logRotatorPipe.Close()
			logRotatorPipe = nil
		}
	})

	os.Args = append([]string{"btcwallet"}, args...)

	cfg, _, err := loadConfig()
	return cfg, err
}

func TestLoadConfigUseActorRescanRequiresSPV(t *testing.T) {
	tempDir := t.TempDir()

	cfg, err := runLoadConfigForTest(
		t,
		"--appdata="+tempDir,
		"--noinitialload",
		"--useactorrescan",
	)
	require.Nil(t, cfg)
	require.ErrorContains(t, err, "--useactorrescan option requires --usespv")
}

func TestLoadConfigUseActorRescanWithSPV(t *testing.T) {
	tempDir := t.TempDir()

	cfg, err := runLoadConfigForTest(
		t,
		"--appdata="+tempDir,
		"--noinitialload",
		"--usespv",
		"--useactorrescan",
	)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.True(t, cfg.NoInitialLoad)
	require.True(t, cfg.UseSPV)
	require.True(t, cfg.UseActorRescan)
	require.Equal(t, neutrino.MaxPeers, cfg.MaxPeers)
	require.Equal(t, neutrino.BanDuration, cfg.BanDuration)
	require.Equal(t, neutrino.BanThreshold, cfg.BanThreshold)
}

func TestLoadConfigUseActorRescanWithSPVPreservesSPVTuning(t *testing.T) {
	tempDir := t.TempDir()

	cfg, err := runLoadConfigForTest(
		t,
		"--appdata="+tempDir,
		"--noinitialload",
		"--usespv",
		"--useactorrescan",
		"--maxpeers=7",
		"--banduration=2h",
		"--banthreshold=77",
	)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	require.Equal(t, 7, cfg.MaxPeers)
	require.Equal(t, 2*time.Hour, cfg.BanDuration)
	require.EqualValues(t, 77, cfg.BanThreshold)
	require.Equal(t, 7, neutrino.MaxPeers)
	require.Equal(t, 2*time.Hour, neutrino.BanDuration)
	require.EqualValues(t, 77, neutrino.BanThreshold)
}
