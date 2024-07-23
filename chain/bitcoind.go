package chain

import (
	"fmt"
	"time"
)

func SetupBitcoind(cfg *BitcoindConfig) (*BitcoindClient, error) {

	c := make(chan *BitcoindConn)

	go func() {
		chainConn, err := NewBitcoindConn(cfg)
		if err != nil {
			log.Errorf("error creating bitcoind connection: %v", err)
		}
		c <- chainConn
	}()

	select {
	case chainConn := <-c:
		btcClient := chainConn.NewBitcoindClient()
		err := btcClient.Start()
		if err != nil {
			return nil, err
		}

		return btcClient, nil
	case <-time.After(2 * time.Second):
		fmt.Println("timeout creating bitcoind connection")
		return nil, fmt.Errorf("timeout creating bitcoind connection")
	}
}

func NewBitcoindConfig(host, user, password string) *BitcoindConfig {
	return &BitcoindConfig{
		Host: host,
		User: user,
		Pass: password,

		PollingConfig: &PollingConfig{
			BlockPollingInterval: time.Millisecond * 100,
			TxPollingInterval:    time.Millisecond * 100,
		},
	}
}
