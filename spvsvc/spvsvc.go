package spvsvc

import "github.com/btcsuite/btcwallet/spvsvc/spvchain"

// SynchronizationService provides an SPV, p2p-based backend for a wallet to
// synchronize it with the network and send transactions it signs.
type SynchronizationService struct {
	chain spvchain.ChainService
}

// SynchronizationServiceOpt is the return type of functional options for
// creating a SynchronizationService object.
type SynchronizationServiceOpt func(*SynchronizationService) error

// NewSynchronizationService creates a new SynchronizationService with
// functional options.
func NewSynchronizationService(opts ...SynchronizationServiceOpt) (*SynchronizationService, error) {
	s := SynchronizationService{
	//userAgentName:    defaultUserAgentName,
	//userAgentVersion: defaultUserAgentVersion,
	}
	for _, opt := range opts {
		err := opt(&s)
		if err != nil {
			return nil, err
		}
	}
	return &s, nil
}

// UserAgent is a functional option to set the user agent information as it
// appears to other nodes.
func UserAgent(agentName, agentVersion string) SynchronizationServiceOpt {
	return func(s *SynchronizationService) error {
		//s.userAgentName = agentName
		//s.userAgentVersion = agentVersion
		return nil
	}
}
