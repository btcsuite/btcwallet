package wallet

import (
	"errors"
	"fmt"
	"github.com/steveyen/gkvlite"
	"os"
	"sync"
)

const DefaultStorageFileName = "addressMap.gkv"
const collectionName = "ethAddress"

type AddressMapStorage struct {
	store *gkvlite.Store
	lock  *sync.RWMutex
}

// NewAddressMapStorage creates a new storage instance using gkvlite with file path param
func NewAddressMapStorage(storageFilePath string) (*AddressMapStorage, error) {
	if storageFilePath == "" {
		storageFilePath = DefaultStorageFileName
	}

	// Open the storage file
	file, err := os.OpenFile(storageFilePath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("cannot open storage file: %w", err)
	}

	store, err := gkvlite.NewStore(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("cannot create storage: %w", err)
	}

	store.SetCollection(collectionName, nil)

	return &AddressMapStorage{
		store: store,
		lock:  new(sync.RWMutex),
	}, nil
}

func (s *AddressMapStorage) GetEthAddress(btcAddress string) (string, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	c := s.store.GetCollection(collectionName)
	if c == nil {
		return "", errors.New("no such collection: " + collectionName)
	}
	ethAddress, err := c.Get([]byte(btcAddress))
	if err != nil {
		return "", err
	}
	return string(ethAddress), err
}

func (s *AddressMapStorage) SetEthAddress(btcAddress, ethAddress string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	c := s.store.GetCollection(collectionName)
	if c == nil {
		return errors.New("no such collection: " + collectionName)
	}
	if err := c.Set([]byte(btcAddress), []byte(ethAddress)); err != nil {
		return fmt.Errorf("cannot set: %w", err)
	}

	return s.store.Flush()
}
