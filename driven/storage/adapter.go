package storage

import (
	"core-building-block/core"
	"core-building-block/core/model"
	"log"
	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

//Adapter implements the Storage interface
type Adapter struct {
	db *database
}

//Start starts the storage
func (sa *Adapter) Start() error {
	err := sa.db.start()
	return err
}

//SetStorageListener sets listener for the storage
func (sa *Adapter) SetStorageListener(storageListener core.StorageListener) {
	sa.db.listener = storageListener
}

//ReadTODO TODO TODO
func (sa *Adapter) ReadTODO() error {
	return nil
}

//NewStorageAdapter creates a new storage adapter instance
func NewStorageAdapter(mongoDBAuth string, mongoDBName string, mongoTimeout string) *Adapter {
	timeout, err := strconv.Atoi(mongoTimeout)
	if err != nil {
		log.Println("Set default timeout - 500")
		timeout = 500
	}
	timeoutMS := time.Millisecond * time.Duration(timeout)

	db := &database{mongoDBAuth: mongoDBAuth, mongoDBName: mongoDBName, mongoTimeout: timeoutMS}
	return &Adapter{db: db}
}
func (sa *Adapter) GetGlobalConfigs() ([]model.GlobalConfig, error) {
	filter := bson.D{}
	var result []model.GlobalConfig
	err := sa.db.globalConfigs.Find(filter, &result, nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

//SaveGlobalConfig saves the global configuration to the storage
func (sa *Adapter) SaveGlobalConfig(*model.GlobalConfig) error {
	filter := bson.D{}
	err := sa.db.globalConfigs.ReplaceOne(filter, nil, nil)
	if err != nil {
		return err
	}
	return nil
}
