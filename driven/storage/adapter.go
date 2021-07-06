package storage

import (
	"core-building-block/core"
	"core-building-block/core/model"

	"strconv"
	"time"

	log "github.com/rokmetro/logging-library/loglib"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

//Adapter implements the Storage interface
type Adapter struct {
	db     *database
	logger *log.StandardLogger
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

//CreateGlobalConfig creates global config
func (sa *Adapter) CreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	globalConfig := model.GlobalConfig{Setting: setting}
	_, err := sa.db.globalConfig.InsertOne(globalConfig)
	if err != nil {
		return nil, err
	}
	return &globalConfig, nil
}

//GetFirebaseAdminCreds finds the Firebase cred document from DB by clientID
func (sa *Adapter) GetFirebaseAdminCreds(clientID string) (*model.FirebaseAdminCreds, error) {
	filter := bson.D{primitive.E{Key: "clientID", Value: clientID}}
	var result []*model.FirebaseAdminCreds
	err := sa.db.firebaseAdminCreds.Find(filter, &result, nil)
	if err != nil {
		return nil, err
	}
	if result == nil || len(result) == 0 {
		//not found
		// log.Info("no Firebase creds found for the given clientID")
		return nil, nil
	}
	return result[0], nil
}

//GetGlobalConfig give config
func (sa *Adapter) GetGlobalConfig() (*model.GlobalConfig, error) {
	filter := bson.D{}
	var result []model.GlobalConfig
	err := sa.db.globalConfig.Find(filter, &result, nil)
	if err != nil {
		return nil, err
	}
	return &result[0], nil

}

//NewStorageAdapter creates a new storage adapter instance
func NewStorageAdapter(mongoDBAuth string, mongoDBName string, mongoTimeout string, logger *log.StandardLogger) *Adapter {
	timeout, err := strconv.Atoi(mongoTimeout)
	if err != nil {
		logger.Error("Set default timeout - 500")
		timeout = 500
	}
	timeoutMS := time.Millisecond * time.Duration(timeout)

	db := &database{mongoDBAuth: mongoDBAuth, mongoDBName: mongoDBName, mongoTimeout: timeoutMS}
	return &Adapter{db: db, logger: logger}
}
