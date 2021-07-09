package storage

import (
	"core-building-block/core"
	"core-building-block/core/auth"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

//FindDomainAuthInfo finds the auth document from DB by domain
func (sa *Adapter) FindDomainAuthInfo(orgID string, appID string) (*auth.AuthInfo, error) {
	filter := bson.D{primitive.E{Key: "org_id", Value: orgID}, primitive.E{Key: "app_id", Value: appID}}
	var result *auth.AuthInfo
	err := sa.db.authInfo.FindOne(filter, &result, nil)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("no auth info found for orgID %s, appID %s:", orgID, appID)
	}
	return result, nil
}

//FindDomainAuthInfo finds the auth document from DB by domain
func (sa *Adapter) LoadAuthInfoDocs() (map[string]auth.AuthInfo, error) {
	filter := bson.D{}
	var result []auth.AuthInfo
	err := sa.db.authInfo.Find(filter, &result, nil)
	if err != nil {
		return nil, err
	}
	if result == nil || len(result) == 0 {
		return nil, errors.New("no auth info documents found")
	}

	authInfoMap := make(map[string]auth.AuthInfo)
	for _, authInfo := range result {
		if len(authInfo.OrgID) > 0 && len(authInfo.AppID) > 0 {
			authInfoMap[fmt.Sprintf("%s_%s", authInfo.OrgID, authInfo.AppID)] = authInfo
		}
	}
	return authInfoMap, nil
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
