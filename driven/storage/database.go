package storage

import (
	"context"
	"core-building-block/core"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type database struct {
	mongoDBAuth     string
	mongoDBName     string
	mongoTimeout    time.Duration
	keysMongoDBName string

	db       *mongo.Database
	dbClient *mongo.Client

	globalConfig       *collectionWrapper
	firebaseAdminCreds *collectionWrapper

	listener core.StorageListener
}

func (m *database) start() error {
	log.Println("database -> start")

	//connect to the database
	clientOptions := options.Client().ApplyURI(m.mongoDBAuth)
	connectContext, cancel := context.WithTimeout(context.Background(), m.mongoTimeout)
	client, err := mongo.Connect(connectContext, clientOptions)
	cancel()
	if err != nil {
		return err
	}

	//ping the database
	pingContext, cancel := context.WithTimeout(context.Background(), m.mongoTimeout)
	err = client.Ping(pingContext, nil)
	cancel()
	if err != nil {
		return err
	}

	//apply checks
	db := client.Database(m.mongoDBName)
	keysDB := client.Database(m.keysMongoDBName)

	globalConfig := &collectionWrapper{database: m, coll: db.Collection("global_config")}
	err = m.applyGlobalConfigChecks(globalConfig)
	if err != nil {
		return err
	}

	firebaseAdminCreds := &collectionWrapper{database: m, coll: keysDB.Collection("firebase_admin_creds")}
	err = m.applyFirebaseCredsChecks(firebaseAdminCreds)
	if err != nil {
		return err
	}

	//asign the db, db client and the collections
	m.db = db
	m.dbClient = client
	m.globalConfig = globalConfig

	//TODO

	return nil
}

func (m *database) applyGlobalConfigChecks(configs *collectionWrapper) error {
	log.Println("apply global config checks.....")

	log.Println("global config checks passed")
	return nil
}

func (m *database) applyFirebaseCredsChecks(firebaseCreds *collectionWrapper) error {
	// Add client_id index
	err := firebaseCreds.AddIndex(bson.D{primitive.E{Key: "clientID", Value: 1}}, false)
	if err != nil {
		return err
	}
	log.Println("FirebaseCreds check passed")
	return nil
}

func (m *database) onDataChanged(changeDoc map[string]interface{}) {
	if changeDoc == nil {
		return
	}
	log.Printf("onDataChanged: %+v\n", changeDoc)
	ns := changeDoc["ns"]
	if ns == nil {
		return
	}
}
