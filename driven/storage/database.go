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
	mongoDBAuth  string
	mongoDBName  string
	mongoTimeout time.Duration

	db       *mongo.Database
	dbClient *mongo.Client

	globalConfig  *collectionWrapper
	organizations *collectionWrapper

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

	globalConfig := &collectionWrapper{database: m, coll: db.Collection("global_config")}
	err = m.applyGlobalConfigChecks(globalConfig)
	if err != nil {
		return err
	}

	organizations := &collectionWrapper{database: m, coll: db.Collection("organizations")}
	err = m.applyOrganizationsChecks(organizations)
	if err != nil {
		return err
	}

	users := &collectionWrapper{database: m, coll: db.Collection("email_credentials")}
	err = m.applyCredsChecks(users)
	if err != nil {
		return err
	}

	//asign the db, db client and the collections
	m.db = db
	m.dbClient = client
	m.globalConfig = globalConfig
	m.organizations = organizations

	//TODO

	return nil
}

func (m *database) applyGlobalConfigChecks(configs *collectionWrapper) error {
	log.Println("apply global config checks.....")

	log.Println("global config checks passed")
	return nil
}

func (m *database) applyOrganizationsChecks(organizations *collectionWrapper) error {
	log.Println("apply organizations checks.....")

	//add name index - unique
	err := organizations.AddIndex(bson.D{primitive.E{Key: "name", Value: 1}}, true)
	if err != nil {
		return err
	}

	log.Println("organizations checks passed")
	return nil
}

func (m *database) applyCredsChecks(organizations *collectionWrapper) error {
	log.Println("apply creds checks.....")

	//add username index - unique
	err := organizations.AddIndex(bson.D{primitive.E{Key: "username", Value: 1}}, true)
	if err != nil {
		return err
	}

	log.Println("users checks passed")
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
