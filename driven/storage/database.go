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

	authInfo *collectionWrapper

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
	//TODO

	//asign the db, db client and the collections
	m.db = db
	m.dbClient = client

	//TODO
	authInfo := &collectionWrapper{database: m, coll: db.Collection("auth_info")}
	err = m.applyAuthInfoChecks(authInfo)
	if err != nil {
		return err
	}

	m.authInfo = authInfo

	//watch for auth info changes
	go m.authInfo.Watch(nil)

	return nil
}

func (m *database) applyAuthInfoChecks(authInfo *collectionWrapper) error {
	// Add client_id index
	err := authInfo.AddIndex(bson.D{primitive.E{Key: "clientID", Value: 1}}, false)
	if err != nil {
		return err
	}
	log.Println("authInfo check passed")
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
	nsMap := ns.(map[string]interface{})
	coll := nsMap["coll"]

	if "auth_info" == coll {
		log.Println("auth_info collection changed")

		if m.listener != nil {
			m.listener.OnAuthInfoUpdated()
		}
	}
}
