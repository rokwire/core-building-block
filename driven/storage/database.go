package storage

import (
	"context"
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

	firebaseAdminCreds *collectionWrapper
	authConfigs   *collectionWrapper
	globalConfig  *collectionWrapper
	organizations *collectionWrapper
	serviceRegs   *collectionWrapper

	listeners []Listener
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
	organizations := &collectionWrapper{database: m, coll: db.Collection("organizations")}
	err = m.applyOrganizationsChecks(organizations)
	if err != nil {
		return err
	}

	serviceRegs := &collectionWrapper{database: m, coll: db.Collection("service_regs")}
	err = m.applyServiceRegsChecks(serviceRegs)
	if err != nil {
		return err
	}

	//asign the db, db client and the collections
	m.db = db
	m.dbClient = client
	m.globalConfig = globalConfig
	m.organizations = organizations
	m.serviceRegs = serviceRegs

	//TODO
	authConfigs := &collectionWrapper{database: m, coll: db.Collection("auth_configs")}
	err = m.applyAuthConfigChecks(authConfigs)
	if err != nil {
		return err
	}

	m.authConfigs = authConfigs

	//watch for auth info changes
	go m.authConfigs.Watch(nil)

	return nil
}

func (m *database) applyAuthConfigChecks(authInfo *collectionWrapper) error {
	// Add org_id, app_id compound index
	err := authInfo.AddIndex(bson.D{primitive.E{Key: "org_id", Value: 1}, primitive.E{Key: "app_id", Value: 1}}, false)
	if err != nil {
		return err
	}
	log.Println("authConfig check passed")
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

func (m *database) applyServiceRegsChecks(serviceRegs *collectionWrapper) error {
	log.Println("apply service regs checks.....")

	//add service_id index - unique
	err := serviceRegs.AddIndex(bson.D{primitive.E{Key: "service_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	log.Println("service regs checks passed")
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

	if coll == "auth_configs" {
		log.Println("auth_configs collection changed")

		for _, listener := range m.listeners {
			go listener.OnAuthConfigUpdated()
		}
	}
}
