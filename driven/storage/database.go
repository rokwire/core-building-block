package storage

import (
	"context"
	"time"

	"github.com/rokmetro/logging-library/logs"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type database struct {
	mongoDBAuth  string
	mongoDBName  string
	mongoTimeout time.Duration

	logger *logs.Logger

	db       *mongo.Database
	dbClient *mongo.Client

	authTypes                 *collectionWrapper
	identityProviders         *collectionWrapper
	accounts                  *collectionWrapper
	devices                   *collectionWrapper
	credentials               *collectionWrapper
	loginsSessions            *collectionWrapper
	globalConfig              *collectionWrapper
	serviceRegs               *collectionWrapper
	serviceAuthorizations     *collectionWrapper
	organizations             *collectionWrapper
	applications              *collectionWrapper
	applicationsOrganizations *collectionWrapper
	applicationsGroups        *collectionWrapper
	applicationsRoles         *collectionWrapper
	applicationsPermissions   *collectionWrapper

	listeners []Listener
}

func (m *database) start() error {
	m.logger.Info("database -> start")

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

	authTypes := &collectionWrapper{database: m, coll: db.Collection("auth_types")}
	err = m.applyAuthTypesChecks(authTypes)
	if err != nil {
		return err
	}

	identityProviders := &collectionWrapper{database: m, coll: db.Collection("identity_providers")}
	err = m.applyIdentityProvidersChecks(identityProviders)
	if err != nil {
		return err
	}

	accounts := &collectionWrapper{database: m, coll: db.Collection("accounts")}
	err = m.applyAccountsChecks(accounts)
	if err != nil {
		return err
	}

	devices := &collectionWrapper{database: m, coll: db.Collection("devices")}
	err = m.applyDevicesChecks(devices)
	if err != nil {
		return err
	}

	credentials := &collectionWrapper{database: m, coll: db.Collection("credentials")}
	err = m.applyCredentialChecks(credentials)
	if err != nil {
		return err
	}

	loginsSessions := &collectionWrapper{database: m, coll: db.Collection("logins_sessions")}
	err = m.applyLoginsSessionsChecks(loginsSessions)
	if err != nil {
		return err
	}

	globalConfig := &collectionWrapper{database: m, coll: db.Collection("global_config")}
	err = m.applyGlobalConfigChecks(globalConfig)
	if err != nil {
		return err
	}

	serviceRegs := &collectionWrapper{database: m, coll: db.Collection("service_regs")}
	err = m.applyServiceRegsChecks(serviceRegs)
	if err != nil {
		return err
	}

	serviceAuthorizations := &collectionWrapper{database: m, coll: db.Collection("service_authorizations")}
	err = m.applyServiceAuthorizationsChecks(serviceAuthorizations)
	if err != nil {
		return err
	}

	organizations := &collectionWrapper{database: m, coll: db.Collection("organizations")}
	err = m.applyOrganizationsChecks(organizations)
	if err != nil {
		return err
	}

	applications := &collectionWrapper{database: m, coll: db.Collection("applications")}
	err = m.applyApplicationsChecks(applications)
	if err != nil {
		return err
	}

	applicationsOrganziations := &collectionWrapper{database: m, coll: db.Collection("applications_organizations")}
	err = m.applyApplicationsOrganizationsChecks(applicationsOrganziations)
	if err != nil {
		return err
	}

	applicationsGroups := &collectionWrapper{database: m, coll: db.Collection("applications_groups")}
	err = m.applyApplicationsGroupsChecks(applicationsGroups)
	if err != nil {
		return err
	}

	applicationsRoles := &collectionWrapper{database: m, coll: db.Collection("applications_roles")}
	err = m.applyApplicationsRolesChecks(applicationsRoles)
	if err != nil {
		return err
	}

	applicationsPermissions := &collectionWrapper{database: m, coll: db.Collection("applications_permissions")}
	err = m.applyApplicationsPermissionsChecks(applicationsPermissions)
	if err != nil {
		return err
	}

	//asign the db, db client and the collections
	m.db = db
	m.dbClient = client

	m.authTypes = authTypes
	m.identityProviders = identityProviders
	m.accounts = accounts
	m.devices = devices
	m.credentials = credentials
	m.loginsSessions = loginsSessions
	m.globalConfig = globalConfig
	m.serviceRegs = serviceRegs
	m.serviceAuthorizations = serviceAuthorizations
	m.organizations = organizations
	m.applications = applications
	m.applicationsOrganizations = applicationsOrganziations
	m.applicationsGroups = applicationsGroups
	m.applicationsRoles = applicationsRoles
	m.applicationsPermissions = applicationsPermissions

	go m.authTypes.Watch(nil)
	go m.identityProviders.Watch(nil)
	go m.serviceRegs.Watch(nil)
	go m.organizations.Watch(nil)
	go m.applications.Watch(nil)
	go m.applicationsOrganizations.Watch(nil)

	m.listeners = []Listener{}

	return nil
}

func (m *database) applyAuthTypesChecks(authenticationTypes *collectionWrapper) error {
	m.logger.Info("apply auth types checks.....")

	m.logger.Info("auth types check passed")
	return nil
}

func (m *database) applyIdentityProvidersChecks(identityProviders *collectionWrapper) error {
	m.logger.Info("apply identity providers checks.....")

	m.logger.Info("identity providers check passed")
	return nil
}

func (m *database) applyAccountsChecks(accounts *collectionWrapper) error {
	m.logger.Info("apply accounts checks.....")

	//add compound unique index - id + app + org
	err := accounts.AddIndex(bson.D{primitive.E{Key: "_id", Value: 1}, primitive.E{Key: "app_id", Value: 1}, primitive.E{Key: "org_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	//add profile index
	err = accounts.AddIndex(bson.D{primitive.E{Key: "profile.id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add auth types index
	err = accounts.AddIndex(bson.D{primitive.E{Key: "auth_types.id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("accounts check passed")
	return nil
}

func (m *database) applyDevicesChecks(devices *collectionWrapper) error {
	m.logger.Info("apply devices checks.....")

	//add users index
	err := devices.AddIndex(bson.D{primitive.E{Key: "users", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("devices check passed")
	return nil
}

func (m *database) applyCredentialChecks(credentials *collectionWrapper) error {
	m.logger.Info("apply credentials checks.....")

	// Add user_auth_type_id index
	err := credentials.AddIndex(bson.D{primitive.E{Key: "user_auth_type_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("credentials check passed")
	return nil
}

func (m *database) applyLoginsSessionsChecks(refreshTokens *collectionWrapper) error {
	m.logger.Info("apply logins sessions checks.....")
	//TODO
	/*
		err := refreshTokens.AddIndex(bson.D{primitive.E{Key: "current_token", Value: 1}}, false)
		if err != nil {
			return err
		}

		err = refreshTokens.AddIndex(bson.D{primitive.E{Key: "previous_token", Value: 1}}, false)
		if err != nil {
			return err
		}

		err = refreshTokens.AddIndex(bson.D{primitive.E{Key: "exp", Value: 1}}, false)
		if err != nil {
			return err
		}

		err = refreshTokens.AddIndex(bson.D{primitive.E{Key: "org_id", Value: 1}, primitive.E{Key: "app_id", Value: 1}, primitive.E{Key: "creds_id", Value: 1}}, false)
		if err != nil {
			return err
		} */
	m.logger.Info("logins sessions check passed")
	return nil
}

func (m *database) applyGlobalConfigChecks(configs *collectionWrapper) error {
	m.logger.Info("apply global config checks.....")

	m.logger.Info("global config checks passed")
	return nil
}

func (m *database) applyServiceRegsChecks(serviceRegs *collectionWrapper) error {
	m.logger.Info("apply service regs checks.....")

	//add service_id index - unique
	err := serviceRegs.AddIndex(bson.D{primitive.E{Key: "registration.service_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("service regs checks passed")
	return nil
}

func (m *database) applyServiceAuthorizationsChecks(serviceAuthorizations *collectionWrapper) error {
	m.logger.Info("apply service authorizations checks.....")

	//add user_id, service_id index - unique
	err := serviceAuthorizations.AddIndex(bson.D{primitive.E{Key: "user_id", Value: 1}, primitive.E{Key: "service_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("service authorizations checks passed")
	return nil
}

func (m *database) applyOrganizationsChecks(organizations *collectionWrapper) error {
	m.logger.Info("apply organizations checks.....")

	//add name index - unique
	err := organizations.AddIndex(bson.D{primitive.E{Key: "name", Value: 1}}, true)
	if err != nil {
		return err
	}

	//TODO

	//add applications index
	err = organizations.AddIndex(bson.D{primitive.E{Key: "applications", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("organizations checks passed")
	return nil
}

func (m *database) applyApplicationsChecks(applications *collectionWrapper) error {
	m.logger.Info("apply applications checks.....")

	//add name index - unique
	err := applications.AddIndex(bson.D{primitive.E{Key: "name", Value: 1}}, true)
	if err != nil {
		return err
	}

	//add application type index - unique
	err = applications.AddIndex(bson.D{primitive.E{Key: "types.id", Value: 1}}, true)
	if err != nil {
		return err
	}

	//add application type identifier index - unique
	err = applications.AddIndex(bson.D{primitive.E{Key: "types.identifier", Value: 1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("applications checks passed")
	return nil
}

func (m *database) applyApplicationsOrganizationsChecks(applicationsOrganizations *collectionWrapper) error {
	m.logger.Info("apply applications organizations checks.....")

	//add compound unique index - application + auth type + auth type identifier
	err := applicationsOrganizations.AddIndex(bson.D{primitive.E{Key: "app_id", Value: 1},
		primitive.E{Key: "org_id", Value: 1}},
		true)
	if err != nil {
		return err
	}

	m.logger.Info("applications organizations checks passed")
	return nil
}

func (m *database) applyApplicationsGroupsChecks(applicationsGroups *collectionWrapper) error {
	m.logger.Info("apply applications groups checks.....")

	//add application index
	err := applicationsGroups.AddIndex(bson.D{primitive.E{Key: "app_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add permissions index
	err = applicationsGroups.AddIndex(bson.D{primitive.E{Key: "permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add roles index
	err = applicationsGroups.AddIndex(bson.D{primitive.E{Key: "roles._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add roles permissions index
	err = applicationsGroups.AddIndex(bson.D{primitive.E{Key: "roles.permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("applications groups checks passed")
	return nil
}

func (m *database) applyApplicationsRolesChecks(applicationsRoles *collectionWrapper) error {
	m.logger.Info("apply applications roles checks.....")

	//add application index
	err := applicationsRoles.AddIndex(bson.D{primitive.E{Key: "app_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add permissions index
	err = applicationsRoles.AddIndex(bson.D{primitive.E{Key: "permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("applications roles checks passed")
	return nil
}

func (m *database) applyApplicationsPermissionsChecks(applicationsPermissions *collectionWrapper) error {
	m.logger.Info("apply applications permissions checks.....")

	//add application index
	err := applicationsPermissions.AddIndex(bson.D{primitive.E{Key: "app_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("applications permissions checks passed")
	return nil
}

func (m *database) onDataChanged(changeDoc map[string]interface{}) {
	if changeDoc == nil {
		return
	}
	m.logger.Debugf("onDataChanged: %+v\n", changeDoc)
	ns := changeDoc["ns"]
	if ns == nil {
		return
	}
	nsMap := ns.(map[string]interface{})
	coll := nsMap["coll"]

	switch coll {
	case "auth_types":
		m.logger.Info("auth_types collection changed")

		for _, listener := range m.listeners {
			go listener.OnAuthTypesUpdated()
		}
	case "identity_providers":
		m.logger.Info("identity_providers collection changed")

		for _, listener := range m.listeners {
			go listener.OnIdentityProvidersUpdated()
		}
	case "service_regs":
		m.logger.Info("service_regs collection changed")

		for _, listener := range m.listeners {
			go listener.OnServiceRegsUpdated()
		}
	case "organizations":
		m.logger.Info("organizations collection changed")

		for _, listener := range m.listeners {
			go listener.OnOrganizationsUpdated()
		}
	case "applications":
		m.logger.Info("applications collection changed")

		for _, listener := range m.listeners {
			go listener.OnApplicationsUpdated()
		}
	case "applications_organizations":
		m.logger.Info("applications organizations collection changed")

		for _, listener := range m.listeners {
			go listener.OnApplicationsOrganizationsUpdated()
		}
	}

}
