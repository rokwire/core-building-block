// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"context"
	"time"

	"github.com/rokwire/logging-library-go/v2/logs"
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

	apiKeys                         *collectionWrapper
	authTypes                       *collectionWrapper
	identityProviders               *collectionWrapper
	accounts                        *collectionWrapper
	devices                         *collectionWrapper
	credentials                     *collectionWrapper
	loginsSessions                  *collectionWrapper
	globalConfig                    *collectionWrapper
	serviceRegs                     *collectionWrapper
	serviceRegistrations            *collectionWrapper
	serviceAccounts                 *collectionWrapper
	serviceAuthorizations           *collectionWrapper
	organizations                   *collectionWrapper
	applications                    *collectionWrapper
	applicationsOrganizations       *collectionWrapper
	applicationsOrganizationsGroups *collectionWrapper
	applicationsOrganizationsRoles  *collectionWrapper
	applicationConfigs              *collectionWrapper
	permissions                     *collectionWrapper
	follows                         *collectionWrapper

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

	serviceRegs := &collectionWrapper{database: m, coll: db.Collection("service_regs")}
	err = m.applyServiceRegsChecks(serviceRegs)
	if err != nil {
		return err
	}

	serviceRegistrations := &collectionWrapper{database: m, coll: db.Collection("service_registrations")}
	err = m.applyServiceRegistrationsChecks(serviceRegistrations)
	if err != nil {
		return err
	}

	serviceAccounts := &collectionWrapper{database: m, coll: db.Collection("service_accounts")}
	err = m.applyServiceAccountsChecks(serviceAccounts)
	if err != nil {
		return err
	}

	loginsSessions := &collectionWrapper{database: m, coll: db.Collection("logins_sessions")}
	err = m.applyLoginsSessionsChecks(loginsSessions)
	if err != nil {
		return err
	}

	serviceAuthorizations := &collectionWrapper{database: m, coll: db.Collection("service_authorizations")}
	err = m.applyServiceAuthorizationsChecks(serviceAuthorizations)
	if err != nil {
		return err
	}

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

	applications := &collectionWrapper{database: m, coll: db.Collection("applications")}
	err = m.applyApplicationsChecks(applications)
	if err != nil {
		return err
	}

	apiKeys := &collectionWrapper{database: m, coll: db.Collection("api_keys")}
	err = m.applyAPIKeysChecks(apiKeys)
	if err != nil {
		return err
	}

	applicationsOrganizations := &collectionWrapper{database: m, coll: db.Collection("applications_organizations")}
	err = m.applyApplicationsOrganizationsChecks(applicationsOrganizations)
	if err != nil {
		return err
	}

	applicationsOrganizationsGroups := &collectionWrapper{database: m, coll: db.Collection("applications_organizations_groups")}
	err = m.applyApplicationsOrganizationsGroupsChecks(applicationsOrganizationsGroups)
	if err != nil {
		return err
	}

	applicationsOrganizationsRoles := &collectionWrapper{database: m, coll: db.Collection("applications_organizations_roles")}
	err = m.applyApplicationsOrganizationsRolesChecks(applicationsOrganizationsRoles)
	if err != nil {
		return err
	}

	permissions := &collectionWrapper{database: m, coll: db.Collection("permissions")}
	err = m.applyPermissionsChecks(permissions)
	if err != nil {
		return err
	}

	follows := &collectionWrapper{database: m, coll: db.Collection("follows")}
	err = m.applyFollowsChecks(follows)
	if err != nil {
		return err
	}

	applicationConfigs := &collectionWrapper{database: m, coll: db.Collection("application_configs")}
	err = m.applyApplicationConfigsChecks(applicationConfigs)
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
	m.apiKeys = apiKeys
	m.serviceRegs = serviceRegs
	m.serviceRegistrations = serviceRegistrations
	m.serviceAccounts = serviceAccounts
	m.serviceAuthorizations = serviceAuthorizations
	m.organizations = organizations
	m.applications = applications
	m.applicationsOrganizations = applicationsOrganizations
	m.applicationConfigs = applicationConfigs
	m.applicationsOrganizationsGroups = applicationsOrganizationsGroups
	m.applicationsOrganizationsRoles = applicationsOrganizationsRoles
	m.permissions = permissions
	m.follows = follows

	go m.apiKeys.Watch(nil, m.logger)
	go m.authTypes.Watch(nil, m.logger)
	go m.identityProviders.Watch(nil, m.logger)
	go m.serviceRegistrations.Watch(nil, m.logger)
	go m.organizations.Watch(nil, m.logger)
	go m.applications.Watch(nil, m.logger)
	go m.applicationsOrganizations.Watch(nil, m.logger)
	go m.applicationConfigs.Watch(nil, m.logger)

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

	//add compound index - auth_type identifier + auth_type_id
	// Can't be unique because of anonymous accounts
	err := accounts.AddIndex(bson.D{primitive.E{Key: "auth_types.identifier", Value: 1}, primitive.E{Key: "auth_types.auth_type_id", Value: 1}, primitive.E{Key: "app_org_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add compound index - app_org_id + username
	err = accounts.AddIndex(bson.D{primitive.E{Key: "app_org_id", Value: 1}, primitive.E{Key: "username", Value: 1}}, false)
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

	//add compound unique index - device_id + account_id
	err := devices.AddIndex(bson.D{primitive.E{Key: "device_id", Value: 1}, primitive.E{Key: "account_id", Value: 1}}, true)
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

	err := refreshTokens.AddIndex(bson.D{primitive.E{Key: "refresh_token", Value: 1}}, false)
	if err != nil {
		return err
	}

	err = refreshTokens.AddIndex(bson.D{primitive.E{Key: "expires", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("logins sessions check passed")
	return nil
}

func (m *database) applyAPIKeysChecks(apiKeys *collectionWrapper) error {
	m.logger.Info("apply api keys checks.....")

	// Add app_id index
	err := apiKeys.AddIndex(bson.D{primitive.E{Key: "app_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	// Add key index
	err = apiKeys.AddIndex(bson.D{primitive.E{Key: "key", Value: 1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("api keys check passed")
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

func (m *database) applyServiceRegistrationsChecks(serviceRegistrations *collectionWrapper) error {
	m.logger.Info("apply service registrations checks.....")

	//add core_host, service_id index - unique
	err := serviceRegistrations.AddIndex(bson.D{primitive.E{Key: "core_host", Value: 1}, primitive.E{Key: "registration.service_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("service registrations checks passed")
	return nil
}

func (m *database) applyServiceAccountsChecks(serviceAccounts *collectionWrapper) error {
	m.logger.Info("apply service accounts checks.....")

	err := serviceAccounts.AddIndex(bson.D{primitive.E{Key: "account_id", Value: 1}, primitive.E{Key: "app_id", Value: 1}, primitive.E{Key: "org_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("service accounts checks passed")
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

func (m *database) applyApplicationsOrganizationsGroupsChecks(applicationsOrganizationGroups *collectionWrapper) error {
	m.logger.Info("apply applications organizations groups checks.....")

	//add compound unique index - name + app_org_id
	err := applicationsOrganizationGroups.AddIndex(bson.D{primitive.E{Key: "name", Value: 1}, primitive.E{Key: "app_org_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	//add application organization index
	err = applicationsOrganizationGroups.AddIndex(bson.D{primitive.E{Key: "app_org_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add permissions index
	err = applicationsOrganizationGroups.AddIndex(bson.D{primitive.E{Key: "permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add roles index
	err = applicationsOrganizationGroups.AddIndex(bson.D{primitive.E{Key: "roles._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add roles permissions index
	err = applicationsOrganizationGroups.AddIndex(bson.D{primitive.E{Key: "roles.permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("applications organizations groups checks passed")
	return nil
}

func (m *database) applyApplicationsOrganizationsRolesChecks(applicationsOrganizationsRoles *collectionWrapper) error {
	m.logger.Info("apply applications organizations roles checks.....")

	//add compound unique index - name + app_org_id
	err := applicationsOrganizationsRoles.AddIndex(bson.D{primitive.E{Key: "name", Value: 1}, primitive.E{Key: "app_org_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	//add application organization index
	err = applicationsOrganizationsRoles.AddIndex(bson.D{primitive.E{Key: "app_org_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add permissions index
	err = applicationsOrganizationsRoles.AddIndex(bson.D{primitive.E{Key: "permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("applications organizations roles checks passed")
	return nil
}

func (m *database) applyPermissionsChecks(permissions *collectionWrapper) error {
	m.logger.Info("apply applications permissions checks.....")

	//add permissions index
	err := permissions.AddIndex(bson.D{primitive.E{Key: "name", Value: 1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("applications permissions checks passed")
	return nil
}

func (m *database) applyFollowsChecks(follows *collectionWrapper) error {
	m.logger.Info("apply applications follows checks.....")

	//add follower index
	err := follows.AddIndex(bson.D{primitive.E{Key: "app_id", Value: 1}, primitive.E{Key: "org_id", Value: 1}, primitive.E{Key: "user_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add following index
	err = follows.AddIndex(bson.D{primitive.E{Key: "app_id", Value: 1}, primitive.E{Key: "org_id", Value: 1}, primitive.E{Key: "followee_id", Value: 1}, primitive.E{Key: "user_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("applications follows checks passed")
	return nil
}

func (m *database) applyApplicationConfigsChecks(applicationConfigs *collectionWrapper) error {
	m.logger.Info("apply applications configs checks.....")

	//add appconfigs index
	err := applicationConfigs.AddIndex(bson.D{primitive.E{Key: "app_type_id", Value: 1}, primitive.E{Key: "app_org_id", Value: 1}, primitive.E{Key: "version.version_numbers.major", Value: -1}, primitive.E{Key: "version.version_numbers.minor", Value: -1}, primitive.E{Key: "version.version_numbers.patch", Value: -1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("applications configs checks passed")
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
	case "api_keys":
		m.logger.Info("api_keys collection changed")

		for _, listener := range m.listeners {
			go listener.OnAPIKeysUpdated()
		}
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
	case "service_registrations":
		m.logger.Info("service_registrations collection changed")

		for _, listener := range m.listeners {
			go listener.OnServiceRegistrationsUpdated()
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
	case "application_configs":
		m.logger.Info("application configs collection changed")

		for _, listener := range m.listeners {
			go listener.OnApplicationConfigsUpdated()
		}
	}
}
