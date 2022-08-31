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
	"core-building-block/core/model"
	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
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
	accounts                        *collectionWrapper
	devices                         *collectionWrapper
	credentials                     *collectionWrapper
	loginsSessions                  *collectionWrapper
	globalConfig                    *collectionWrapper
	serviceRegs                     *collectionWrapper
	serviceAccounts                 *collectionWrapper
	serviceAuthorizations           *collectionWrapper
	organizations                   *collectionWrapper
	applications                    *collectionWrapper
	applicationsOrganizations       *collectionWrapper
	applicationsOrganizationsGroups *collectionWrapper
	applicationsOrganizationsRoles  *collectionWrapper
	applicationConfigs              *collectionWrapper
	permissions                     *collectionWrapper

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

	applicationConfigs := &collectionWrapper{database: m, coll: db.Collection("application_configs")}
	err = m.applyApplicationConfigsChecks(applicationConfigs)
	if err != nil {
		return err
	}

	//asign the db, db client and the collections
	m.db = db
	m.dbClient = client

	m.accounts = accounts
	m.devices = devices
	m.credentials = credentials
	m.loginsSessions = loginsSessions
	m.globalConfig = globalConfig
	m.apiKeys = apiKeys
	m.serviceRegs = serviceRegs
	m.serviceAccounts = serviceAccounts
	m.serviceAuthorizations = serviceAuthorizations
	m.organizations = organizations
	m.applications = applications
	m.applicationsOrganizations = applicationsOrganizations
	m.applicationConfigs = applicationConfigs
	m.applicationsOrganizationsGroups = applicationsOrganizationsGroups
	m.applicationsOrganizationsRoles = applicationsOrganizationsRoles
	m.permissions = permissions

	go m.apiKeys.Watch(nil, m.logger)
	go m.serviceRegs.Watch(nil, m.logger)
	go m.organizations.Watch(nil, m.logger)
	go m.applications.Watch(nil, m.logger)
	go m.applicationsOrganizations.Watch(nil, m.logger)
	go m.applicationConfigs.Watch(nil, m.logger)

	m.listeners = []Listener{}

	//used for very specific (likely one-time) operations
	//update or comment out this call after a set of updates is no longer necessary
	// err = m.applyDataChanges()
	// if err != nil {
	// 	m.logger.Warnf("error applying data changes: %v", err)
	// }

	return nil
}

func (m *database) applyAccountsChecks(accounts *collectionWrapper) error {
	m.logger.Info("apply accounts checks.....")

	//add compound unique index - identifier + auth_type_code + app_org_id
	err := accounts.AddIndex(bson.D{primitive.E{Key: "auth_types.identifier", Value: 1}, primitive.E{Key: "auth_types.auth_type_code", Value: 1}, primitive.E{Key: "app_org_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	//add app_org index
	err = accounts.AddIndex(bson.D{primitive.E{Key: "app_org_id", Value: 1}}, false)
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

	//add compound unique index - application + organization
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

func (m *database) applyApplicationConfigsChecks(applicationConfigs *collectionWrapper) error {
	m.logger.Info("apply applications configs checks.....")

	//disable the problem index for now! Look at https://github.com/rokwire/core-building-block/issues/424
	/*
		//add appconfigs index
		err := applicationConfigs.AddIndex(bson.D{primitive.E{Key: "app_type_id", Value: 1}, primitive.E{Key: "app_org_id", Value: 1}, primitive.E{Key: "version.version_numbers.major", Value: -1}, primitive.E{Key: "version.version_numbers.minor", Value: -1}, primitive.E{Key: "version.version_numbers.patch", Value: -1}}, true)
		if err != nil {
			return err
		}
	*/

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
	case "application_configs":
		m.logger.Info("application configs collection changed")

		for _, listener := range m.listeners {
			go listener.OnApplicationConfigsUpdated()
		}
	}
}

// applyDataChanges should be used to make any necessary updates to existing data when the building block is deployed
func (m *database) applyDataChanges() error {
	now := time.Now().UTC()

	//1. update auth type codes (illinois_oidc)
	aatFilter := bson.D{primitive.E{Key: "auth_types.auth_type_code", Value: "illinois_oidc"}}
	aatUpdate := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "auth_types.$[at].auth_type_code", Value: "oidc"},
			primitive.E{Key: "date_updated", Value: &now},
		}},
	}

	opts := options.UpdateOptions{}
	arrayFilters := []interface{}{bson.M{"at.auth_type_code": "illinois_oidc"}}
	opts.SetArrayFilters(options.ArrayFilters{Filters: arrayFilters})
	res, err := m.accounts.UpdateMany(aatFilter, aatUpdate, &opts)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, &logutils.FieldArgs{"auth_type_code": "illinois_oidc"}, err)
	}
	if res.ModifiedCount != res.MatchedCount {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, &logutils.FieldArgs{"auth_type_code": "illinois_oidc", "modified": res.ModifiedCount, "expected": res.MatchedCount})
	}

	lsFilter := bson.D{primitive.E{Key: "auth_type_code", Value: "illinois_oidc"}}
	lsUpdate := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "auth_type_code", Value: "oidc"},
			primitive.E{Key: "date_updated", Value: &now},
		}},
	}
	res, err = m.loginsSessions.UpdateMany(lsFilter, lsUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeLoginSession, &logutils.FieldArgs{"auth_type_code": "illinois_oidc"}, err)
	}
	if res.ModifiedCount != res.MatchedCount {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeLoginSession, &logutils.FieldArgs{"auth_type_code": "illinois_oidc", "modified": res.ModifiedCount, "expected": res.MatchedCount})
	}

	//2. update auth type codes (twilio_phone)
	aatFilter = bson.D{primitive.E{Key: "auth_types.auth_type_code", Value: "twilio_phone"}}
	aatUpdate = bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "auth_types.$[at].auth_type_code", Value: "phone"},
			primitive.E{Key: "date_updated", Value: &now},
		}},
	}

	opts = options.UpdateOptions{}
	arrayFilters = []interface{}{bson.M{"at.auth_type_code": "twilio_phone"}}
	opts.SetArrayFilters(options.ArrayFilters{Filters: arrayFilters})
	res, err = m.accounts.UpdateMany(aatFilter, aatUpdate, &opts)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, &logutils.FieldArgs{"auth_type_code": "twilio_phone"}, err)
	}
	if res.ModifiedCount != res.MatchedCount {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, &logutils.FieldArgs{"auth_type_code": "twilio_phone", "modified": res.ModifiedCount, "expected": res.MatchedCount})
	}

	lsFilter = bson.D{primitive.E{Key: "auth_type_code", Value: "twilio_phone"}}
	lsUpdate = bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "auth_type_code", Value: "phone"},
			primitive.E{Key: "date_updated", Value: &now},
		}},
	}
	res, err = m.loginsSessions.UpdateMany(lsFilter, lsUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeLoginSession, &logutils.FieldArgs{"auth_type_code": "twilio_phone"}, err)
	}
	if res.ModifiedCount != res.MatchedCount {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeLoginSession, &logutils.FieldArgs{"auth_type_code": "twilio_phone", "modified": res.ModifiedCount, "expected": res.MatchedCount})
	}

	//3. remove auth type ids
	aatFilter = bson.D{primitive.E{Key: "auth_types.auth_type_id", Value: bson.M{"$exists": true}}}
	aatUpdate = bson.D{
		primitive.E{Key: "$unset", Value: bson.D{
			primitive.E{Key: "auth_types.$[].auth_type_id", Value: ""},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: &now},
		}},
	}
	res, err = m.accounts.UpdateMany(aatFilter, aatUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, logutils.StringArgs("auth_type_id"), err)
	}
	if res.ModifiedCount != res.MatchedCount {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, &logutils.FieldArgs{"auth_type_id": "", "modified": res.ModifiedCount, "expected": res.MatchedCount})
	}

	credFilter := bson.D{primitive.E{Key: "auth_type_id", Value: bson.M{"$exists": true}}}
	credUpdate := bson.D{
		primitive.E{Key: "$unset", Value: bson.D{
			primitive.E{Key: "auth_type_id", Value: ""},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: &now},
		}},
	}
	res, err = m.credentials.UpdateMany(credFilter, credUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, logutils.StringArgs("auth_type_id"), err)
	}
	if res.ModifiedCount != res.MatchedCount {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeCredential, &logutils.FieldArgs{"auth_type_id": "", "modified": res.ModifiedCount, "expected": res.MatchedCount})
	}

	return nil
}
