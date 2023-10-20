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
	"fmt"
	"log"
	"time"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
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
	accounts                        *collectionWrapper //deprecated
	tenantsAccounts                 *collectionWrapper
	devices                         *collectionWrapper
	credentials                     *collectionWrapper
	loginsSessions                  *collectionWrapper
	configs                         *collectionWrapper
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

	uiucAuthTypeCodeMigrationSource string //email or illinois_oidc //to be removed when migration is compelted
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

	//deprecated
	accounts := &collectionWrapper{database: m, coll: db.Collection("accounts")}
	err = m.applyAccountsChecks(accounts)
	if err != nil {
		return err
	}

	tenantsAccounts := &collectionWrapper{database: m, coll: db.Collection("tenants_accounts")}
	err = m.applyTenantsAccountsIdentitiesChecks(tenantsAccounts)
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

	configs := &collectionWrapper{database: m, coll: db.Collection("configs")}
	err = m.applyConfigsChecks(configs)
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
	m.tenantsAccounts = tenantsAccounts
	m.devices = devices
	m.credentials = credentials
	m.loginsSessions = loginsSessions
	m.configs = configs
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
	go m.configs.Watch(nil, m.logger)

	// migrate to tenants accounts - remove this code when migrated to all environments
	err = m.migrateToTenantsAccounts(accounts, tenantsAccounts, applicationsOrganizations)
	if err != nil {
		return err
	}

	m.listeners = []Listener{}

	return nil
}

// migrate to tenants accounts
func (m *database) migrateToTenantsAccounts(accountsColl *collectionWrapper, tenantsAccountsColl *collectionWrapper,
	appsOrgsColl *collectionWrapper) error {
	m.logger.Debug("migrateToTenantsAccounts START")

	//all in transaction!
	transaction := func(context TransactionContext) error {

		//TODO - check if need to apply processing

		//process duplicate events
		err := m.processDuplicateAccounts(context, accountsColl, tenantsAccountsColl, appsOrgsColl)
		if err != nil {
			return err
		}

		return nil
	}

	err := m.performTransaction(transaction)
	if err != nil {
		return err
	}

	m.logger.Debug("migrateToTenantsAccounts END")
	return nil
}

func (m *database) processDuplicateAccounts(context TransactionContext, accountsColl *collectionWrapper,
	tenantsAccountsColl *collectionWrapper, appsOrgsColl *collectionWrapper) error {

	//find the duplicate accounts
	items, err := m.findDuplicateAccounts(context, accountsColl)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		m.logger.Info("there is no duplicated accounts")
		return nil
	}

	//construct tenants accounts
	tenantsAccounts, err := m.constructTenantsAccounts(context, appsOrgsColl, items)
	if err != nil {
		return err
	}

	//save tenants accounts
	log.Println(tenantsAccounts)

	//mark the old accounts as processed

	return nil
}

func (m *database) constructTenantsAccounts(context TransactionContext, appsOrgsColl *collectionWrapper, duplicateAccounts map[string][]account) ([]tenantAccount, error) {
	//we need to load the apps orgs object from the database as we will need them
	var allAppsOrgs []applicationOrganization
	err := appsOrgsColl.FindWithContext(context, bson.D{}, &allAppsOrgs, nil)
	if err != nil {
		return nil, err
	}

	//segment by org
	data := map[string][]orgAccounts{}
	for identifier, accounts := range duplicateAccounts {
		orgAccounts, err := m.segmentByOrgID(allAppsOrgs, accounts)
		if err != nil {
			return nil, err
		}

		data[identifier] = orgAccounts
	}

	//print 1
	fmt.Print("print 1\n")
	for identifier, dataItem := range data {
		fmt.Print("\n\n")

		fmt.Printf("%s\n", identifier)
		for _, orgAccounts := range dataItem {
			fmt.Printf("\torg_id:%s\n\n", orgAccounts.OrgID)
			for _, account := range orgAccounts.Accounts {
				fmt.Printf("\t\taccount_id:%s\tapp_org_id:%s\n\n", account.ID, account.AppOrgID)
				authTypes := account.AuthTypes
				for _, authType := range authTypes {
					fmt.Printf("\t\t\tauth_type_code:%s\tauth_type_identifier:%s\n\n", authType.AuthTypeCode, authType.Identifier)
				}
			}
		}
	}

	//use orgAccounts for easier manipulating
	orgIDsAccounts := m.simplifyStructureData(data)
	//print 2
	fmt.Print("print 2\n")
	for _, item := range orgIDsAccounts {
		fmt.Print("\n\n")

		fmt.Printf("%s\n", item.OrgID)
		for _, account := range item.Accounts {
			fmt.Printf("\t\taccount_id:%s\tapp_org_id:%s\n\n", account.ID, account.AppOrgID)
			authTypes := account.AuthTypes
			for _, authType := range authTypes {
				fmt.Printf("\t\t\tauth_type_code:%s\tauth_type_identifier:%s\n\n", authType.AuthTypeCode, authType.Identifier)
			}
		}

	}

	res := []tenantAccount{}
	for _, item := range orgIDsAccounts {
		orgItems, err := m.constructTenantsAccountsForOrg(item.OrgID, item.Accounts)
		if err != nil {
			return nil, err
		}
		res = append(res, orgItems...)
	}

	return res, nil
}

func (m *database) constructTenantsAccountsForOrg(orgID string, accounts []account) ([]tenantAccount, error) {
	if orgID != "0a2eff20-e2cd-11eb-af68-60f81db5ecc0" { //University of Illinois
		//we know that we do not have repeatable identities for the other organizations

		//TODO
		//verify that this is true

		//process them

	} else {
		//we have repeatable identities for University of Illinois

		//find all UIUC accounts
		uiucAccounts, otherAccounts := m.findUIUCAccounts(accounts)

		log.Println(uiucAccounts)
		log.Println(otherAccounts)
	}

	//TODO
	return nil, nil
}

func (m *database) findUIUCAccounts(accounts []account) ([]account, []account) {
	uiucAccounts := []account{}
	otherAccounts := []account{}

	for _, accountItem := range accounts {
		account := accountItem //pointer issue

		if account.AppOrgID == "1" { //UIUC app / University of Illinois
			uiucAccounts = append(uiucAccounts, account)
		} else {
			otherAccounts = append(otherAccounts, account)
		}
	}

	return uiucAccounts, otherAccounts
}

func (m *database) simplifyStructureData(data map[string][]orgAccounts) []orgAccounts {
	temp := map[string][]account{}
	seen := map[string]struct{}{}
	for _, dataItem := range data {
		for _, orgAccounts := range dataItem {
			orgID := orgAccounts.OrgID
			orgAllAccounts := temp[orgID]

			for _, acc := range orgAccounts.Accounts {
				if _, exists := seen[acc.ID]; !exists { // Check if already added
					seen[acc.ID] = struct{}{}
					orgAllAccounts = append(orgAllAccounts, acc)
				}
			}

			temp[orgID] = orgAllAccounts
		}
	}

	//prepare response
	res := []orgAccounts{}
	for orgID, tempItem := range temp {
		res = append(res, orgAccounts{OrgID: orgID, Accounts: tempItem})
	}
	return res
}

type orgAccounts struct {
	OrgID    string
	Accounts []account
}

func (m *database) segmentByOrgID(allAppsOrgs []applicationOrganization, accounts []account) ([]orgAccounts, error) {
	tempMap := map[string][]account{}
	for _, account := range accounts {
		currentOrgID, err := m.findOrgIDByAppOrgID(account.AppOrgID, allAppsOrgs)
		if err != nil {
			return nil, err
		}

		orgAccountsMap := tempMap[currentOrgID]
		orgAccountsMap = append(orgAccountsMap, account)
		tempMap[currentOrgID] = orgAccountsMap

	}

	result := []orgAccounts{}
	for orgID, accounts := range tempMap {
		current := orgAccounts{OrgID: orgID, Accounts: accounts}
		result = append(result, current)
	}

	return result, nil
}

func (m *database) findOrgIDByAppOrgID(appOrgID string, allAppsOrgs []applicationOrganization) (string, error) {
	for _, item := range allAppsOrgs {
		if item.ID == appOrgID {
			return item.OrgID, nil
		}
	}
	return "", errors.Newf("no org for app org id - %s", appOrgID)
}

func (m *database) findDuplicateAccounts(context TransactionContext, accountsColl *collectionWrapper) (map[string][]account, error) {
	pipeline := []bson.M{
		{
			"$unwind": "$auth_types",
		},
		{
			"$group": bson.M{
				"_id": "$auth_types.identifier",
				"accounts": bson.M{
					"$push": bson.M{
						"id": "$_id",
					},
				},
				"count": bson.M{
					"$sum": 1,
				},
			},
		},
		{
			"$match": bson.M{
				"count": bson.M{
					"$gt": 1,
				},
			},
		},
		{
			"$group": bson.M{
				"_id": nil,
				"result": bson.M{
					"$push": bson.M{
						"k": "$_id",
						"v": bson.M{
							"accounts": "$accounts",
						},
					},
				},
			},
		},
		{
			"$replaceRoot": bson.M{
				"newRoot": bson.M{
					"$arrayToObject": "$result",
				},
			},
		},
	}

	cursor, err := accountsColl.coll.Aggregate(context, pipeline)
	if err != nil {
		return nil, err
	}

	var result bson.M
	if cursor.Next(context) {
		err := cursor.Decode(&result)
		if err != nil {
			return nil, err
		}
	}

	if len(result) == 0 {

		return nil, nil
	}

	var resTypeResult []identityAccountsItem

	for key, value := range result {
		valueM := value.(primitive.M)
		accountsArr := valueM["accounts"].(primitive.A)

		var accounts []accountItem

		for _, element := range accountsArr {
			accountObj := element.(primitive.M)

			var account accountItem
			account.ID = accountObj["id"].(string)

			accounts = append(accounts, account)
		}

		item := identityAccountsItem{
			Identifier: key,
			Accounts:   accounts,
		}

		resTypeResult = append(resTypeResult, item)
	}

	//prepare founded duplicate accounts
	preparedResponse, err := m.prepareFoundedDuplicateAccounts(context, accountsColl, resTypeResult)
	if err != nil {
		return nil, err
	}

	return preparedResponse, nil
}

type accountItem struct {
	ID string `bson:"id"`
}
type identityAccountsItem struct {
	Identifier string        `bson:"id"`
	Accounts   []accountItem `bson:"accounts"`
}

func (m *database) prepareFoundedDuplicateAccounts(context TransactionContext, accountsColl *collectionWrapper,
	foundedItems []identityAccountsItem) (map[string][]account, error) {

	if len(foundedItems) == 0 {
		return nil, nil
	}

	//load all accounts
	accountsIDs := []string{}
	for _, item := range foundedItems {
		accounts := item.Accounts
		for _, acc := range accounts {
			accountsIDs = append(accountsIDs, acc.ID)
		}
	}
	findFilter := bson.M{"_id": bson.M{"$in": accountsIDs}}
	var accounts []account
	err := accountsColl.FindWithContext(context, findFilter, &accounts, nil)
	if err != nil {
		return nil, err
	}

	//prepare result
	result := map[string][]account{}
	for _, item := range foundedItems {
		identifier := item.Identifier
		accountsIDs := item.Accounts

		resAccounts, err := m.getFullAccountsObjects(accountsIDs, accounts)
		if err != nil {
			return nil, err
		}
		result[identifier] = resAccounts
	}

	return result, nil
}

func (m *database) getFullAccountsObjects(accountsIDs []accountItem, allAccounts []account) ([]account, error) {
	result := []account{}
	for _, item := range accountsIDs {
		//find the full account object
		var resAccount *account
		for _, acc := range allAccounts {
			if item.ID == acc.ID {
				resAccount = &acc
				break
			}
		}

		if resAccount == nil {
			return nil, errors.Newf("cannot find full account for %s", item.ID)
		}
		result = append(result, *resAccount)
	}

	return result, nil
}

func (m *database) performTransaction(transaction func(context TransactionContext) error) error {
	// transaction
	err := m.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			m.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionStart, logutils.TypeTransaction, nil, err)
		}

		err = transaction(sessionContext)
		if err != nil {
			m.abortTransaction(sessionContext)
			return errors.WrapErrorAction("performing", logutils.TypeTransaction, nil, err)
		}

		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			m.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionCommit, logutils.TypeTransaction, nil, err)
		}
		return nil
	})

	return err
}

func (m *database) abortTransaction(sessionContext mongo.SessionContext) {
	err := sessionContext.AbortTransaction(sessionContext)
	if err != nil {
		m.logger.Errorf("error aborting an accounts transaction - %s", err)
	}
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

// deprecated
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

	// err = accounts.AddIndex(bson.D{primitive.E{Key: "username", Value: "text"}, primitive.E{Key: "profile.first_name", Value: "text"}, primitive.E{Key: "profile.last_name", Value: "text"}}, false)
	// if err != nil {
	// 	return err
	// }

	m.logger.Info("accounts check passed")
	return nil
}

func (m *database) applyTenantsAccountsIdentitiesChecks(tenantAccounts *collectionWrapper) error {
	m.logger.Info("apply tenants accounts checks.....")

	//add org id index
	err := tenantAccounts.AddIndex(bson.D{primitive.E{Key: "org_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add profile index
	err = tenantAccounts.AddIndex(bson.D{primitive.E{Key: "profile.id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add auth types index
	err = tenantAccounts.AddIndex(bson.D{primitive.E{Key: "auth_types.id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add auth types identifier
	err = tenantAccounts.AddIndex(bson.D{primitive.E{Key: "auth_types.identifier", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add auth types auth type id
	err = tenantAccounts.AddIndex(bson.D{primitive.E{Key: "auth_types.auth_type_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add username index
	err = tenantAccounts.AddIndex(bson.D{primitive.E{Key: "username", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add org apps memberships id index
	err = tenantAccounts.AddIndex(bson.D{primitive.E{Key: "org_apps_memberships.id", Value: 1}}, true)
	if err != nil {
		return err
	}

	//add org apps memberships app org id index
	err = tenantAccounts.AddIndex(bson.D{primitive.E{Key: "org_apps_memberships.app_org_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("tenants accounts check passed")
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

func (m *database) applyConfigsChecks(configs *collectionWrapper) error {
	m.logger.Info("apply configs checks.....")

	err := configs.AddIndex(bson.D{primitive.E{Key: "type", Value: 1}, primitive.E{Key: "app_id", Value: 1}, primitive.E{Key: "org_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("configs checks passed")
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
	err := follows.AddIndex(bson.D{primitive.E{Key: "app_id", Value: 1}, primitive.E{Key: "org_id", Value: 1}, primitive.E{Key: "follower_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add following index
	err = follows.AddIndex(bson.D{primitive.E{Key: "app_id", Value: 1}, primitive.E{Key: "org_id", Value: 1}, primitive.E{Key: "following_id", Value: 1}, primitive.E{Key: "follower_id", Value: 1}}, true)
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
	case "configs":
		m.logger.Info("configs collection changed")

		for _, listener := range m.listeners {
			go listener.OnConfigsUpdated()
		}
	}
}
