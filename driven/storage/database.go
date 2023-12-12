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
	"time"

	"github.com/google/uuid"
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
	//accounts := &collectionWrapper{database: m, coll: db.Collection("_for_test_accounts")}
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

	//organizations := &collectionWrapper{database: m, coll: db.Collection("_for_test_organizations")}
	organizations := &collectionWrapper{database: m, coll: db.Collection("organizations")}
	err = m.applyOrganizationsChecks(organizations)
	if err != nil {
		return err
	}

	//applications := &collectionWrapper{database: m, coll: db.Collection("_for_test_applications")}
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

	//applicationsOrganizations := &collectionWrapper{database: m, coll: db.Collection("_for_test_applications_organizations")}
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

	// migrate to tenants accounts - remove this code when migrated to all environments
	err = m.migrateToTenantsAccounts(accounts, tenantsAccounts, applicationsOrganizations)
	if err != nil {
		return err
	}
	//before the threads below!!

	go m.apiKeys.Watch(nil, m.logger)
	go m.authTypes.Watch(nil, m.logger)
	go m.identityProviders.Watch(nil, m.logger)
	go m.serviceRegistrations.Watch(nil, m.logger)
	go m.organizations.Watch(nil, m.logger)
	go m.applications.Watch(nil, m.logger)
	go m.applicationsOrganizations.Watch(nil, m.logger)
	go m.applicationConfigs.Watch(nil, m.logger)
	go m.configs.Watch(nil, m.logger)

	m.listeners = []Listener{}

	return nil
}

// migrate to tenants accounts
func (m *database) migrateToTenantsAccounts(accountsColl *collectionWrapper, tenantsAccountsColl *collectionWrapper,
	appsOrgsColl *collectionWrapper) error {
	m.logger.Debug("migrateToTenantsAccounts START")

	err := m.startPhase1(accountsColl, tenantsAccountsColl, appsOrgsColl)
	if err != nil {
		return err
	}

	time.Sleep(1 * time.Second) // sleep for 1 second

	err = m.startPhase2(accountsColl, tenantsAccountsColl, appsOrgsColl)
	if err != nil {
		return err
	}

	m.logger.Debug("migrateToTenantsAccounts END")
	return nil
}

func (m *database) startPhase2(accountsColl *collectionWrapper, tenantsAccountsColl *collectionWrapper,
	appsOrgsColl *collectionWrapper) error {
	m.logger.Debug("startPhase2 START")

	//check if need to apply processing
	notMigratedCount, err := m.findNotMigratedCount(nil, accountsColl)
	if err != nil {
		return err
	}
	if *notMigratedCount == 0 {
		m.logger.Debug("there is no what to be migrated, so do nothing")
		return nil
	}

	//WE MUST APPLY MIGRATION
	m.logger.Debugf("there are %d accounts to be migrated", *notMigratedCount)

	//first load all aprs orgs as we need them
	var allAppsOrgs []applicationOrganization
	err = appsOrgsColl.Find(bson.D{}, &allAppsOrgs, nil)
	if err != nil {
		return err
	}
	//prepare the orgs and its aprs orgs items
	orgsData := m.appsOrgsToMap(allAppsOrgs)
	for orgID, orgItems := range orgsData {
		//process for every organization

		err := m.processPhase2ForOrg(accountsColl, orgID, orgItems)
		if err != nil {
			return err
		}
	}

	m.logger.Debug("startPhase2 END")
	return nil
}

func (m *database) processPhase2ForOrg(accountsColl *collectionWrapper, orgID string, orgApps []string) error {
	m.logger.Debugf("...start processing org id %s with apps orgs ids - %s", orgID, orgApps)

	i := 0
	for {
		ids, err := m.loadAccountsIDsForMigration(nil, accountsColl)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			break //no more records
		}

		// process
		err = m.processPhase2ForOrgPiece(accountsColl, ids, orgID, orgApps)
		if err != nil {
			return err
		}

		m.logger.Infof("Iteration:%d", i)

		// 1 second sleep
		time.Sleep(time.Second)

		i++
	}

	m.logger.Debugf("...end processing org id %s", orgID)
	return nil
}

func (m *database) loadAccountsIDsForMigration(context TransactionContext, accountsColl *collectionWrapper) ([]string, error) {
	filter := bson.M{"migrated": bson.M{"$in": []interface{}{nil, false}}}

	findOptions := options.Find()
	findOptions.SetLimit(int64(5000))

	var accountsResult []account
	err := accountsColl.FindWithContext(context, filter, &accountsResult, findOptions)
	if err != nil {
		return nil, err
	}
	if len(accountsResult) == 0 {
		return []string{}, nil //empty
	}

	res := make([]string, len(accountsResult))
	for i, c := range accountsResult {
		res[i] = c.ID
	}
	return res, nil
}

func (m *database) processPhase2ForOrgPiece(accountsColl *collectionWrapper, idsList []string, orgID string, orgApps []string) error {
	//all in transaction!
	transaction := func(contextTr TransactionContext) error {
		//1. first mark the accounts as migrated
		err := m.markAccountsAsProcessed(contextTr, idsList, accountsColl)
		if err != nil {
			return err
		}

		//2. $out/merge cannot be used in a transaction
		ctx := context.Background()
		err = m.moveToTenantsAccounts(ctx, accountsColl, idsList, orgID, orgApps)
		if err != nil {
			return err //rollback if the move fails
		}

		//once we know that the huge data operation is sucessfull then we can commit the transaction from step 1
		return nil
	}

	err := m.performTransaction(transaction)
	if err != nil {
		return err
	}

	return nil
}

func (m *database) appsOrgsToMap(allAppsOrgs []applicationOrganization) map[string][]string {
	orgMap := make(map[string][]string)

	for _, appOrg := range allAppsOrgs {
		orgMap[appOrg.OrgID] = append(orgMap[appOrg.OrgID], appOrg.ID)
	}

	return orgMap
}

func (m *database) startPhase1(accountsColl *collectionWrapper, tenantsAccountsColl *collectionWrapper,
	appsOrgsColl *collectionWrapper) error {
	m.logger.Debug("startPhase1 START")

	//all in transaction!
	transaction := func(context TransactionContext) error {

		//check if need to apply processing
		notMigratedCount, err := m.findNotMigratedCount(context, accountsColl)
		if err != nil {
			return err
		}
		if *notMigratedCount == 0 {
			m.logger.Debug("there is no what to be migrated, so do nothing")
			return nil
		}

		//WE MUST APPLY MIGRATION
		m.logger.Debugf("there are %d accounts to be migrated", *notMigratedCount)

		//process duplicate events
		err = m.processDuplicateAccounts(context, accountsColl, tenantsAccountsColl, appsOrgsColl)
		if err != nil {
			return err
		}

		return nil
	}

	err := m.performTransaction(transaction)
	if err != nil {
		return err
	}

	m.logger.Debug("startPhase1 END")
	return nil
}

func (m *database) moveToTenantsAccounts(context context.Context, accountsColl *collectionWrapper, idsList []string, orgID string, appsOrgsIDs []string) error {
	matchStage := bson.D{
		{Key: "$match", Value: bson.D{
			{Key: "_id", Value: bson.M{"$in": idsList}},
			{Key: "$or", Value: bson.A{
				bson.D{{Key: "migrated", Value: bson.M{"$type": 10}}}, //10 is the number for null
				bson.D{{Key: "migrated", Value: false}},
				bson.D{{Key: "migrated", Value: bson.D{{Key: "$exists", Value: false}}}},
			}},
			{Key: "app_org_id", Value: bson.M{"$in": appsOrgsIDs}},
		}},
	}

	addFieldsStage := bson.D{
		{Key: "$addFields", Value: bson.D{
			{Key: "_id", Value: "$_id"},
			{Key: "org_id", Value: orgID},
			{Key: "org_apps_memberships", Value: bson.A{
				bson.D{
					{Key: "id", Value: bson.D{{Key: "$concat", Value: bson.A{"$app_org_id", "_", "$_id"}}}},
					{Key: "app_org_id", Value: "$app_org_id"},
					{Key: "permissions", Value: "$permissions"},
					{Key: "roles", Value: "$roles"},
					{Key: "groups", Value: "$groups"},
					{Key: "preferences", Value: "$preferences"},
					{Key: "most_recent_client_version", Value: "$most_recent_client_version"},
				},
			}},
			{Key: "scopes", Value: "$scopes"},
			{Key: "auth_types", Value: "$auth_types"},
			{Key: "mfa_types", Value: "$mfa_types"},
			{Key: "username", Value: "$username"},
			{Key: "external_ids", Value: "$external_ids"},
			{Key: "system_configs", Value: "$system_configs"},
			{Key: "profile", Value: "$profile"},
			{Key: "devices", Value: "$devices"},
			{Key: "anonymous", Value: "$anonymous"},
			{Key: "privacy", Value: "$privacy"},
			{Key: "verified", Value: "$verified"},
			{Key: "date_created", Value: "$date_created"},
			{Key: "date_updated", Value: "$date_updated"},
			{Key: "is_following", Value: "$is_following"},
			{Key: "last_login_date", Value: "$last_login_date"},
			{Key: "last_access_token_date", Value: "$last_access_token_date"},
		}},
	}

	projectStage := bson.D{
		{Key: "$project", Value: bson.D{
			{Key: "app_org_id", Value: 0},
			{Key: "permissions", Value: 0},
			{Key: "roles", Value: 0},
			{Key: "groups", Value: 0},
			{Key: "preferences", Value: 0},
			{Key: "most_recent_client_version", Value: 0},
		}},
	}

	/*outStage := bson.D{
		{Key: "$out", Value: "tenants_accounts"},
	} */

	mergeStage := bson.D{
		{Key: "$merge", Value: bson.M{"into": "tenants_accounts", "whenMatched": "keepExisting", "whenNotMatched": "insert"}},
	}

	_, err := accountsColl.coll.Aggregate(context, mongo.Pipeline{matchStage, addFieldsStage, projectStage, mergeStage})
	if err != nil {
		return err
	}

	return nil
}

func (m *database) findNotMigratedCount(context TransactionContext, accountsColl *collectionWrapper) (*int64, error) {
	filter := bson.M{"migrated": bson.M{"$in": []interface{}{nil, false}}}
	count, err := accountsColl.CountDocumentsWithContext(context, filter)
	if err != nil {
		return nil, err
	}
	return &count, nil
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
	err = m.insertTenantAccounts(context, tenantsAccounts, tenantsAccountsColl)
	if err != nil {
		return err
	}

	//mark the old accounts as processed
	accountsIDs := m.getUniqueAccountsIDs(items)
	err = m.markAccountsAsProcessed(context, accountsIDs, accountsColl)
	if err != nil {
		return err
	}

	return nil
}

func (m *database) getUniqueAccountsIDs(items map[string][]account) []string {
	uniqueIDs := make(map[string]struct{})
	var result []string

	for _, accounts := range items {
		for _, acc := range accounts {
			if _, found := uniqueIDs[acc.ID]; !found {
				uniqueIDs[acc.ID] = struct{}{}
				result = append(result, acc.ID)
			}
		}
	}

	return result
}

func (m *database) markAccountsAsProcessed(context TransactionContext, accountsIDs []string, accountsColl *collectionWrapper) error {
	filter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": accountsIDs}}}

	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "migrated", Value: true},
		}},
	}

	_, err := accountsColl.UpdateManyWithContext(context, filter, update, nil)
	if err != nil {
		return err
	}

	return nil
}

func (m *database) insertTenantAccounts(context TransactionContext, items []tenantAccount, tenantsAccountsColl *collectionWrapper) error {

	stgItems := make([]interface{}, len(items))
	for i, p := range items {
		stgItems[i] = p
	}

	res, err := tenantsAccountsColl.InsertManyWithContext(context, stgItems, nil)
	if err != nil {
		return err
	}

	if len(res.InsertedIDs) != len(items) {
		return errors.Newf("inserted:%d items:%d", len(res.InsertedIDs), len(items))
	}

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

		//verify that this is true
		notExist := m.verifyNotExist(accounts)
		if !notExist {
			return nil, errors.Newf("%s has repetable items")
		}

		//process them
		resAccounts := []tenantAccount{}
		for _, account := range accounts {
			newTenantAccount := m.createTenantAccount(orgID, account)
			resAccounts = append(resAccounts, newTenantAccount)
		}

		return resAccounts, nil
	}

	//we have repeatable identities for University of Illinois

	//find all UIUC accounts
	uiucAccounts, otherAccounts := m.findUIUCAccounts(accounts)

	if len(uiucAccounts) == 0 {
		return nil, errors.New("no accounts for UIUC")
	}

	//first create tenant accounts from the UIUC accounts
	uiucTenantAccounts := []tenantAccount{}
	for _, uiucAccount := range uiucAccounts {
		newUIUCTenantAccount := m.createTenantAccount(orgID, uiucAccount)
		uiucTenantAccounts = append(uiucTenantAccounts, newUIUCTenantAccount)
	}

	//now create tenant accounts for the other accounts
	currentTenantAccounts := uiucTenantAccounts
	for _, otherAccount := range otherAccounts {
		//for every account determine if we need to create a new tenant account or to add it to already created

		foundedTenantAccounts := m.findTenantAccountsByIdentities(otherAccount.AuthTypes, currentTenantAccounts)
		if len(foundedTenantAccounts) == 0 {
			//it is not there so, create a new one

			newCreated := m.createTenantAccount(orgID, otherAccount)
			currentTenantAccounts = append(currentTenantAccounts, newCreated)
		} else if len(foundedTenantAccounts) == 1 {
			//it is there only once, so add it to it

			updatedTenantAccount := m.addAccountToTenantAccount(otherAccount, foundedTenantAccounts[0])

			//replace item
			currentTenantAccounts = m.replaceItem(updatedTenantAccount, currentTenantAccounts)
		} else if len(foundedTenantAccounts) == 2 {
			//it is there into two accounts, so merge them first and then add it to the merged one
			tenantAccount1 := foundedTenantAccounts[0]
			tenantAccount2 := foundedTenantAccounts[1]
			mixedTenantAccount, err := m.mixTenantAccount(tenantAccount1, tenantAccount2)
			if err != nil {
				return nil, err
			}

			//replace the two items with the mixed one
			currentTenantAccounts = m.replaceMixedItems(tenantAccount1, tenantAccount2, *mixedTenantAccount, currentTenantAccounts)

			//add to the merged item
			updatedTenantAccount := m.addAccountToTenantAccount(otherAccount, *mixedTenantAccount)

			//replace item
			currentTenantAccounts = m.replaceItem(updatedTenantAccount, currentTenantAccounts)
		} else {
			return nil, errors.New("we do not support more than 2 appearings")
		}
	}

	return currentTenantAccounts, nil

}

func (m *database) replaceMixedItems(item1 tenantAccount, item2 tenantAccount, mixedItem tenantAccount, list []tenantAccount) []tenantAccount {
	newList := make([]tenantAccount, 0)

	for _, item := range list {
		if item.ID != item1.ID && item.ID != item2.ID {
			newList = append(newList, item)
		}
	}

	newList = append(newList, mixedItem)

	return newList
}

func (m *database) mixTenantAccount(tenantAccount1 tenantAccount, tenantAccount2 tenantAccount) (*tenantAccount, error) {
	var source *tenantAccount
	var second *tenantAccount
	if m.isUIUCSource(tenantAccount1) {
		source = &tenantAccount1
		second = &tenantAccount2
	} else if m.isUIUCSource(tenantAccount2) {
		source = &tenantAccount2
		second = &tenantAccount1
	}
	if source == nil || second == nil {
		return nil, errors.New("no uiuc source")
	}

	mixedEntity := source

	//add auth types
	//add only the auth types which are not already in the mixed tenant account
	newAuthTypes := m.findNewAuthTypes(second.AuthTypes, mixedEntity.AuthTypes)
	if len(newAuthTypes) > 0 {
		currentAuthTypes := mixedEntity.AuthTypes
		currentAuthTypes = append(currentAuthTypes, newAuthTypes...)
		mixedEntity.AuthTypes = currentAuthTypes
	}

	///add memberships
	mergedMemberships, err := m.mergeMemberships(mixedEntity.OrgAppsMemberships, second.OrgAppsMemberships)
	if err != nil {
		return nil, err
	}
	mixedEntity.OrgAppsMemberships = mergedMemberships

	return mixedEntity, nil
}

func (m *database) mergeMemberships(mixedEntityMemberships []orgAppMembership, secondEntityMemberships []orgAppMembership) ([]orgAppMembership, error) {
	result := mixedEntityMemberships
	for i, current := range secondEntityMemberships {
		if current.AppOrgID == "1" { //we must merge it
			mixedUIUCMembership := m.findUIUCMembership(mixedEntityMemberships)
			if mixedUIUCMembership == nil {
				return nil, errors.New("no UIUC membership")
			}

			mergedUIUCMembership := mixedUIUCMembership

			mergedUIUCMembership.Permissions = append(mergedUIUCMembership.Permissions, current.Permissions...)
			mergedUIUCMembership.Roles = append(mergedUIUCMembership.Roles, current.Roles...)
			mergedUIUCMembership.Groups = append(mergedUIUCMembership.Groups, current.Groups...)

			mergedUIUCMembership.Preferences = m.mergeMaps(mergedUIUCMembership.Preferences, current.Preferences)

			result[i] = *mergedUIUCMembership
		} else {
			result = append(result, current)
		}
	}
	return result, nil
}

func (m *database) mergeMaps(map1, map2 map[string]interface{}) map[string]interface{} {
	mergedMap := make(map[string]interface{})

	for key, value := range map1 {
		mergedMap[key] = value
	}

	for key, value := range map2 {
		mergedMap[key] = value
	}

	return mergedMap
}

func (m *database) findUIUCMembership(mixedEntityMemberships []orgAppMembership) *orgAppMembership {
	for _, current := range mixedEntityMemberships {
		if current.AppOrgID == "1" {
			return &current
		}
	}
	return nil
}

func (m *database) isUIUCSource(tenantAccount tenantAccount) bool {
	isUIUC := false
	for _, m := range tenantAccount.OrgAppsMemberships {
		if m.AppOrgID == "1" { //UIUC/University of Illinois
			isUIUC = true
			break
		}
	}
	if !isUIUC {
		return false
	}

	hasAuthTypeSource := false
	for _, at := range tenantAccount.AuthTypes {
		if at.AuthTypeCode == m.uiucAuthTypeCodeMigrationSource {
			hasAuthTypeSource = true
		}
	}
	if !hasAuthTypeSource {
		return false
	}

	return true
}

func (m *database) replaceItem(item tenantAccount, list []tenantAccount) []tenantAccount {
	for i, current := range list {
		if current.ID == item.ID {
			list[i] = item
			break
		}
	}
	return list
}

func (m *database) addAccountToTenantAccount(account account, tenantAccount tenantAccount) tenantAccount {

	//create org app memberhip
	oaID := uuid.NewString()
	oaAppOrgID := account.AppOrgID
	oaPermissions := account.Permissions
	oaRoles := account.Roles
	oaGroups := account.Groups
	oaPreferences := account.Preferences
	oaMostRecentClientVersion := account.MostRecentClientVersion

	oaMembership := orgAppMembership{ID: oaID, AppOrgID: oaAppOrgID,
		Permissions: oaPermissions, Roles: oaRoles, Groups: oaGroups,
		Preferences: oaPreferences, MostRecentClientVersion: oaMostRecentClientVersion}

	//add the created oa membership to the tenant account
	current := tenantAccount.OrgAppsMemberships
	current = append(current, oaMembership)
	tenantAccount.OrgAppsMemberships = current

	//add only the auth types which are not already in the tenant account
	newAuthTypes := m.findNewAuthTypes(account.AuthTypes, tenantAccount.AuthTypes)
	if len(newAuthTypes) > 0 {
		currentAuthTypes := tenantAccount.AuthTypes
		currentAuthTypes = append(currentAuthTypes, newAuthTypes...)
		tenantAccount.AuthTypes = currentAuthTypes
	}

	return tenantAccount
}

func (m *database) findNewAuthTypes(toBeAdded []accountAuthType, currentList []accountAuthType) []accountAuthType {
	newAuthTypes := []accountAuthType{}

	for _, accAuthType := range toBeAdded {
		code := accAuthType.AuthTypeCode

		containsCode := false
		for _, tenantAuthType := range currentList {
			tenantCode := tenantAuthType.AuthTypeCode
			if tenantCode == code {
				containsCode = true
				break
			}
		}

		if !containsCode {
			newAuthTypes = append(newAuthTypes, accAuthType)
		}
	}
	return newAuthTypes
}

func (m *database) verifyNotExist(accounts []account) bool {
	for _, acc := range accounts {
		for _, acc2 := range accounts {
			if acc.ID == acc2.ID {
				continue //skip
			}

			if m.containsAuthType(acc.AuthTypes, acc2.AuthTypes) {
				return false
			}
		}
	}
	return true
}

func (m *database) containsAuthType(authTypes1 []accountAuthType, authTypes2 []accountAuthType) bool {
	for _, at := range authTypes1 {
		for _, at2 := range authTypes2 {
			if at.Identifier == at2.Identifier {
				return true
			}
		}
	}
	return false
}

func (m *database) findTenantAccountsByIdentities(identities []accountAuthType, tenantAccounts []tenantAccount) []tenantAccount {
	result := []tenantAccount{}

	for _, tenantAccount := range tenantAccounts {
		if m.containsIdentity(identities, tenantAccount.AuthTypes) {
			result = append(result, tenantAccount)
		}
	}
	return result
}

func (m *database) containsIdentity(aut1 []accountAuthType, aut2 []accountAuthType) bool {
	for _, aut1Item := range aut1 {
		for _, aut2Item := range aut2 {
			if aut1Item.Identifier == aut2Item.Identifier {
				return true
			}
		}
	}
	return false
}

func (m *database) createTenantAccount(orgID string, account account) tenantAccount {

	id := account.ID
	scopes := account.Scopes
	authTypes := account.AuthTypes
	mfaTypes := account.MFATypes
	username := account.Username
	externalIDs := account.ExternalIDs
	systemConfigs := account.SystemConfigs
	profile := account.Profile
	devices := account.Devices
	anonymous := account.Anonymous
	privacy := account.Privacy

	var verified *bool //not used?
	if account.Verified {
		verified = &account.Verified
	}

	dateCreated := account.DateCreated
	dateUpdated := account.DateUpdated
	isFollowing := account.IsFollowing
	lastLoginDate := account.LastLoginDate
	lastAccessTokenDate := account.LastAccessTokenDate

	//create org apps membership
	oaID := uuid.NewString()
	oaAppOrgID := account.AppOrgID
	oaPermissions := account.Permissions
	oaRoles := account.Roles
	oaGroups := account.Groups
	oaPreferences := account.Preferences
	oaMostRecentClientVersion := account.MostRecentClientVersion

	orgAppMembershipObj := orgAppMembership{ID: oaID, AppOrgID: oaAppOrgID,
		Permissions: oaPermissions, Roles: oaRoles, Groups: oaGroups,
		Preferences: oaPreferences, MostRecentClientVersion: oaMostRecentClientVersion}

	orgAppsMemberships := []orgAppMembership{orgAppMembershipObj}

	return tenantAccount{ID: id, OrgID: orgID, OrgAppsMemberships: orgAppsMemberships, Scopes: scopes,
		AuthTypes: authTypes, MFATypes: mfaTypes, Username: username, ExternalIDs: externalIDs,
		SystemConfigs: systemConfigs, Profile: profile, Devices: devices, Anonymous: anonymous,
		Privacy: privacy, Verified: verified, DateCreated: dateCreated, DateUpdated: dateUpdated,
		IsFollowing: isFollowing, LastLoginDate: lastLoginDate, LastAccessTokenDate: lastAccessTokenDate}
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
			"$match": bson.M{"migrated": bson.M{"$in": []interface{}{nil, false}}}, //iterate only not migrated records
		},
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
	// Setting a timeout for the transaction
	desiredTimeout := 10 * time.Minute // adjust as needed
	ctx, cancel := context.WithTimeout(context.Background(), desiredTimeout)
	defer cancel()

	err := m.dbClient.UseSession(ctx, func(sessionContext mongo.SessionContext) error {
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
