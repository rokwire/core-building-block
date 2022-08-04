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

package core

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"core-building-block/utils"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) admGetTest() string {
	return "Admin - test"
}

func (app *application) admGetTestModel() string {
	/* disable it as it is not up to date with the latest model changes
	//global config
	globalConfig := model.GlobalConfig{Setting: "setting_value"}

	//organizations configs
	illinoisDomains := []string{"illinois.edu"}
	illinoisOrganizationConfig := model.OrganizationConfig{ID: "1", Setting: "setting_value", Domains: illinoisDomains, Custom: "Illinois organization custom config"}

	danceOrganizationConfig := model.OrganizationConfig{ID: "2", Setting: "setting_value", Domains: []string{}, Custom: "Dance organization custom config"}

	//organizations
	illinoisOrganization := model.Organization{ID: "1", Name: "Illinois", Type: "large", Config: illinoisOrganizationConfig}

	danceOrganization := model.Organization{ID: "2", Name: "Dance", Type: "medium", Config: danceOrganizationConfig}

	//global permissions and roles

	glRole1 := model.GlobalRole{ID: "1", Name: "super_admin", Permissions: nil} //super_admin has nil permissions as it has all
	glPermission1 := model.GlobalPermission{ID: "1", Name: "invite_organization_admin"}
	glPermission2 := model.GlobalPermission{ID: "2", Name: "read_log"}
	glPermission3 := model.GlobalPermission{ID: "3", Name: "modify_config"}
	glRole2 := model.GlobalRole{ID: "2", Name: "lite_admin",
		Permissions: []model.GlobalPermission{glPermission1, glPermission2, glPermission3}}

	//Illinois permissions, roles and groups

	illinoisRole1 := model.OrganizationRole{ID: "1", Name: "organization_super_admin", Permissions: nil, Organization: illinoisOrganization} //organization_super_admin has nil permissions as it has all
	illinoisPermission1 := model.OrganizationPermission{ID: "1", Name: "read_audit", Organization: illinoisOrganization}
	illinoisPermission2 := model.OrganizationPermission{ID: "2", Name: "read_manual_test", Organization: illinoisOrganization}
	illinoisPermission3 := model.OrganizationPermission{ID: "3", Name: "modify_manual_test", Organization: illinoisOrganization}
	illinoisRole2 := model.OrganizationRole{ID: "2", Name: "manual_tests_manager",
		Permissions: []model.OrganizationPermission{illinoisPermission2, illinoisPermission3}, Organization: illinoisOrganization}
	illinoisGroup1 := model.OrganizationGroup{ID: "1", Name: "students", Organization: illinoisOrganization}
	illinoisGroup2 := model.OrganizationGroup{ID: "2", Name: "manual tests managers", Organization: illinoisOrganization}

	//Dance permissions, roles and groups

	danceRole1 := model.OrganizationRole{ID: "3", Name: "organization_super_admin", Permissions: nil, Organization: danceOrganization} //organization_super_admin has nil permissions as it has all
	dancePermission1 := model.OrganizationPermission{ID: "4", Name: "view_video", Organization: danceOrganization}
	dancePermission2 := model.OrganizationPermission{ID: "5", Name: "write_video", Organization: danceOrganization}
	dancePermission3 := model.OrganizationPermission{ID: "6", Name: "view_schedule", Organization: danceOrganization}
	danceRole2 := model.OrganizationRole{ID: "4", Name: "videos_manager",
		Permissions: []model.OrganizationPermission{dancePermission1, dancePermission2}, Organization: danceOrganization}
	danceGroup1 := model.OrganizationGroup{ID: "3", Name: "videos managers", Organization: danceOrganization}

	//users

	globalUser1Account := model.UserAccount{ID: "1", Email: "petyo.stoyanov@inabit.eu"}
	globalUser1Profile := model.UserProfile{ID: "1", PII: &model.UserPII{FirstName: "Petyo", LastName: "Stoyanov"}}
	globalUser1 := model.User{ID: "1", Account: globalUser1Account, Profile: globalUser1Profile,
		Permissions: nil, Roles: []model.GlobalRole{glRole1}, Groups: nil, OrganizationsMemberships: nil}

	globalUser2Account := model.UserAccount{ID: "2", Email: "pencho.penchev@inabit.eu"}
	globalUser2Profile := model.UserProfile{ID: "2", PII: &model.UserPII{FirstName: "Pencho", LastName: "penchev"}}
	globalUser2 := model.User{ID: "2", Account: globalUser2Account, Profile: globalUser2Profile,
		Permissions: nil, Roles: []model.GlobalRole{glRole2}, Groups: nil, OrganizationsMemberships: nil}

	illiniUser1Account := model.UserAccount{ID: "3", Email: "vivon@inabit.eu"}
	illiniUser1Profile := model.UserProfile{ID: "3", PII: &model.UserPII{FirstName: "Vivon", LastName: "Vivonov"}}
	illiniUser1 := model.User{ID: "3", Account: illiniUser1Account, Profile: illiniUser1Profile,
		Permissions: nil, Roles: nil, Groups: nil, OrganizationsMemberships: nil}
	illiniUser1Organization := model.OrganizationMembership{ID: "1", User: illiniUser1, Organization: illinoisOrganization,
		OrgUserData: nil, Permissions: nil, Roles: []model.OrganizationRole{illinoisRole1}, Groups: nil}
	illiniUser1.OrganizationsMemberships = []model.OrganizationMembership{illiniUser1Organization}

	illiniUser2Account := model.UserAccount{ID: "4", Email: "vivon2@inabit.eu"}
	illiniUser2Profile := model.UserProfile{ID: "4", PII: &model.UserPII{FirstName: "Vivon2", LastName: "Vivonov2"}}
	illiniUser2 := model.User{ID: "4", Account: illiniUser2Account, Profile: illiniUser2Profile,
		Permissions: nil, Roles: nil, Groups: nil, OrganizationsMemberships: nil}
	illiniUser2Organization := model.OrganizationMembership{ID: "2", User: illiniUser2, Organization: illinoisOrganization,
		OrgUserData: nil,
		Permissions: []model.OrganizationPermission{illinoisPermission1},
		Roles:       []model.OrganizationRole{illinoisRole2},
		Groups:      []model.OrganizationGroup{illinoisGroup1}}
	illiniUser2.OrganizationsMemberships = []model.OrganizationMembership{illiniUser2Organization}

	illiniUser3Account := model.UserAccount{ID: "5", Email: "vivon3@inabit.eu"}
	illiniUser3Profile := model.UserProfile{ID: "5", PII: &model.UserPII{FirstName: "Vivon3", LastName: "Vivonov3"}}
	illiniUser3 := model.User{ID: "5", Account: illiniUser3Account, Profile: illiniUser3Profile,
		Permissions: nil, Roles: nil, Groups: nil, OrganizationsMemberships: nil}
	illiniUser3Organization := model.OrganizationMembership{ID: "3", User: illiniUser3, Organization: illinoisOrganization,
		OrgUserData: nil,
		Permissions: []model.OrganizationPermission{illinoisPermission1},
		Roles:       []model.OrganizationRole{illinoisRole2},
		Groups:      []model.OrganizationGroup{illinoisGroup1}}
	illiniUser3.OrganizationsMemberships = []model.OrganizationMembership{illiniUser3Organization}

	illiniUsersRel := model.OrganizationUserRelations{ID: "1", Type: "family",
		Manager: illiniUser2Organization, Members: []model.OrganizationMembership{illiniUser3Organization}}

	danceUser1Account := model.UserAccount{ID: "6", Email: "cocun@inabit.eu"}
	danceUser1Profile := model.UserProfile{ID: "6", PII: &model.UserPII{FirstName: "Cocun", LastName: "Cocunov"}}
	danceUser1 := model.User{ID: "6", Account: danceUser1Account, Profile: danceUser1Profile,
		Permissions: nil, Roles: nil, Groups: nil, OrganizationsMemberships: nil}
	danceUser1Organization := model.OrganizationMembership{ID: "4", User: danceUser1, Organization: danceOrganization,
		OrgUserData: nil, Permissions: nil, Roles: []model.OrganizationRole{danceRole1}, Groups: nil}
	danceUser1.OrganizationsMemberships = []model.OrganizationMembership{danceUser1Organization}

	diAccount := model.UserAccount{ID: "7", Email: "di@inabit.eu"}
	diProfile := model.UserProfile{ID: "7", PII: &model.UserPII{FirstName: "Dinko", LastName: "Dinkov"}}
	diUser := model.User{ID: "7", Account: diAccount, Profile: diProfile,
		Permissions: nil, Roles: nil, Groups: nil, OrganizationsMemberships: nil}
	danceDIOrganization := model.OrganizationMembership{ID: "5", User: diUser, Organization: danceOrganization,
		OrgUserData: nil, Permissions: nil, Roles: []model.OrganizationRole{danceRole2}, Groups: []model.OrganizationGroup{danceGroup1}}
	illinoisDIOrganization := model.OrganizationMembership{ID: "6", User: diUser, Organization: illinoisOrganization,
		OrgUserData: nil, Permissions: nil, Roles: []model.OrganizationRole{illinoisRole2}, Groups: []model.OrganizationGroup{illinoisGroup2}}
	diUser.OrganizationsMemberships = []model.OrganizationMembership{danceDIOrganization, illinoisDIOrganization}

	res := fmt.Sprintf("GlobalConfig:\n\t%s\n\n"+
		"IllinoisOrganizationConfig:\n\t%s\n\n"+
		"DanceOrganizationConfig:\n\t%s\n\n"+
		"IllinoisOrganization:\n\t%s\n\n"+
		"DanceOrganization:\n\t%s\n\n"+
		"GlobalRole1:\n\t%s\n\n"+
		"GlobalPermission1:\n\t%s\n\n"+
		"GlobalPermission2:\n\t%s\n\n"+
		"GlobalPermission3:\n\t%s\n\n"+
		"GlobalRole2:\n\t%s\n\n"+
		"IllinoisRole1:\n\t%s\n\n"+
		"IllinoisPermission1:\n\t%s\n\n"+
		"IllinoisPermission2:\n\t%s\n\n"+
		"IllinoisPermission3:\n\t%s\n\n"+
		"IllinoisRole2:\n\t%s\n\n"+
		"IllinoisGroup1:\n\t%s\n\n"+
		"IllinoisGroup2:\n\t%s\n\n"+
		"DanceRole1:\n\t%s\n\n"+
		"DancePermission1:\n\t%s\n\n"+
		"DancePermission2:\n\t%s\n\n"+
		"DancePermission3:\n\t%s\n\n"+
		"DanceRole2:\n\t%s\n\n"+
		"DanceGroup1:\n\t%s\n\n"+
		"GlobalUser1:\n\t%s\n\n"+
		"GlobalUser2:\n\t%s\n\n"+
		"IlliniUser1:\n\t%s\n\n"+
		"IlliniUser2:\n\t%s\n\n"+
		"IlliniUser3:\n\t%s\n\n"+
		"IlliniUserRelations:\n\t%s\n\n"+
		"DanceUser1:\n\t%s\n\n"+
		"DIUser1:\n\t%s\n\n",
		globalConfig, illinoisOrganizationConfig, danceOrganizationConfig,
		illinoisOrganization, danceOrganization,
		glRole1, glPermission1, glPermission2, glPermission3, glRole2,
		illinoisRole1, illinoisPermission1, illinoisPermission2, illinoisPermission3, illinoisRole2, illinoisGroup1, illinoisGroup2,
		danceRole1, dancePermission1, dancePermission2, dancePermission3, danceRole2, danceGroup1,
		globalUser1, globalUser2, illiniUser1, illiniUser2, illiniUser3, illiniUsersRel, danceUser1, diUser)
	return res
	*/
	return ""
}

func (app *application) admGetApplications(orgID string) ([]model.Application, error) {
	applicationsOrganizations, err := app.storage.FindApplicationsOrganizationsByOrgID(orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}

	if len(applicationsOrganizations) == 0 {
		return nil, nil
	}

	var apps []model.Application
	for _, appOrg := range applicationsOrganizations {
		apps = append(apps, appOrg.Application)
	}
	return apps, nil
}

func (app *application) admCreateAppOrgGroup(name string, permissionNames []string, rolesIDs []string, appID string, orgID string, assignerPermissions []string, system bool, l *logs.Log) (*model.AppOrgGroup, error) {
	var newGroup *model.AppOrgGroup
	transaction := func(context storage.TransactionContext) error {
		//1. get application organization entity
		appOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
		if err != nil || appOrg == nil {
			return errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
		}

		//2. validate permissions
		permissions, err := app.auth.CheckPermissions(context, appOrg, permissionNames, assignerPermissions)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionValidate, model.TypePermission, nil, err)
		}

		//3. check roles
		roles, err := app.auth.CheckRoles(context, appOrg, rolesIDs, assignerPermissions)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionValidate, model.TypeAppOrgRole, nil, err)
		}

		//4. create and insert group
		id, _ := uuid.NewUUID()
		now := time.Now()
		group := model.AppOrgGroup{ID: id.String(), Name: name, Roles: roles, Permissions: permissions, AppOrg: *appOrg, System: system, DateCreated: now}
		err = app.storage.InsertAppOrgGroup(context, group)
		if err != nil {
			return err
		}

		newGroup = &group
		return nil
	}

	err := app.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, err
	}
	return newGroup, nil
}

func (app *application) admGetAppOrgGroups(appID string, orgID string) ([]model.AppOrgGroup, error) {
	//find application organization
	getAppOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}
	//find application organization groups
	getAppOrgGroups, err := app.storage.FindAppOrgGroups(getAppOrg.ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeAppOrgGroup, nil, err)
	}

	return getAppOrgGroups, nil
}

func (app *application) admDeleteAppOrgGroup(ID string, appID string, orgID string, assignerPermissions []string, system bool, l *logs.Log) error {
	//1. get application organization entity
	appOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}

	//2. find the group
	group, err := app.storage.FindAppOrgGroup(ID, appOrg.ID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAppOrgGroup, nil, err)
	}
	if group == nil {
		return errors.Newf("there is no a group for id %s", ID)
	}

	//3. check group permissions
	for _, permission := range group.Permissions {
		err = permission.CheckAssigners(assignerPermissions)
		if err != nil {
			return errors.Wrapf("error checking permission assigners", err)
		}
	}

	//4. check group roles
	for _, roles := range group.Roles {
		err = roles.CheckAssigners(assignerPermissions)
		if err != nil {
			return errors.Wrapf("error checking roles assigners", err)
		}
	}

	//5. do not allow to delete system groups
	if group.System && !system {
		return errors.Newf("%s group is a system grup and cannot be deleted", group.Name)
	}

	//6. check if the group has accounts relations
	numberOfAccounts, err := app.storage.CountAccountsByGroupID(ID)
	if err != nil {
		return errors.WrapErrorAction("error checking the accounts count by group id", "", nil, err)
	}
	if *numberOfAccounts > 0 {
		return errors.Newf("the %s is already used by account and cannot be deleted", group.Name)
	}

	//7. delete the group
	err = app.storage.DeleteAppOrgGroup(ID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAppOrgGroup, nil, err)
	}
	return nil
}

func (app *application) admAddAccountsToGroup(appID string, orgID string, groupID string, accountIDs []string, assignerPermissions []string, l *logs.Log) error {
	//validate
	if len(assignerPermissions) == 0 {
		return errors.New("no permissions from admin assigner")
	}
	if len(groupID) == 0 {
		return errors.New("no group id")
	}
	if len(accountIDs) == 0 {
		return errors.New("no accounts ids")
	}

	//find accounts
	accounts, err := app.storage.FindAccountsByAccountID(appID, orgID, accountIDs)
	if err != nil {
		return errors.Wrap("error finding account", err)
	}
	if len(accounts) != len(accountIDs) {
		return errors.New("bad accounts ids params")
	}

	//find group
	group, err := app.storage.FindAppOrgGroup(groupID, accounts[0].AppOrg.ID)
	if err != nil {
		return errors.Wrap("error finding app org group", err)
	}
	if group == nil {
		return errors.New("bad group id params")
	}

	//check assigners
	err = group.CheckAssigners(assignerPermissions)
	if err != nil {
		return errors.Wrap("not allowed", err)
	}

	//ensure that the accounts do not have the group before adding
	updateAccounts := make([]model.Account, 0)
	for _, account := range accounts {
		if account.GetGroup(groupID) == nil {
			updateAccounts = append(updateAccounts, account)
		}
	}

	//insert accounts to group
	accountGroup := model.AccountGroup{Group: *group, Active: true, AdminSet: true}
	err = app.storage.InsertAccountsGroup(accountGroup, updateAccounts)
	if err != nil {
		return errors.Wrapf("error inserting accounts group - %s", err, groupID)
	}

	return nil
}

func (app *application) admRemoveAccountsFromGroup(appID string, orgID string, groupID string, accountIDs []string, assignerPermissions []string, l *logs.Log) error {
	//validate
	if len(assignerPermissions) == 0 {
		return errors.New("no permissions from admin assigner")
	}
	if len(groupID) == 0 {
		return errors.New("no group id")
	}
	if len(accountIDs) == 0 {
		return errors.New("no accounts ids")
	}

	//find accounts
	accounts, err := app.storage.FindAccountsByAccountID(appID, orgID, accountIDs)
	if err != nil {
		return errors.Wrap("error finding account", err)
	}
	if len(accounts) != len(accountIDs) {
		return errors.New("bad accounts ids params")
	}

	//find group
	appOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return errors.Wrap("error getting app org on add accounts to group", err)
	}
	group, err := app.storage.FindAppOrgGroup(groupID, appOrg.ID)
	if err != nil {
		return errors.Wrap("error finding app org group", err)
	}
	if group == nil {
		return errors.New("bad group id params")
	}

	//check assigners
	err = group.CheckAssigners(assignerPermissions)
	if err != nil {
		return errors.Wrap("not allowed", err)
	}

	//ensure that the accounts have the group
	updateAccounts := make([]model.Account, 0)
	hasPermissions := make([]bool, 0)
	for _, account := range accounts {
		if account.GetGroup(groupID) != nil {
			updateAccounts = append(updateAccounts, account)
			hasPermissions = append(hasPermissions, len(account.Permissions) > 0 || len(account.Roles) > 0 || len(account.Groups) > 1)
		}
	}

	//remove the accounts from the group
	err = app.storage.RemoveAccountsGroup(group.ID, updateAccounts, hasPermissions)
	if err != nil {
		return errors.Wrapf("error removing accounts from a group - %s", err, groupID)
	}

	return nil
}

func (app *application) admCreateAppOrgRole(name string, description string, permissionNames []string, appID string, orgID string, assignerPermissions []string, system bool, l *logs.Log) (*model.AppOrgRole, error) {
	var newRole *model.AppOrgRole
	transaction := func(context storage.TransactionContext) error {
		//1. get application organization entity
		appOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
		if err != nil || appOrg == nil {
			return errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
		}

		//2. check role permissions
		permissions, err := app.auth.CheckPermissions(context, appOrg, permissionNames, assignerPermissions)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionValidate, model.TypePermission, nil, err)
		}

		//3. create and insert role
		id, _ := uuid.NewUUID()
		now := time.Now()
		role := model.AppOrgRole{ID: id.String(), Name: name, Description: description, System: system, Permissions: permissions, AppOrg: *appOrg, DateCreated: now}
		err = app.storage.InsertAppOrgRole(context, role)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAppOrgRole, nil, err)
		}

		newRole = &role
		return nil
	}

	err := app.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, err
	}

	return newRole, nil
}

func (app *application) admGetAppOrgRoles(appID string, orgID string) ([]model.AppOrgRole, error) {
	//find application organization
	getAppOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}

	//find application organization roles
	getAppOrgRoles, err := app.storage.FindAppOrgRoles(getAppOrg.ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeAppOrgRole, nil, err)
	}

	return getAppOrgRoles, nil
}

func (app *application) admDeleteAppOrgRole(ID string, appID string, orgID string, assignerPermissions []string, system bool, l *logs.Log) error {
	//1. get application organization entity
	appOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}

	//2. find the role
	role, err := app.storage.FindAppOrgRole(ID, appOrg.ID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAppOrgRole, nil, err)
	}
	if role == nil {
		return errors.Newf("there is no role for id %s", ID)
	}

	//3. check assigners field
	for _, permission := range role.Permissions {
		err = permission.CheckAssigners(assignerPermissions)
		if err != nil {
			return errors.Wrapf("error checking permission assigners", err)
		}
	}

	//4. do not allow to delete system roles
	if role.System && !system {
		return errors.Newf("%s role is a system role and cannot be deleted", role.Name)
	}

	//5. check if the role has accounts relations
	numberOfAccounts, err := app.storage.CountAccountsByRoleID(ID)
	if err != nil {
		return errors.WrapErrorAction("error checking the accounts count by role id", "", nil, err)
	}
	if *numberOfAccounts > 0 {
		return errors.Newf("%s is already used by account and cannot be deleted", role.Name)
	}

	//6. check if the role has groups relations
	numberOfGroups, err := app.storage.CountGroupsByRoleID(ID)
	if err != nil {
		return errors.WrapErrorAction("error checking the groups count by role id", "", nil, err)
	}
	if *numberOfGroups > 0 {
		return errors.Newf("%s is already used by groups and cannot be deleted", role.Name)
	}

	//7. delete the role
	err = app.storage.DeleteAppOrgRole(ID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAppOrgRole, nil, err)
	}
	return nil
}

func (app *application) admGetApplicationPermissions(appID string, orgID string, l *logs.Log) ([]model.Permission, error) {
	//1. find application organization
	appOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID})
	}

	//2. find permissions by the service ids
	permissions, err := app.storage.FindPermissionsByServiceIDs(appOrg.ServicesIDs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypePermission, nil, err)
	}
	return permissions, nil
}

func (app *application) admGetAccounts(limit int, offset int, appID string, orgID string, accountID *string, firstName *string, lastName *string, authType *string,
	authTypeIdentifier *string, hasPermissions *bool, permissions []string, roleIDs []string, groupIDs []string) ([]model.Account, error) {
	//find the accounts
	accounts, err := app.storage.FindAccounts(limit, offset, appID, orgID, accountID, firstName, lastName, authType, authTypeIdentifier, hasPermissions, permissions, roleIDs, groupIDs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	return accounts, nil
}

func (app *application) admGetAccount(accountID string) (*model.Account, error) {
	return app.getAccount(accountID)
}

func (app *application) admGetAccountSystemConfigs(appID string, orgID string, accountID string, l *logs.Log) (map[string]interface{}, error) {
	//find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"account_id": accountID}, err)
	}
	if account == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"account_id": accountID}, err)
	}
	if account.AppOrg.Application.ID != appID || account.AppOrg.Organization.ID != orgID {
		l.Warnf("someone is trying to get system configs for %s for different app/org", accountID)
		return nil, errors.Newf("not allowed").SetStatus(utils.ErrorStatusNotAllowed)
	}

	return account.SystemConfigs, nil
}

func (app *application) admUpdateAccountSystemConfigs(appID string, orgID string, accountID string, configs map[string]interface{}, l *logs.Log) error {
	//TODO: If account does not exist, create anonymous account
	if len(configs) == 0 {
		return errors.New("no new configs")
	}

	transaction := func(context storage.TransactionContext) error {
		//1. verify that the account is for the current app/org
		account, err := app.storage.FindAccountByID(context, accountID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"account_id": accountID}, err)
		}
		if account == nil {
			return errors.WrapErrorData(logutils.StatusMissing, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"account_id": accountID}, err)
		}
		if account.AppOrg.Application.ID != appID || account.AppOrg.Organization.ID != orgID {
			l.Warnf("someone is trying to update system configs for %s for different app/org", accountID)
			return errors.Newf("not allowed").SetStatus(utils.ErrorStatusNotAllowed)
		}

		//2. merge new configs on top of existing ones
		accountConfigs := account.SystemConfigs
		for key, val := range configs {
			if val != nil {
				accountConfigs[key] = val
			} else {
				delete(accountConfigs, key)
			}
		}

		//3. update configs
		err = app.storage.UpdateAccountSystemConfigs(context, accountID, accountConfigs)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"account_id": accountID}, err)
		}

		return nil
	}

	return app.storage.PerformTransaction(transaction)
}

func (app *application) admGetApplicationLoginSessions(appID string, orgID string, identifier *string, accountAuthTypeIdentifier *string,
	appTypeID *string, appTypeIdentifier *string, anonymous *bool, deviceID *string, ipAddress *string) ([]model.LoginSession, error) {
	//find the login sessions
	loginSessions, err := app.storage.FindLoginSessionsByParams(appID, orgID, nil, identifier, accountAuthTypeIdentifier, appTypeID, appTypeIdentifier, anonymous, deviceID, ipAddress)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession, nil, err)
	}
	return loginSessions, nil
}

func (app *application) admDeleteApplicationLoginSession(appID string, orgID string, currentAccountID string, identifier string, sessionID string, l *logs.Log) error {
	//1. do not allow to logout the current account
	if currentAccountID == identifier {
		l.Infof("%s is trying to logout yourself", currentAccountID)
		return errors.New("cannot logout yourself")
	}

	//2. validate if the session is for the current app/org and account
	sessions, err := app.storage.FindLoginSessionsByParams(appID, orgID, &sessionID, &identifier, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return errors.Wrap("error checking if it is valid to remove account session", err)
	}
	if len(sessions) == 0 {
		return errors.New("not valid params")
	}

	//3. delete the session
	err = app.storage.DeleteLoginSessionByID(nil, sessionID)
	if err != nil {
		return errors.Wrap("error dleting session by id", err)
	}

	return nil
}

func (app *application) admGetApplicationAccountDevices(appID string, orgID string, accountID string, l *logs.Log) ([]model.Device, error) {
	//1. find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return nil, errors.Wrapf("error finding account on getting devices", err)
	}
	if account == nil {
		return nil, errors.Newf("no account for id %s", accountID)
	}

	//2. verify that the account is for the current app/org
	appOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return nil, errors.Wrapf("error finding app org on getting devices", err)
	}
	if appOrg.ID != account.AppOrg.ID {
		l.Warnf("someone from app(%s) org(%s) is trying to access an account %s", appID, orgID, accountID)
		return nil, errors.Newf("not allowed to access data")
	}

	return account.Devices, nil
}

func (app *application) admGrantAccountPermissions(appID string, orgID string, accountID string, permissionNames []string, assignerPermissions []string, l *logs.Log) error {
	//check if there is data
	if len(assignerPermissions) == 0 {
		return errors.New("no permissions from admin assigner")
	}
	if len(permissionNames) == 0 {
		return errors.New("no permissions for granting")
	}

	transaction := func(context storage.TransactionContext) error {
		//1. verify that the account is for the current app/org
		account, err := app.storage.FindAccountByID(context, accountID)
		if err != nil {
			return errors.Wrap("error finding account on permissions granting", err)
		}
		if account == nil {
			return errors.WrapErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"account_id": accountID}, err)
		}
		if (account.AppOrg.Application.ID != appID) || (account.AppOrg.Organization.ID != orgID) {
			l.Warnf("someone is trying to grant permissions to %s for different app/org", accountID)
			return errors.Newf("not allowed")
		}

		//2. grant account permissions
		err = app.auth.GrantAccountPermissions(context, account, permissionNames, assignerPermissions)
		if err != nil {
			return errors.Wrap("error granting account permissions", err)
		}

		return nil
	}

	return app.storage.PerformTransaction(transaction)
}

func (app *application) admRevokeAccountPermissions(appID string, orgID string, accountID string, permissionNames []string, assignerPermissions []string, l *logs.Log) error {
	//check if there is data
	if len(assignerPermissions) == 0 {
		return errors.New("no permissions from admin assigner")
	}
	if len(permissionNames) == 0 {
		return errors.New("no permissions for revoking")
	}

	//verify that the account is for the current app/org
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return errors.Wrap("error finding account on permissions revoking", err)
	}
	if account == nil {
		return errors.Newf("no account")
	}
	if (account.AppOrg.Application.ID != appID) || (account.AppOrg.Organization.ID != orgID) {
		l.Warnf("someone is trying to revoke permissions from %s for different app/org", accountID)
		return errors.Newf("not allowed")
	}

	//verify that the account has the permissions which are supposed to be revoked
	numRevoked := 0
	for _, current := range permissionNames {
		hasP := account.GetPermissionNamed(current)
		if hasP == nil {
			l.Infof("trying to revoke %s for %s but the account does not have it", current, accountID)
			return errors.Newf("%s cannot be revoked from %s", current, accountID)
		}

		numRevoked++
	}

	//find permissions
	permissions, err := app.storage.FindPermissionsByName(nil, permissionNames)
	if err != nil {
		return err
	}
	if len(permissions) == 0 {
		return errors.Newf("no permissions found for names: %v", permissionNames)
	}

	//check if authorized
	for _, permission := range permissions {
		err = permission.CheckAssigners(assignerPermissions)
		if err != nil {
			return errors.Wrapf("error checking permission assigners", err)
		}
	}

	hasPermissions := len(account.Permissions) > numRevoked || len(account.Roles) > 0 || len(account.Groups) > 0
	//delete permissions from an account AND delete all sessions for the account
	transaction := func(context storage.TransactionContext) error {
		//delete permissions from an account
		err = app.storage.DeleteAccountPermissions(context, accountID, hasPermissions, permissions)
		if err != nil {
			return errors.Wrap("error deleting account permissions", err)
		}

		//delete all sessions for the account
		err = app.storage.DeleteLoginSessionsByIdentifier(context, accountID)
		if err != nil {
			return errors.Wrap("error deleting sessions by identifier on revoking permissions", err)
		}

		return nil
	}
	err = app.storage.PerformTransaction(transaction)
	if err != nil {
		return errors.Wrapf("error revoking permissions %s from an account %s", err, accountID, permissionNames)
	}

	return nil
}

func (app *application) admGrantAccountRoles(appID string, orgID string, accountID string, roleIDs []string, assignerPermissions []string, l *logs.Log) error {
	//check if there is data
	if len(assignerPermissions) == 0 {
		return errors.New("no permissions from admin assigner")
	}
	if len(roleIDs) == 0 {
		return errors.New("no roles for granting")
	}

	transaction := func(context storage.TransactionContext) error {
		//1. verify that the account is for the current app/org
		account, err := app.storage.FindAccountByID(context, accountID)
		if err != nil {
			return errors.Wrap("error finding account on roles granting", err)
		}
		if account == nil {
			return errors.WrapErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"account_id": accountID}, err)
		}
		if (account.AppOrg.Application.ID != appID) || (account.AppOrg.Organization.ID != orgID) {
			l.Warnf("someone is trying to grant roles to %s for different app/org", accountID)
			return errors.Newf("not allowed")
		}

		//2. grant account roles
		err = app.auth.GrantAccountRoles(context, account, roleIDs, assignerPermissions)
		if err != nil {
			return errors.Wrap("error granting account roles", err)
		}

		return nil
	}

	return app.storage.PerformTransaction(transaction)
}

func (app *application) admRevokeAccountRoles(appID string, orgID string, accountID string, roleIDs []string, assignerPermissions []string, l *logs.Log) error {
	//check if there is data
	if len(assignerPermissions) == 0 {
		return errors.New("no permissions from admin assigner")
	}
	if len(roleIDs) == 0 {
		return errors.New("no roles for revoking")
	}

	//verify that the account is for the current app/org
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return errors.Wrap("error finding account on roles revoking", err)
	}
	if account == nil {
		return errors.Newf("no account")
	}
	if (account.AppOrg.Application.ID != appID) || (account.AppOrg.Organization.ID != orgID) {
		l.Warnf("someone is trying to revoke roles from %s for different app/org", accountID)
		return errors.Newf("not allowed")
	}

	//verify that the account has the roles which are supposed to be revoked
	numRevoked := 0
	for _, roleID := range roleIDs {
		hasR := account.GetRole(roleID)
		if hasR == nil {
			l.Infof("trying to revoke role %s for %s but the account does not have it", roleID, accountID)
			return errors.Newf("%s cannot be revoked from %s", roleID, accountID)
		}

		numRevoked++
	}

	//find roles
	roles, err := app.storage.FindAppOrgRolesByIDs(nil, roleIDs, account.AppOrg.ID)
	if err != nil {
		return errors.Wrap("error finding roles on revoking roles", err)
	}
	if len(roles) == 0 {
		return errors.Newf("no roles found for ids: %v", roleIDs)
	}

	//check if authorized
	for _, role := range roles {
		err = role.CheckAssigners(assignerPermissions)
		if err != nil {
			return errors.Wrapf("error checking permission assigners when revoking roles from an account", err)
		}
	}

	hasPermissions := len(account.Permissions) > 0 || len(account.Roles) > numRevoked || len(account.Groups) > 0
	//delete roles from an account AND delete all sessions for the account
	transaction := func(context storage.TransactionContext) error {
		//delete roles from an account
		err = app.storage.DeleteAccountRoles(context, accountID, hasPermissions, roleIDs)
		if err != nil {
			return errors.Wrap("error deleting account roles", err)
		}

		//delete all sessions for the account
		err = app.storage.DeleteLoginSessionsByIdentifier(context, accountID)
		if err != nil {
			return errors.Wrap("error deleting sessions by identifier on revoking roles", err)
		}

		return nil
	}
	err = app.storage.PerformTransaction(transaction)
	if err != nil {
		return errors.Wrapf("error revoking roles %s from an account %s", err, accountID, roleIDs)
	}

	return nil
}

func (app *application) admGrantPermissionsToRole(appID string, orgID string, roleID string, permissionNames []string, assignerPermissions []string, system bool, l *logs.Log) error {
	//check if there is data
	if len(assignerPermissions) == 0 {
		return errors.New("no permissions from admin assigner")
	}
	if len(permissionNames) == 0 {
		return errors.New("no permissions for granting")
	}

	//verify that the role is for the current app/org
	appOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return errors.Wrap("there is no application organization with that IDs", err)
	}
	role, err := app.storage.FindAppOrgRole(roleID, appOrg.ID)
	if err != nil {
		return errors.Wrap("error finding account on permissions granting", err)
	}

	if role.System && !system {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeClaim, logutils.StringArgs("system"))
	}

	//verify that the role do not have any of the permissions which are supposed to be granted
	for _, current := range permissionNames {
		hasP := role.GetPermissionNamed(current)
		if hasP != nil {
			l.Infof("trying to double grant %s for %s", current, roleID)
			return errors.Newf("role %s already has %s granted", roleID, current)
		}
	}

	//find permissions
	permissions, err := app.storage.FindPermissionsByName(nil, permissionNames)
	if err != nil {
		return err
	}
	if len(permissions) == 0 {
		return errors.Newf("no permissions found for names: %v", permissionNames)
	}

	//verify that the permissions are for the current app/org
	for _, permission := range permissions {
		pServiceID := permission.ServiceID
		contains := utils.Contains(appOrg.ServicesIDs, pServiceID)
		if !contains {
			return errors.Newf("not allowed to grant %s for app/org %s", permission.Name, appOrg.ID)
		}
	}

	//check if authorized
	for _, permission := range permissions {
		err = permission.CheckAssigners(assignerPermissions)
		if err != nil {
			return errors.Wrapf("error checking permission assigners", err)
		}
	}

	//insert permission into a role
	err = app.storage.InsertAppOrgRolePermissions(nil, roleID, permissions)
	if err != nil {
		return errors.Wrap("error inserting permissions to roles", err)
	}

	return nil
}
