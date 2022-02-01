package core

import (
	"core-building-block/core/model"
	"fmt"
	"log"
	"strings"
	"sync"
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

func (app *application) admGetBuildingBlocks(appID string, orgID string) ([]*model.BuildingBlock, error) {
	buildingBlocks, err := app.storage.ReadAllBuildingBlocks(appID, orgID)
	if err != nil {
		return nil, err
	}

	wg := sync.WaitGroup{}
	for _, bb := range buildingBlocks {
		//check if can get the version
		if bb.VersionURL != nil {
			wg.Add(1)
			go func(bb *model.BuildingBlock) {
				app.updateBuildingBlock(bb)
				wg.Done()
			}(bb)
		}
	}
	wg.Wait()

	return buildingBlocks, nil
}

func (app *application) updateBuildingBlock(buildingBlock *model.BuildingBlock) {
	wg := sync.WaitGroup{}

	updatedEnvs := make([]model.BuildingBlockEnvironment, len(buildingBlock.Environments))
	for index, environment := range buildingBlock.Environments {
		wg.Add(1)
		go func(i int, bb *model.BuildingBlock, env model.BuildingBlockEnvironment) {
			updatedEnv := app.updateBuildingBlockEnvironment(bb, env)
			updatedEnvs[i] = updatedEnv

			wg.Done()
		}(index, buildingBlock, environment)

	}
	wg.Wait()

	buildingBlock.Environments = updatedEnvs
}

func (app *application) updateBuildingBlockEnvironment(buildingBlock *model.BuildingBlock, environment model.BuildingBlockEnvironment) model.BuildingBlockEnvironment {
	versionURL := *buildingBlock.VersionURL
	index := strings.Index(versionURL, "}")

	hostKey := versionURL[1:index]
	path := versionURL[index+1:]

	var url string
	switch hostKey {
	case "apis_url":
		url = fmt.Sprintf("%s%s", *environment.ApisURL, path)
	case "web_url":
		url = fmt.Sprintf("%s%s", *environment.WebURL, path)
	}

	content, statusCode, err := app.requestExecutor.Get(url)
	if err != nil || *statusCode != 200 {
		log.Printf("error getting version for %s - %s - %d", url, err, *statusCode)

		environment.HealthStatus = "down"
	} else {
		environment.HealthStatus = "working"
		environment.Version = *content
	}

	return environment
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

func (app *application) admCreateAppOrgGroup(name string, permissionIDs []string, rolesIDs []string, appID string, orgID string, l *logs.Log) (*model.AppOrgGroup, error) {
	//1. get application organization entity
	appOrg, err := app.storage.FindApplicationOrganizations(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}

	//2. check permissions
	groupPermissions, err := app.checkPermissions(*appOrg, permissionIDs, l)
	if err != nil {
		return nil, errors.WrapErrorAction("error checking if the permissions ids are valid", "", nil, err)
	}

	//3. check roles
	groupRoles, err := app.checkRoles(*appOrg, rolesIDs, l)
	if err != nil {
		return nil, errors.WrapErrorAction("error checking if the permissions ids are valid", "", nil, err)
	}

	id, _ := uuid.NewUUID()
	now := time.Now()
	group := model.AppOrgGroup{ID: id.String(), Name: name, Roles: groupRoles, Permissions: groupPermissions, AppOrg: *appOrg, DateCreated: now}
	err = app.storage.InsertAppOrgGroup(group)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

func (app *application) admGetAppOrgGroups(appID string, orgID string) ([]model.AppOrgGroup, error) {
	//find application organization
	getAppOrg, err := app.storage.FindApplicationOrganizations(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}
	//find application organization groups
	getAppOrgGroups, err := app.storage.FindAppOrgGroups(nil, getAppOrg.ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeAppOrgGroup, nil, err)
	}

	return getAppOrgGroups, nil
}

func (app *application) admDeleteAppOrgGroup(ID string, appID string, orgID string) error {
	//1. get application organization entity
	appOrg, err := app.storage.FindApplicationOrganizations(appID, orgID)
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

	//3. do not allow to delete system groups
	if group.System {
		return errors.Newf("%s group is a system grup and cannot be deleted", group.Name)
	}

	//4. check if the group has accounts relations
	numberOfAccounts, err := app.storage.CountAccountsByGroupID(ID)
	if err != nil {
		return errors.WrapErrorAction("error checking the accounts count by group id", "", nil, err)
	}
	if *numberOfAccounts > 0 {
		return errors.Newf("the %s is already used by account and cannot be deleted", group.Name)
	}

	//5. delete the group
	err = app.storage.DeleteAppOrgGroup(ID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAppOrgGroup, nil, err)
	}
	return nil
}

func (app *application) admCreateAppOrgRole(name string, description string, permissionIDs []string, appID string, orgID string, l *logs.Log) (*model.AppOrgRole, error) {
	//1. get application organization entity
	appOrg, err := app.storage.FindApplicationOrganizations(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}

	//2. check permissions
	rolePermissions, err := app.checkPermissions(*appOrg, permissionIDs, l)
	if err != nil {
		return nil, errors.WrapErrorAction("error checking if the permissions ids are valid", "", nil, err)
	}

	//3. create role
	id, _ := uuid.NewUUID()
	now := time.Now()
	role := model.AppOrgRole{ID: id.String(), Name: name, Description: description, Permissions: rolePermissions, AppOrg: *appOrg, DateCreated: now}
	err = app.storage.InsertAppOrgRole(role)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeAppOrgRole, nil, err)
	}
	return &role, nil
}

func (app *application) AdmGetAppOrgRoles(appID string, orgID string) ([]model.AppOrgRole, error) {
	//find application organization
	getAppOrg, err := app.storage.FindApplicationOrganizations(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}

	//find application organization roles
	getAppOrgRoles, err := app.storage.FindAppOrgRoles(nil, getAppOrg.ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeAppOrgRole, nil, err)
	}

	return getAppOrgRoles, nil
}

func (app *application) admDeleteAppOrgRole(ID string, appID string, orgID string) error {
	//1. get application organization entity
	appOrg, err := app.storage.FindApplicationOrganizations(appID, orgID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}

	//2. find the role
	role, err := app.storage.FindAppOrgRole(ID, appOrg.ID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAppOrgRole, nil, err)
	}
	if role == nil {
		return errors.Newf("there is no a role for id %s", ID)
	}

	//3. do not allow to delete system roles
	if role.System {
		return errors.Newf("%s role is a system role and cannot be deleted", role.Name)
	}

	//4. check if the role has accounts relations
	numberOfAccounts, err := app.storage.CountAccountsByRoleID(ID)
	if err != nil {
		return errors.WrapErrorAction("error checking the accounts count by role id", "", nil, err)
	}
	if *numberOfAccounts > 0 {
		return errors.Newf("the %s is already used by account and cannot be deleted", role.Name)
	}

	//5. check if the group has groups relations
	numberOfGroups, err := app.storage.CountGroupsByRoleID(ID)
	if err != nil {
		return errors.WrapErrorAction("error checking the groups count by role id", "", nil, err)
	}
	if *numberOfGroups > 0 {
		return errors.Newf("the %s is already used by groups and cannot be deleted", role.Name)
	}

	//6. delete the group
	err = app.storage.DeleteAppOrgRole(ID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAppOrgRole, nil, err)
	}
	return nil
}

func (app *application) admGetApplicationPermissions(appID string, orgID string, l *logs.Log) ([]model.Permission, error) {
	//1. find application organization
	appOrg, err := app.storage.FindApplicationOrganizations(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}
	if appOrg == nil {
		return nil, errors.New("there is no app org for app ID and org ID")
	}

	//2. find permissions by the service ids
	permissions, err := app.storage.FindPermissionsByServiceIDs(appOrg.ServicesIDs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypePermission, nil, err)
	}
	return permissions, nil
}

func (app *application) admGetAccounts(appID string, orgID string, accountID *string, authTypeIdentifier *string) ([]model.Account, error) {
	//find the accounts
	accounts, err := app.storage.FindAccounts(appID, orgID, accountID, authTypeIdentifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	return accounts, nil
}

func (app *application) admGetApplicationLoginSessions(appID string, orgID string, identifier *string, accountAuthTypeIdentifier *string) ([]model.LoginSession, error) {
	//find the login sessions
	loginSessions, err := app.storage.FindLoginSessionsByParams(appID, orgID, identifier, accountAuthTypeIdentifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession, nil, err)
	}
	return loginSessions, nil
}

func (app *application) admGetAccount(accountID string) (*model.Account, error) {
	return app.getAccount(accountID)
}
