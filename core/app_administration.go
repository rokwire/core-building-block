package core

import (
	"core-building-block/core/model"
	"time"

	"github.com/google/uuid"
	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logutils"
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

func (app *application) admCreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	gc, err := app.storage.GetGlobalConfig()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeGlobalConfig, nil, err)
	}
	if gc != nil {
		return nil, errors.New("global config already exists")
	}

	gc, err = app.storage.CreateGlobalConfig(setting)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeGlobalConfig, nil, err)
	}
	return gc, nil
}

func (app *application) admGetGlobalConfig() (*model.GlobalConfig, error) {
	gc, err := app.storage.GetGlobalConfig()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeGlobalConfig, nil, err)
	}
	return gc, nil
}

func (app *application) admUpdateGlobalConfig(setting string) error {
	gc, err := app.storage.GetGlobalConfig()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeGlobalConfig, nil, err)
	}
	if gc == nil {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeGlobalConfig, nil, err)
	}

	gc.Setting = setting
	err = app.storage.SaveGlobalConfig(gc)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeGlobalConfig, nil, err)
	}
	return nil
}

func (app *application) admCreateOrganization(name string, requestType string, organizationDomains []string) (*model.Organization, error) {
	now := time.Now()

	orgConfigID, _ := uuid.NewUUID()
	orgConfig := model.OrganizationConfig{ID: orgConfigID.String(), Domains: organizationDomains, DateCreated: now}

	organizationID, _ := uuid.NewUUID()
	organization := model.Organization{ID: organizationID.String(), Name: name, Type: requestType, Config: orgConfig, DateCreated: now}

	insertedOrg, err := app.storage.InsertOrganization(organization)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
	}
	return insertedOrg, nil
}

func (app *application) admGetOrganization(ID string) (*model.Organization, error) {
	organization, err := app.storage.FindOrganization(ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err)
	}

	return organization, nil
}

func (app *application) admGetOrganizations() ([]model.Organization, error) {
	getOrganization, err := app.storage.LoadOrganizations()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err)
	}

	return getOrganization, nil
}

func (app *application) admUpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error {
	err := app.storage.UpdateOrganization(ID, name, requestType, organizationDomains)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeOrganization, nil, err)
	}

	return err

}

func (app *application) admGetApplication(ID string) (*model.Application, error) {
	appAdm, err := app.storage.FindApplication(ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplication, nil, err)
	}

	return appAdm, nil
}

func (app *application) admCreateApplication(name string, multiTenant bool, requiresOwnUsers bool, identifier string, nameInType string, versions []string) (*model.Application, error) {
	/*now := time.Now()

	applicationID, _ := uuid.NewUUID()
	application := model.Application{ID: applicationID.String(), Name: name, MultiTenant: multiTenant, RequiresOwnUsers: requiresOwnUsers,
		DateCreated: now}

	insertedApplication, err := app.storage.InsertApplication(application)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
	}*/
	return /*insertedApplication,*/ nil, nil
}

func (app *application) admGetApplications() ([]model.Application, error) {
	getApplications, err := app.storage.FindApplications()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplication, nil, err)
	}

	return getApplications, nil
}

func (app *application) admCreateApplicationPermission(name string, appID string) (*model.ApplicationPermission, error) {
	id, _ := uuid.NewUUID()
	now := time.Now()
	permission := model.ApplicationPermission{ID: id.String(), Name: name, Application: model.Application{ID: appID}, DateCreated: now}

	err := app.storage.InsertApplicationPermission(permission)
	if err != nil {
		return nil, err
	}
	return &permission, nil
}

func (app *application) admCreateApplicationRole(name string, appID string, description string, permissionNames []string) (*model.ApplicationRole, error) {
	permissions, err := app.storage.FindApplicationPermissionsByName(permissionNames, appID)
	if err != nil {
		return nil, err
	}

	id, _ := uuid.NewUUID()
	now := time.Now()
	role := model.ApplicationRole{ID: id.String(), Name: name, Description: description, Application: model.Application{ID: appID}, Permissions: permissions, DateCreated: now}
	err = app.storage.InsertApplicationRole(role)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (app *application) admGrantAccountPermissions(accountID string, appID string, permissionNames []string) error {
	permissions, err := app.storage.FindApplicationPermissionsByName(permissionNames, appID)
	if err != nil {
		return err
	}

	if len(permissions) == 0 {
		return errors.Newf("no permissions found for names: %v", permissionNames)
	}

	err = app.storage.InsertAccountPermissions(accountID, appID, permissions)
	if err != nil {
		return err
	}
	return nil
}

func (app *application) admGrantAccountRoles(accountID string, appID string, roleIDs []string) error {
	roles, err := app.storage.FindApplicationRoles(roleIDs, appID)
	if err != nil {
		return err
	}

	if len(roles) == 0 {
		return errors.Newf("no roles found for IDs: %v", roleIDs)
	}

	err = app.storage.InsertAccountRoles(accountID, appID, roles)
	if err != nil {
		return err
	}
	return nil
}
