package core

import (
	"core-building-block/core/auth"
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

//APIs exposes to the drivers adapters access to the core functionality
type APIs struct {
	Services       Services       //expose to the drivers adapters
	Administration Administration //expose to the drivers adapters
	Encryption     Encryption     //expose to the drivers adapters
	BBs            BBs            //expose to the drivers adapters
	System         System         //expose to the drivers adapters

	Auth auth.APIs //expose to the drivers auth

	app *application

	systemAppNamespace    string
	systemAppTypeName     string
	systemAPIKey          string
	systemAccountEmail    string
	systemAccountPassword string

	logger *logs.Logger
}

//Start starts the core part of the application
func (c *APIs) Start() {
	c.app.start()
	c.Auth.Start()

	err := c.storeSystemData()
	if err != nil {
		c.logger.Fatalf("error initializing system data: %s", err.Error())
	}
}

//AddListener adds application listener
func (c *APIs) AddListener(listener ApplicationListener) {
	c.app.addListener(listener)
}

//GetVersion gives the service version
func (c *APIs) GetVersion() string {
	return c.app.version
}

func (c *APIs) storeSystemData() error {
	transaction := func(context storage.TransactionContext) error {
		//1. insert email auth type if doesn't exist
		emailAuthType, err := c.app.storage.FindAuthType(auth.AuthTypeEmail)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, nil, err)
		}
		if emailAuthType == nil {
			emailAuthType = &model.AuthType{ID: uuid.NewString(), Code: auth.AuthTypeEmail, Description: "Authentication type relying on email and password",
				IsExternal: false, IsAnonymous: false, UseCredentials: true, IgnoreMFA: false}
			_, err = c.app.storage.InsertAuthType(context, *emailAuthType)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAuthType, nil, err)
			}
		}

		//2. insert system org if doesn't exist
		systemOrg, err := c.app.storage.FindSystemOrganization(context)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
		}
		if systemOrg == nil {
			systemOrgConfig := model.OrganizationConfig{ID: uuid.NewString(), DateCreated: time.Now().UTC()}
			newSystemOrg := model.Organization{ID: uuid.NewString(), Name: "System", Type: "small", System: true, Config: systemOrgConfig, DateCreated: time.Now().UTC()}
			_, err = c.app.storage.InsertOrganization(context, newSystemOrg)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionInsert, model.TypeOrganization, nil, err)
			}

			systemOrg = &newSystemOrg
		}

		//3. insert system app and appOrg if they don't exist
		systemAdminAppOrgs, err := c.app.storage.FindApplicationsOrganizationsByOrgID(context, systemOrg.ID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, nil, err)
		}
		if len(systemAdminAppOrgs) == 0 {
			//insert system admin app
			if c.systemAppNamespace == "" || c.systemAppTypeName == "" {
				return errors.ErrorData(logutils.StatusMissing, "initial system app namespace or type name", nil)
			}
			newAndroidAppType := model.ApplicationType{ID: uuid.NewString(), Identifier: c.systemAppNamespace, Name: c.systemAppTypeName, Versions: nil}
			newSystemAdminApp := model.Application{ID: uuid.NewString(), Name: "System Admin application", MultiTenant: false, Admin: true,
				SharedIdentities: false, Types: []model.ApplicationType{newAndroidAppType}, DateCreated: time.Now().UTC()}
			_, err = c.app.storage.InsertApplication(context, newSystemAdminApp)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionInsert, model.TypeApplication, nil, err)
			}

			systemAdminApp := &newSystemAdminApp

			//insert system admin apporg
			emailSupport := []struct {
				AuthTypeID string                 `bson:"auth_type_id"`
				Params     map[string]interface{} `bson:"params"`
			}{
				{emailAuthType.ID, nil},
			}
			supportedAuthTypes := make([]model.AuthTypesSupport, len(systemAdminApp.Types))
			for i, appType := range systemAdminApp.Types {
				supportedAuthTypes[i] = model.AuthTypesSupport{AppTypeID: appType.ID, SupportedAuthTypes: emailSupport}
			}

			newSystemAdminAppOrg := model.ApplicationOrganization{ID: uuid.NewString(), Application: *systemAdminApp, Organization: *systemOrg,
				SupportedAuthTypes: supportedAuthTypes, DateCreated: time.Now().UTC()}
			_, err = c.app.storage.InsertApplicationOrganization(context, newSystemAdminAppOrg)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionSave, model.TypeApplicationOrganization, nil, err)
			}

			systemAdminAppOrgs = append(systemAdminAppOrgs, newSystemAdminAppOrg)
		}

		systemAppOrg := systemAdminAppOrgs[0]

		//4. insert api key if doesn't exist
		apiKeys, err := c.app.storage.FindApplicationAPIKeys(context, systemAppOrg.Application.ID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAPIKey, nil, err)
		}

		if len(apiKeys) == 0 {
			if c.systemAPIKey == "" {
				return errors.ErrorData(logutils.StatusMissing, "initial system api key", nil)
			}
			newAPIKey := model.APIKey{ID: uuid.NewString(), AppID: systemAppOrg.Application.ID, Key: c.systemAPIKey}
			_, err := c.app.storage.InsertAPIKey(context, newAPIKey)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAPIKey, nil, err)
			}
		}

		//5. insert system account if needed
		err = c.insertSystemAccountIfNeeded(context, *emailAuthType, systemAppOrg)
		if err != nil {
			return err
		}

		return nil
	}

	return c.app.storage.PerformTransaction(transaction)
}

func (c *APIs) insertSystemAccountIfNeeded(context storage.TransactionContext, authType model.AuthType, appOrg model.ApplicationOrganization) error {
	systemAccounts, err := c.app.storage.FindAccounts(appOrg.Application.ID, appOrg.Organization.ID, nil, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	if len(systemAccounts) == 0 {
		if c.systemAccountEmail == "" || c.systemAccountPassword == "" {
			return errors.ErrorData(logutils.StatusMissing, "initial system account email or password", nil)
		}
		err = c.Auth.InitializeSystemAccount(context, authType, appOrg, c.systemAccountEmail, c.systemAccountPassword, c.logger.NewRequestLog(nil))
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionInitialize, "system account", nil, err)
		}
	}

	return nil
}

//NewCoreAPIs creates new CoreAPIs
func NewCoreAPIs(env string, version string, build string, storage Storage, auth auth.APIs, systemInitSettings map[string]string, logger *logs.Logger) *APIs {
	//add application instance
	listeners := []ApplicationListener{}
	application := application{env: env, version: version, build: build, storage: storage, listeners: listeners, auth: auth}

	//add coreAPIs instance
	servicesImpl := &servicesImpl{app: &application}
	administrationImpl := &administrationImpl{app: &application}
	encryptionImpl := &encryptionImpl{app: &application}
	bbsImpl := &bbsImpl{app: &application}
	systemImpl := &systemImpl{app: &application}

	//+ auth
	coreAPIs := APIs{Services: servicesImpl, Administration: administrationImpl, Encryption: encryptionImpl,
		BBs: bbsImpl, System: systemImpl, Auth: auth, app: &application, systemAppNamespace: systemInitSettings["app_namespace"],
		systemAppTypeName: systemInitSettings["app_type_name"], systemAPIKey: systemInitSettings["api_key"],
		systemAccountEmail: systemInitSettings["email"], systemAccountPassword: systemInitSettings["password"], logger: logger}

	return &coreAPIs
}

///

//servicesImpl
type servicesImpl struct {
	app *application
}

func (s *servicesImpl) SerDeleteAccount(id string) error {
	return s.app.serDeleteAccount(id)
}

func (s *servicesImpl) SerGetAccount(accountID string) (*model.Account, error) {
	return s.app.serGetAccount(accountID)
}

func (s *servicesImpl) SerGetProfile(accountID string) (*model.Profile, error) {
	return s.app.serGetProfile(accountID)
}

func (s *servicesImpl) SerGetPreferences(accountID string) (map[string]interface{}, error) {
	return s.app.serGetPreferences(accountID)
}

func (s *servicesImpl) SerGetAuthTest(l *logs.Log) string {
	return s.app.serGetAuthTest(l)
}

func (s *servicesImpl) SerGetCommonTest(l *logs.Log) string {
	return s.app.serGetCommonTest(l)
}

func (s *servicesImpl) SerUpdateAccountPreferences(id string, preferences map[string]interface{}) error {
	return s.app.serUpdateAccountPreferences(id, preferences)
}

func (s *servicesImpl) SerUpdateProfile(accountID string, profile model.Profile) error {
	return s.app.serUpdateProfile(accountID, profile)
}

func (s *servicesImpl) SerGetAppConfig(appTypeIdentifier string, orgID *string, versionNumbers model.VersionNumbers, apiKey *string) (*model.ApplicationConfig, error) {
	return s.app.serGetAppConfig(appTypeIdentifier, orgID, versionNumbers, apiKey)
}

///

//administrationImpl

type administrationImpl struct {
	app *application
}

func (s *administrationImpl) AdmGetTest() string {
	return s.app.admGetTest()
}

func (s *administrationImpl) AdmGetTestModel() string {
	return s.app.admGetTestModel()
}

func (s *administrationImpl) AdmGetApplications(orgID string) ([]model.Application, error) {
	return s.app.admGetApplications(orgID)
}

func (s *administrationImpl) AdmCreateAppOrgGroup(name string, permissionIDs []string, rolesIDs []string, appID string, orgID string, assignerPermissions []string, l *logs.Log) (*model.AppOrgGroup, error) {
	return s.app.admCreateAppOrgGroup(name, permissionIDs, rolesIDs, appID, orgID, assignerPermissions, l)
}

func (s *administrationImpl) AdmGetAppOrgGroups(appID string, orgID string) ([]model.AppOrgGroup, error) {
	return s.app.admGetAppOrgGroups(appID, orgID)
}

func (s *administrationImpl) AdmDeleteAppOrgGroup(ID string, appID string, orgID string, assignerPermissions []string, l *logs.Log) error {
	return s.app.admDeleteAppOrgGroup(ID, appID, orgID, assignerPermissions, l)
}

func (s *administrationImpl) AdmAddAccountsToGroup(appID string, orgID string, groupID string, accountIDs []string, assignerPermissions []string, l *logs.Log) error {
	return s.app.admAddAccountsToGroup(appID, orgID, groupID, accountIDs, assignerPermissions, l)
}

func (s *administrationImpl) AdmRemoveAccountsFromGroup(appID string, orgID string, groupID string, accountIDs []string, assignerPermissions []string, l *logs.Log) error {
	return s.app.admRemoveAccountsFromGroup(appID, orgID, groupID, accountIDs, assignerPermissions, l)
}

func (s *administrationImpl) AdmCreateAppOrgRole(name string, description string, permissionIDs []string, appID string, orgID string, assignerPermissions []string, l *logs.Log) (*model.AppOrgRole, error) {
	return s.app.admCreateAppOrgRole(name, description, permissionIDs, appID, orgID, assignerPermissions, l)
}

func (s *administrationImpl) AdmGetAppOrgRoles(appID string, orgID string) ([]model.AppOrgRole, error) {
	return s.app.AdmGetAppOrgRoles(appID, orgID)
}

func (s *administrationImpl) AdmDeleteAppOrgRole(ID string, appID string, orgID string, assignerPermissions []string, l *logs.Log) error {
	return s.app.admDeleteAppOrgRole(ID, appID, orgID, assignerPermissions, l)
}

func (s *administrationImpl) AdmGrantPermissionsToRole(appID string, orgID string, roleID string, permissionNames []string, assignerPermissions []string, l *logs.Log) error {
	return s.app.admGrantPermissionsToRole(appID, orgID, roleID, permissionNames, assignerPermissions, l)
}

func (s *administrationImpl) AdmGetApplicationPermissions(appID string, orgID string, l *logs.Log) ([]model.Permission, error) {
	return s.app.admGetApplicationPermissions(appID, orgID, l)
}

func (s *administrationImpl) AdmGetAccounts(appID string, orgID string, accountID *string, authTypeIdentifier *string) ([]model.Account, error) {
	return s.app.admGetAccounts(appID, orgID, accountID, authTypeIdentifier)
}

func (s *administrationImpl) AdmGetAccount(accountID string) (*model.Account, error) {
	return s.app.admGetAccount(accountID)
}

func (s *administrationImpl) AdmGrantAccountPermissions(appID string, orgID string, accountID string, permissionNames []string, assignerPermissions []string, l *logs.Log) error {
	return s.app.admGrantAccountPermissions(appID, orgID, accountID, permissionNames, assignerPermissions, l)
}

func (s *administrationImpl) AdmGrantAccountRoles(appID string, orgID string, accountID string, roleIDs []string, assignerPermissions []string, l *logs.Log) error {
	return s.app.admGrantAccountRoles(appID, orgID, accountID, roleIDs, assignerPermissions, l)
}

func (s *administrationImpl) AdmGetApplicationLoginSessions(appID string, orgID string, identifier *string, accountAuthTypeIdentifier *string,
	appTypeID *string, appTypeIdentifier *string, anonymous *bool, deviceID *string, ipAddress *string) ([]model.LoginSession, error) {
	return s.app.admGetApplicationLoginSessions(appID, orgID, identifier, accountAuthTypeIdentifier, appTypeID, appTypeIdentifier, anonymous, deviceID, ipAddress)
}

func (s *administrationImpl) AdmDeleteApplicationLoginSession(appID string, orgID string, currentAccountID string, identifier string, sessionID string, l *logs.Log) error {
	return s.app.admDeleteApplicationLoginSession(appID, orgID, currentAccountID, identifier, sessionID, l)
}

func (s *administrationImpl) AdmGetApplicationAccountDevices(appID string, orgID string, accountID string, l *logs.Log) ([]model.Device, error) {
	return s.app.admGetApplicationAccountDevices(appID, orgID, accountID, l)
}

///

//encryptionImpl

type encryptionImpl struct {
	app *application
}

func (s *encryptionImpl) EncGetTest() string {
	return s.app.encGetTest()
}

///

//bbsImpl

type bbsImpl struct {
	app *application
}

func (s *bbsImpl) BBsGetTest() string {
	return s.app.bbsGetTest()
}

///

//systemImpl

type systemImpl struct {
	app *application
}

func (s *systemImpl) SysCreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	return s.app.sysCreateGlobalConfig(setting)
}

func (s *systemImpl) SysGetGlobalConfig() (*model.GlobalConfig, error) {
	return s.app.sysGetGlobalConfig()
}

func (s *systemImpl) SysUpdateGlobalConfig(setting string) error {
	return s.app.sysUpdateGlobalConfig(setting)
}

func (s *systemImpl) SysCreateOrganization(name string, requestType string, organizationDomains []string) (*model.Organization, error) {
	return s.app.sysCreateOrganization(name, requestType, organizationDomains)
}

func (s *systemImpl) SysUpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error {
	return s.app.sysUpdateOrganization(ID, name, requestType, organizationDomains)
}

func (s *systemImpl) SysGetOrganizations() ([]model.Organization, error) {
	return s.app.sysGetOrganizations()
}

func (s *systemImpl) SysGetOrganization(ID string) (*model.Organization, error) {
	return s.app.sysGetOrganization(ID)
}

func (s *systemImpl) SysCreateApplication(name string, multiTenant bool, admin bool, sharedIdentities bool, appTypes []model.ApplicationType) (*model.Application, error) {
	return s.app.sysCreateApplication(name, multiTenant, admin, sharedIdentities, appTypes)
}

func (s *systemImpl) SysGetApplication(ID string) (*model.Application, error) {
	return s.app.sysGetApplication(ID)
}

func (s *systemImpl) SysGetApplications() ([]model.Application, error) {
	return s.app.sysGetApplications()
}

func (s *systemImpl) SysCreatePermission(name string, serviceID string, assigners *[]string) (*model.Permission, error) {
	return s.app.sysCreatePermission(name, serviceID, assigners)
}

func (s *systemImpl) SysUpdatePermission(name string, serviceID *string, assigners *[]string) (*model.Permission, error) {
	return s.app.sysUpdatePermission(name, serviceID, assigners)
}

func (s *systemImpl) SysCreateAppOrgRole(name string, appOrgID string, description string, permissionNames []string) (*model.AppOrgRole, error) {
	return s.app.sysCreateAppOrgRole(name, appOrgID, description, permissionNames)
}

func (s *systemImpl) SysGetAppConfigs(appTypeID string, orgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error) {
	return s.app.sysGetAppConfigs(appTypeID, orgID, versionNumbers)
}

func (s *systemImpl) SysGetAppConfig(id string) (*model.ApplicationConfig, error) {
	return s.app.sysGetAppConfig(id)
}

func (s *systemImpl) SysCreateAppConfig(appTypeID string, orgID *string, data map[string]interface{}, versionNumbers model.VersionNumbers) (*model.ApplicationConfig, error) {
	return s.app.sysCreateAppConfig(appTypeID, orgID, data, versionNumbers)
}

func (s *systemImpl) SysUpdateAppConfig(id string, appTypeID string, orgID *string, data map[string]interface{}, versionNumbers model.VersionNumbers) error {
	return s.app.sysUpdateAppConfig(id, appTypeID, orgID, data, versionNumbers)
}

func (s *systemImpl) SysDeleteAppConfig(id string) error {
	return s.app.sysDeleteAppConfig(id)
}

func (s *systemImpl) SysGrantAccountPermissions(accountID string, permissionNames []string, assignerPermissions []string) error {
	return s.app.sysGrantAccountPermissions(accountID, permissionNames, assignerPermissions)
}

func (s *systemImpl) SysGrantAccountRoles(accountID string, appID string, roleIDs []string) error {
	return s.app.sysGrantAccountRoles(accountID, appID, roleIDs)
}

func (s *systemImpl) SysCreateAuthTypes(code string, description string, isExternal bool, isAnonymous bool, useCredentials bool, ignoreMFA bool, params map[string]interface{}) (*model.AuthType, error) {
	return s.app.sysCreateAuthTypes(code, description, isExternal, isAnonymous, useCredentials, ignoreMFA, params)
}

func (s *systemImpl) SysGetAuthTypes() ([]model.AuthType, error) {
	return s.app.sysGetAuthTypes()
}

func (s *systemImpl) SysUpdateAuthTypes(ID string, code string, description string, isExternal bool, isAnonymous bool, useCredentials bool, ignoreMFA bool, params map[string]interface{}) error {
	return s.app.SysUpdateAuthTypes(ID, code, description, isExternal, isAnonymous, useCredentials, ignoreMFA, params)
}

///
