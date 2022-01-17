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

	SystemOrgID      string
	SystemAdminAppID string

	app *application
}

//Start starts the core part of the application
func (c *APIs) Start() {
	c.app.start()
	c.Auth.Start()

	c.storeSystemData()
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
		//1. insert system admin app if doesn't exist
		systemAdminApp, err := c.app.storage.FindApplication(c.SystemAdminAppID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
		}
		if systemAdminApp == nil {
			id, _ := uuid.NewUUID()
			newAndroidAppType := model.ApplicationType{ID: id.String(), Identifier: "edu.illinois.rokwire.admin.android",
				Name: "System Admin Android", Versions: []string{"1.0.0"}}
			newSystemAdminApp := model.Application{ID: c.SystemAdminAppID, Name: "System Admin Application", MultiTenant: false, Admin: true,
				RequiresOwnUsers: false, Types: []model.ApplicationType{newAndroidAppType}, DateCreated: time.Now().UTC()}
			_, err = c.app.storage.InsertApplication(newSystemAdminApp)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionInsert, model.TypeApplication, nil, err)
			}

			systemAdminApp = &newSystemAdminApp
		}

		//2. insert system org if doesn't exist
		systemOrg, err := c.app.storage.FindOrganization(c.SystemOrgID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
		}
		if systemOrg == nil {
			id, _ := uuid.NewUUID()
			systemOrgConfig := model.OrganizationConfig{ID: id.String(), DateCreated: time.Now().UTC()}
			newSystemOrg := model.Organization{ID: c.SystemOrgID, Name: "System", Type: "small", Config: systemOrgConfig, DateCreated: time.Now().UTC()}
			_, err = c.app.storage.InsertOrganization(newSystemOrg)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionInsert, model.TypeOrganization, nil, err)
			}

			systemOrg = &newSystemOrg
		}

		//3. insert system appOrg if doesn't exist
		systemAdminAppOrg, err := c.app.storage.FindApplicationOrganizations(c.SystemAdminAppID, c.SystemOrgID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, nil, err)
		}
		if systemAdminAppOrg == nil {
			id, _ := uuid.NewUUID()

			emailAuthType, err := c.app.storage.FindAuthType("email")
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, nil, err)
			}
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

			newSystemAdminAppOrg := model.ApplicationOrganization{ID: id.String(), Application: *systemAdminApp, Organization: *systemOrg,
				SupportedAuthTypes: supportedAuthTypes, DateCreated: time.Now().UTC()}
			_, err = c.app.storage.InsertApplicationOrganization(newSystemAdminAppOrg)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionSave, model.TypeApplicationOrganization, nil, err)
			}
		}

		return nil
	}

	return c.app.storage.PerformTransaction(transaction)
}

//NewCoreAPIs creates new CoreAPIs
func NewCoreAPIs(env string, version string, build string, storage Storage, auth auth.APIs, systemAdminAppID string, systemOrgID string) *APIs {
	//add application instance
	listeners := []ApplicationListener{}
	application := application{env: env, version: version, build: build, storage: storage, listeners: listeners}

	//add coreAPIs instance
	servicesImpl := &servicesImpl{app: &application}
	administrationImpl := &administrationImpl{app: &application}
	encryptionImpl := &encryptionImpl{app: &application}
	bbsImpl := &bbsImpl{app: &application}
	systemImpl := &systemImpl{app: &application}

	//+ auth
	coreAPIs := APIs{Services: servicesImpl, Administration: administrationImpl, Encryption: encryptionImpl,
		BBs: bbsImpl, System: systemImpl, Auth: auth, SystemAdminAppID: systemAdminAppID, SystemOrgID: systemOrgID,
		app: &application}

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

func (s *servicesImpl) SerUpdateProfile(accountID string, profile *model.Profile) error {
	return s.app.serUpdateProfile(accountID, profile)
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

func (s *administrationImpl) AdmGetAppOrgGroups(appID string, orgID string) ([]model.AppOrgGroup, error) {
	return s.app.admGetAppOrgGroups(appID, orgID)
}

func (s *administrationImpl) AdmGetAppOrgRoles(appID string, orgID string) ([]model.AppOrgRole, error) {
	return s.app.AdmGetAppOrgRoles(appID, orgID)
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

func (s *systemImpl) SysCreateApplication(name string, multiTenant bool, requiresOwnUsers bool, maxLoginSessionDuration *int, identifier string, nameInType string, versions []string) (*model.Application, error) {
	return s.app.sysCreateApplication(name, multiTenant, requiresOwnUsers, maxLoginSessionDuration, identifier, nameInType, versions)
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

func (s *systemImpl) SysGrantAccountPermissions(accountID string, permissionNames []string, assignerPermissions []string) error {
	return s.app.sysGrantAccountPermissions(accountID, permissionNames, assignerPermissions)
}

func (s *systemImpl) SysGrantAccountRoles(accountID string, appID string, roleIDs []string) error {
	return s.app.sysGrantAccountRoles(accountID, appID, roleIDs)
}

///
