package core

import (
	"core-building-block/core/auth"
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/logs"
)

//APIs exposes to the drivers adapters access to the core functionality
type APIs struct {
	Services       Services       //expose to the drivers adapters
	Administration Administration //expose to the drivers adapters
	Encryption     Encryption     //expose to the drivers adapters
	BBs            BBs            //expose to the drivers adapters

	Auth auth.APIs //expose to the drivers auth

	app *application
}

//Start starts the core part of the application
func (c *APIs) Start() {
	c.app.start()
	c.Auth.Start()
}

//AddListener adds application listener
func (c *APIs) AddListener(listener ApplicationListener) {
	c.app.addListener(listener)
}

//GetVersion gives the service version
func (c *APIs) GetVersion() string {
	return c.app.version
}

//NewCoreAPIs creates new CoreAPIs
func NewCoreAPIs(env string, version string, build string, storage Storage, auth auth.APIs) *APIs {
	//add application instance
	listeners := []ApplicationListener{}
	application := application{env: env, version: version, build: build, storage: storage, listeners: listeners}

	//add coreAPIs instance
	servicesImpl := &servicesImpl{app: &application}
	administrationImpl := &administrationImpl{app: &application}
	encryptionImpl := &encryptionImpl{app: &application}
	bbsImpl := &bbsImpl{app: &application}

	//+ auth
	coreAPIs := APIs{Services: servicesImpl, Administration: administrationImpl, Encryption: encryptionImpl,
		BBs: bbsImpl, Auth: auth, app: &application}

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

func (s *administrationImpl) AdmCreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	return s.app.admCreateGlobalConfig(setting)
}

func (s *administrationImpl) AdmGetGlobalConfig() (*model.GlobalConfig, error) {
	return s.app.admGetGlobalConfig()
}

func (s *administrationImpl) AdmUpdateGlobalConfig(setting string) error {
	return s.app.admUpdateGlobalConfig(setting)
}

func (s *administrationImpl) AdmCreateOrganization(name string, requestType string, organizationDomains []string) (*model.Organization, error) {
	return s.app.admCreateOrganization(name, requestType, organizationDomains)
}

func (s *administrationImpl) AdmUpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error {
	return s.app.admUpdateOrganization(ID, name, requestType, organizationDomains)
}

func (s *administrationImpl) AdmGetOrganizations() ([]model.Organization, error) {
	return s.app.admGetOrganizations()
}

func (s *administrationImpl) AdmGetOrganization(ID string) (*model.Organization, error) {
	return s.app.admGetOrganization(ID)
}

func (s *administrationImpl) AdmCreateApplication(name string, multiTenant bool, requiresOwnUsers bool, identifier string, nameInType string, versions []string) (*model.Application, error) {
	return s.app.admCreateApplication(name, multiTenant, requiresOwnUsers, identifier, nameInType, versions)
}

func (s *administrationImpl) AdmGetApplication(ID string) (*model.Application, error) {
	return s.app.admGetApplication(ID)
}

func (s *administrationImpl) AdmGetApplications() ([]model.Application, error) {
	return s.app.admGetApplications()
}

func (s *administrationImpl) AdmCreateApplicationPermission(name string, appID string) (*model.ApplicationPermission, error) {
	return s.app.admCreateApplicationPermission(name, appID)
}

func (s *administrationImpl) AdmCreateApplicationRole(name string, appID string, description string, permissionNames []string) (*model.ApplicationRole, error) {
	return s.app.admCreateApplicationRole(name, appID, description, permissionNames)
}

func (s *administrationImpl) AdmGrantAccountPermissions(accountID string, appID string, permissionNames []string) error {
	return s.app.admGrantAccountPermissions(accountID, appID, permissionNames)
}

func (s *administrationImpl) AdmGrantAccountRoles(accountID string, appID string, roleIDs []string) error {
	return s.app.admGrantAccountRoles(accountID, appID, roleIDs)
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
