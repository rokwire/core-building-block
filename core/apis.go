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

	Auth *auth.Auth //expose to the drivers auth

	app *application
}

//Start starts the core part of the application
func (c *APIs) Start() {
	c.app.start()

	storageListener := auth.StorageListener{Auth: c.Auth}
	c.app.storage.RegisterStorageListener(&storageListener)
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
func NewCoreAPIs(env string, version string, build string, storage Storage, auth *auth.Auth) *APIs {
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

func (s *servicesImpl) SerGetAuthTest(l *logs.Log) string {
	return s.app.serGetAuthTest(l)
}

func (s *servicesImpl) SerGetCommonTest(l *logs.Log) string {
	return s.app.serGetCommonTest(l)
}

func (s *servicesImpl) CreateAnonymousProfile(l *logs.Log, profile *model.AnonymousProfile) (*model.AnonymousProfile, error) {
	return s.app.createAnonymousProfile(l, profile)
}

func (s *servicesImpl) UpdateAnonymousProfile(l *logs.Log, id string, favorites *[]string, interests *[]string,
	negativeInterestTags *[]string, positiveInterestTags *[]string, privacySettings *string, over13 *bool) error {
	return s.app.updateAnonymousProfile(l, id, favorites, interests, negativeInterestTags, positiveInterestTags, privacySettings, over13)
}

func (s *servicesImpl) DeleteAnonymousProfile(l *logs.Log, id string) error {
	return s.app.deleteAnonymousProfile(l, id)
}

func (s *servicesImpl) GetAnonymousProfile(l *logs.Log, id string) (*model.AnonymousProfile, error) {
	return s.app.getAnonymousProfile(l, id)
}

func (s *servicesImpl) UpdateUserAnonymousProfile(l *logs.Log, id string, profile *model.UserAnonymousProfile) error {
	return s.app.updateUserAnonymousProfile(l, id, profile)
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

func (s *administrationImpl) AdmCreateOrganization(name string, requestType string, requiresOwnLogin bool, loginTypes []string, organizationDomains []string) (*model.Organization, error) {
	return s.app.admCreateOrganization(name, requestType, requiresOwnLogin, loginTypes, organizationDomains)
}

func (s *administrationImpl) AdmUpdateOrganization(ID string, name string, requestType string, requiresOwnLogin bool, loginTypes []string, organizationDomains []string) error {
	return s.app.admUpdateOrganization(ID, name, requestType, requiresOwnLogin, loginTypes, organizationDomains)
}

func (s *administrationImpl) AdmGetOrganizations() ([]model.Organization, error) {
	return s.app.admGetOrganizations()
}

func (s *administrationImpl) AdmGetOrganization(ID string) (*model.Organization, error) {
	return s.app.admGetOrganization(ID)
}

func (s *administrationImpl) AdmGetApplication(ID string) (*model.Application, error) {
	return s.app.admGetApplication(ID)
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
