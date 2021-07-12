package core

import (
	"core-building-block/core/auth"
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
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
}

//AddListener adds application listener
func (c *APIs) AddListener(listener ApplicationListener) {
	c.app.addListener(listener)
}

//NewCoreAPIs creates new CoreAPIs
func NewCoreAPIs(version string, build string, storage Storage, auth *auth.Auth) *APIs {
	//add application instance
	listeners := []ApplicationListener{}
	application := application{version: version, build: build, storage: storage, listeners: listeners}

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

func (s *servicesImpl) SerGetVersion(l *log.Log) string {
	return s.app.serGetVersion(l)
}

func (s *servicesImpl) SerGetAuthTest(l *log.Log) string {
	return s.app.serGetAuthTest(l)
}

func (s *servicesImpl) SerGetCommonTest(l *log.Log) string {
	return s.app.serGetCommonTest(l)
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

func (s *administrationImpl) AdmGetOrganizations() ([]model.Organization, error) {
	return s.app.admGetOrganizations()
}

func (s *administrationImpl) AdmUpdateOrganization(ID string, name string, requestType string, requiresOwnLogin bool, loginTypes []string, organizationDomains []string) error {
	return s.app.admUpdateOrganization(ID, name, requestType, requiresOwnLogin, loginTypes, organizationDomains)

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
