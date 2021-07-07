package core

import (
	"core-building-block/core/auth"
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

//CoreAPIs exposes to the drivers adapters access to the core functionality
type CoreAPIs struct {
	Services       Services       //expose to the drivers adapters
	Administration Administration //expose to the drivers adapters
	Encryption     Encryption     //expose to the drivers adapters
	BBs            BBs            //expose to the drivers adapters

	Auth *auth.Auth //expose to the drivers auth

	app *Application
}

//Start starts the core part of the application
func (c *CoreAPIs) Start() {
	c.app.start()
}

//AddListener adds application listener
func (c *CoreAPIs) AddListener(listener ApplicationListener) {
	c.app.addListener(listener)
}

//NewCoreAPIs creates new CoreAPIs
func NewCoreAPIs(version string, build string, storage Storage, auth *auth.Auth) *CoreAPIs {
	//add application instance
	listeners := []ApplicationListener{}
	application := Application{version: version, build: build, storage: storage, listeners: listeners}

	//add coreAPIs instance
	servicesImpl := &servicesImpl{app: &application}
	administrationImpl := &administrationImpl{app: &application}
	encryptionImpl := &encryptionImpl{app: &application}
	bbsImpl := &bbsImpl{app: &application}

	//+ auth
	coreAPIs := CoreAPIs{Services: servicesImpl, Administration: administrationImpl, Encryption: encryptionImpl,
		BBs: bbsImpl, Auth: auth, app: &application}

	return &coreAPIs
}

///

//servicesImpl
type servicesImpl struct {
	app *Application
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
	app *Application
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

///

//encryptionImpl

type encryptionImpl struct {
	app *Application
}

func (s *encryptionImpl) EncGetTest() string {
	return s.app.encGetTest()
}

///

//bbsImpl

type bbsImpl struct {
	app *Application
}

func (s *bbsImpl) BBsGetTest() string {
	return s.app.bbsGetTest()
}

///

//Application represents the core application code based on hexagonal architecture
type Application struct {
	version string
	build   string

	storage Storage

	listeners []ApplicationListener
}

//start starts the core part of the application
func (app *Application) start() {
	//set storage listener
	storageListener := storageListenerImpl{app: app}
	app.storage.SetStorageListener(&storageListener)
}

//addListener adds application listener
func (app *Application) addListener(listener ApplicationListener) {
	//TODO
	//log.Println("Application -> AddListener")

	app.listeners = append(app.listeners, listener)
}

func (app *Application) notifyListeners(message string, data interface{}) {
	go func() {
		//TODO

	}()
}
