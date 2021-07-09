package core

//Services exposes APIs for the driver adapters
type Services interface {
	SerGetVersion() string
	SerGetAuthTest() string
	SerGetCommonTest() string
}

type servicesImpl struct {
	app *Application
}

func (s *servicesImpl) SerGetVersion() string {
	return s.app.serGetVersion()
}

func (s *servicesImpl) SerGetAuthTest() string {
	return s.app.serGetAuthTest()
}

func (s *servicesImpl) SerGetCommonTest() string {
	return s.app.serGetCommonTest()
}

//Administration exposes administration APIs for the driver adapters
type Administration interface {
	AdmGetTest() string
	AdmGetTestModel() string
}

type administrationImpl struct {
	app *Application
}

func (s *administrationImpl) AdmGetTest() string {
	return s.app.admGetTest()
}

func (s *administrationImpl) AdmGetTestModel() string {
	return s.app.admGetTestModel()
}

//Encryption exposes APIs for the Encryption building block
type Encryption interface {
	EncGetTest() string
}

type encryptionImpl struct {
	app *Application
}

func (s *encryptionImpl) EncGetTest() string {
	return s.app.encGetTest()
}

//BBs exposes users related APIs used by the platform building blocks
type BBs interface {
	BBsGetTest() string
}

type bbsImpl struct {
	app *Application
}

func (s *bbsImpl) BBsGetTest() string {
	return s.app.bbsGetTest()
}

//Storage is used by core to storage data - DB storage adapter, file storage adapter etc
type Storage interface {
	SetStorageListener(storageListener StorageListener)
}

//StorageListener listenes for change data storage events
type StorageListener interface {
	OnAuthConfigUpdated()
}

type storageListenerImpl struct {
	app *Application
}

func (a *storageListenerImpl) OnAuthConfigUpdated() {
	a.app.notifyListeners("onAuthConfigUpdated", nil)
}

//ApplicationListener represents application listener
type ApplicationListener interface {
	OnAuthConfigUpdated()
}
