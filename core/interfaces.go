package core

//Services exposes APIs for the driver adapters
type Services interface {
	SerGetAuthTest() string

	SerGetCommonTest() string
}

type servicesImpl struct {
	app *Application
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
}

type administrationImpl struct {
	app *Application
}

func (s *administrationImpl) AdmGetTest() string {
	return s.app.admGetTest()
}

//Encryption exposes APIs for the Encryption building block
type Encryption interface {
}

type encryptionImpl struct {
	app *Application
}

//BBs exposes users related APIs used by the platform building blocks
type BBs interface {
}

type bbsImpl struct {
	app *Application
}

//Storage is used by core to storage data - DB storage adapter, file storage adapter etc
type Storage interface {
	SetStorageListener(storageListener StorageListener)
}

//StorageListener listenes for change data storage events
type StorageListener interface {
}

type storageListenerImpl struct {
	app *Application
}

//ApplicationListener represents application listener
type ApplicationListener interface {
}
