package core

//Services exposes APIs for the driver adapters
type Services interface {
}

type servicesImpl struct {
	app *Application
}

//Administration exposes administration APIs for the driver adapters
type Administration interface {
}

type administrationImpl struct {
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
