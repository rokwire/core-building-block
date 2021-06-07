package core

import (
	"log"
)

//Application represents the core application code based on hexagonal architecture
type Application struct {
	version string
	build   string

	Services       Services       //expose to the drivers adapters
	Administration Administration //expose to the drivrs adapters

	storage Storage

	listeners []ApplicationListener
}

//Start starts the core part of the application
func (app *Application) Start() {
	//set storage listener
	storageListener := storageListenerImpl{app: app}
	app.storage.SetStorageListener(&storageListener)
}

//AddListener adds application listener
func (app *Application) AddListener(listener ApplicationListener) {
	log.Println("Application -> AddListener")

	app.listeners = append(app.listeners, listener)
}

func (app *Application) notifyListeners(message string, data interface{}) {
	go func() {
		//TODO

	}()
}

//NewApplication creates new Application
func NewApplication(version string, build string, storage Storage) *Application {
	listeners := []ApplicationListener{}

	application := Application{version: version, build: build, storage: storage, listeners: listeners}

	//add the drivers ports/interfaces
	application.Services = &servicesImpl{app: &application}
	application.Administration = &administrationImpl{app: &application}

	return &application
}
