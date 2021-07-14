package core

//application represents the core application code based on hexagonal architecture
type application struct {
	version string
	build   string

	storage Storage

	listeners []ApplicationListener
}

//start starts the core part of the application
func (app *application) start() {
	//set storage listener
	storageListener := storageListenerImpl{app: app}
	app.storage.SetCoreStorageListener(&storageListener)
}

//addListener adds application listener
func (app *application) addListener(listener ApplicationListener) {
	//TODO
	//log.Println("Application -> AddListener")

	app.listeners = append(app.listeners, listener)
}

func (app *application) notifyListeners(message string, data interface{}) {
	go func() {
		// TODO
	}()
}
