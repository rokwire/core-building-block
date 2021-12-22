package core

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

//application represents the core application code based on hexagonal architecture
type application struct {
	env     string
	version string
	build   string

	storage Storage

	listeners       []ApplicationListener
	requestExecutor HTTPRequestExecutor
}

//start starts the core part of the application
func (app *application) start() {
	//set storage listener
	storageListener := StorageListener{app: app}
	app.storage.RegisterStorageListener(&storageListener)
}

//addListener adds application listener
func (app *application) addListener(listener ApplicationListener) {
	//TODO
	//logs.Println("Application -> AddListener")

	app.listeners = append(app.listeners, listener)
}

func (app *application) notifyListeners(message string, data interface{}) {
	go func() {
		// TODO
	}()
}

func (app *application) getAccount(accountID string) (*model.Account, error) {
	//find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	return account, nil
}
