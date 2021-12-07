package core

import (
	"core-building-block/core/model"

	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"

	"github.com/rokwire/logging-library-go/logs"
)

const (
	accountsDeletePeriod int = 2
)

//application represents the core application code based on hexagonal architecture
type application struct {
	env     string
	version string
	build   string

	storage Storage

	listeners []ApplicationListener

	//delete accounts timer
	deleteAccountsTimer *time.Timer
	timerDone           chan bool

	logger *logs.Logger
}

//start starts the core part of the application
func (app *application) start() {
	//set storage listener
	storageListener := StorageListener{app: app}
	app.storage.RegisterStorageListener(&storageListener)

	go app.setupDeleteAccountsTimer()
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

func (app *application) setupDeleteAccountsTimer() {
	if app.logger != nil {
		app.logger.Info("setupDeleteAccountsTimer")
	}

	//cancel if active
	if app.deleteAccountsTimer != nil {
		app.timerDone <- true
		app.deleteAccountsTimer.Stop()
	}

	app.deleteAccounts()
}

func (app *application) deleteAccounts() {
	if app.logger != nil {
		app.logger.Info("deleteAccounts")
	}

	err := app.storage.DeleteFlaggedAccounts(nil)
	if err != nil {
		app.logger.Error(err.Error())
	}

	duration := time.Hour * time.Duration(accountsDeletePeriod)
	app.deleteAccountsTimer = time.NewTimer(duration)
	select {
	case <-app.deleteAccountsTimer.C:
		// timer expired
		app.deleteAccountsTimer = nil

		app.deleteAccounts()
	case <-app.timerDone:
		// timer aborted
		app.deleteAccountsTimer = nil
	}
}
