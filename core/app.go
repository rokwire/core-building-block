package core

import (
	"core-building-block/core/auth"
	"core-building-block/core/model"

	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	deleteAccountsPeriodDefault uint = 2
)

//application represents the core application code based on hexagonal architecture
type application struct {
	env     string
	version string
	build   string

	storage Storage

	listeners []ApplicationListener

	auth auth.APIs

	//delete accounts timer
	deleteAccountsPeriod *uint64
	deleteAccountsTimer  *time.Timer
	timerDone            chan bool

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

//checkPermissions checks if the provided permissions ids are valid for the app/org.
//	it returns the permissions list for these ids if they are valid
func (app *application) checkPermissions(appOrg model.ApplicationOrganization, permissionIDs []string, l *logs.Log) ([]model.Permission, error) {
	if len(permissionIDs) == 0 {
		return nil, nil
	}

	permissions, err := app.storage.FindPermissionsByServiceIDs(appOrg.ServicesIDs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypePermission, nil, err)
	}
	if len(permissionIDs) > len(permissions) {
		return nil, errors.New("mismatch permissions count")
	}
	rolePermissions := make([]model.Permission, len(permissionIDs))
	for i, permissionID := range permissionIDs {
		var rolePermission *model.Permission

		for _, permission := range permissions {
			if permission.ID == permissionID {
				rolePermission = &permission
				break
			}
		}

		if rolePermission == nil {
			l.Infof("%s permission does not match", permissionID)
			return nil, errors.Newf("%s permission does not match", permissionID)
		}
		rolePermissions[i] = *rolePermission
	}
	return rolePermissions, nil
}

//checkRoles checkRoles if the provided roles ids are valid for the app/org.
//	it returns the roles list for these ids if they are valid
func (app *application) checkRoles(appOrg model.ApplicationOrganization, rolesIDs []string, l *logs.Log) ([]model.AppOrgRole, error) {
	if len(rolesIDs) == 0 {
		return nil, nil
	}

	appOrgRoles, err := app.storage.FindAppOrgRolesByIDs(nil, rolesIDs, appOrg.ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAppOrgRole, nil, err)
	}

	if len(rolesIDs) != len(appOrgRoles) {
		return nil, errors.New("mismatch roles count")
	}

	return appOrgRoles, nil
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

	deletePeriod := uint64(deleteAccountsPeriodDefault)
	if app.deleteAccountsPeriod != nil {
		deletePeriod = *app.deleteAccountsPeriod
	}
	duration := time.Hour * time.Duration(deletePeriod)

	err := app.storage.DeleteFlaggedAccounts(time.Now().UTC().Add(-duration))
	if err != nil {
		app.logger.Error(err.Error())
	}

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
