package core

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

//application represents the core application code based on hexagonal architecture
type application struct {
	env     string
	version string
	build   string

	storage Storage

	listeners []ApplicationListener
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

//checkPermissions checks if the provided permissions ids are valid for the app/org.
//	it returns the permissions list for these ids if they are valid
func (app *application) checkPermissions(appOrg model.ApplicationOrganization, permissionIDs []string, l *logs.Log) ([]model.Permission, error) {
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
