package core

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) bbsGetDeletedAccounts(appID string, orgID string) ([]string, error) {
	accounts, err := app.storage.FindDeletedAccounts(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	deletedAccounts := make([]string, len(accounts))
	for i, account := range accounts {
		deletedAccounts[i] = account.ID
	}

	return deletedAccounts, nil
}

func (app *application) bbsGetTest() string {
	return "BBs - test"
}
