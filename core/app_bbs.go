package core

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) bbsGetDeletedAccounts() ([]string, error) {
	var deletedAccounts []string

	accounts, err := app.storage.FindDeletedAccounts()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	for _, account := range accounts {
		deletedAccounts = append(deletedAccounts, account.ID)
	}

	return deletedAccounts, nil
}

func (app *application) bbsGetTest() string {
	return "BBs - test"
}
