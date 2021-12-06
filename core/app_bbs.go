package core

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) bbsGetDeletedAccounts() ([]string, error) {
	var deletedAccounts []string
	transaction := func(context storage.TransactionContext) error {
		//1. find accounts flagged for deletion
		accounts, err := app.storage.FindDeletedAccounts(context)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
		}
		if accounts == nil {
			return nil
		}

		for _, account := range accounts {
			deletedAccounts = append(deletedAccounts, account.ID)
		}

		//2. delete flagged accounts
		err = app.storage.DeleteFlaggedAccounts(context)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
		}

		return nil
	}

	err := app.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, "deleted accounts", nil, err)
	}

	return deletedAccounts, nil
}

func (app *application) bbsGetTest() string {
	return "BBs - test"
}
