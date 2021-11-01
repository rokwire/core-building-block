package core

import (
	"core-building-block/core/model"
	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func (app *application) serGetProfile(accountID string) (*model.Profile, error) {
	//find the account
	account, err := app.storage.FindAccountByID(accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	//get the profile for the account
	profile := account.Profile
	return &profile, nil
}

func (app *application) serGetPreferences(accountID string) (map[string]interface{}, error) {
	//find the account
	account, err := app.storage.FindAccountByID(accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountPreferences, nil, err)
	}

	preferences := account.Preferences
	return preferences, nil
}

func (app *application) serUpdateProfile(accountID string, profile *model.Profile) error {
	return app.storage.UpdateProfile(accountID, profile)
}

func (app *application) serUpdateAccountPreferences(id string, preferences map[string]interface{}) error {
	err := app.storage.UpdateAccountPreferences(id, preferences)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
	}
	return nil
}

func (app *application) serDeleteAccount(id string) error {
	transaction := func(sessionContext mongo.SessionContext) error {
		account, err := app.storage.FindAccountByID(sessionContext, id)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
		}
		if account == nil {
			return errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
		}

		err = app.storage.DeleteAccount(sessionContext, id)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
		}

		for _, device := range account.Devices {
			filter := bson.M{"_id": device.ID}
			if len(device.Accounts) > 1 {
				for _, deviceAccount := range device.Accounts {
					// if deviceAccount.ID == id {
					// 	device.Accounts =
					// }
				}
				update := bson.D{
					primitive.E{Key: "$pull", Value: bson.D{
						primitive.E{Key: "accounts", Value: account.ID},
					}},
					primitive.E{Key: "$set", Value: bson.D{
						primitive.E{Key: "date_updated", Value: time.Now().UTC()},
					}},
				}
				res, err := app.storage.UpdateOneWithContext(sessionContext, filter, update, nil)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeDevice, nil, err)
				}
				if res.ModifiedCount != 1 {
					return errors.ErrorAction(logutils.ActionUpdate, model.TypeDevice, logutils.StringArgs("unexpected modified count"))
				}
			} else {
				app.storage.DeleteDevice(sessionContext, device.ID)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionDelete, model.TypeDevice, nil, err)
				}
			}
		}
	}

	return app.storage.PerformTransaction(transaction)

	// return app.storage.DeleteAccount(id)
}

func (app *application) serGetAuthTest(l *logs.Log) string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest(l *logs.Log) string {
	return "Services - Common - test"
}
