// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package core

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"core-building-block/utils"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

func (app *application) serGetProfile(accountID string) (*model.Profile, *string, *string, error) {
	//find the account
	account, err := app.storage.FindAccountByID(nil, nil, nil, accountID)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	//get the profile for the account
	profile := account.Profile
	var email *string
	if emailIdentifier := account.GetAccountIdentifier("email", "", true); emailIdentifier != nil {
		email = &emailIdentifier.Identifier
	}
	var phone *string
	if phoneIdentifier := account.GetAccountIdentifier("phone", "", true); phoneIdentifier != nil {
		phone = &phoneIdentifier.Identifier
	}

	return &profile, email, phone, nil
}

func (app *application) serGetPreferences(cOrgID string, cAppID string, accountID string) (map[string]interface{}, error) {
	//find the account
	account, err := app.storage.FindAccountByID(nil, &cOrgID, &cAppID, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountPreferences, &logutils.FieldArgs{"account_id": accountID}, err)
	}
	if account == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAccountPreferences, &logutils.FieldArgs{"account_id": accountID}, err)
	}

	preferences := account.Preferences
	return preferences, nil
}

func (app *application) serGetAccountSystemConfigs(cOrgID string, cAppID string, accountID string) (map[string]interface{}, error) {
	//find the account
	account, err := app.storage.FindAccountByID(nil, &cOrgID, &cAppID, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"account_id": accountID}, err)
	}
	if account == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"account_id": accountID}, err)
	}

	return account.SystemConfigs, nil
}

func (app *application) serUpdateAccountProfile(accountID string, profile model.Profile, email *string, phone *string) error {
	transaction := func(context storage.TransactionContext) error {
		//1. verify that the account is for the current app/org
		//find the account
		account, err := app.storage.FindAccountByID(context, nil, nil, accountID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"account_id": accountID}, err)
		}
		if account == nil {
			return errors.WrapErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"account_id": accountID}, err)
		}

		var newAccountIdentifiers []model.AccountIdentifier
		// can update the email used for the profile to any valid email because the client is not needed to verify it
		if email != nil {
			profileEmailIdentifier := account.GetAccountIdentifier("email", "", true)
			// try to update the profile email identifier if it does not exist or is being changed
			if profileEmailIdentifier == nil || profileEmailIdentifier.Identifier != *email {
				emailIdentifier := account.GetAccountIdentifier("email", *email, false)
				if emailIdentifier != nil {
					// do not use the old profile email identifier for the profile anymore
					if profileEmailIdentifier != nil {
						profileEmailIdentifier.UseForProfile = false
					}
					emailIdentifier.UseForProfile = true
				} else if utils.IsValidEmail(*email) {
					// do not use the old profile email identifier for the profile anymore
					if profileEmailIdentifier != nil {
						profileEmailIdentifier.UseForProfile = false
					}
					// add to identifiers and send verification code if adding a new valid email
					newIdentifier := model.AccountIdentifier{ID: uuid.NewString(), Code: "email", Identifier: *email, Linked: true, Sensitive: true, UseForProfile: true, DateCreated: time.Now().UTC()}
					account.Identifiers = append(account.Identifiers, newIdentifier)

					err := app.auth.SendVerifyIdentifierAuthenticated(context, account, &newIdentifier)
					if err != nil {
						return errors.WrapErrorAction(logutils.ActionVerify, model.TypeAccountIdentifier, &logutils.FieldArgs{"code": email, "identifier": *email}, err)
					}
				} else {
					return errors.ErrorData(logutils.StatusInvalid, "profile email", &logutils.FieldArgs{"email": *email})
				}

				newAccountIdentifiers = make([]model.AccountIdentifier, len(account.Identifiers))
				for j, aIdentifier := range account.Identifiers {
					if emailIdentifier != nil && aIdentifier.ID == emailIdentifier.ID {
						newAccountIdentifiers[j] = *emailIdentifier
					} else if profileEmailIdentifier != nil && aIdentifier.ID == profileEmailIdentifier.ID {
						newAccountIdentifiers[j] = *profileEmailIdentifier
					} else {
						newAccountIdentifiers[j] = aIdentifier
					}
				}
				account.Identifiers = newAccountIdentifiers
			}
		}

		// can only update the phone used for the profile if it is already a verified identifier because clients using the profile phone do not provide a way to verify it
		if phone != nil {
			profilePhoneIdentifier := account.GetAccountIdentifier("phone", "", true)
			// try to update the profile phone identifier if it does not exist or is being changed
			if profilePhoneIdentifier == nil || profilePhoneIdentifier.Identifier != *phone {
				phoneIdentifier := account.GetAccountIdentifier("phone", *phone, false)
				if phoneIdentifier != nil && phoneIdentifier.Verified {
					// do not use the old profile phone identifier for the profile anymore if the new one is verified
					if profilePhoneIdentifier != nil {
						profilePhoneIdentifier.UseForProfile = false
					}
					phoneIdentifier.UseForProfile = true
				} else {
					return errors.ErrorData(logutils.StatusInvalid, "profile phone", &logutils.FieldArgs{"phone": *phone, "verified": false})
				}

				newAccountIdentifiers = make([]model.AccountIdentifier, len(account.Identifiers))
				for j, aIdentifier := range account.Identifiers {
					if aIdentifier.ID == phoneIdentifier.ID {
						newAccountIdentifiers[j] = *phoneIdentifier
					} else if profilePhoneIdentifier != nil && aIdentifier.ID == profilePhoneIdentifier.ID {
						newAccountIdentifiers[j] = *profilePhoneIdentifier
					} else {
						newAccountIdentifiers[j] = aIdentifier
					}
				}
				account.Identifiers = newAccountIdentifiers
			}
		}

		err = app.storage.UpdateAccountProfile(context, accountID, profile, account.Identifiers)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeProfile, nil, err)
		}
		return nil
	}

	err := app.storage.PerformTransaction(transaction)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
	}
	return nil
}

func (app *application) serUpdateAccountPrivacy(accountID string, privacy model.Privacy) error {
	err := app.storage.UpdateAccountPrivacy(nil, accountID, privacy)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypePrivacy, nil, err)
	}
	return nil
}

func (app *application) serUpdateAccountPreferences(id string, appID string, orgID string, anonymous bool, preferences map[string]interface{}, l *logs.Log) (bool, error) {
	if anonymous {
		created := false
		transaction := func(context storage.TransactionContext) error {
			//1. verify that the account is for the current app/org
			account, err := app.storage.FindAccountByID(context, &orgID, &appID, id)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"account_id": id}, err)
			}
			if account == nil {
				created = true
				_, err = app.auth.CreateAnonymousAccount(context, appID, orgID, id, preferences, nil, true, l)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccount, nil, err)
				}
				return nil
			}
			err = app.storage.UpdateAccountPreferences(context, orgID, appID, id, preferences)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountPreferences, nil, err)
			}
			return nil
		}

		err := app.storage.PerformTransaction(transaction)
		if err != nil {
			return false, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
		}
		return created, nil
	}

	err := app.storage.UpdateAccountPreferences(nil, orgID, appID, id, preferences)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountPreferences, nil, err)
	}
	return false, nil
}

func (app *application) serUpdateAccountSecrets(accountID string, appID string, orgID string, secrets map[string]interface{}) error {
	encryptedSecrets, err := app.auth.EncryptSecrets(secrets)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionEncrypt, model.TypeAccountSecrets, nil, err)
	}

	err = app.storage.UpdateAccountSecrets(nil, orgID, appID, accountID, encryptedSecrets)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountSecrets, &logutils.FieldArgs{"id": accountID}, err)
	}

	return nil
}

func (app *application) serDeleteAccount(id string, apps []string) error {
	return app.auth.DeleteAccount(id, apps)
}

func (app *application) serGetAccounts(limit int, offset int, appID string, orgID string, accountID *string, firstName *string, lastName *string, authType *string,
	authTypeIdentifier *string, anonymous *bool, hasPermissions *bool, permissions []string, roleIDs []string, groupIDs []string) ([]model.Account, error) {
	//find the accounts
	accounts, err := app.storage.FindAccounts(nil, &limit, &offset, appID, orgID, accountID, firstName, lastName, authType, authTypeIdentifier, anonymous, hasPermissions, permissions, roleIDs, groupIDs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	return accounts, nil
}

func (app *application) serGetPublicAccounts(appID string, orgID string, limit int, offset int, search *string, firstName *string,
	lastName *string, username *string, followingID *string, followerID *string, userID string) ([]model.PublicAccount, error) {
	//find the accounts
	accounts, err := app.storage.FindPublicAccounts(nil, appID, orgID, &limit, &offset, search, firstName, lastName, username, followingID, followerID, userID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	return accounts, nil
}

func (app *application) serAddFollow(follow model.Follow) error {
	follow.ID = uuid.NewString()
	follow.DateCreated = time.Now()
	err := app.storage.InsertFollow(nil, follow)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeFollow, nil, err)
	}
	return nil
}

func (app *application) serDeleteFollow(appID string, orgID string, followingID string, followerID string) error {
	err := app.storage.DeleteFollow(nil, appID, orgID, followingID, followerID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeFollow, nil, err)
	}
	return nil
}

func (app *application) serGetAuthTest() string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest() string {
	return "Services - Common - test"
}

func (app *application) serGetAppConfig(appTypeIdentifier string, orgID *string, versionNumbers model.VersionNumbers, apiKey *string) (*model.ApplicationConfig, error) {
	return app.sharedGetAppConfig(appTypeIdentifier, orgID, versionNumbers, apiKey, false)
}
