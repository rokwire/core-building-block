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

package storage

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Database Migration functions

func (sa *Adapter) migrateAuthTypes() error {
	transaction := func(context TransactionContext) error {
		//1. insert new auth types
		newAuthTypes := map[string]model.AuthType{
			"password": {ID: uuid.NewString(), Code: "password", Description: "Authentication type relying on password", UseCredentials: true, Aliases: []string{"email", "username"}},
			"code":     {ID: uuid.NewString(), Code: "code", Description: "Authentication type relying on codes sent over a communication channel", Aliases: []string{"phone", "twilio_phone"}},
			"webauthn": {ID: uuid.NewString(), Code: "webauthn", Description: "Authentication type relying on WebAuthn", UseCredentials: true},
		}
		inserted := false
		for code, authType := range newAuthTypes {
			existing, err := sa.FindAuthType(code)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, logutils.StringArgs(code), err)
			}
			if existing == nil {
				_, err = sa.InsertAuthType(context, authType)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAuthType, logutils.StringArgs(code), err)
				}

				inserted = true
			}
		}
		// if all already exist, migration is done so return no error
		if !inserted {
			return nil
		}

		//2. remove old auth types if they exist
		removedAuthTypeIDs := make(map[string]model.AuthType)
		removedAuthTypeCodes := map[string]model.AuthType{
			"email":        newAuthTypes["password"],
			"username":     newAuthTypes["password"],
			"phone":        newAuthTypes["code"],
			"twilio_phone": newAuthTypes["code"],
		}
		for old, new := range removedAuthTypeCodes {
			// need to load auth type directly from DB so that we do not get one of the new auth types by alias
			var authTypes []model.AuthType
			err := sa.db.authTypes.FindWithContext(context, bson.M{"code": old}, &authTypes, nil)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, logutils.StringArgs(old), err)
			}
			if len(authTypes) == 0 {
				continue
			}

			removedAuthTypeIDs[authTypes[0].ID] = new

			// remove the unwanted auth type, which also updates the cache
			_, err = sa.db.authTypes.DeleteOneWithContext(context, bson.M{"code": old}, nil)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAuthType, logutils.StringArgs(old), err)
			}
		}

		//3. migrate credentials
		removedCredentials, err := sa.migrateCredentials(context, removedAuthTypeIDs)
		if err != nil {
			return errors.WrapErrorAction("migrating", model.TypeCredential, nil, err)
		}

		//4. migrate app orgs
		err = sa.migrateAppOrgs(context, removedAuthTypeIDs, removedCredentials)
		if err != nil {
			return errors.WrapErrorAction("migrating", model.TypeApplicationOrganization, nil, err)
		}

		//5. migrate login sessions
		err = sa.migrateLoginSessions(context, removedAuthTypeCodes)
		if err != nil {
			return errors.WrapErrorAction("migrating", model.TypeLoginSession, nil, err)
		}

		return nil
	}

	return sa.PerformTransaction(transaction)
}

func (sa *Adapter) migrateCredentials(context TransactionContext, removedAuthTypes map[string]model.AuthType) ([]string, error) {
	var allCredentials []credential
	err := sa.db.credentials.FindWithContext(context, bson.M{}, &allCredentials, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
	}

	type passwordCreds struct {
		Password string `json:"password"`

		ResetCode   *string    `json:"reset_code,omitempty"`
		ResetExpiry *time.Time `json:"reset_expiry,omitempty"`
	}

	type webauthnCreds struct {
		Credential *string `json:"credential,omitempty"`
		Session    *string `json:"session,omitempty"`
	}

	migratedCredentials := make([]interface{}, 0)
	removedCredentials := make([]string, 0)
	for _, cred := range allCredentials {
		var migrated credential
		if newAuthType, exists := removedAuthTypes[cred.AuthTypeID]; exists && newAuthType.Code == "password" {
			// found a password credential, migrate it
			passwordValue, err := utils.JSONConvert[passwordCreds, map[string]interface{}](cred.Value)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionParse, "password credential value map", &logutils.FieldArgs{"id": cred.ID}, err)
			}
			if passwordValue == nil || passwordValue.Password == "" {
				removedCredentials = append(removedCredentials, cred.ID)
				continue
			}
			if passwordValue.ResetCode != nil && *passwordValue.ResetCode == "" {
				passwordValue.ResetCode = nil
			}
			if passwordValue.ResetExpiry != nil && passwordValue.ResetExpiry.IsZero() {
				passwordValue.ResetExpiry = nil
			}

			passwordValueMap, err := utils.JSONConvert[map[string]interface{}, passwordCreds](*passwordValue)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionParse, "password credential value", &logutils.FieldArgs{"id": cred.ID}, err)
			}
			if passwordValueMap == nil {
				removedCredentials = append(removedCredentials, cred.ID)
				continue
			}

			migrated = credential{ID: cred.ID, AuthTypeID: newAuthType.ID, AccountsAuthTypes: cred.AccountsAuthTypes, Value: *passwordValueMap,
				DateCreated: cred.DateCreated, DateUpdated: cred.DateUpdated}
		} else {
			// found something other than a password credential, try to migrate it as a webauthn credential
			webauthnValue, err := utils.JSONConvert[webauthnCreds, map[string]interface{}](cred.Value)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionParse, "webauthn credential value map", &logutils.FieldArgs{"id": cred.ID}, err)
			}

			// credential value is not for webauthn or it is in a hanging state or is missing its credential
			if webauthnValue == nil || webauthnValue.Session != nil || webauthnValue.Credential == nil {
				removedCredentials = append(removedCredentials, cred.ID)
				continue
			}

			webauthnValueMap, err := utils.JSONConvert[map[string]interface{}, webauthnCreds](*webauthnValue)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionParse, "webauthn credential value", &logutils.FieldArgs{"id": cred.ID}, err)
			}
			if webauthnValueMap == nil {
				removedCredentials = append(removedCredentials, cred.ID)
				continue
			}

			migrated = credential{ID: cred.ID, AuthTypeID: cred.AuthTypeID, AccountsAuthTypes: cred.AccountsAuthTypes, Value: *webauthnValueMap,
				DateCreated: cred.DateCreated, DateUpdated: cred.DateUpdated}
		}

		if migrated.ID != "" {
			migratedCredentials = append(migratedCredentials, migrated)
		} else {
			removedCredentials = append(removedCredentials, cred.ID)
		}
	}

	_, err = sa.db.credentials.DeleteManyWithContext(context, bson.M{}, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionDelete, model.TypeCredential, nil, err)
	}

	_, err = sa.db.credentials.InsertManyWithContext(context, migratedCredentials, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeCredential, nil, err)
	}

	return removedCredentials, nil
}

func (sa *Adapter) migrateAppOrgs(context TransactionContext, removedAuthTypes map[string]model.AuthType, removedCredentials []string) error {
	appOrgs, err := sa.FindApplicationsOrganizations()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, nil, err)
	}

	for _, appOrg := range appOrgs {
		updated := false
		for i, appType := range appOrg.SupportedAuthTypes {
			updatedIDs := make([]string, 0)
			for j, authType := range appType.SupportedAuthTypes {
				if newAuthType, exists := removedAuthTypes[authType.AuthTypeID]; exists {
					if !utils.Contains(updatedIDs, newAuthType.ID) {
						appType.SupportedAuthTypes[j] = model.SupportedAuthType{AuthTypeID: newAuthType.ID}
						updatedIDs = append(updatedIDs, newAuthType.ID)
					} else {
						// remove the obsolete supported auth type if the newID is already included in the list
						appType.SupportedAuthTypes = append(appType.SupportedAuthTypes[:j], appType.SupportedAuthTypes[j+1:]...)
					}
				}
			}

			if len(updatedIDs) > 0 {
				appOrg.SupportedAuthTypes[i] = appType
				updated = true
			}
		}

		if updated {
			err = sa.UpdateApplicationOrganization(context, appOrg)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeApplicationOrganization, &logutils.FieldArgs{"id": appOrg.ID}, err)
			}
		}

		err = sa.migrateAccounts(context, appOrg, removedAuthTypes, removedCredentials)
		if err != nil {
			return errors.WrapErrorAction("migrating", model.TypeAccount, &logutils.FieldArgs{"app_org_id": appOrg.ID}, err)
		}
	}

	return nil
}

func (sa *Adapter) migrateAccounts(context TransactionContext, appOrg model.ApplicationOrganization, removedAuthTypes map[string]model.AuthType, removedCredentials []string) error {
	filter := bson.M{"app_org_id": appOrg.ID}
	var accounts []account

	err := sa.db.accounts.Find(filter, &accounts, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"app_org_id": appOrg.ID}, err)
	}
	if len(accounts) == 0 {
		return nil
	}

	migratedAccounts := make([]interface{}, len(accounts))
	for i, acct := range accounts {
		migrated := acct
		identifiers := make([]accountIdentifier, 0)
		authTypes := make([]accountAuthType, 0)
		addedIdentifiers := make([]string, 0)
		for _, aat := range acct.AuthTypes {
			newAat := aat
			isExternal := (aat.Params["user"] != nil)
			newAuthType, exists := removedAuthTypes[aat.AuthTypeID]
			if aat.Identifier != nil && !isExternal {
				identifier := *aat.Identifier
				identifierCode, _ := strings.CutPrefix(aat.AuthTypeCode, "twilio_")
				if !exists {
					if strings.Contains(identifier, "@") {
						identifierCode = "email"
					} else if strings.Contains(identifier, "+") {
						identifierCode = "phone"
					} else {
						identifierCode = "username"
					}

					if strings.Contains(identifier, "-") {
						identifierParts := strings.Split(identifier, "-")
						identifier = identifierParts[0]
					}
				}

				if !utils.Contains(addedIdentifiers, identifier) {
					verified := true
					if aat.Unverified != nil {
						verified = !*aat.Unverified
					}
					linked := false
					if aat.Linked != nil {
						linked = *aat.Linked
					}

					newIdentifier := accountIdentifier{ID: uuid.NewString(), Code: identifierCode, Identifier: identifier, Verified: verified, Linked: linked,
						Sensitive: identifierCode == "email" || identifierCode == "phone", DateCreated: aat.DateCreated, DateUpdated: aat.DateUpdated}
					identifiers = append(identifiers, newIdentifier)
					addedIdentifiers = append(addedIdentifiers, identifier)
				}
			}

			if exists {
				// update the auth type ID and code if the current auth type was removed
				newAat.AuthTypeID = newAuthType.ID
				newAat.AuthTypeCode = newAuthType.Code
			} else if isExternal {
				// parse the external user from params
				externalUser, err := utils.JSONConvert[model.ExternalSystemUser, interface{}](aat.Params["user"])
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionParse, model.TypeExternalSystemUser, &logutils.FieldArgs{"auth_types.id": aat.ID}, err)
				}
				if externalUser != nil {
					externalAatID := aat.ID
					linked := false
					if aat.Linked != nil {
						linked = *aat.Linked
					}
					var dateUpdated *time.Time
					if aat.DateUpdated != nil {
						dateUpdatedVal := *aat.DateUpdated
						dateUpdated = &dateUpdatedVal
					}

					// add the primary external identifier
					code := ""
					primary := true
					for k, v := range appOrg.IdentityProvidersSettings[0].ExternalIDFields {
						if v == appOrg.IdentityProvidersSettings[0].UserIdentifierField {
							code = k
							break
						}
					}
					primaryIdentifier := accountIdentifier{ID: uuid.NewString(), Code: code, Identifier: externalUser.Identifier, Verified: true, Linked: linked,
						AccountAuthTypeID: &externalAatID, Primary: &primary, DateCreated: aat.DateCreated, DateUpdated: dateUpdated}
					identifiers = append(identifiers, primaryIdentifier)

					// add the other external identifiers from external IDs
					for code, id := range externalUser.ExternalIDs {
						if code != primaryIdentifier.Code {
							primary := false
							newIdentifier := accountIdentifier{ID: uuid.NewString(), Code: code, Identifier: id, Verified: true, Linked: linked,
								AccountAuthTypeID: &externalAatID, Primary: &primary, DateCreated: aat.DateCreated, DateUpdated: dateUpdated}
							identifiers = append(identifiers, newIdentifier)
						}
					}

					// add the external email if there is one
					if externalUser.Email != "" && externalUser.Email != externalUser.Identifier {
						primary := false
						externalEmail := accountIdentifier{ID: uuid.NewString(), Code: "email", Identifier: externalUser.Email, Verified: true, Linked: linked,
							Sensitive: true, Primary: &primary, AccountAuthTypeID: &externalAatID, DateCreated: aat.DateCreated, DateUpdated: dateUpdated}
						identifiers = append(identifiers, externalEmail)
					}
				}
			}

			// do not keep the account auth type if its associated credential was removed
			if newAat.CredentialID != nil && utils.Contains(removedCredentials, *newAat.CredentialID) {
				continue
			}

			newAat.Identifier = nil
			newAat.Unverified = nil
			newAat.Linked = nil
			authTypes = append(authTypes, newAat)
		}

		now := time.Now().UTC()
		// add profile email to identifiers if not already there
		if acct.Profile.Email != nil && *acct.Profile.Email != "" {
			foundEmail := false
			for _, identifier := range identifiers {
				if identifier.Code == "email" && identifier.Identifier == *acct.Profile.Email {
					foundEmail = true
					break
				}
			}
			if !foundEmail {
				emailIdentifier := accountIdentifier{ID: uuid.NewString(), Code: "email", Identifier: *acct.Profile.Email, Sensitive: true, DateCreated: now}
				identifiers = append(identifiers, emailIdentifier)
			}
		}
		// add profile phone to identifiers if not already there
		if acct.Profile.Phone != nil && *acct.Profile.Phone != "" {
			foundPhone := false
			for _, identifier := range identifiers {
				if identifier.Code == "phone" && identifier.Identifier == *acct.Profile.Phone {
					foundPhone = true
					break
				}
			}
			if !foundPhone {
				identifiers = append(identifiers, accountIdentifier{ID: uuid.NewString(), Code: "phone", Identifier: *acct.Profile.Phone, Sensitive: true, DateCreated: now})
			}
		}
		// add account username to identifiers if not already there
		if acct.Username != nil && *acct.Username != "" {
			foundUsername := false
			for _, identifier := range identifiers {
				if identifier.Code == "username" {
					foundUsername = true
					break
				}
			}
			if !foundUsername {
				identifiers = append(identifiers, accountIdentifier{ID: uuid.NewString(), Code: "username", Identifier: *acct.Username, Verified: true, DateCreated: now})
			}
		}

		migrated.AuthTypes = authTypes
		migrated.Identifiers = identifiers
		migrated.ExternalIDs = nil
		migrated.Profile.Email = nil
		migrated.Profile.Phone = nil
		migrated.Username = nil
		migratedAccounts[i] = migrated
	}

	_, err = sa.db.accounts.DeleteManyWithContext(context, filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
	}

	_, err = sa.db.accounts.InsertManyWithContext(context, migratedAccounts, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccount, nil, err)
	}

	return nil
}

func (sa *Adapter) migrateLoginSessions(context TransactionContext, removedAuthTypes map[string]model.AuthType) error {
	// remove the following fields from all login sessions
	update := bson.D{primitive.E{Key: "$unset", Value: bson.D{
		primitive.E{Key: "account_auth_type_id", Value: 1},
		primitive.E{Key: "account_auth_type_identifier", Value: 1},
		primitive.E{Key: "external_ids", Value: 1},
	}}}
	res, err := sa.db.loginsSessions.UpdateManyWithContext(context, bson.M{}, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeLoginSession, nil, err)
	}
	if res.ModifiedCount != res.MatchedCount {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeLoginSession, &logutils.FieldArgs{"matched": res.MatchedCount, "modified": res.ModifiedCount})
	}

	for oldCode, authType := range removedAuthTypes {
		// update the auth_type_code field for all removed auth types
		update := bson.D{
			primitive.E{Key: "$set", Value: bson.D{
				primitive.E{Key: "auth_type_code", Value: authType.Code},
			}},
		}

		res, err := sa.db.loginsSessions.UpdateManyWithContext(context, bson.M{"auth_type_code": oldCode}, update, nil)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeLoginSession, &logutils.FieldArgs{"auth_type_code": oldCode}, err)
		}
		if res.ModifiedCount != res.MatchedCount {
			return errors.ErrorAction(logutils.ActionUpdate, model.TypeLoginSession, &logutils.FieldArgs{"auth_type_code": oldCode, "matched": res.MatchedCount, "modified": res.ModifiedCount})
		}
	}

	return nil
}
