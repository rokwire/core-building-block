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
	if len(allCredentials) == 0 {
		return nil, nil
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

	orgIDs := make(map[string]model.IdentityProviderSetting)
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
						if len(appType.SupportedAuthTypes) > j {
							appType.SupportedAuthTypes = append(appType.SupportedAuthTypes[:j], appType.SupportedAuthTypes[j+1:]...)
						} else {
							appType.SupportedAuthTypes = appType.SupportedAuthTypes[:j]
						}
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

		if _, exists := orgIDs[appOrg.Organization.ID]; !exists {
			if len(appOrg.IdentityProvidersSettings) > 0 {
				orgIDs[appOrg.Organization.ID] = appOrg.IdentityProvidersSettings[0] // use the first identity provider setting for all apps in this organization
			} else {
				orgIDs[appOrg.Organization.ID] = model.IdentityProviderSetting{}
			}
		}
	}

	for orgID, identityProviderSettings := range orgIDs {
		err = sa.migrateAccounts(context, orgID, identityProviderSettings, removedAuthTypes, removedCredentials)
		if err != nil {
			return errors.WrapErrorAction("migrating", model.TypeAccount, &logutils.FieldArgs{"org_id": orgID}, err)
		}
	}

	return nil
}

func (sa *Adapter) migrateAccounts(context TransactionContext, orgID string, identityProviderSettings model.IdentityProviderSetting, removedAuthTypes map[string]model.AuthType, removedCredentials []string) error {
	filter := bson.M{"org_id": orgID}
	var accounts []tenantAccount

	err := sa.db.tenantsAccounts.Find(filter, &accounts, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"org_id": orgID}, err)
	}
	if len(accounts) == 0 {
		return nil
	}

	migratedAccounts := []interface{}{}
	for _, acct := range accounts {
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
					for k, v := range identityProviderSettings.ExternalIDFields {
						if v == identityProviderSettings.UserIdentifierField {
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

		// if there are no valid auth types then the account is inaccessible, so do not re-insert it
		if len(authTypes) == 0 {
			continue
		}

		now := time.Now().UTC()
		// add profile email to identifiers if valid and not already there
		if acct.Profile.Email != nil && utils.IsValidEmail(*acct.Profile.Email) {
			foundEmail := false
			for _, identifier := range identifiers {
				if identifier.Code == "email" && identifier.Identifier == *acct.Profile.Email {
					foundEmail = true
					break
				}
			}
			if !foundEmail {
				identifiers = append(identifiers, accountIdentifier{ID: uuid.NewString(), Code: "email", Identifier: *acct.Profile.Email, Sensitive: true, DateCreated: now})
			}
		}
		// add profile phone to identifiers if valid and not already there
		if acct.Profile.Phone != nil && utils.IsValidPhone(*acct.Profile.Phone) {
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
		migratedAccounts = append(migratedAccounts, migrated)
	}

	_, err = sa.db.tenantsAccounts.DeleteManyWithContext(context, filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
	}

	if len(migratedAccounts) > 0 {
		_, err = sa.db.tenantsAccounts.InsertManyWithContext(context, migratedAccounts, nil)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccount, nil, err)
		}
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

// migrate to tenants accounts
func (sa *Adapter) migrateToTenantsAccounts() error {
	sa.logger.Debug("migrateToTenantsAccounts START")

	err := sa.startPhase1()
	if err != nil {
		return err
	}

	sa.logger.Debug("migrateToTenantsAccounts END")
	return nil
}

func (sa *Adapter) startPhase1() error {
	sa.logger.Debug("startPhase1 START")

	//all in transaction!
	transaction := func(context TransactionContext) error {

		//check if need to apply processing
		notMigratedCount, err := sa.findNotMigratedCount(context)
		if err != nil {
			return err
		}
		if *notMigratedCount == 0 {
			sa.logger.Debug("there is no what to be migrated, so do nothing")
			return nil
		}

		//WE MUST APPLY MIGRATION
		sa.logger.Debugf("there are %d accounts to be migrated", *notMigratedCount)

		//process duplicate events
		err = sa.processDuplicateAccounts(context)
		if err != nil {
			return err
		}

		return nil
	}

	err := sa.PerformTransaction(transaction)
	if err != nil {
		return err
	}

	sa.logger.Debug("startPhase1 END")
	return nil
}

func (sa *Adapter) findNotMigratedCount(context TransactionContext) (*int64, error) {
	filter := bson.M{"migrated": bson.M{"$in": []interface{}{nil, false}}}
	count, err := sa.db.accounts.CountDocumentsWithContext(context, filter)
	if err != nil {
		return nil, err
	}
	return &count, nil
}

func (sa *Adapter) processDuplicateAccounts(context TransactionContext) error {

	//find the duplicate accounts
	items, err := sa.findDuplicateAccounts(context)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		sa.logger.Info("there is no duplicated accounts")
		return nil
	}

	//construct tenants accounts
	tenantsAccounts, err := sa.constructTenantsAccounts(items)
	if err != nil {
		return err
	}

	//save tenants accounts
	err = sa.insertTenantAccounts(context, tenantsAccounts)
	if err != nil {
		return err
	}

	//mark the old accounts as processed
	accountsIDs := sa.getUniqueAccountsIDs(items)
	err = sa.markAccountsAsProcessed(context, accountsIDs)
	if err != nil {
		return err
	}

	return nil
}

func (sa *Adapter) getUniqueAccountsIDs(items map[string][]account) []string {
	var result []string

	for _, accounts := range items {
		for _, acc := range accounts {
			if !utils.Contains(result, acc.ID) {
				result = append(result, acc.ID)
			}
		}
	}

	return result
}

func (sa *Adapter) markAccountsAsProcessed(context TransactionContext, accountsIDs []string) error {
	filter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": accountsIDs}}}

	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "migrated", Value: true},
		}},
	}

	_, err := sa.db.accounts.UpdateManyWithContext(context, filter, update, nil)
	if err != nil {
		return err
	}

	return nil
}

func (sa *Adapter) insertTenantAccounts(context TransactionContext, items []tenantAccount) error {

	stgItems := make([]interface{}, len(items))
	for i, p := range items {
		stgItems[i] = p
	}

	res, err := sa.db.tenantsAccounts.InsertManyWithContext(context, stgItems, nil)
	if err != nil {
		return err
	}

	if len(res.InsertedIDs) != len(items) {
		return errors.Newf("inserted:%d items:%d", len(res.InsertedIDs), len(items))
	}

	return nil
}

func (sa *Adapter) constructTenantsAccounts(duplicateAccounts map[string][]account) ([]tenantAccount, error) {
	//we need to load the apps orgs object from the database as we will need them
	allAppsOrgs, err := sa.getCachedApplicationOrganizations()
	if err != nil {
		return nil, err
	}

	//segment by org
	data := map[string][]orgAccounts{}
	for identifier, accounts := range duplicateAccounts {
		orgAccounts, err := sa.segmentByOrgID(allAppsOrgs, accounts)
		if err != nil {
			return nil, err
		}

		data[identifier] = orgAccounts
	}

	//use orgAccounts for easier manipulating
	orgIDsAccounts := sa.simplifyStructureData(data)

	res := []tenantAccount{}
	for _, item := range orgIDsAccounts {
		orgItems, err := sa.constructTenantsAccountsForOrg(item.OrgID, item.Accounts)
		if err != nil {
			return nil, err
		}
		res = append(res, orgItems...)
	}

	return res, nil
}

func (sa *Adapter) constructTenantsAccountsForOrg(orgID string, accounts []account) ([]tenantAccount, error) {
	//verify that there are no repeated identities across org applications
	notExist := sa.verifyNotExist(accounts)
	if !notExist {
		return nil, errors.Newf("%s has repeated items")
	}

	//process them
	resAccounts := []tenantAccount{}
	for _, account := range accounts {
		newTenantAccount := sa.createTenantAccount(orgID, account)
		resAccounts = append(resAccounts, newTenantAccount)
	}

	return resAccounts, nil
}

func (sa *Adapter) verifyNotExist(accounts []account) bool {
	for _, acc := range accounts {
		for _, acc2 := range accounts {
			if acc.ID == acc2.ID {
				continue //skip
			}

			if sa.containsIdentifier(acc.Identifiers, acc2.Identifiers) {
				// sa.logger.ErrorWithFields("duplicate identifier", logutils.Fields{"account1_id": acc.ID, "account2_id": acc2.ID})
				return false
			}
		}
	}
	return true
}

func (sa *Adapter) containsIdentifier(identifiers1 []accountIdentifier, identifiers2 []accountIdentifier) bool {
	for _, id := range identifiers1 {
		for _, id2 := range identifiers2 {
			if id.Identifier == id2.Identifier {
				// sa.logger.ErrorWithFields("duplicate identifier", logutils.Fields{"identifier1": id.Identifier, "identifier2": id2.Identifier})
				return true
			}
		}
	}
	return false
}

func (sa *Adapter) createTenantAccount(orgID string, account account) tenantAccount {

	id := account.ID
	scopes := account.Scopes
	identifiers := account.Identifiers
	authTypes := account.AuthTypes
	mfaTypes := account.MFATypes
	systemConfigs := account.SystemConfigs
	profile := account.Profile
	devices := account.Devices
	anonymous := account.Anonymous
	privacy := account.Privacy

	var verified *bool //not used?
	if account.Verified {
		verified = &account.Verified
	}

	dateCreated := account.DateCreated
	dateUpdated := account.DateUpdated
	isFollowing := account.IsFollowing
	lastLoginDate := account.LastLoginDate
	lastAccessTokenDate := account.LastAccessTokenDate

	//create org apps membership
	oaID := uuid.NewString()
	oaAppOrgID := account.AppOrgID
	oaPermissions := account.Permissions
	oaRoles := account.Roles
	oaGroups := account.Groups
	oaSecrets := account.Secrets
	oaPreferences := account.Preferences
	oaMostRecentClientVersion := account.MostRecentClientVersion

	orgAppsMemberships := []orgAppMembership{{ID: oaID, AppOrgID: oaAppOrgID,
		Permissions: oaPermissions, Roles: oaRoles, Groups: oaGroups, Secrets: oaSecrets,
		Preferences: oaPreferences, MostRecentClientVersion: oaMostRecentClientVersion}}

	return tenantAccount{ID: id, OrgID: orgID, OrgAppsMemberships: orgAppsMemberships, Scopes: scopes,
		Identifiers: identifiers, AuthTypes: authTypes, MFATypes: mfaTypes,
		SystemConfigs: systemConfigs, Profile: profile, Devices: devices, Anonymous: anonymous,
		Privacy: privacy, Verified: verified, DateCreated: dateCreated, DateUpdated: dateUpdated,
		IsFollowing: isFollowing, LastLoginDate: lastLoginDate, LastAccessTokenDate: lastAccessTokenDate}
}

func (sa *Adapter) simplifyStructureData(data map[string][]orgAccounts) []orgAccounts {
	temp := map[string][]account{}
	seen := []string{}
	for _, dataItem := range data {
		for _, orgAccounts := range dataItem {
			orgID := orgAccounts.OrgID
			orgAllAccounts := temp[orgID]

			for _, acc := range orgAccounts.Accounts {
				if !utils.Contains(seen, acc.ID) { // Check if already added
					seen = append(seen, acc.ID)
					orgAllAccounts = append(orgAllAccounts, acc)
				}
			}

			temp[orgID] = orgAllAccounts
		}
	}

	//prepare response
	res := []orgAccounts{}
	for orgID, tempItem := range temp {
		res = append(res, orgAccounts{OrgID: orgID, Accounts: tempItem})
	}
	return res
}

type orgAccounts struct {
	OrgID    string
	Accounts []account
}

func (sa *Adapter) segmentByOrgID(allAppsOrgs []model.ApplicationOrganization, accounts []account) ([]orgAccounts, error) {
	tempMap := map[string][]account{}
	for _, account := range accounts {
		currentOrgID, err := sa.findOrgIDByAppOrgID(account.AppOrgID, allAppsOrgs)
		if err != nil {
			return nil, err
		}

		orgAccountsMap := tempMap[currentOrgID]
		orgAccountsMap = append(orgAccountsMap, account)
		tempMap[currentOrgID] = orgAccountsMap

	}

	result := []orgAccounts{}
	for orgID, accounts := range tempMap {
		current := orgAccounts{OrgID: orgID, Accounts: accounts}
		result = append(result, current)
	}

	return result, nil
}

func (sa *Adapter) findOrgIDByAppOrgID(appOrgID string, allAppsOrgs []model.ApplicationOrganization) (string, error) {
	for _, item := range allAppsOrgs {
		if item.ID == appOrgID {
			return item.Organization.ID, nil
		}
	}
	return "", errors.Newf("no org for app org id - %s", appOrgID)
}

func (sa *Adapter) findDuplicateAccounts(context TransactionContext) (map[string][]account, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{"migrated": bson.M{"$in": []interface{}{nil, false}}}, //iterate only not migrated records
		},
		{
			"$unwind": "$identifiers",
		},
		{
			"$group": bson.M{
				"_id": "$identifiers.identifier",
				"accounts": bson.M{
					"$push": bson.M{
						"id": "$_id",
					},
				},
				"count": bson.M{
					"$sum": 1,
				},
			},
		},
		// {
		// 	"$match": bson.M{
		// 		"count": bson.M{
		// 			"$gt": 1,
		// 		},
		// 	},
		// },
		{
			"$group": bson.M{
				"_id": nil,
				"result": bson.M{
					"$push": bson.M{
						"k": "$_id",
						"v": bson.M{
							"accounts": "$accounts",
						},
					},
				},
			},
		},
		{
			"$replaceRoot": bson.M{
				"newRoot": bson.M{
					"$arrayToObject": "$result",
				},
			},
		},
	}

	cursor, err := sa.db.accounts.coll.Aggregate(context, pipeline)
	if err != nil {
		return nil, err
	}

	var result bson.M
	if cursor.Next(context) {
		err := cursor.Decode(&result)
		if err != nil {
			return nil, err
		}
	}

	if len(result) == 0 {

		return nil, nil
	}

	var resTypeResult []identityAccountsItem

	for key, value := range result {
		valueM := value.(primitive.M)
		accountsArr := valueM["accounts"].(primitive.A)

		var accounts []accountItem

		for _, element := range accountsArr {
			accountObj := element.(primitive.M)

			var account accountItem
			account.ID = accountObj["id"].(string)

			accounts = append(accounts, account)
		}

		item := identityAccountsItem{
			Identifier: key,
			Accounts:   accounts,
		}

		resTypeResult = append(resTypeResult, item)
	}

	//prepare founded duplicate accounts
	preparedResponse, err := sa.prepareFoundedDuplicateAccounts(context, resTypeResult)
	if err != nil {
		return nil, err
	}

	return preparedResponse, nil
}

type accountItem struct {
	ID string `bson:"id"`
}
type identityAccountsItem struct {
	Identifier string        `bson:"id"`
	Accounts   []accountItem `bson:"accounts"`
}

func (sa *Adapter) prepareFoundedDuplicateAccounts(context TransactionContext, foundedItems []identityAccountsItem) (map[string][]account, error) {

	if len(foundedItems) == 0 {
		return nil, nil
	}

	//load all accounts
	accountsIDs := []string{}
	for _, item := range foundedItems {
		accounts := item.Accounts
		for _, acc := range accounts {
			accountsIDs = append(accountsIDs, acc.ID)
		}
	}
	findFilter := bson.M{"_id": bson.M{"$in": accountsIDs}}
	var accounts []account
	err := sa.db.accounts.FindWithContext(context, findFilter, &accounts, nil)
	if err != nil {
		return nil, err
	}

	//prepare result
	result := map[string][]account{}
	for _, item := range foundedItems {
		identifier := item.Identifier
		accountsIDs := item.Accounts

		resAccounts, err := sa.getFullAccountsObjects(accountsIDs, accounts)
		if err != nil {
			return nil, err
		}
		result[identifier] = resAccounts
	}

	return result, nil
}

func (sa *Adapter) getFullAccountsObjects(accountsIDs []accountItem, allAccounts []account) ([]account, error) {
	result := []account{}
	for _, item := range accountsIDs {
		//find the full account object
		var resAccount *account
		for _, acc := range allAccounts {
			if item.ID == acc.ID {
				resAccount = &acc
				break
			}
		}

		if resAccount == nil {
			return nil, errors.Newf("cannot find full account for %s", item.ID)
		}
		result = append(result, *resAccount)
	}

	return result, nil
}
