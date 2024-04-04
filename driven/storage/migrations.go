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
	"context"
	"core-building-block/core/model"
	"core-building-block/utils"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	migrationBatchSize int = 5000
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
		removedAuthTypeIDsMap := make(map[string]model.AuthType)
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

			removedAuthTypeIDsMap[authTypes[0].ID] = new

			// remove the unwanted auth type, which also updates the cache
			_, err = sa.db.authTypes.DeleteOneWithContext(context, bson.M{"code": old}, nil)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAuthType, logutils.StringArgs(old), err)
			}
		}

		//3. migrate credentials in batches
		removedCredentialIDs := make([]string, 0)
		batch := 0
		for {
			removedPermanentlyIDsBatch, err := sa.migrateCredentials(context, batch, removedAuthTypeIDsMap)
			if err != nil {
				return errors.WrapErrorAction("migrating", model.TypeCredential, nil, err)
			}
			if removedPermanentlyIDsBatch == nil {
				break
			}

			for _, id := range removedPermanentlyIDsBatch {
				removedPermanentlyIDsBatch = append(removedPermanentlyIDsBatch, id)
			}
			batch++
		}

		//4. migrate app orgs
		err := sa.migrateAppOrgs(context, removedAuthTypeIDsMap, removedCredentialIDs)
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

	return sa.performTransactionWithTimeout(transaction, 10*time.Minute)
}

func (sa *Adapter) migrateCredentials(context TransactionContext, batch int, removedAuthTypes map[string]model.AuthType) ([]string, error) {
	findOptions := options.Find()
	findOptions.SetLimit(int64(migrationBatchSize))
	findOptions.SetSkip(int64(batch * migrationBatchSize))

	var credentialsBatch []credential
	err := sa.db.credentials.FindWithContext(context, bson.M{}, &credentialsBatch, findOptions)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
	}
	if len(credentialsBatch) == 0 {
		return nil, nil
	}

	type passwordCreds struct {
		Password string `json:"password"`

		ResetCode   *string    `json:"reset_code,omitempty"`
		ResetExpiry *time.Time `json:"reset_expiry,omitempty"`
	}

	credentialsBatchIDs := make([]string, 0)
	migratedCredentials := make([]interface{}, 0)
	removePermanentlyIDs := make([]string, 0)
	for _, cred := range credentialsBatch {
		credentialsBatchIDs = append(credentialsBatchIDs, cred.ID)

		var migrated credential
		if newAuthType, exists := removedAuthTypes[cred.AuthTypeID]; exists && newAuthType.Code == "password" {
			// found a password credential, migrate it
			passwordValue, err := utils.JSONConvert[passwordCreds](cred.Value)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionParse, "password credential value map", &logutils.FieldArgs{"id": cred.ID}, err)
			}
			if passwordValue == nil || passwordValue.Password == "" {
				removePermanentlyIDs = append(removePermanentlyIDs, cred.ID)
				continue
			}
			if passwordValue.ResetCode != nil && *passwordValue.ResetCode == "" {
				passwordValue.ResetCode = nil
			}
			if passwordValue.ResetExpiry != nil && passwordValue.ResetExpiry.IsZero() {
				passwordValue.ResetExpiry = nil
			}

			passwordValueMap, err := utils.JSONConvert[map[string]interface{}](*passwordValue)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionParse, "password credential value", &logutils.FieldArgs{"id": cred.ID}, err)
			}
			if passwordValueMap == nil {
				removePermanentlyIDs = append(removePermanentlyIDs, cred.ID)
				continue
			}

			migrated = credential{ID: cred.ID, AuthTypeID: newAuthType.ID, AccountsAuthTypes: cred.AccountsAuthTypes, Value: *passwordValueMap,
				DateCreated: cred.DateCreated, DateUpdated: cred.DateUpdated}
		}

		if migrated.ID != "" {
			migratedCredentials = append(migratedCredentials, migrated)
		} else {
			removePermanentlyIDs = append(removePermanentlyIDs, cred.ID)
		}
	}

	// delete all the credentials that have been processed
	_, err = sa.db.credentials.DeleteManyWithContext(context, bson.M{"_id": bson.M{"$in": credentialsBatchIDs}}, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionDelete, model.TypeCredential, nil, err)
	}

	// re-insert the credentials we want to keep
	_, err = sa.db.credentials.InsertManyWithContext(context, migratedCredentials, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeCredential, nil, err)
	}

	return removePermanentlyIDs, nil
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

		if orgSettings := orgIDs[appOrg.Organization.ID]; orgSettings.IdentityProviderID == "" {
			for _, settings := range appOrg.IdentityProvidersSettings {
				if len(settings.ExternalIDFields) > 0 && settings.UserIdentifierField != "" {
					orgIDs[appOrg.Organization.ID] = settings // use the first identity provider setting with specified ExternalIDFields and UserIdentifierField for all apps in this organization
					break
				}
			}
			if _, exists := orgIDs[appOrg.Organization.ID]; !exists {
				orgIDs[appOrg.Organization.ID] = model.IdentityProviderSetting{}
			}
		}
	}

	for orgID, identityProviderSettings := range orgIDs {
		batch := 0
		for {
			accountsBatchSize, err := sa.migrateAccounts(context, batch, orgID, identityProviderSettings, removedAuthTypes, removedCredentials)
			if err != nil {
				return errors.WrapErrorAction("migrating", model.TypeAccount, &logutils.FieldArgs{"org_id": orgID}, err)
			}
			if accountsBatchSize != nil && *accountsBatchSize == 0 {
				break
			}

			batch++
		}
	}

	return nil
}

func (sa *Adapter) migrateAccounts(context TransactionContext, batch int, orgID string, identityProviderSettings model.IdentityProviderSetting, removedAuthTypes map[string]model.AuthType, removedCredentials []string) (*int, error) {
	findOptions := options.Find()
	findOptions.SetLimit(int64(migrationBatchSize))
	findOptions.SetSkip(int64(batch * migrationBatchSize))

	var accountsBatch []tenantAccount
	err := sa.db.tenantsAccounts.Find(bson.M{"org_id": orgID}, &accountsBatch, findOptions)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"org_id": orgID}, err)
	}

	numAccounts := len(accountsBatch)
	if numAccounts == 0 {
		return &numAccounts, nil
	}

	accountsBatchIDs := make([]string, len(accountsBatch))
	migratedAccounts := []interface{}{}
	for i, acct := range accountsBatch {
		accountsBatchIDs[i] = acct.ID
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
				externalUser, err := utils.JSONConvert[model.ExternalSystemUser](aat.Params["user"])
				if err != nil {
					return nil, errors.WrapErrorAction(logutils.ActionParse, model.TypeExternalSystemUser, &logutils.FieldArgs{"auth_types.id": aat.ID}, err)
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
					primaryIdentifierCode := ""
					primary := true
					for k, v := range identityProviderSettings.ExternalIDFields {
						if v == identityProviderSettings.UserIdentifierField {
							primaryIdentifierCode = k
							break
						}
					}
					if primaryIdentifierCode != "" {
						primaryIdentifier := accountIdentifier{ID: uuid.NewString(), Code: primaryIdentifierCode, Identifier: externalUser.Identifier, Verified: true, Linked: linked,
							AccountAuthTypeID: &externalAatID, Primary: &primary, DateCreated: aat.DateCreated, DateUpdated: dateUpdated}
						identifiers = append(identifiers, primaryIdentifier)
					}

					// add the other external identifiers from external IDs
					for code, id := range externalUser.ExternalIDs {
						if code != primaryIdentifierCode {
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

		// if there are no valid auth types or identifiers then the account is inaccessible, so do not re-insert it
		if len(authTypes) == 0 || len(identifiers) == 0 {
			continue
		}

		now := time.Now().UTC()
		// add profile email to identifiers if valid and not already there
		if acct.Profile.Email != nil && utils.IsValidEmail(*acct.Profile.Email) {
			foundEmail := false
			for i, identifier := range identifiers {
				if identifier.Code == "email" && identifier.Identifier == *acct.Profile.Email {
					foundEmail = true
					identifiers[i].UseForProfile = true
					break
				}
			}
			if !foundEmail {
				identifiers = append(identifiers, accountIdentifier{ID: uuid.NewString(), Code: "email", Identifier: *acct.Profile.Email, Sensitive: true, UseForProfile: true, DateCreated: now})
			}
		} else {
			for i, identifier := range identifiers {
				if identifier.Code == "email" {
					identifiers[i].UseForProfile = true // if no profile email already, use the first email identifier for the profile
					break
				}
			}
		}

		// add profile phone to identifiers if valid and not already there
		if acct.Profile.Phone != nil && utils.IsValidPhone(*acct.Profile.Phone) {
			foundPhone := false
			for i, identifier := range identifiers {
				if identifier.Code == "phone" && identifier.Identifier == *acct.Profile.Phone {
					foundPhone = true
					identifiers[i].UseForProfile = true
					break
				}
			}
			if !foundPhone {
				identifiers = append(identifiers, accountIdentifier{ID: uuid.NewString(), Code: "phone", Identifier: *acct.Profile.Phone, Sensitive: true, UseForProfile: true, DateCreated: now})
			}
		} else {
			for i, identifier := range identifiers {
				if identifier.Code == "phone" {
					identifiers[i].UseForProfile = true // if no profile phone already, use the first phone identifier for the profile
					break
				}
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
				identifiers = append(identifiers, accountIdentifier{ID: uuid.NewString(), Code: "username", Identifier: strings.TrimSpace(strings.ToLower(*acct.Username)), Verified: true, DateCreated: now})
			}
		}

		migrated.OrgAppsMemberships = sa.mergeDuplicateAppMemberships(migrated) // merge multiple orgAppMemberships with the same app_org_id if any are found
		migrated.AuthTypes = authTypes
		migrated.Identifiers = identifiers
		migrated.ExternalIDs = nil
		migrated.Profile.Email = nil
		migrated.Profile.Phone = nil
		migrated.Username = nil
		migratedAccounts = append(migratedAccounts, migrated)
	}

	_, err = sa.db.tenantsAccounts.DeleteManyWithContext(context, bson.M{"_id": bson.M{"$in": accountsBatchIDs}, "org_id": orgID}, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
	}

	if len(migratedAccounts) > 0 {
		_, err = sa.db.tenantsAccounts.InsertManyWithContext(context, migratedAccounts, nil)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccount, nil, err)
		}
	}

	return &numAccounts, nil
}

func (sa *Adapter) mergeDuplicateAppMemberships(account tenantAccount) []orgAppMembership {
	appMembershipIDs := make(map[string]int)
	appMemberships := make([]orgAppMembership, 0)
	for _, appMembership := range account.OrgAppsMemberships {
		if _, foundID := appMembershipIDs[appMembership.AppOrgID]; !foundID {
			appMembershipIDs[appMembership.AppOrgID] = len(appMemberships) // appMembershipIDs map value gives the index in updatedMemberships where all memberships with this app_org_id should be merged
			appMemberships = append(appMemberships, appMembership)
		} else {
			index := appMembershipIDs[appMembership.AppOrgID]
			// merge permissions
			for _, permission := range appMembership.Permissions {
				permissionExists := false
				for _, existingPermission := range appMemberships[index].Permissions {
					if existingPermission.ID == permission.ID {
						permissionExists = true
						break
					}
				}

				if !permissionExists {
					if appMemberships[index].Permissions == nil {
						appMemberships[index].Permissions = make([]model.Permission, 0)
					}
					appMemberships[index].Permissions = append(appMemberships[index].Permissions, permission)
				}
			}
			// merge roles
			for _, role := range appMembership.Roles {
				roleExists := false
				for _, existingRole := range appMemberships[index].Roles {
					if existingRole.Role.ID == role.Role.ID {
						roleExists = true
						break
					}
				}

				if !roleExists {
					if appMemberships[index].Roles == nil {
						appMemberships[index].Roles = make([]accountRole, 0)
					}
					appMemberships[index].Roles = append(appMemberships[index].Roles, role)
				}
			}
			// merge groups
			for _, group := range appMembership.Groups {
				groupExists := false
				for _, existingGroup := range appMemberships[index].Groups {
					if existingGroup.Group.ID == group.Group.ID {
						groupExists = true
						break
					}
				}

				if !groupExists {
					if appMemberships[index].Groups == nil {
						appMemberships[index].Groups = make([]accountGroup, 0)
					}
					appMemberships[index].Groups = append(appMemberships[index].Groups, group)
				}
			}

			// merge preferences
			for k, v := range appMembership.Preferences {
				if _, foundKey := appMemberships[index].Preferences[k]; !foundKey {
					appMemberships[index].Preferences[k] = v
				}
			}
			// tenant accounts existing before this migration have no stored secrets (nothing to merge)

			// use the newer of the two most recent client versions
			if appMemberships[index].MostRecentClientVersion == nil {
				appMemberships[index].MostRecentClientVersion = appMembership.MostRecentClientVersion
			} else if appMembership.MostRecentClientVersion != nil {
				existingClientVersionNumbers := model.VersionNumbersFromString(*appMemberships[index].MostRecentClientVersion)
				clientVersionNumbers := model.VersionNumbersFromString(*appMembership.MostRecentClientVersion)

				if clientVersionNumbers != nil && !clientVersionNumbers.LessThanOrEqualTo(existingClientVersionNumbers) {
					versionString := clientVersionNumbers.String()
					appMemberships[index].MostRecentClientVersion = &versionString
				}
			}
		}
	}

	return appMemberships
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

func (sa *Adapter) performTransactionWithTimeout(transaction func(context TransactionContext) error, timeout time.Duration) error {
	// Setting a timeout for the transaction
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// transaction
	err := sa.db.dbClient.UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionStart, logutils.TypeTransaction, nil, err)
		}

		err = transaction(sessionContext)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction("performing", logutils.TypeTransaction, nil, err)
		}

		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionCommit, logutils.TypeTransaction, nil, err)
		}
		return nil
	})

	return err
}
