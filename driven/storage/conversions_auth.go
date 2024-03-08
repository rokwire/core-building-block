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

	"github.com/rokwire/core-auth-library-go/v3/authutils"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

// LoginSession
func loginSessionFromStorage(item loginSession, authType model.AuthType, account *model.Account,
	appOrg model.ApplicationOrganization) model.LoginSession {
	id := item.ID

	appType := model.ApplicationType{ID: item.AppTypeID, Identifier: item.AppTypeIdentifier}

	anonymous := item.Anonymous
	identifier := item.Identifier
	externalIDs := item.ExternalIDs
	var accountAuthType *model.AccountAuthType
	if item.AccountAuthTypeID != nil && account != nil {
		accountAuthType = account.GetAccountAuthTypeByID(*item.AccountAuthTypeID)
	}
	var deviceID string
	if item.DeviceID != nil {
		deviceID = *item.DeviceID
	}
	device := &model.Device{ID: deviceID}
	idAddress := item.IPAddress
	accessToken := item.AccessToken
	refreshTokens := item.RefreshTokens
	params := item.Params

	var state string
	if item.State != nil {
		state = *item.State
	}
	stateExpires := item.StateExpires
	var mfaAttempts int
	if item.MfaAttempts != nil {
		mfaAttempts = *item.MfaAttempts
	}

	dateRefreshed := item.DateRefreshed

	dateUpdated := item.DateUpdated
	dateCreated := item.DateCreated

	return model.LoginSession{ID: id, AppOrg: appOrg, AuthType: authType, AppType: appType,
		Anonymous: anonymous, Identifier: identifier, ExternalIDs: externalIDs, AccountAuthType: accountAuthType,
		Device: device, IPAddress: idAddress, AccessToken: accessToken, RefreshTokens: refreshTokens, Params: params,
		State: state, StateExpires: stateExpires, MfaAttempts: mfaAttempts,
		DateRefreshed: dateRefreshed, DateUpdated: dateUpdated, DateCreated: dateCreated}
}

func loginSessionToStorage(item model.LoginSession) *loginSession {
	id := item.ID

	appID := item.AppOrg.Application.ID
	orgID := item.AppOrg.Organization.ID

	authTypeCode := item.AuthType.Code

	appTypeID := item.AppType.ID
	appTypeIdentifier := item.AppType.Identifier

	anonymous := item.Anonymous
	identifier := item.Identifier
	externalIDs := item.ExternalIDs
	var accountAuthTypeID *string
	var accountAuthTypeIdentifier *string
	if item.AccountAuthType != nil && len(item.AccountAuthType.ID) != 0 {
		accountAuthTypeID = &item.AccountAuthType.ID
		accountAuthTypeIdentifier = &item.AccountAuthType.Identifier
	}
	var deviceID *string
	if item.Device != nil {
		deviceID = &item.Device.ID
	}
	ipAddress := item.IPAddress
	accessToken := item.AccessToken
	refreshTokens := item.RefreshTokens
	params := item.Params

	var state *string
	if item.State != "" {
		state = &item.State
	}
	stateExpires := item.StateExpires
	var mfaAttempts *int
	if item.MfaAttempts != 0 {
		mfaAttempts = &item.MfaAttempts
	}

	dateRefreshed := item.DateRefreshed

	dateUpdated := item.DateUpdated
	dateCreated := item.DateCreated

	return &loginSession{ID: id, AppID: appID, OrgID: orgID, AuthTypeCode: authTypeCode,
		AppTypeID: appTypeID, AppTypeIdentifier: appTypeIdentifier, Anonymous: anonymous,
		Identifier: identifier, ExternalIDs: externalIDs, AccountAuthTypeID: accountAuthTypeID, AccountAuthTypeIdentifier: accountAuthTypeIdentifier,
		DeviceID: deviceID, IPAddress: ipAddress, AccessToken: accessToken, RefreshTokens: refreshTokens,
		Params: params, State: state, StateExpires: stateExpires, MfaAttempts: mfaAttempts,
		DateRefreshed: dateRefreshed, DateUpdated: dateUpdated, DateCreated: dateCreated}
}

// ServiceAccount
func serviceAccountFromStorage(item serviceAccount, sa *Adapter) (*model.ServiceAccount, error) {
	var err error
	var application *model.Application
	if item.AppID != authutils.AllApps {
		application, err = sa.getCachedApplication(item.AppID)
		if err != nil || application == nil {
			return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplication, &logutils.FieldArgs{"app_id": item.AppID}, err)
		}
	}
	var organization *model.Organization
	if item.OrgID != authutils.AllOrgs {
		organization, err = sa.getCachedOrganization(item.OrgID)
		if err != nil || organization == nil {
			return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeOrganization, &logutils.FieldArgs{"org_id": item.OrgID}, err)
		}
	}

	return &model.ServiceAccount{AccountID: item.AccountID, Name: item.Name, Application: application, Organization: organization, Permissions: item.Permissions,
		Scopes: item.Scopes, FirstParty: item.FirstParty, Credentials: item.Credentials, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}, nil
}

func serviceAccountListFromStorage(items []serviceAccount, sa *Adapter) []model.ServiceAccount {
	accountList := make([]model.ServiceAccount, len(items))

	for i, account := range items {
		modelAccount, err := serviceAccountFromStorage(account, sa)
		if err != nil {
			sa.logger.Warn(err.Error())
		}
		accountList[i] = *modelAccount
	}
	return accountList
}

func serviceAccountToStorage(item model.ServiceAccount) *serviceAccount {
	appID := authutils.AllApps
	if item.Application != nil {
		appID = item.Application.ID
	}
	orgID := authutils.AllOrgs
	if item.Organization != nil {
		orgID = item.Organization.ID
	}

	return &serviceAccount{AccountID: item.AccountID, Name: item.Name, AppID: appID, OrgID: orgID, Permissions: item.Permissions, Scopes: item.Scopes,
		FirstParty: item.FirstParty, Credentials: item.Credentials, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}
