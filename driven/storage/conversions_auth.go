package storage

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

//LoginSession
func loginSessionFromStorage(item loginSession, authType model.AuthType, account *model.Account,
	appOrg model.ApplicationOrganization) model.LoginSession {
	id := item.ID

	appType := model.ApplicationType{ID: item.AppTypeID, Identifier: item.AppTypeIdentifier}

	anonymous := item.Anonymous
	identifier := item.Identifier
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
		Anonymous: anonymous, Identifier: identifier, AccountAuthType: accountAuthType,
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
	var accountAuthTypeID *string
	var accountAuthTypeIdentifier *string
	if item.AccountAuthType != nil {
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
		Identifier: identifier, AccountAuthTypeID: accountAuthTypeID, AccountAuthTypeIdentifier: accountAuthTypeIdentifier,
		DeviceID: deviceID, IPAddress: ipAddress, AccessToken: accessToken, RefreshTokens: refreshTokens,
		Params: params, State: state, StateExpires: stateExpires, MfaAttempts: mfaAttempts,
		DateRefreshed: dateRefreshed, DateUpdated: dateUpdated, DateCreated: dateCreated}
}

//ServiceAccount
func serviceAccountFromStorage(item serviceAccount, sa *Adapter) (*model.ServiceAccount, error) {
	var err error
	var application *model.Application
	if item.AppID != nil {
		application, err = sa.getCachedApplication(*item.AppID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, &logutils.FieldArgs{"app_id": *item.AppID}, err)
		}
	}
	var organization *model.Organization
	if item.OrgID != nil {
		organization, err = sa.getCachedOrganization(*item.OrgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, &logutils.FieldArgs{"org_id": *item.OrgID}, err)
		}
	}

	roles := make([]model.AccountRole, len(item.Roles))
	for i, role := range item.Roles {
		appOrg, err := sa.getCachedApplicationOrganizationByKey(role.Role.AppOrgID)
		if err != nil || appOrg == nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_org_id": role.Role.AppOrgID}, err)
		}
		roles[i] = accountRoleFromStorage(&role, *appOrg)
	}

	return &model.ServiceAccount{ID: item.ID, Name: item.Name, Application: application, Organization: organization, Permissions: item.Permissions,
		Roles: roles, Credentials: item.Credentials, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}, nil
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
	roles := accountRolesToStorage(item.Roles)

	var appID *string
	if item.Application != nil {
		appID = &item.Application.ID
	}
	var orgID *string
	if item.Organization != nil {
		orgID = &item.Organization.ID
	}

	return &serviceAccount{ID: item.ID, Name: item.Name, AppID: appID, OrgID: orgID, Permissions: item.Permissions, Roles: roles,
		Credentials: item.Credentials, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}
