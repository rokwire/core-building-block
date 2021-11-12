package storage

import "core-building-block/core/model"

//LoginSession
func loginSessionFromStorage(item loginSession, authType model.AuthType, account *model.Account,
	appOrg model.ApplicationOrganization) model.LoginSession {
	id := item.ID

	appType := model.ApplicationType{ID: item.AppTypeID, Identifier: item.AppTypeIdentifier}

	anonymous := item.Anonymous
	identifier := item.Identifier
	var accountAuthType *model.AccountAuthType
	if item.AccountAuthTypeID != nil {
		accountAuthType = account.GetAccountAuthTypeByID(*item.AccountAuthTypeID)
	}
	device := model.Device{ID: item.DeviceID}
	idAddress := item.IPAddress
	accessToken := item.AccessToken
	refreshTokens := item.RefreshTokens
	params := item.Params
	expires := item.Expires
	forceExpires := item.ForceExpires
	dateUpdated := item.DateUpdated
	dateCreated := item.DateCreated

	return model.LoginSession{ID: id, AppOrg: appOrg, AuthType: authType, AppType: appType,
		Anonymous: anonymous, Identifier: identifier, AccountAuthType: accountAuthType,
		Device: device, IPAddress: idAddress, AccessToken: accessToken, RefreshTokens: refreshTokens, Params: params,
		Expires: expires, ForceExpires: forceExpires, DateUpdated: dateUpdated, DateCreated: dateCreated}
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
	deviceID := item.Device.ID
	ipAddress := item.IPAddress
	accessToken := item.AccessToken
	refreshTokens := item.RefreshTokens
	params := item.Params
	expires := item.Expires
	forceExpires := item.ForceExpires
	dateUpdated := item.DateUpdated
	dateCreated := item.DateCreated

	return &loginSession{ID: id, AppID: appID, OrgID: orgID, AuthTypeCode: authTypeCode,
		AppTypeID: appTypeID, AppTypeIdentifier: appTypeIdentifier, Anonymous: anonymous,
		Identifier: identifier, AccountAuthTypeID: accountAuthTypeID, AccountAuthTypeIdentifier: accountAuthTypeIdentifier,
		DeviceID: deviceID, IPAddress: ipAddress, AccessToken: accessToken, RefreshTokens: refreshTokens,
		Params: params, Expires: expires, ForceExpires: forceExpires, DateUpdated: dateUpdated, DateCreated: dateCreated}
}

//ServiceAccount
func serviceAccountFromStorage(item serviceAccount, appOrg *model.ApplicationOrganization) *model.ServiceAccount {
	if appOrg == nil {
		return &model.ServiceAccount{ID: item.ID, Permissions: item.Permissions, Tokens: item.Tokens,
			DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
	}

	roles := accountRolesFromStorage(item.Roles, *appOrg)

	return &model.ServiceAccount{ID: item.ID, AppOrg: *appOrg, Permissions: item.Permissions, Roles: roles,
		Tokens: item.Tokens, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func serviceAccountToStorage(item model.ServiceAccount) *serviceAccount {
	roles := accountRolesToStorage(item.Roles)

	return &serviceAccount{ID: item.ID, AppOrgID: item.AppOrg.ID, Permissions: item.Permissions, Roles: roles,
		Tokens: item.Tokens, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}
