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
		aatID := *item.AccountAuthTypeID
		aatIdentifier := *item.AccountAuthTypeIdentifier
		aatAccount := *account
		accountAuthType = &model.AccountAuthType{ID: aatID, Identifier: aatIdentifier, Account: aatAccount}
	}
	device := model.Device{ID: item.DeviceID}
	idAddress := item.IPAddress
	accessToken := item.AccessToken
	refreshToken := item.RefreshToken
	params := item.Params
	expires := item.Expires
	dateUpdated := item.DateUpdated
	dateCreated := item.DateCreated

	return model.LoginSession{ID: id, AppOrg: appOrg, AuthType: authType, AppType: appType,
		Anonymous: anonymous, Identifier: identifier, AccountAuthType: accountAuthType,
		Device: device, IPAddress: idAddress, AccessToken: accessToken, RefreshToken: refreshToken, Params: params,
		Expires: expires, DateUpdated: dateUpdated, DateCreated: dateCreated}
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
	refreshToken := item.RefreshToken
	params := item.Params
	state := item.State
	expires := item.Expires
	dateUpdated := item.DateUpdated
	dateCreated := item.DateCreated

	return &loginSession{ID: id, AppID: appID, OrgID: orgID, AuthTypeCode: authTypeCode,
		AppTypeID: appTypeID, AppTypeIdentifier: appTypeIdentifier, Anonymous: anonymous,
		Identifier: identifier, AccountAuthTypeID: accountAuthTypeID,
		AccountAuthTypeIdentifier: accountAuthTypeIdentifier, DeviceID: deviceID, IPAddress: ipAddress,
		AccessToken: accessToken, RefreshToken: refreshToken, Params: params, State: state, Expires: expires,
		DateUpdated: dateUpdated, DateCreated: dateCreated}
}
