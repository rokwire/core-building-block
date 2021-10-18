package storage

import "core-building-block/core/model"

//LoginSession
func loginSessionFromStorage(item loginSession, app model.Application, org model.Organization) model.LoginSession {
	id := item.ID

	appOrg := model.ApplicationOrganization{Application: app, Organization: org}

	authType := model.AuthType{ID: item.AuthTypeID, Code: item.AuthTypeCode}

	anonymous := item.Anonymous
	identifier := item.Identifier
	var accountAuthType *model.AccountAuthType
	if item.AccountAuthTypeID != nil {
		accountAuthType = &model.AccountAuthType{ID: *item.AccountAuthTypeID, Identifier: *item.AccountAuthTypeIdentifier}
	}
	device := model.Device{ID: item.DeviceID}
	IP := item.IP
	accessToken := item.AccessToken
	refreshToken := item.RefreshToken
	params := item.Params
	expires := item.Expires
	dateUpdated := item.DateUpdated
	dateCreated := item.DateCreated

	return model.LoginSession{ID: id, AppOrg: appOrg, AuthType: authType, Anonymous: anonymous,
		Identifier: identifier, AccountAuthType: accountAuthType, Device: device, IP: IP,
		AccessToken: accessToken, RefreshToken: refreshToken, Params: params,
		Expires: expires, DateUpdated: dateUpdated, DateCreated: dateCreated}
}

func loginSessionToStorage(item *model.LoginSession) *loginSession {
	id := item.ID

	appID := item.AppOrg.Application.ID
	orgID := item.AppOrg.Organization.ID

	authTypeID := item.AuthType.ID
	authTypeCode := item.AuthType.Code

	anonymous := item.Anonymous
	identifier := item.Identifier
	var accountAuthTypeID *string
	var accountAuthTypeIdentifier *string
	if item.AccountAuthType != nil {
		accountAuthTypeID = &item.AccountAuthType.ID
		accountAuthTypeIdentifier = &item.AccountAuthType.Identifier
	}
	deviceID := item.Device.ID
	IP := item.IP
	accessToken := item.AccessToken
	refreshToken := item.RefreshToken
	params := item.Params
	expires := item.Expires
	dateUpdated := item.DateUpdated
	dateCreated := item.DateCreated

	return &loginSession{ID: id, AppID: appID, OrgID: orgID, AuthTypeID: authTypeID,
		AuthTypeCode: authTypeCode, Anonymous: anonymous, Identifier: identifier,
		AccountAuthTypeID: accountAuthTypeID, AccountAuthTypeIdentifier: accountAuthTypeIdentifier, DeviceID: deviceID,
		IP: IP, AccessToken: accessToken, RefreshToken: refreshToken, Params: params, Expires: expires,
		DateUpdated: dateUpdated, DateCreated: dateCreated}
}
