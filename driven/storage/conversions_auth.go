package storage

import "core-building-block/core/model"

//LoginSession
func loginSessionFromStorage(item loginSession) model.LoginSession {
	id := item.ID
	anonymous := item.Anonymous
	identifier := item.Identifier
	var accountAuthType *model.AccountAuthType
	if item.AccountAuthTypeID != nil {
		accountAuthType = &model.AccountAuthType{ID: *item.AccountAuthTypeID}
	}
	device := model.Device{ID: item.DeviceID}
	IP := item.IP
	accessToken := item.AccessToken
	refreshToken := item.RefreshToken
	params := item.Params
	expires := item.Expires
	dateUpdated := item.DateUpdated
	dateCreated := item.DateCreated

	return model.LoginSession{ID: id, Anonymous: anonymous, Identifier: identifier, AccountAuthType: accountAuthType,
		Device: device, IP: IP, AccessToken: accessToken, RefreshToken: refreshToken, Params: params,
		Expires: expires, DateUpdated: dateUpdated, DateCreated: dateCreated}
}

func loginSessionToStorage(item *model.LoginSession) *loginSession {
	id := item.ID
	anonymous := item.Anonymous
	identifier := item.Identifier
	var accountAuthTypeID *string
	if item.AccountAuthType != nil {
		accountAuthTypeID = &item.AccountAuthType.ID
	}
	deviceID := item.Device.ID
	IP := item.IP
	accessToken := item.AccessToken
	refreshToken := item.RefreshToken
	params := item.Params
	expires := item.Expires
	dateUpdated := item.DateUpdated
	dateCreated := item.DateCreated

	return &loginSession{ID: id, Anonymous: anonymous, Identifier: identifier, AccountAuthTypeID: accountAuthTypeID,
		DeviceID: deviceID, IP: IP, AccessToken: accessToken, RefreshToken: refreshToken, Params: params,
		Expires: expires, DateUpdated: dateUpdated, DateCreated: dateCreated}
}
