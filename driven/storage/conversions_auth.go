package storage

import "core-building-block/core/model"

//LoginSession
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
	dateCreated := item.DateCreated

	return &loginSession{ID: id, Anonymous: anonymous, Identifier: identifier, AccountAuthTypeID: accountAuthTypeID,
		DeviceID: deviceID, IP: IP, AccessToken: accessToken, RefreshToken: refreshToken, Params: params,
		Expires: expires, DateCreated: dateCreated}
}
