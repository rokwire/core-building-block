package storage

import (
	"core-building-block/core/model"
)

//User
func userFromStorage(item *user, sa *Adapter) model.Account {
	/*	if item == nil {
			return model.User{}
		}

		id := item.ID
		applicationsAccounts := item.ApplicationsAccounts
		profile := item.Profile
		devices := userDevicesFromStorage(*item)
		dateCreated := item.DateCreated
		dateUpdated := item.DateUpdated

		return model.User{ID: id, ApplicationsAccounts: applicationsAccounts, Profile: profile,
			Devices: devices, DateCreated: dateCreated, DateUpdated: dateUpdated} */
	return model.Account{}

}

func userToStorage(item *model.Account) *user {
	/*	if item == nil {
			return nil
		}

		id := item.ID
		applicationsAccounts := item.ApplicationsAccounts
		profile := item.Profile
		devices := userDevicesToStorage(item)
		dateCreated := item.DateCreated
		dateUpdated := item.DateUpdated

		return &user{ID: id, ApplicationsAccounts: applicationsAccounts, Profile: profile,
			Devices: devices, DateCreated: dateCreated, DateUpdated: dateUpdated} */
	return nil
}

func userDevicesFromStorage(item user) []model.Device {
	devices := make([]model.Device, len(item.Devices))

	for i, device := range item.Devices {
		devices[i] = userDeviceFromStorage(device)
	}
	return devices
}

func userDeviceFromStorage(item userDevice) model.Device {
	return model.Device{ID: item.ID, Type: item.Type, OS: item.OS, MacAddress: item.MacAddress,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func userDevicesToStorage(item *model.Account) []userDevice {
	devices := make([]userDevice, len(item.Devices))

	for i, device := range item.Devices {
		devices[i] = userDeviceToStorage(device)
	}
	return devices
}

func userDeviceToStorage(item model.Device) userDevice {
	return userDevice{ID: item.ID, Type: item.Type, OS: item.OS, MacAddress: item.MacAddress,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

//Device

func deviceToStorage(item *model.Device) *device {
	if item == nil {
		return nil
	}

	users := make([]string, len(item.Accounts))
	for i, user := range item.Accounts {
		users[i] = user.ID
	}

	return &device{ID: item.ID, Type: item.Type, OS: item.OS, MacAddress: item.MacAddress,
		Users: users, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}
