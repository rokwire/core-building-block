package storage

import "core-building-block/core/model"

//Organization
func organizationFromStorage(item *organization, applications []model.Application) model.Organization {
	if item == nil {
		return model.Organization{}
	}

	return model.Organization{ID: item.ID, Name: item.Name, Type: item.Type, RequiresOwnLogin: item.RequiresOwnLogin,
		LoginTypes: item.LoginTypes, Config: item.Config, Applications: nil,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func organizationToStorage(item *model.Organization) *organization {
	if item == nil {
		return nil
	}

	//prepare applications
	applicationsIDs := make([]string, len(item.Applications))
	for i, application := range item.Applications {
		applicationsIDs[i] = application.ID
	}

	return &organization{ID: item.ID, Name: item.Name, Type: item.Type, RequiresOwnLogin: item.RequiresOwnLogin,
		LoginTypes: item.LoginTypes, Config: item.Config, Applications: nil, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}
