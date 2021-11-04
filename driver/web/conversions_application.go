package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"regexp"

	"github.com/rokwire/logging-library-go/errors"
)

//Application
func applicationToDef(item *model.Application) *Def.ApplicationFields {
	if item == nil {
		return nil
	}

	return &Def.ApplicationFields{Id: item.ID, Name: item.Name, MultiTenant: &item.MultiTenant, RequiresOwnUsers: &item.RequiresOwnUsers}
}

//ApplicationPermission
func applicationPermissionToDef(item model.Permission) Def.ApplicationPermissionFields {
	return Def.ApplicationPermissionFields{Id: item.ID, Name: item.Name}
}

func applicationPermissionsToDef(items []model.Permission) []Def.ApplicationPermissionFields {
	result := make([]Def.ApplicationPermissionFields, len(items))
	for i, item := range items {
		result[i] = applicationPermissionToDef(item)
	}
	return result
}

//ApplicationRole
func applicationRoleToDef(item model.ApplicationRole) Def.ApplicationRoleFields {
	return Def.ApplicationRoleFields{Id: item.ID, Name: item.Name}
}

func applicationRolesToDef(items []model.ApplicationRole) []Def.ApplicationRoleFields {
	result := make([]Def.ApplicationRoleFields, len(items))
	for i, item := range items {
		result[i] = applicationRoleToDef(item)
	}
	return result
}

//ApplicationGroup
func applicationGroupToDef(item model.ApplicationGroup) Def.ApplicationGroupFields {
	return Def.ApplicationGroupFields{Id: item.ID, Name: item.Name}
}

func applicationGroupsToDef(items []model.ApplicationGroup) []Def.ApplicationGroupFields {
	result := make([]Def.ApplicationGroupFields, len(items))
	for i, item := range items {
		result[i] = applicationGroupToDef(item)
	}
	return result
}

//Organization
func organizationToDef(item *model.Organization) *Def.OrganizationFields {
	if item == nil {
		return nil
	}

	return &Def.OrganizationFields{Id: item.ID, Name: item.Name, Type: Def.OrganizationFieldsType(item.Type)}
}

func organizationsToDef(items []model.Organization) []Def.OrganizationFields {
	result := make([]Def.OrganizationFields, len(items))
	for i, item := range items {
		result[i] = *organizationToDef(&item)
	}
	return result
}

func appConfigFromDef(requestData Def.ReqCreateApplicationConfigsRequest) (map[string]interface{}, error) {
	// appConfig := model.ApplicationConfigs{
	// 	AppID:                   requestData.AppId,
	// 	MobileAppVersion:        requestData.MobileAppVersion,
	// 	PlatformBuildingBlocks:  requestData.PlatformBuildingBlocks,
	// 	ThirdPartyServices:      requestData.ThirdPartyServices,
	// 	OtherUniversityServices: requestData.OtherUniversityServices,
	// 	SecretKeys:              requestData.SecretKeys,
	// }

	configData := map[string]interface{}{
		"platformBuildingBlocks":  requestData.PlatformBuildingBlocks,
		"thirdPartyServices":      requestData.ThirdPartyServices,
		"otherUniversityServices": requestData.OtherUniversityServices,
		"secretKeys":              requestData.SecretKeys,
		"upgrade":                 requestData.Upgrade,
	}

	version := requestData.MobileAppVersion
	validVersionRegex := regexp.MustCompile(`^(?P<major>\d+).(?P<minor>\d+).(?P<patch>\d+)$`)
	if !validVersionRegex.MatchString(version) {
		return nil, errors.New("MobileAppVersion query parameter is not valid, please use major.minor.patch format")
	}

	n1 := validVersionRegex.SubexpNames()
	r2 := validVersionRegex.FindAllStringSubmatch(version, -1)[0]
	md := map[string]string{}
	for i, n := range r2 {
		md[n1[i]] = n
	}

	versionNumbers := map[string]string{
		"major": md["major"],
		"minor": md["minor"],
		"patch": md["patch"],
	}
	configData["version_numbers"] = versionNumbers

	return configData, nil
}
