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
func applicationPermissionToDef(item model.Permission) Def.PermissionFields {
	return Def.PermissionFields{Id: item.ID, Name: item.Name}
}

func applicationPermissionsToDef(items []model.Permission) []Def.PermissionFields {
	result := make([]Def.PermissionFields, len(items))
	for i, item := range items {
		result[i] = applicationPermissionToDef(item)
	}
	return result
}

//AppOrgRole
func appOrgRoleToDef(item model.AppOrgRole) Def.AppOrgRoleFields {
	return Def.AppOrgRoleFields{Id: item.ID, Name: item.Name}
}

func appOrgRolesToDef(items []model.AppOrgRole) []Def.AppOrgRoleFields {
	result := make([]Def.AppOrgRoleFields, len(items))
	for i, item := range items {
		result[i] = appOrgRoleToDef(item)
	}
	return result
}

//AppOrgGroup
func appOrgGroupToDef(item model.AppOrgGroup) Def.AppOrgGroupFields {
	return Def.AppOrgGroupFields{Id: item.ID, Name: item.Name}
}

func appOrgGroupsToDef(items []model.AppOrgGroup) []Def.AppOrgGroupFields {
	result := make([]Def.AppOrgGroupFields, len(items))
	for i, item := range items {
		result[i] = appOrgGroupToDef(item)
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

func checkAppVersionFormat(version string) bool {
	valid := regexp.MustCompile(`^\d+.\d+.\d+$`)
	if !valid.MatchString(version) {
		return false
	}

	return true
}
