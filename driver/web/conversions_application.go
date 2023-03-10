// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"core-building-block/utils"
)

// Application
func applicationToDef(item model.Application) Def.Application {
	types := applicationTypeListToDef(item.Types)

	return Def.Application{Id: &item.ID, Name: item.Name, MultiTenant: item.MultiTenant, Admin: item.Admin,
		SharedIdentities: item.SharedIdentities, Types: &types}
}

func applicationsToDef(item []model.Application) []Def.Application {
	result := make([]Def.Application, len(item))
	for i, item := range item {
		result[i] = applicationToDef(item)
	}
	return result
}

// Application Type
func applicationTypeListFromDef(items []Def.ApplicationType) []model.ApplicationType {
	result := make([]model.ApplicationType, len(items))
	for i, item := range items {
		result[i] = *applicationTypeFromDef(&item)
	}
	return result
}

func applicationTypeFromDef(item *Def.ApplicationType) *model.ApplicationType {
	if item == nil {
		return nil
	}

	id := ""
	if item.Id != nil {
		id = *item.Id
	}
	name := ""
	if item.Name != nil {
		name = *item.Name
	}
	versions := make([]model.Version, 0)
	if item.Versions != nil {
		for _, v := range *item.Versions {
			versionNumbers := model.VersionNumbersFromString(v)
			if versionNumbers != nil {
				versions = append(versions, model.Version{VersionNumbers: *versionNumbers, ApplicationType: model.ApplicationType{ID: id}})
			}
		}
	}

	return &model.ApplicationType{ID: id, Identifier: item.Identifier, Name: name, Versions: versions}
}

func applicationTypeListToDef(items []model.ApplicationType) []Def.ApplicationType {
	result := make([]Def.ApplicationType, len(items))
	for i, item := range items {
		result[i] = *applicationTypeToDef(&item)
	}
	return result
}

func applicationTypeToDef(item *model.ApplicationType) *Def.ApplicationType {
	if item == nil {
		return nil
	}

	var name *string
	if len(item.Name) > 0 {
		nameStr := item.Name
		name = &nameStr
	}
	var versions *[]string
	if item.Versions != nil {
		versionList := make([]string, len(item.Versions))
		for i, v := range item.Versions {
			versionList[i] = v.VersionNumbers.String()
		}
		versions = &versionList
	}

	id := item.ID
	return &Def.ApplicationType{Id: &id, Identifier: item.Identifier, Name: name, Versions: versions}
}

// ApplicationPermission
func applicationPermissionToDef(item model.Permission) Def.Permission {
	assigners := item.Assigners
	if assigners == nil {
		assigners = make([]string, 0)
	}
	assigners = append(assigners, model.PermissionGrantAllPermissions)

	//dates
	var dateUpdated *string
	dateCreated := utils.FormatTime(&item.DateCreated)
	if item.DateUpdated != nil {
		formatted := utils.FormatTime(item.DateUpdated)
		dateUpdated = &formatted
	}
	description := item.Description
	serviceID := item.ServiceID
	return Def.Permission{Id: &item.ID, Name: item.Name, Description: &description, ServiceId: &serviceID, Assigners: &assigners, DateCreated: &dateCreated, DateUpdated: dateUpdated}
}

func applicationPermissionsToDef(items []model.Permission) []Def.Permission {
	result := make([]Def.Permission, len(items))
	for i, item := range items {
		result[i] = applicationPermissionToDef(item)
	}
	return result
}

// AppOrg
func appOrgFromDef(item *Def.ApplicationOrganization) *model.ApplicationOrganization {
	if item == nil {
		return nil
	}
	var id string
	if item.Id != nil {
		id = *item.Id
	}
	var serviceIds []string
	if item.ServicesIds != nil {
		serviceIds = *item.ServicesIds
	}

	authTypes := supportedAuthTypesFromDef(item.AuthTypes.AdditionalProperties)

	loginSessionSettings := model.LoginSessionSettings{}
	if item.LoginSessionSettings != nil {
		var defaultSettings model.AppAuthLoginSessionSettings
		defaultSettingsVal := loginSessionSettingsFromDef(item.LoginSessionSettings.Default)
		if defaultSettingsVal != nil {
			defaultSettings = *defaultSettingsVal
		}

		var overrideSettings []model.AppAuthLoginSessionSettings
		if item.LoginSessionSettings.Overrides != nil {
			overrideSettings = loginSessionSettingsListFromDef(*item.LoginSessionSettings.Overrides)
		}

		loginSessionSettings = model.LoginSessionSettings{
			Default:   defaultSettings,
			Overrides: overrideSettings,
		}
	}

	return &model.ApplicationOrganization{ID: id, ServicesIDs: serviceIds, AuthTypes: authTypes, LoginSessionSettings: loginSessionSettings}
}

func appOrgToDef(item *model.ApplicationOrganization) *Def.ApplicationOrganization {
	if item == nil {
		return nil
	}

	authTypes := Def.ApplicationOrganization_AuthTypes{AdditionalProperties: supportedAuthTypesToDef(item.AuthTypes)}

	defaultSettingsVal := item.LoginSessionSettings.Default
	defaultSettings := loginSessionSettingsToDef(&defaultSettingsVal)
	overrideSettings := loginSessionSettingsListToDef(item.LoginSessionSettings.Overrides)
	loginSessionSettings := Def.LoginSessionSettings{
		Default:   defaultSettings,
		Overrides: &overrideSettings,
	}

	id := item.ID
	serviceIDs := item.ServicesIDs
	return &Def.ApplicationOrganization{Id: &id, AppId: item.Application.ID, OrgId: item.Organization.ID, ServicesIds: &serviceIDs,
		AuthTypes: &authTypes, LoginSessionSettings: &loginSessionSettings}
}

func appOrgsToDef(items []model.ApplicationOrganization) []Def.ApplicationOrganization {
	if items == nil {
		return nil
	}
	out := make([]Def.ApplicationOrganization, len(items))
	for i, item := range items {
		defItem := appOrgToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.ApplicationOrganization{}
		}
	}

	return out
}

func loginSessionSettingsListFromDef(items []Def.AppAuthLoginSessionSettings) []model.AppAuthLoginSessionSettings {
	out := make([]model.AppAuthLoginSessionSettings, len(items))
	for i, item := range items {
		defItem := loginSessionSettingsFromDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = model.AppAuthLoginSessionSettings{}
		}
	}

	return out
}

func loginSessionSettingsFromDef(item *Def.AppAuthLoginSessionSettings) *model.AppAuthLoginSessionSettings {
	if item == nil {
		return nil
	}

	var maxConcurrentSessions int
	if item.MaxConcurrentSessions != nil {
		maxConcurrentSessions = *item.MaxConcurrentSessions
	}
	inactivityExpirePolicy := model.InactivityExpirePolicy{}
	if item.InactivityExpirePolicy != nil {
		inactivityExpirePolicy = model.InactivityExpirePolicy{Active: item.InactivityExpirePolicy.Active, InactivityPeriod: item.InactivityExpirePolicy.InactivityPeriod}
	}
	tslExpirePolicy := model.TSLExpirePolicy{}
	if item.TimeSinceLoginExpirePolicy != nil {
		tslExpirePolicy = model.TSLExpirePolicy{Active: item.TimeSinceLoginExpirePolicy.Active, TimeSinceLoginPeriod: item.TimeSinceLoginExpirePolicy.TimeSinceLoginPeriod}
	}
	yearlyExpirePolicy := model.YearlyExpirePolicy{}
	if item.YearlyExpirePolicy != nil {
		yearlyExpirePolicy = model.YearlyExpirePolicy{Active: item.YearlyExpirePolicy.Active, Day: item.YearlyExpirePolicy.Day, Month: item.YearlyExpirePolicy.Month,
			Hour: item.YearlyExpirePolicy.Hour, Min: item.YearlyExpirePolicy.Min}
	}

	return &model.AppAuthLoginSessionSettings{MaxConcurrentSessions: maxConcurrentSessions, InactivityExpirePolicy: inactivityExpirePolicy,
		TSLExpirePolicy: tslExpirePolicy, YearlyExpirePolicy: yearlyExpirePolicy}
}

func loginSessionSettingsListToDef(items []model.AppAuthLoginSessionSettings) []Def.AppAuthLoginSessionSettings {
	out := make([]Def.AppAuthLoginSessionSettings, len(items))
	for i, item := range items {
		defItem := loginSessionSettingsToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.AppAuthLoginSessionSettings{}
		}
	}

	return out
}

func loginSessionSettingsToDef(item *model.AppAuthLoginSessionSettings) *Def.AppAuthLoginSessionSettings {
	if item == nil {
		return nil
	}

	inactivityExpirePolicy := Def.InactiveExpirePolicy{Active: item.InactivityExpirePolicy.Active, InactivityPeriod: item.InactivityExpirePolicy.InactivityPeriod}
	tslExpirePolicy := Def.TSLExpirePolicy{Active: item.TSLExpirePolicy.Active, TimeSinceLoginPeriod: item.TSLExpirePolicy.TimeSinceLoginPeriod}
	yearlyExpirePolicy := Def.YearlyExpirePolicy{Active: item.YearlyExpirePolicy.Active, Day: item.YearlyExpirePolicy.Day, Month: item.YearlyExpirePolicy.Month,
		Hour: item.YearlyExpirePolicy.Hour, Min: item.YearlyExpirePolicy.Min}

	maxConcurrentSessions := item.MaxConcurrentSessions
	return &Def.AppAuthLoginSessionSettings{MaxConcurrentSessions: &maxConcurrentSessions, InactivityExpirePolicy: &inactivityExpirePolicy,
		TimeSinceLoginExpirePolicy: &tslExpirePolicy, YearlyExpirePolicy: &yearlyExpirePolicy}
}

func supportedAuthTypesFromDef(items map[string]Def.SupportedAuthType) map[string]model.SupportedAuthType {
	if items == nil {
		return nil
	}

	out := make(map[string]model.SupportedAuthType)
	for code, authType := range items {
		out[code] = supportedAuthTypeFromDef(authType)
	}
	return out
}

func supportedAuthTypeFromDef(item Def.SupportedAuthType) model.SupportedAuthType {
	var configs map[string]interface{}
	if item.Configs != nil {
		configs = item.Configs.AdditionalProperties
	}
	var appTypeConfigs map[string]interface{}
	if item.AppTypeConfigs != nil {
		appTypeConfigs = item.AppTypeConfigs.AdditionalProperties
	}

	return model.SupportedAuthType{Configs: configs, AppTypeConfigs: appTypeConfigs, Alias: item.Alias}
}

func supportedAuthTypesToDef(items map[string]model.SupportedAuthType) map[string]Def.SupportedAuthType {
	if items == nil {
		return nil
	}

	out := make(map[string]Def.SupportedAuthType)
	for code, authType := range items {
		out[code] = supportedAuthTypeToDef(authType)
	}
	return out
}

func supportedAuthTypeToDef(item model.SupportedAuthType) Def.SupportedAuthType {
	configs := Def.SupportedAuthType_Configs{AdditionalProperties: item.Configs}
	appTypeConfigs := Def.SupportedAuthType_AppTypeConfigs{AdditionalProperties: item.AppTypeConfigs}

	return Def.SupportedAuthType{Configs: &configs, AppTypeConfigs: &appTypeConfigs, Alias: item.Alias}
}

// AppOrgRole
func appOrgRoleToDef(item model.AppOrgRole) Def.AppOrgRole {
	permissions := applicationPermissionsToDef(item.Permissions)

	//dates
	var dateUpdated *string
	dateCreated := utils.FormatTime(&item.DateCreated)
	if item.DateUpdated != nil {
		formatted := utils.FormatTime(item.DateUpdated)
		dateUpdated = &formatted
	}
	id := item.ID
	description := item.Description
	system := item.System
	return Def.AppOrgRole{Id: &id, Name: item.Name, Description: &description, System: &system, DateCreated: &dateCreated, DateUpdated: dateUpdated, Permissions: &permissions}
}

func appOrgRolesToDef(items []model.AppOrgRole) []Def.AppOrgRole {
	result := make([]Def.AppOrgRole, len(items))
	for i, item := range items {
		result[i] = appOrgRoleToDef(item)
	}
	return result
}

// AppOrgGroup
func appOrgGroupToDef(item model.AppOrgGroup) Def.AppOrgGroup {
	permissions := applicationPermissionsToDef(item.Permissions)
	roles := appOrgRolesToDef(item.Roles)

	//dates
	var dateUpdated *string
	dateCreated := utils.FormatTime(&item.DateCreated)
	if item.DateUpdated != nil {
		formatted := utils.FormatTime(item.DateUpdated)
		dateUpdated = &formatted
	}

	return Def.AppOrgGroup{Id: &item.ID, Name: item.Name, Description: &item.Description, System: &item.System, DateCreated: &dateCreated, DateUpdated: dateUpdated, Permissions: &permissions, Roles: &roles}
}

func appOrgGroupsToDef(items []model.AppOrgGroup) []Def.AppOrgGroup {
	result := make([]Def.AppOrgGroup, len(items))
	for i, item := range items {
		result[i] = appOrgGroupToDef(item)
	}
	return result
}

// Organization
func organizationToDef(item *model.Organization) *Def.Organization {
	if item == nil {
		return nil
	}
	id := item.ID
	config := item.Config

	return &Def.Organization{Id: &id, Name: item.Name, Type: Def.OrganizationType(item.Type), Config: organizationConfigToDef(&config)}
}

func organizationsToDef(items []model.Organization) []Def.Organization {
	result := make([]Def.Organization, len(items))
	for i, item := range items {
		result[i] = *organizationToDef(&item)
	}
	return result
}

func organizationConfigToDef(item *model.OrganizationConfig) *Def.OrganizationConfig {
	if item == nil {
		return nil
	}

	var id *string
	if len(item.ID) > 0 {
		id = &item.ID
	}

	return &Def.OrganizationConfig{Id: id, Domains: item.Domains}
}

// App Config
func appConfigToDef(item model.ApplicationConfig) Def.ApplicationConfig {
	defConfig := Def.ApplicationConfig{Id: &item.ID, AppTypeId: item.ApplicationType.ID, Version: item.Version.VersionNumbers.String(), Data: item.Data}
	if item.AppOrg != nil {
		orgID := item.AppOrg.Organization.ID
		defConfig.OrgId = &orgID
	}

	return defConfig
}

func appConfigsToDef(items []model.ApplicationConfig) []Def.ApplicationConfig {
	result := make([]Def.ApplicationConfig, len(items))
	for i, item := range items {
		result[i] = appConfigToDef(item)
	}
	return result
}
