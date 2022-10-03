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

//Application
//TODO
/*
func applicationToDef(item *model.Application) *Def.Application {
	if item == nil {
		return nil
	}

	fields := Def.ApplicationFields{Id: item.ID, Name: item.Name, MultiTenant: &item.MultiTenant,
		RequiresOwnUsers: &item.RequiresOwnUsers}
	types := applicationTypeListToDef(item.Types)

	return &Def.Application{Fields: &fields, Types: &types}
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
		name = &item.Name
	}
	var versions *[]string
	if len(item.Versions) > 0 {
		versions = &item.Versions
	}

	return &Def.ApplicationType{Fields: &Def.ApplicationTypeFields{Id: item.ID, Identifier: item.Identifier, Name: name, Versions: versions}}
} */

func applicationToDef(item model.Application) Def.ApplicationFields {

	return Def.ApplicationFields{Id: &item.ID, Name: item.Name, MultiTenant: &item.MultiTenant,
		SharedIdentities: &item.SharedIdentities}
}

func applicationsToDef(item []model.Application) []Def.ApplicationFields {
	result := make([]Def.ApplicationFields, len(item))
	for i, item := range item {
		result[i] = applicationToDef(item)
	}
	return result
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

	return Def.Permission{Id: item.ID, Name: item.Name, Description: &item.Description, ServiceId: &item.ServiceID, Assigners: &assigners, DateCreated: &dateCreated, DateUpdated: dateUpdated}
}

func applicationPermissionsToDef(items []model.Permission) []Def.Permission {
	result := make([]Def.Permission, len(items))
	for i, item := range items {
		result[i] = applicationPermissionToDef(item)
	}
	return result
}

// AppOrg
func appOrgFromDef(item *Def.AppOrg) *model.ApplicationOrganization {
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

	identityProviderSettings := identityProviderSettingsFromDef(item.IdentityProviderSettings)
	supportedAuthTypes := supportedAuthTypesFromDef(item.SupportedAuthTypes)
	loginsSessionsSetting := loginSessionSettingsFromDef(item.LoginSessionSettings)

	return &model.ApplicationOrganization{ID: id, ServicesIDs: serviceIds, IdentityProvidersSettings: identityProviderSettings, SupportedAuthTypes: supportedAuthTypes, LoginsSessionsSetting: *loginsSessionsSetting}
}

func appOrgToDef(item *model.ApplicationOrganization) *Def.AppOrg {
	if item == nil {
		return nil
	}

	identityProviderSettings := identityProviderSettingsToDef(item.IdentityProvidersSettings)
	supportedAuthTypes := supportedAuthTypesToDef(item.SupportedAuthTypes)
	loginsSessionsSetting := loginSessionSettingsToDef(item.LoginsSessionsSetting)
	return &Def.AppOrg{Id: &item.ID, AppId: item.Application.ID, OrgId: item.Organization.ID, ServicesIds: &item.ServicesIDs,
		IdentityProviderSettings: &identityProviderSettings, SupportedAuthTypes: &supportedAuthTypes, LoginSessionSettings: &loginsSessionsSetting}
}

func appOrgsToDef(items []model.ApplicationOrganization) []Def.AppOrg {
	if items == nil {
		return nil
	}
	out := make([]Def.AppOrg, len(items))
	for i, item := range items {
		defItem := appOrgToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.AppOrg{}
		}
	}

	return out
}

func loginSessionSettingsFromDef(item *Def.LoginSessionSettings) *model.LoginsSessionsSetting {
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

	return &model.LoginsSessionsSetting{MaxConcurrentSessions: maxConcurrentSessions, InactivityExpirePolicy: inactivityExpirePolicy,
		TSLExpirePolicy: tslExpirePolicy, YearlyExpirePolicy: yearlyExpirePolicy}
}

func loginSessionSettingsToDef(item model.LoginsSessionsSetting) Def.LoginSessionSettings {
	inactivityExpirePolicy := Def.InactiveExpirePolicy{Active: item.InactivityExpirePolicy.Active, InactivityPeriod: item.InactivityExpirePolicy.InactivityPeriod}
	tslExpirePolicy := Def.TSLExpirePolicy{Active: item.TSLExpirePolicy.Active, TimeSinceLoginPeriod: item.TSLExpirePolicy.TimeSinceLoginPeriod}
	yearlyExpirePolicy := Def.YearlyExpirePolicy{Active: item.YearlyExpirePolicy.Active, Day: item.YearlyExpirePolicy.Day, Month: item.YearlyExpirePolicy.Month,
		Hour: item.YearlyExpirePolicy.Hour, Min: item.YearlyExpirePolicy.Min}

	return Def.LoginSessionSettings{MaxConcurrentSessions: &item.MaxConcurrentSessions, InactivityExpirePolicy: &inactivityExpirePolicy,
		TimeSinceLoginExpirePolicy: &tslExpirePolicy, YearlyExpirePolicy: &yearlyExpirePolicy}
}

func supportedAuthTypesFromDef(items *[]Def.SupportedAuthTypes) []model.AuthTypesSupport {
	if items == nil {
		return nil
	}
	out := make([]model.AuthTypesSupport, len(*items))
	for i, item := range *items {
		defItem := supportedAuthTypeFromDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = model.AuthTypesSupport{}
		}
	}

	return out
}

func supportedAuthTypeFromDef(item *Def.SupportedAuthTypes) *model.AuthTypesSupport {
	if item == nil || item.AppTypeId == nil {
		return nil
	}

	supportedAuthTypes := []model.SupportedAuthType{}
	if item.SupportedAuthTypes != nil {
		for _, authType := range *item.SupportedAuthTypes {
			if authType.AuthTypeId != nil && authType.Params != nil {
				supportedAuthTypes = append(supportedAuthTypes, model.SupportedAuthType{AuthTypeID: *authType.AuthTypeId, Params: authType.Params.AdditionalProperties})
			}
		}
	}

	return &model.AuthTypesSupport{AppTypeID: *item.AppTypeId, SupportedAuthTypes: supportedAuthTypes}
}

func supportedAuthTypesToDef(items []model.AuthTypesSupport) []Def.SupportedAuthTypes {
	if items == nil {
		return nil
	}
	out := make([]Def.SupportedAuthTypes, len(items))
	for i, item := range items {
		defItem := supportedAuthTypeToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.SupportedAuthTypes{}
		}
	}

	return out
}

func supportedAuthTypeToDef(item *model.AuthTypesSupport) *Def.SupportedAuthTypes {
	if item == nil {
		return nil
	}
	supportedAuthTypes := []Def.SupportedAuthType{}
	for _, authType := range item.SupportedAuthTypes {
		params := Def.SupportedAuthType_Params{AdditionalProperties: authType.Params}
		supportedAuthTypes = append(supportedAuthTypes, Def.SupportedAuthType{AuthTypeId: &authType.AuthTypeID, Params: &params})
	}
	return &Def.SupportedAuthTypes{AppTypeId: &item.AppTypeID, SupportedAuthTypes: &supportedAuthTypes}
}

func identityProviderSettingsFromDef(items *[]Def.IdentityProviderSettings) []model.IdentityProviderSetting {
	if items == nil {
		return nil
	}
	out := make([]model.IdentityProviderSetting, len(*items))
	for i, item := range *items {
		defItem := identityProviderSettingFromDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = model.IdentityProviderSetting{}
		}
	}

	return out
}

func identityProviderSettingFromDef(item *Def.IdentityProviderSettings) *model.IdentityProviderSetting {
	if item == nil {
		return nil
	}

	var firstNameField string
	if item.FirstNameField != nil {
		firstNameField = *item.FirstNameField
	}
	var lastNameField string
	if item.LastNameField != nil {
		lastNameField = *item.LastNameField
	}
	var middleNameField string
	if item.MiddleNameField != nil {
		middleNameField = *item.MiddleNameField
	}
	var emailField string
	if item.EmailField != nil {
		emailField = *item.EmailField
	}
	var rolesField string
	if item.RolesField != nil {
		rolesField = *item.RolesField
	}
	var groupsField string
	if item.GroupsField != nil {
		groupsField = *item.GroupsField
	}
	var userSpecificFields []string
	if item.UserSpecificFields != nil {
		userSpecificFields = *item.UserSpecificFields
	}
	var roles map[string]string
	if item.Roles != nil {
		roles = item.Roles.AdditionalProperties
	}
	var groups map[string]string
	if item.Groups != nil {
		groups = item.Groups.AdditionalProperties
	}
	var alwaysSyncProfile bool
	if item.AlwaysSyncProfile != nil {
		alwaysSyncProfile = *item.AlwaysSyncProfile
	}

	return &model.IdentityProviderSetting{IdentityProviderID: item.IdentityProviderId, UserIdentifierField: item.UserIdentifierField,
		ExternalIDFields: item.ExternalIdFields.AdditionalProperties, FirstNameField: firstNameField, MiddleNameField: middleNameField,
		LastNameField: lastNameField, EmailField: emailField, RolesField: rolesField, GroupsField: groupsField,
		UserSpecificFields: userSpecificFields, Roles: roles, Groups: groups, AlwaysSyncProfile: alwaysSyncProfile}
}

func identityProviderSettingsToDef(items []model.IdentityProviderSetting) []Def.IdentityProviderSettings {
	out := make([]Def.IdentityProviderSettings, len(items))
	for i, item := range items {
		defItem := identityProviderSettingToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.IdentityProviderSettings{}
		}
	}

	return out
}

func identityProviderSettingToDef(item *model.IdentityProviderSetting) *Def.IdentityProviderSettings {
	if item == nil {
		return nil
	}

	externalIDs := Def.IdentityProviderSettings_ExternalIdFields{AdditionalProperties: item.ExternalIDFields}
	roles := Def.IdentityProviderSettings_Roles{AdditionalProperties: item.Roles}
	groups := Def.IdentityProviderSettings_Groups{AdditionalProperties: item.Groups}

	return &Def.IdentityProviderSettings{IdentityProviderId: item.IdentityProviderID, UserIdentifierField: item.UserIdentifierField,
		ExternalIdFields: &externalIDs, FirstNameField: &item.FirstNameField, MiddleNameField: &item.MiddleNameField,
		LastNameField: &item.LastNameField, EmailField: &item.EmailField, RolesField: &item.RolesField, GroupsField: &item.GroupsField,
		UserSpecificFields: &item.UserSpecificFields, Roles: &roles, Groups: &groups, AlwaysSyncProfile: &item.AlwaysSyncProfile}
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

	return Def.AppOrgRole{Id: &item.ID, Name: item.Name, Description: &item.Description, System: &item.System, DateCreated: &dateCreated, DateUpdated: dateUpdated, Permissions: &permissions}
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

	fields := Def.OrganizationFields{Id: &item.ID, Name: item.Name, Type: Def.OrganizationFieldsType(item.Type)}
	config := item.Config

	return &Def.Organization{Config: organizationConfigToDef(&config), Fields: &fields}
}

func organizationsToDef(items []model.Organization) []Def.Organization {
	result := make([]Def.Organization, len(items))
	for i, item := range items {
		result[i] = *organizationToDef(&item)
	}
	return result
}

func organizationConfigToDef(item *model.OrganizationConfig) *Def.OrganizationConfigFields {
	if item == nil {
		return nil
	}

	var id *string
	if len(item.ID) > 0 {
		id = &item.ID
	}
	var domains *[]string
	if len(item.Domains) > 0 {
		domains = &item.Domains
	}

	return &Def.OrganizationConfigFields{Id: id, Domains: domains}
}

// App Config
func appConfigToDef(item model.ApplicationConfig) Def.ApplicationConfig {
	defConfig := Def.ApplicationConfig{Id: item.ID, AppTypeId: item.ApplicationType.ID, Version: item.Version.VersionNumbers.String(), Data: item.Data}
	if item.AppOrg != nil {
		defConfig.OrgId = &item.AppOrg.Organization.ID
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
