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

	return Def.ApplicationFields{Id: item.ID, Name: item.Name, MultiTenant: &item.MultiTenant,
		SharedIdentities: &item.SharedIdentities}
}

func applicationsToDef(item []model.Application) []Def.ApplicationFields {
	result := make([]Def.ApplicationFields, len(item))
	for i, item := range item {
		result[i] = applicationToDef(item)
	}
	return result
}

//ApplicationPermission
func applicationPermissionToDef(item model.Permission) Def.Permission {
	assigners := item.Assigners
	if assigners == nil {
		assigners = make([]string, 0)
	}

	//dates
	var dateUpdated *string
	dateCreated := item.DateCreated.Format("2006-01-02T15:04:05.000Z")
	if item.DateUpdated != nil {
		formatted := item.DateUpdated.Format("2006-01-02T15:04:05.000Z")
		dateUpdated = &formatted
	}

	return Def.Permission{Id: item.ID, Name: item.Name, ServiceId: &item.ServiceID, Assigners: &assigners, DateCreated: &dateCreated, DateUpdated: dateUpdated}
}

func applicationPermissionsToDef(items []model.Permission) []Def.Permission {
	result := make([]Def.Permission, len(items))
	for i, item := range items {
		result[i] = applicationPermissionToDef(item)
	}
	return result
}

//AppOrgRole
func appOrgRoleToDef(item model.AppOrgRole) Def.AppOrgRole {
	permissions := applicationPermissionsToDef(item.Permissions)

	//dates
	var dateUpdated *string
	dateCreated := item.DateCreated.Format("2006-01-02T15:04:05.000Z")
	if item.DateUpdated != nil {
		formatted := item.DateUpdated.Format("2006-01-02T15:04:05.000Z")
		dateUpdated = &formatted
	}

	fields := Def.AppOrgRoleFields{Id: item.ID, Name: item.Name, Description: &item.Description, System: &item.System, DateCreated: &dateCreated, DateUpdated: dateUpdated}
	return Def.AppOrgRole{Fields: &fields, Permissions: &permissions}
}

func appOrgRolesToDef(items []model.AppOrgRole) []Def.AppOrgRole {
	result := make([]Def.AppOrgRole, len(items))
	for i, item := range items {
		result[i] = appOrgRoleToDef(item)
	}
	return result
}

//AppOrgGroup
func appOrgGroupToDef(item model.AppOrgGroup) Def.AppOrgGroup {
	permissions := applicationPermissionsToDef(item.Permissions)
	roles := appOrgRolesToDef(item.Roles)

	//dates
	var dateUpdated *string
	dateCreated := item.DateCreated.Format("2006-01-02T15:04:05.000Z")
	if item.DateUpdated != nil {
		formatted := item.DateUpdated.Format("2006-01-02T15:04:05.000Z")
		dateUpdated = &formatted
	}

	fields := Def.AppOrgGroupFields{Id: item.ID, Name: item.Name, Description: &item.Description, System: &item.System, DateCreated: &dateCreated, DateUpdated: dateUpdated}
	return Def.AppOrgGroup{Fields: &fields, Permissions: &permissions, Roles: &roles}
}

func appOrgGroupsToDef(items []model.AppOrgGroup) []Def.AppOrgGroup {
	result := make([]Def.AppOrgGroup, len(items))
	for i, item := range items {
		result[i] = appOrgGroupToDef(item)
	}
	return result
}

//Organization
func organizationToDef(item *model.Organization) *Def.Organization {
	if item == nil {
		return nil
	}

	fields := Def.OrganizationFields{Id: item.ID, Name: item.Name, Type: Def.OrganizationFieldsType(item.Type)}
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

//App Config
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
