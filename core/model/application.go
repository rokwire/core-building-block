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

package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rokwire/core-auth-library-go/v3/authutils"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//TypeApplication ...
	TypeApplication logutils.MessageDataType = "application"
	//TypePermission ...
	TypePermission logutils.MessageDataType = "permission"
	//TypeAppOrgRole ...
	TypeAppOrgRole logutils.MessageDataType = "application organization role"
	//TypeAppOrgRolePermissions ...
	TypeAppOrgRolePermissions logutils.MessageDataType = "application organization role permissions"
	//TypeAppOrgGroup ...
	TypeAppOrgGroup logutils.MessageDataType = "application organization group"
	//TypeOrganization ...
	TypeOrganization logutils.MessageDataType = "organization"
	//TypeApplicationOrganization ...
	TypeApplicationOrganization logutils.MessageDataType = "application organization"
	//TypeApplicationType ...
	TypeApplicationType logutils.MessageDataType = "application type"
	//TypeApplicationTypeVersionList ...
	TypeApplicationTypeVersionList logutils.MessageDataType = "application type supported version list"
	//TypeApplicationUserRelations ...
	TypeApplicationUserRelations logutils.MessageDataType = "app user relations"
	//TypeApplicationConfig ...
	TypeApplicationConfig logutils.MessageDataType = "app config"
	//TypeApplicationConfigsVersion ...
	TypeApplicationConfigsVersion logutils.MessageDataType = "app config version number"
	//TypeVersionNumbers ...
	TypeVersionNumbers logutils.MessageDataType = "version numbers"

	//PermissionAllSystemCore ...
	PermissionAllSystemCore string = "all_system_core"
	//PermissionGrantAllPermissions ...
	PermissionGrantAllPermissions string = "grant_all_permissions"
	//ServiceIDCore ...
	ServiceIDCore string = "core"
)

// Permission represents permission entity
type Permission struct {
	ID          string `bson:"_id"`
	Name        string `bson:"name"`
	Description string `bson:"description"`

	ServiceID string   `bson:"service_id"`
	Assigners []string `bson:"assigners"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

// PermissionContainer is a set of functions used to interact with objects containing permissions
type PermissionContainer interface {
	// GetPermissionNamed returns the permission for a name if the container has it directly
	GetPermissionNamed(name string) *Permission
	// GetAssignedPermissionNames returns a list of names of directly assigned permissions
	GetAssignedPermissionNames() []string
	// GetAppOrg returns the container's application organization
	GetAppOrg() ApplicationOrganization
}

// CheckAssigners checks if the passed permissions satisfy the needed assigners for the permission
func (p Permission) CheckAssigners(assignerPermissions []string) error {
	if authutils.ContainsString(assignerPermissions, PermissionGrantAllPermissions) {
		return nil
	}
	if len(p.Assigners) == 0 {
		return errors.ErrorData(logutils.StatusMissing, "assigners", &logutils.FieldArgs{"name": p.Name})
	}

	authorizedAssigners := p.Assigners
	for _, authorizedAssigner := range authorizedAssigners {
		if authutils.ContainsString(assignerPermissions, authorizedAssigner) {
			return nil
		}
	}
	//no assigners are satisfied
	return errors.ErrorAction(logutils.ActionValidate, "assigner permissions", &logutils.FieldArgs{"name": p.Name})
}

func (p Permission) String() string {
	return fmt.Sprintf("[ID:%s\nName:%s\nServiceID:%s]", p.ID, p.Name, p.ServiceID)
}

// AppOrgRole represents application organization role entity. It is a collection of permissions
type AppOrgRole struct {
	ID          string
	Name        string
	Description string

	System bool

	Permissions []Permission
	Scopes      []string

	AppOrg ApplicationOrganization

	DateCreated time.Time
	DateUpdated *time.Time
}

// RoleContainer is a set of functions used to interact with objects containing roles
type RoleContainer interface {
	// GetRole returns the role for an ID if the container has it directly
	GetRole(id string) *AppOrgRole
	// GetAssignedRoleIDs returns a list of ids of directly assigned roles
	GetAssignedRoleIDs() []string
	// GetAppOrg returns the container's application organization
	GetAppOrg() ApplicationOrganization
}

// CheckAssigners checks if the passed permissions satisfy the needed assigners for all role permissions
func (c AppOrgRole) CheckAssigners(assignerPermissions []string) error {
	if authutils.ContainsString(assignerPermissions, PermissionGrantAllPermissions) {
		return nil
	}
	if len(c.Permissions) == 0 {
		return nil //no permission
	}

	for _, permission := range c.Permissions {
		err := permission.CheckAssigners(assignerPermissions)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionValidate, "role permission", &logutils.FieldArgs{"id": c.ID, "name": c.Name}, err)
		}
	}
	//all permissions may be assigned
	return nil
}

// GetPermissionNamed returns the permission for a name if the role has it directly
func (c AppOrgRole) GetPermissionNamed(name string) *Permission {
	for _, permission := range c.Permissions {
		if permission.Name == name {
			return &permission
		}
	}
	return nil
}

// GetAssignedPermissionNames returns a list of names of assigned permissions for this role
func (c AppOrgRole) GetAssignedPermissionNames() []string {
	names := make([]string, len(c.Permissions))
	for i, permission := range c.Permissions {
		names[i] = permission.Name
	}
	return names
}

// GetAppOrg returns the role's application organization
func (c AppOrgRole) GetAppOrg() ApplicationOrganization {
	return c.AppOrg
}

func (c AppOrgRole) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tPermissions:%s\tAppOrg:%s]", c.ID, c.Name, c.Permissions, c.AppOrg.ID)
}

// AppOrgGroup represents application organization group entity. It is a collection of users
type AppOrgGroup struct {
	ID          string
	Name        string
	Description string

	System bool

	Permissions []Permission
	Roles       []AppOrgRole

	AppOrg ApplicationOrganization

	DateCreated time.Time
	DateUpdated *time.Time
}

// CheckAssigners checks if the passed permissions satisfy the needed assigners for the group
func (cg AppOrgGroup) CheckAssigners(assignerPermissions []string) error {
	if authutils.ContainsString(assignerPermissions, PermissionGrantAllPermissions) {
		return nil
	}

	//check permission
	for _, permission := range cg.Permissions {
		err := permission.CheckAssigners(assignerPermissions)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionValidate, "group permission", &logutils.FieldArgs{"id": cg.ID, "name": cg.Name}, err)
		}
	}
	//check roles
	for _, role := range cg.Roles {
		err := role.CheckAssigners(assignerPermissions)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionValidate, "group role", &logutils.FieldArgs{"id": cg.ID, "name": cg.Name}, err)
		}
	}
	//all permissions and roles may be assigned
	return nil
}

// GetAssignedPermissionNames returns a list of names of assigned permissions for this group
func (cg AppOrgGroup) GetAssignedPermissionNames() []string {
	names := make([]string, len(cg.Permissions))
	for i, permission := range cg.Permissions {
		names[i] = permission.Name
	}
	return names
}

// GetAssignedRoleIDs returns a list of ids of assigned roles for this group
func (cg AppOrgGroup) GetAssignedRoleIDs() []string {
	ids := make([]string, len(cg.Roles))
	for i, role := range cg.Roles {
		ids[i] = role.ID
	}
	return ids
}

func (cg AppOrgGroup) String() string {
	return fmt.Sprintf("[ID:%s\nName:%s\nAppOrg:%s]", cg.ID, cg.Name, cg.AppOrg.ID)
}

// GetPermissionNamed returns the permission for a name if the group has it directly
func (cg AppOrgGroup) GetPermissionNamed(name string) *Permission {
	for _, permission := range cg.Permissions {
		if permission.Name == name {
			return &permission
		}
	}
	return nil
}

// GetRole returns the role for an ID if the group has it
func (cg AppOrgGroup) GetRole(id string) *AppOrgRole {
	for _, role := range cg.Roles {
		if role.ID == id {
			return &role
		}
	}
	return nil
}

// GetAppOrg returns the group's application organization
func (cg AppOrgGroup) GetAppOrg() ApplicationOrganization {
	return cg.AppOrg
}

// Application represents users application entity - safer community, uuic, etc
type Application struct {
	ID   string
	Name string //safer community, uuic, etc

	MultiTenant bool //safer community is multi-tenant
	Admin       bool //is this an admin app?
	Code        string
	Types       []ApplicationType

	Organizations []ApplicationOrganization

	DateCreated time.Time
	DateUpdated *time.Time
}

// FindApplicationType finds app type
func (a Application) FindApplicationType(id string) *ApplicationType {
	for _, appType := range a.Types {
		if appType.Identifier == id || appType.ID == id {
			return &appType
		}
	}
	return nil
}

// Organization represents organization entity
type Organization struct {
	ID   string
	Name string
	Type string //micro small medium large - based on the users count

	System bool //is this a system org?

	Config OrganizationConfig

	Applications []ApplicationOrganization

	DateCreated time.Time
	DateUpdated *time.Time
}

func (c Organization) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tType:%s\tConfig:%s]", c.ID, c.Name, c.Type, c.Config)
}

// ApplicationOrganization represents application organization entity
type ApplicationOrganization struct {
	ID string

	Application  Application
	Organization Organization

	ServicesIDs []string //which services are used for this app/org

	IdentityProvidersSettings []IdentityProviderSetting

	SupportedAuthTypes []AuthTypesSupport //supported auth types for this organization in this application

	LoginsSessionsSetting LoginsSessionsSetting

	DateCreated time.Time
	DateUpdated *time.Time
}

// FindIdentityProviderSetting finds the identity provider setting for the application
func (ao ApplicationOrganization) FindIdentityProviderSetting(identityProviderID string) *IdentityProviderSetting {
	for _, idPrSetting := range ao.IdentityProvidersSettings {
		if idPrSetting.IdentityProviderID == identityProviderID {
			return &idPrSetting
		}
	}
	return nil
}

// IsAuthTypeSupported checks if an auth type is supported for application type
func (ao ApplicationOrganization) IsAuthTypeSupported(appType ApplicationType, authType AuthType) bool {
	for _, sat := range ao.SupportedAuthTypes {
		if sat.AppTypeID == appType.ID {
			for _, at := range sat.SupportedAuthTypes {
				if at.AuthTypeID == authType.ID {
					return true
				}
			}
		}
	}
	return false
}

// IdentityProviderSetting represents identity provider setting for an organization in an application
//
//	 User specific fields
//	 For example:
//			UIUC Application has uiucedu_uin specific field for Illinois identity provider
//
//	 Groups mapping: maps an identity provider groups to application groups
//		For example:
//	 	for the UIUC application the Illinois group "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire groups access" is mapped to an application group called "groups access"
//	 	for the Safer Illinois application the Illinois group "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire health test verify" is mapped to an application group called "tests verifiers"
type IdentityProviderSetting struct {
	IdentityProviderID string `bson:"identity_provider_id"`

	UserIdentifierField string            `bson:"user_identifier_field"`
	ExternalIDFields    map[string]string `bson:"external_id_fields"`

	FirstNameField  string `bson:"first_name_field"`
	MiddleNameField string `bson:"middle_name_field"`
	LastNameField   string `bson:"last_name_field"`
	EmailField      string `bson:"email_field"`
	RolesField      string `bson:"roles_field"`
	GroupsField     string `bson:"groups_field"`
	FerpaField      string `bson:"ferpa_field"`

	UserSpecificFields []string `bson:"user_specific_fields"`

	AlwaysSyncProfile bool   `bson:"always_sync_profile"` // if true, profile data will be overwritten with data from external user on each login/refresh
	IdentityBBBaseURL string `bson:"identity_bb_base_url"`

	Roles  map[string]string `bson:"roles"`  //map[identity_provider_role]app_role_id
	Groups map[string]string `bson:"groups"` //map[identity_provider_group]app_group_id

	AdminAppAccessRoles []string `bson:"admin_app_access_roles"` //list with the identity provider roles which are approved for admin app account creation
}

// LoginsSessionsSetting represents logins sessions setting for an organization in an application
type LoginsSessionsSetting struct {
	MaxConcurrentSessions int `bson:"max_concurrent_sessions"`

	InactivityExpirePolicy InactivityExpirePolicy `bson:"inactivity_expire_policy"`
	TSLExpirePolicy        TSLExpirePolicy        `bson:"time_since_login_expire_policy"`
	YearlyExpirePolicy     YearlyExpirePolicy     `bson:"yearly_expire_policy"`
}

// InactivityExpirePolicy represents expires policy based on inactivity
type InactivityExpirePolicy struct {
	Active           bool `bson:"active"`
	InactivityPeriod int  `bson:"inactivity_period"` //in minutes
}

// TSLExpirePolicy represents expires policy based on the time since login
type TSLExpirePolicy struct {
	Active               bool `bson:"active"`
	TimeSinceLoginPeriod int  `bson:"time_since_login_period"` //in minutes
}

// YearlyExpirePolicy represents expires policy based on fixed date
type YearlyExpirePolicy struct {
	Active bool `bson:"active"`
	Day    int  `bson:"day"`
	Month  int  `bson:"month"`
	Hour   int  `bson:"hour"`
	Min    int  `bson:"min"`
}

// ApplicationType represents users application type entity - safer community android, safer community ios, safer community web, uuic android etc
type ApplicationType struct {
	ID         string
	Identifier string    //edu.illinois.rokwire etc
	Name       string    //safer community android, safer community ios, safer community web, uuic android etc
	Versions   []Version //1.1.0, 1.2.0 etc

	Application Application

	DateCreated time.Time
	DateUpdated *time.Time
}

// FindVersion finds a version by string
func (at ApplicationType) FindVersion(version string) *Version {
	for _, v := range at.Versions {
		if v.VersionNumbers.String() == version {
			return &v
		}
	}
	return nil
}

// AuthTypesSupport represents supported auth types for an organization in an application type with configs/params
type AuthTypesSupport struct {
	AppTypeID          string              `bson:"app_type_id"`
	SupportedAuthTypes []SupportedAuthType `bson:"supported_auth_types"`
}

// SupportedAuthType represents a supported auth type
type SupportedAuthType struct {
	AuthTypeID string                 `bson:"auth_type_id"`
	Params     map[string]interface{} `bson:"params"`
}

// ApplicationConfig represents app configs
type ApplicationConfig struct {
	ID              string
	ApplicationType ApplicationType
	Version         Version
	AppOrg          *ApplicationOrganization
	Data            map[string]interface{}

	DateCreated time.Time
	DateUpdated *time.Time
}

// Version represents app config version information
type Version struct {
	ID             string
	VersionNumbers VersionNumbers

	ApplicationType ApplicationType
	DateCreated     time.Time
	DateUpdated     *time.Time
}

// VersionNumbers represents app config version numbers
type VersionNumbers struct {
	Major int `json:"major" bson:"major"`
	Minor int `json:"minor" bson:"minor"`
	Patch int `json:"patch" bson:"patch"`
}

func (v *VersionNumbers) String() string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// LessThanOrEqualTo evaluates if v1 is less than or equal to v
func (v VersionNumbers) LessThanOrEqualTo(v1 *VersionNumbers) bool {
	if v1 == nil {
		return false
	}

	if v.Major < v1.Major {
		return true
	}
	if v.Major == v1.Major && v.Minor < v1.Minor {
		return true
	}
	if v.Major == v1.Major && v.Minor == v1.Minor && v.Patch <= v1.Patch {
		return true
	}

	return false
}

// VersionNumbersFromString parses a string into a VersionNumbers struct. Returns nil if invalid format.
func VersionNumbersFromString(version string) *VersionNumbers {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return nil
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil
	}

	return &VersionNumbers{Major: major, Minor: minor, Patch: patch}
}

// GetMissingAccountIDs returns a list of account IDs missing from items
func GetMissingAccountIDs(items []Account, ids []string) []string {
	missingIDs := make([]string, 0)
	for _, id := range ids {
		missing := true
		for _, e := range items {
			if e.ID == id {
				missing = false
				break
			}
		}
		if missing {
			missingIDs = append(missingIDs, id)
		}
	}
	return missingIDs
}
