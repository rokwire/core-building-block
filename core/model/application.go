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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//TypeApplication ...
	TypeApplication logutils.MessageDataType = "application"
	//TypePermission ...
	TypePermission logutils.MessageDataType = "permission"
	//TypeAppOrgRole ...
	TypeAppOrgRole logutils.MessageDataType = "application organization role"
	//TypeAppOrgGroup ...
	TypeAppOrgGroup logutils.MessageDataType = "application organization group"
	//TypeOrganization ...
	TypeOrganization logutils.MessageDataType = "organization"
	//TypeApplicationOrganization ...
	TypeApplicationOrganization logutils.MessageDataType = "application organization"
	//TypeApplicationType ...
	TypeApplicationType logutils.MessageDataType = "application type"
	//TypeAuthTypeConfig ...
	TypeAuthTypeConfig logutils.MessageDataType = "auth type config"
	//TypeApplicationTypeAuthConfig ...
	TypeApplicationTypeAuthConfig logutils.MessageDataType = "application type auth config"
	//TypeIdentityProviderSetting ...
	TypeIdentityProviderSetting logutils.MessageDataType = "identity provider setting"
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

// CheckAssigners checks if the passed permissions satisfy the needed assigners for the permission
func (p Permission) CheckAssigners(assignerPermissions []string) error {
	if authutils.ContainsString(assignerPermissions, PermissionGrantAllPermissions) {
		return nil
	}
	if len(p.Assigners) == 0 {
		return errors.Newf("not defined assigners for %s permission", p.Name)
	}

	authorizedAssigners := p.Assigners
	for _, authorizedAssigner := range authorizedAssigners {
		if !authutils.ContainsString(assignerPermissions, authorizedAssigner) {
			return errors.Newf("assigner %s is not satisfied", authorizedAssigner)
		}
	}
	//all assigners are satisfied
	return nil
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

	AppOrg ApplicationOrganization

	DateCreated time.Time
	DateUpdated *time.Time
}

// GetPermissionNamed returns the permission for a name if the role has it
func (c AppOrgRole) GetPermissionNamed(name string) *Permission {
	for _, permission := range c.Permissions {
		if permission.Name == name {
			return &permission
		}
	}
	return nil
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
			return errors.Wrapf("error checking role permission assigners", err)
		}
	}
	//it satisfies all permissions
	return nil
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
	if len(cg.Permissions) > 0 {
		for _, permission := range cg.Permissions {
			err := permission.CheckAssigners(assignerPermissions)
			if err != nil {
				return err
			}
		}
	}
	//check roles
	if len(cg.Roles) > 0 {
		for _, role := range cg.Roles {
			err := role.CheckAssigners(assignerPermissions)
			if err != nil {
				return err
			}
		}
	}
	//all assigners are satisfied
	return nil
}

func (cg AppOrgGroup) String() string {
	return fmt.Sprintf("[ID:%s\nName:%s\nAppOrg:%s]", cg.ID, cg.Name, cg.AppOrg.ID)
}

// Application represents users application entity - safer community, uuic, etc
type Application struct {
	ID   string
	Name string //safer community, uuic, etc

	MultiTenant bool //safer community is multi-tenant
	Admin       bool //is this an admin app?

	//if to share identities between the organizations within the appication or to use e separate identities for every organization
	//if true - the user uses shared profile between all organizations within the application
	//if false - the user uses a separate profile for every organization within the application
	SharedIdentities bool

	Types []ApplicationType

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

	AuthTypes             map[string]SupportedAuthType //supported auth types for this organization in this application
	LoginsSessionsSetting LoginsSessionsSetting

	DateCreated time.Time
	DateUpdated *time.Time
}

// GetAuthTypeConfig finds the configuration for the given auth type
func (ao ApplicationOrganization) GetAuthTypeConfig(authType string) map[string]interface{} {
	supportedType, exists := ao.AuthTypes[authType]
	if !exists {
		return nil
	}
	return supportedType.Configs
}

// GetIdentityProviderSetting returns the configuration for the given auth type as an identity provider setting, if possible
func (ao ApplicationOrganization) GetIdentityProviderSetting(authType string) (*IdentityProviderSetting, error) {
	errFields := &logutils.FieldArgs{"app_org_id": ao.ID, "auth_type": authType}

	authTypeConfig := ao.GetAuthTypeConfig(authType)
	if authTypeConfig == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, TypeAuthTypeConfig, errFields)
	}

	configBytes, err := json.Marshal(authTypeConfig)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, TypeAuthTypeConfig, errFields, err)
	}

	var idpSettings IdentityProviderSetting
	err = json.Unmarshal(configBytes, &idpSettings)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, TypeAuthTypeConfig, errFields, err)
	}

	validate := validator.New()
	err = validate.Struct(idpSettings)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, TypeIdentityProviderSetting, errFields, err)
	}

	return &idpSettings, nil
}

// GetAppTypeAuthConfig finds the app type auth configuration for the given auth type and app type ID
func (ao ApplicationOrganization) GetAppTypeAuthConfig(authType string, appTypeID string) map[string]interface{} {
	supportedType, exists := ao.AuthTypes[authType]
	if !exists {
		return nil
	}

	appTypeConfig, exists := supportedType.AppTypeConfigs[appTypeID]
	if !exists {
		return nil
	}
	return appTypeConfig
}

// IsAuthTypeSupported checks if an auth type is supported for application type
func (ao ApplicationOrganization) IsAuthTypeSupported(authType string) bool {
	_, supported := ao.AuthTypes[authType]
	return supported
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
	UserIdentifierField string            `json:"user_identifier_field" bson:"user_identifier_field"`
	ExternalIDFields    map[string]string `json:"external_id_fields" bson:"external_id_fields"`

	FirstNameField  string `json:"first_name_field" bson:"first_name_field"`
	MiddleNameField string `json:"middle_name_field" bson:"middle_name_field"`
	LastNameField   string `json:"last_name_field" bson:"last_name_field"`
	EmailField      string `json:"email_field" bson:"email_field"`
	RolesField      string `json:"roles_field" bson:"roles_field"`
	GroupsField     string `json:"groups_field" bson:"groups_field"`

	UserSpecificFields []string `json:"user_specific_fields" bson:"user_specific_fields"`

	Roles  map[string]string `json:"roles" bson:"roles"`   //map[identity_provider_role]app_role_id
	Groups map[string]string `json:"groups" bson:"groups"` //map[identity_provider_group]app_group_id
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
}

// SupportedAuthType represents a supported auth type for an application organization with configs
type SupportedAuthType struct {
	Configs        map[string]interface{}            `bson:"configs,omitempty"`
	AppTypeConfigs map[string]map[string]interface{} `bson:"app_type_configs,omitempty"`
	Alias          *string                           `bson:"alias,omitempty"`
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
