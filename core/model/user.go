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
	"core-building-block/utils"
	"sort"
	"time"

	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//TypeAccount account
	TypeAccount logutils.MessageDataType = "account"
	//TypeAccountPreferences account preferences
	TypeAccountPreferences logutils.MessageDataType = "account preferences"
	//TypeAccountUsername account username
	TypeAccountUsername logutils.MessageDataType = "account username"
	//TypeAccountSystemConfigs account system configs
	TypeAccountSystemConfigs logutils.MessageDataType = "account system configs"
	//TypeAccountAuthType account auth type
	TypeAccountAuthType logutils.MessageDataType = "account auth type"
	//TypeAccountPermissions account permissions
	TypeAccountPermissions logutils.MessageDataType = "account permissions"
	//TypeAccountRoles account roles
	TypeAccountRoles logutils.MessageDataType = "account roles"
	//TypeAccountUsageInfo account usage information
	TypeAccountUsageInfo logutils.MessageDataType = "account usage information"
	//TypeExternalSystemUser external system user
	TypeExternalSystemUser logutils.MessageDataType = "external system user"
	//TypeMFAType mfa type
	TypeMFAType logutils.MessageDataType = "mfa type"
	//TypeAccountGroups account groups
	TypeAccountGroups logutils.MessageDataType = "account groups"
	//TypeProfile profile
	TypeProfile logutils.MessageDataType = "profile"
	//TypePrivacy privacy
	TypePrivacy logutils.MessageDataType = "privacy"
	//TypeDevice device
	TypeDevice logutils.MessageDataType = "device"
	//TypeFollow follow
	TypeFollow logutils.MessageDataType = "follow"
	//TypeOrgAppMembership org app membership
	TypeOrgAppMembership logutils.MessageDataType = "org app membership"
	//TypeDeletedOrgAppMembership deleted org app membership
	TypeDeletedOrgAppMembership logutils.MessageDataType = "deleted org app membership"
)

// Privacy represents the privacy options for each account
type Privacy struct {
	Public bool `json:"public" bson:"public"`
}

// OrgAppMembership represents application organization membership entity
type OrgAppMembership struct {
	ID     string
	AppOrg ApplicationOrganization

	Permissions []Permission
	Roles       []AccountRole
	Groups      []AccountGroup

	Preferences map[string]interface{}

	MostRecentClientVersion *string
}

// DeletedOrgAppMembership represents a user-deleted OrgAppMembership
type DeletedOrgAppMembership struct {
	ID string

	AccountID   string
	ExternalIDs map[string]string

	AppOrg ApplicationOrganization

	Context map[string]interface{} // some data for other building blocks to consider when deleting some user data for an account app membership

	DateCreated time.Time
}

// Account represents account entity
//
//	The account is the user himself or herself.
//	This is what the person provides to the system so that to use it.
//
//	Every account is for an organization
type Account struct {
	ID string //this is ID for the account

	OrgID              string
	OrgAppsMemberships []OrgAppMembership

	/// Current App Org Membership // we keep this for easier migration to tenant accounts
	AppOrg                  ApplicationOrganization
	Permissions             []Permission
	Roles                   []AccountRole
	Groups                  []AccountGroup
	Preferences             map[string]interface{}
	MostRecentClientVersion *string
	/// End Current App Org Membership

	Scopes []string

	AuthTypes []AccountAuthType

	MFATypes []MFAType

	Username      string
	ExternalIDs   map[string]string
	SystemConfigs map[string]interface{}
	Profile       Profile //one account has one profile
	Privacy       Privacy

	Devices []Device

	Anonymous bool
	Verified  bool

	DateCreated time.Time
	DateUpdated *time.Time

	LastLoginDate       *time.Time
	LastAccessTokenDate *time.Time
}

// HasAppMembership checks if there is app membership
func (a Account) HasAppMembership(appOrgID string) bool {
	if len(a.OrgAppsMemberships) == 0 {
		return false
	}
	for _, oam := range a.OrgAppsMemberships {
		if oam.AppOrg.ID == appOrgID {
			return true
		}
	}
	return false
}

// HasApp checks if there is app
func (a Account) HasApp(appID string) bool {
	if len(a.OrgAppsMemberships) == 0 {
		return false
	}
	for _, oam := range a.OrgAppsMemberships {
		if oam.AppOrg.Application.ID == appID {
			return true
		}
	}
	return false
}

// SetCurrentMembership sets current membership
func (a *Account) SetCurrentMembership(current OrgAppMembership) {
	a.AppOrg = current.AppOrg
	a.Permissions = current.Permissions
	a.Roles = current.Roles
	a.Groups = current.Groups
	a.Preferences = current.Preferences
	a.MostRecentClientVersion = current.MostRecentClientVersion
}

// GetAccountAuthTypeByID finds account auth type by id
func (a Account) GetAccountAuthTypeByID(ID string) *AccountAuthType {
	for _, aat := range a.AuthTypes {
		if aat.ID == ID {
			aat.Account = a
			return &aat
		}
	}
	return nil
}

// GetAccountAuthType finds account auth type
func (a Account) GetAccountAuthType(authTypeID string, identifier string) *AccountAuthType {
	for _, aat := range a.AuthTypes {
		if aat.AuthType.ID == authTypeID && aat.Identifier == identifier {
			aat.Account = a
			return &aat
		}
	}
	return nil
}

// SortAccountAuthTypes sorts account auth types by matching the given uid
func (a Account) SortAccountAuthTypes(uid string) {
	sort.Slice(a.AuthTypes, func(i, _ int) bool {
		return a.AuthTypes[i].Identifier == uid
	})
}

// GetPermissions returns all permissions granted to this account
func (a Account) GetPermissions() []Permission {
	permissionsMap := a.GetPermissionsMap()
	permissions := make([]Permission, len(permissionsMap))
	i := 0
	for _, permission := range permissionsMap {
		permissions[i] = permission
		i++
	}
	return permissions
}

// GetPermissionNames returns all names of permissions granted to this account
func (a Account) GetPermissionNames() []string {
	permissionsMap := a.GetPermissionsMap()
	permissions := make([]string, len(permissionsMap))
	i := 0
	for name := range permissionsMap {
		permissions[i] = name
		i++
	}
	return permissions
}

// GetPermissionsMap returns a map of all permissions granted to this account
func (a Account) GetPermissionsMap() map[string]Permission {
	permissionsMap := make(map[string]Permission, len(a.Permissions))
	for _, permission := range a.Permissions {
		permissionsMap[permission.Name] = permission
	}
	for _, role := range a.Roles {
		if role.Active {
			for _, permission := range role.Role.Permissions {
				permissionsMap[permission.Name] = permission
			}
		}
	}
	for _, group := range a.Groups {
		if group.Active {
			for _, permission := range group.Group.Permissions {
				permissionsMap[permission.Name] = permission
			}
			for _, role := range group.Group.Roles {
				for _, permission := range role.Permissions {
					permissionsMap[permission.Name] = permission
				}
			}
		}
	}
	return permissionsMap
}

// GetScopes returns all scopes granted to this account
func (a Account) GetScopes() []string {
	scopes := []string{}
	scopes = append(scopes, a.Scopes...)
	for _, role := range a.Roles {
		if role.Active {
			scopes = append(scopes, role.Role.Scopes...)
		}
	}
	return scopes
}

// GetVerifiedMFATypes returns a list of only verified MFA types for this account
func (a Account) GetVerifiedMFATypes() []MFAType {
	mfaTypes := make([]MFAType, 0)
	for _, mfa := range a.MFATypes {
		if mfa.Verified {
			mfaTypes = append(mfaTypes, mfa)
		}
	}
	return mfaTypes
}

// GetPermission returns the permission for an ID if the account has it
func (a Account) GetPermission(id string) *Permission {
	for _, permission := range a.Permissions {
		if permission.ID == id {
			return &permission
		}
	}
	return nil
}

// GetPermissionNamed returns the permission for a name if the account has it
func (a Account) GetPermissionNamed(name string) *Permission {
	for _, permission := range a.Permissions {
		if permission.Name == name {
			return &permission
		}
	}
	return nil
}

// GetAssignedPermissionNames returns a list of names of directly assigned permissions for this account
func (a Account) GetAssignedPermissionNames() []string {
	names := make([]string, len(a.Permissions))
	for i, permission := range a.Permissions {
		names[i] = permission.Name
	}
	return names
}

// GetActiveRoles returns all active roles
func (a Account) GetActiveRoles() []AccountRole {
	roles := []AccountRole{}
	for _, role := range a.Roles {
		if role.Active {
			roles = append(roles, role)
		}
	}
	return roles
}

// GetRole returns the role for an id if the account has it directly
func (a Account) GetRole(id string) *AppOrgRole {
	for _, role := range a.Roles {
		if role.Role.ID == id {
			return &role.Role
		}
	}
	return nil
}

// GetAssignedRoleIDs returns a list of IDs of directly assigned roles for this account
func (a Account) GetAssignedRoleIDs() []string {
	ids := make([]string, len(a.Roles))
	for i, role := range a.Roles {
		ids[i] = role.Role.ID
	}
	return ids
}

// GetActiveGroups returns all active groups
func (a Account) GetActiveGroups() []AccountGroup {
	groups := []AccountGroup{}
	for _, group := range a.Groups {
		if group.Active {
			groups = append(groups, group)
		}
	}
	return groups
}

// GetGroup returns the group for an id if the account has it
func (a Account) GetGroup(id string) *AccountGroup {
	for _, group := range a.Groups {
		if group.Group.ID == id {
			return &group
		}
	}
	return nil
}

// GetAssignedGroupIDs returns a list of IDs of directly assigned groups for this account
func (a Account) GetAssignedGroupIDs() []string {
	ids := make([]string, len(a.Groups))
	for i, group := range a.Groups {
		ids[i] = group.Group.ID
	}
	return ids
}

// GetAppOrg returns the account's application organization
func (a Account) GetAppOrg() ApplicationOrganization {
	return a.AppOrg
}

// AccountRole represents a role assigned to an account
type AccountRole struct {
	Role     AppOrgRole
	Active   bool
	AdminSet bool
}

// AccountRolesFromAppOrgRoles converts AppOrgRoles to AccountRoles
func AccountRolesFromAppOrgRoles(items []AppOrgRole, active bool, adminSet bool) []AccountRole {
	accountRoles := make([]AccountRole, len(items))
	for i, role := range items {
		accountRoles[i] = AccountRole{Role: role, Active: active, AdminSet: adminSet}
	}
	return accountRoles
}

// AccountGroup represents a group assigned to an account
type AccountGroup struct {
	Group    AppOrgGroup
	Active   bool
	AdminSet bool
}

// AccountGroupsFromAppOrgGroups converts AppOrgGroups to AccountGroups
func AccountGroupsFromAppOrgGroups(items []AppOrgGroup, active bool, adminSet bool) []AccountGroup {
	accountGroups := make([]AccountGroup, len(items))
	for i, group := range items {
		accountGroups[i] = AccountGroup{Group: group, Active: active, AdminSet: adminSet}
	}
	return accountGroups
}

// AccountAuthType represents account auth type
type AccountAuthType struct {
	ID string

	AuthType AuthType //one of the supported auth type
	Account  Account

	Identifier string
	Params     map[string]interface{}

	Credential *Credential //this can be nil as the external auth types authenticates the users outside the system

	Active     bool
	Unverified bool
	Linked     bool

	DateCreated time.Time
	DateUpdated *time.Time
}

// SetUnverified sets the Unverified flag to value in the account auth type itself and the appropriate account auth type within the account member
func (aat *AccountAuthType) SetUnverified(value bool) {
	if aat == nil {
		return
	}

	aat.Unverified = false
	for i := 0; i < len(aat.Account.AuthTypes); i++ {
		if aat.Account.AuthTypes[i].ID == aat.ID {
			aat.Account.AuthTypes[i].Unverified = false
		}
	}
}

// Equals checks if two account auth types are equal
func (aat *AccountAuthType) Equals(other AccountAuthType) bool {
	if aat.Identifier != other.Identifier {
		return false
	}
	if aat.Account.ID != other.Account.ID {
		return false
	}
	if aat.AuthType.Code != other.AuthType.Code {
		return false
	}
	if aat.Active != other.Active {
		return false
	}
	if aat.Unverified != other.Unverified {
		return false
	}
	if aat.Linked != other.Linked {
		return false
	}
	if !utils.DeepEqual(aat.Params, other.Params) {
		return false
	}

	thisCred := aat.Credential
	otherCred := other.Credential
	if (thisCred != nil) != (otherCred != nil) {
		return false
	} else if thisCred != nil && otherCred != nil && (thisCred.ID != otherCred.ID) {
		return false
	}

	return true
}

// Credential represents a credential for account auth type/s
type Credential struct {
	ID string

	AuthType          AuthType
	AccountsAuthTypes []AccountAuthType //one credential can be used for more than one account auth type
	Verified          bool
	Value             map[string]interface{} //credential value

	DateCreated time.Time
	DateUpdated *time.Time
}

// MFAType represents a MFA type used by an account
type MFAType struct {
	ID   string
	Type string

	Verified bool
	Params   map[string]interface{} //mfa type params

	DateCreated time.Time
	DateUpdated *time.Time
}

// Profile represents profile entity
//
//		The profile is an information about the user
//	 What the person shares with the system/other users/
//		The person should be able to use the system even all profile fields are empty/it is just an information for the user/
type Profile struct {
	ID string

	PhotoURL  string
	FirstName string
	LastName  string
	Email     string
	Phone     string
	BirthYear int16
	Address   string
	ZipCode   string
	State     string
	Country   string

	DateCreated time.Time
	DateUpdated *time.Time

	UnstructuredProperties map[string]interface{}
}

// GetFullName returns the user's full name
func (p Profile) GetFullName() string {
	fullname := p.FirstName
	if len(fullname) > 0 {
		fullname += " "
	}
	fullname += p.LastName
	return fullname
}

// Merge applies any non-empty fields from the provided profile to receiver
func (p Profile) Merge(src Profile) Profile {
	if src.FirstName != "" {
		p.FirstName = src.FirstName
	}
	if src.LastName != "" {
		p.LastName = src.LastName
	}
	if src.Email != "" {
		p.Email = src.Email
	}
	if src.Phone != "" {
		p.Phone = src.Phone
	}
	if src.Address != "" {
		p.Address = src.Address
	}
	if src.ZipCode != "" {
		p.ZipCode = src.ZipCode
	}
	if src.State != "" {
		p.State = src.State
	}
	if src.Country != "" {
		p.Country = src.Country
	}
	if src.BirthYear != 0 {
		p.BirthYear = src.BirthYear
	}
	if src.PhotoURL != "" {
		p.PhotoURL = src.PhotoURL
	}

	newUnstructured := map[string]interface{}{}
	for key, val := range p.UnstructuredProperties {
		newUnstructured[key] = val
	}
	for key, val := range src.UnstructuredProperties {
		newUnstructured[key] = val
	}
	p.UnstructuredProperties = newUnstructured

	return p
}

// ProfileFromMap parses a map and converts it into a Profile struct
func ProfileFromMap(profileMap map[string]interface{}) Profile {
	profile := Profile{UnstructuredProperties: make(map[string]interface{})}
	for key, val := range profileMap {
		if key == "first_name" {
			if typeVal, ok := val.(string); ok {
				profile.FirstName = typeVal
			}
		} else if key == "last_name" {
			if typeVal, ok := val.(string); ok {
				profile.LastName = typeVal
			}
		} else if key == "email" {
			if typeVal, ok := val.(string); ok {
				profile.Email = typeVal
			}
		} else if key == "phone" {
			if typeVal, ok := val.(string); ok {
				profile.Phone = typeVal
			}
		} else if key == "birth_year" {
			if typeVal, ok := val.(int16); ok {
				profile.BirthYear = typeVal
			}
		} else if key == "address" {
			if typeVal, ok := val.(string); ok {
				profile.Address = typeVal
			}
		} else if key == "zip_code" {
			if typeVal, ok := val.(string); ok {
				profile.ZipCode = typeVal
			}
		} else if key == "state" {
			if typeVal, ok := val.(string); ok {
				profile.State = typeVal
			}
		} else if key == "country" {
			if typeVal, ok := val.(string); ok {
				profile.Country = typeVal
			}
		} else if key == "photo_url" {
			if typeVal, ok := val.(string); ok {
				profile.Phone = typeVal
			}
		} else {
			profile.UnstructuredProperties[key] = val
		}
	}
	return profile
}

// Device represents user devices entity.
type Device struct {
	ID string

	DeviceID *string //provided by client
	Account  Account

	Type string //mobile, web, desktop, other
	OS   string

	DateCreated time.Time
	DateUpdated *time.Time
}

// ExternalSystemUser represents external system user
type ExternalSystemUser struct {
	Identifier  string            `json:"identifier" bson:"identifier"` //this is the identifier used in our system to map the user
	ExternalIDs map[string]string `json:"external_ids" bson:"external_ids"`

	//these are common fields which should be popuated by the external system
	FirstName  string   `json:"first_name" bson:"first_name"`
	MiddleName string   `json:"middle_name" bson:"middle_name"`
	LastName   string   `json:"last_name" bson:"last_name"`
	Email      string   `json:"email" bson:"email"`
	Roles      []string `json:"roles" bson:"roles"`
	Groups     []string `json:"groups" bson:"groups"`
	Farpa      bool     `json:"farpa" bson:"farpa"`

	//here are the system specific data for the user - uiucedu_uin etc
	SystemSpecific map[string]interface{} `json:"system_specific" bson:"system_specific"`
}

// Equals checks if two external system users are equals
func (esu ExternalSystemUser) Equals(other ExternalSystemUser) bool {
	if esu.Identifier != other.Identifier {
		return false
	}
	if !utils.DeepEqual(esu.ExternalIDs, other.ExternalIDs) {
		return false
	}
	if esu.FirstName != other.FirstName {
		return false
	}
	if esu.MiddleName != other.MiddleName {
		return false
	}
	if esu.LastName != other.LastName {
		return false
	}
	if esu.Email != other.Email {
		return false
	}
	if !utils.DeepEqual(esu.Roles, other.Roles) {
		return false
	}
	if !utils.DeepEqual(esu.Groups, other.Groups) {
		return false
	}
	if !utils.DeepEqual(esu.SystemSpecific, other.SystemSpecific) {
		return false
	}
	return true
}

// AccountRelations represents external relations between the application accounts in an organization
// For example in Safer Illinois application:
// - families takes discount for covid tests.
// - couples gets discount for the taxes.
// For other applications:
// - relatives are hosted in the same building etc.
type AccountRelations struct {
	ID   string
	Type string //family, couple, relatives, brothers/sisters, external roommate when there is no provided place by the university for example

	Manager Account
	Members []Account
}

// PublicAccount shows public account information
type PublicAccount struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Verified    bool   `json:"verified"`
	IsFollowing bool   `json:"is_following"`
}

// Follow shows the relationship between user and follower
type Follow struct {
	ID          string    `json:"id" bson:"_id"`
	AppID       string    `json:"app_id" bson:"app_id"`
	OrgID       string    `json:"org_id" bson:"org_id"`
	FollowerID  string    `json:"follower_id" bson:"follower_id"`
	FollowingID string    `json:"following_id" bson:"following_id"`
	DateCreated time.Time `json:"date_created" bson:"date_created"`
}

// AccountData shows AccountData information
type AccountData struct {
	AuthType    string    `json:"auth_type"`
	GroupIds    *[]string `json:"group_ids,omitempty"`
	Identifier  string    `json:"identifier"`
	Permissions *[]string `json:"permissions,omitempty"`
	Privacy     *Privacy  `json:"privacy"`
	Profile     *Profile  `json:"profile"`
	RoleIds     *[]string `json:"role_ids,omitempty"`
	Scopes      *[]string `json:"scopes,omitempty"`
	Username    *string   `json:"username"`
	AppID       string    `json:"app_id"`
	OrgID       string    `json:"org_id"`
}

// FarpaAccountIDResponse shows ids with the farpa field true
type FarpaAccountIDResponse struct {
	ID string `json:"_id" bson:"_id"`
}
