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
	//TypeAccountIdentifier account identifier
	TypeAccountIdentifier logutils.MessageDataType = "account identifier"
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
)

// Privacy represents the privacy options for each account
type Privacy struct {
	Public bool `json:"public" bson:"public"`
}

// Account represents account entity
//
//	The account is the user himself or herself.
//	This is what the person provides to the system so that to use it.
//
//	Every account is for an organization within an application
type Account struct {
	ID string //this is ID for the account

	AppOrg ApplicationOrganization

	Permissions []Permission
	Roles       []AccountRole
	Groups      []AccountGroup
	Scopes      []string

	Identifiers []AccountIdentifier
	AuthTypes   []AccountAuthType

	MFATypes []MFAType

	Preferences   map[string]interface{}
	SystemConfigs map[string]interface{}
	Profile       Profile //one account has one profile, one profile can be shared between many accounts
	Privacy       Privacy

	Devices []Device

	Anonymous bool
	Verified  bool

	DateCreated time.Time
	DateUpdated *time.Time

	LastLoginDate           *time.Time
	LastAccessTokenDate     *time.Time
	MostRecentClientVersion *string
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

// GetAccountAuthTypes finds account auth types
func (a Account) GetAccountAuthTypes(authTypeIDorCode string) []AccountAuthType {
	authTypes := make([]AccountAuthType, 0)
	for _, aat := range a.AuthTypes {
		if aat.SupportedAuthType.AuthType.ID == authTypeIDorCode || aat.SupportedAuthType.AuthType.Code == authTypeIDorCode {
			aat.Account = a
			authTypes = append(authTypes, aat)
		}
	}
	return authTypes
}

// SortAccountAuthTypes sorts account auth types by matching the given id
func (a Account) SortAccountAuthTypes(id string, authType string) {
	sort.Slice(a.AuthTypes, func(i, _ int) bool {
		return (id != "" && a.AuthTypes[i].ID == id) || (authType != "" && a.AuthTypes[i].SupportedAuthType.AuthType.Code == authType)
	})
}

// GetAccountIdentifier finds account identifier
func (a Account) GetAccountIdentifier(code string, identifier string) *AccountIdentifier {
	for _, id := range a.Identifiers {
		if code != "" && id.Code == code && identifier != "" && id.Identifier == identifier {
			id.Account = a
			return &id
		}
		if code != "" && id.Code == code {
			id.Account = a
			return &id
		}
		if identifier != "" && id.Identifier == identifier {
			id.Account = a
			return &id
		}
	}
	return nil
}

// GetAccountIdentifierByID finds account identifier by its ID
func (a Account) GetAccountIdentifierByID(id string) *AccountIdentifier {
	for _, ai := range a.Identifiers {
		if ai.ID == id {
			ai.Account = a
			return &ai
		}
	}
	return nil
}

// GetVerifiedAccountIdentifiers returns a list of only verified identifiers for this account
func (a Account) GetVerifiedAccountIdentifiers() []AccountIdentifier {
	identifiers := make([]AccountIdentifier, 0)
	for _, id := range a.Identifiers {
		if id.Verified {
			identifiers = append(identifiers, id)
		}
	}
	return identifiers
}

// GetExternalAccountIdentifiers returns a list of only external identifiers for this account
func (a Account) GetExternalAccountIdentifiers() []AccountIdentifier {
	identifiers := make([]AccountIdentifier, 0)
	for _, id := range a.Identifiers {
		if id.AccountAuthTypeID != nil {
			identifiers = append(identifiers, id)
		}
	}
	return identifiers
}

// SortAccountIdentifiers sorts account identifiers by matching the given identifier
func (a Account) SortAccountIdentifiers(identifier string) {
	sort.Slice(a.Identifiers, func(i, _ int) bool {
		return a.Identifiers[i].Identifier == identifier
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

	SupportedAuthType SupportedAuthType //one of the supported auth type
	Account           Account

	Params map[string]interface{}

	Credential *Credential //this can be nil as the external auth types authenticates the users outside the system

	Active bool

	DateCreated time.Time
	DateUpdated *time.Time
}

// Equals checks if two account auth types are equal
func (aat *AccountAuthType) Equals(other AccountAuthType) bool {
	if aat.Account.ID != other.Account.ID {
		return false
	}
	if aat.SupportedAuthType.AuthType.Code != other.SupportedAuthType.AuthType.Code {
		return false
	}
	if aat.Active != other.Active {
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

// AccountIdentifier represents account identifiers
type AccountIdentifier struct {
	ID         string
	Code       string
	Identifier string

	Verified  bool
	Linked    bool
	Sensitive bool

	AccountAuthTypeID *string
	Primary           *bool

	Account Account

	VerificationCode   *string
	VerificationExpiry *time.Time

	DateCreated time.Time
	DateUpdated *time.Time
}

// SetVerified sets the Verified flag to value in the account auth type itself and the appropriate account auth type within the account member
func (ai *AccountIdentifier) SetVerified(value bool) {
	if ai == nil {
		return
	}

	ai.Verified = value
	for i := 0; i < len(ai.Account.Identifiers); i++ {
		if ai.Account.Identifiers[i].Identifier == ai.Identifier {
			ai.Account.Identifiers[i].Verified = value
		}
	}
}

// Equals checks if two account identifiers are equal
func (ai *AccountIdentifier) Equals(other AccountIdentifier) bool {
	if ai.Identifier != other.Identifier {
		return false
	}
	if ai.Account.ID != other.Account.ID {
		return false
	}
	if ai.Verified != other.Verified {
		return false
	}
	if ai.Linked != other.Linked {
		return false
	}

	return true
}

// Credential represents a credential for account auth type/s
type Credential struct {
	ID string

	AuthType          AuthType
	AccountsAuthTypes []AccountAuthType      //one credential can be used for more than one account auth type
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
	BirthYear int16
	Address   string
	ZipCode   string
	State     string
	Country   string

	Accounts []Account //the users can share profiles between their applications accounts for some applications

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
				profile.PhotoURL = typeVal
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

	DeviceID string //provided by client
	Account  Account

	Type string //mobile, web, desktop, other
	OS   string

	DateCreated time.Time
	DateUpdated *time.Time
}

// ExternalSystemUser represents external system user
type ExternalSystemUser struct {
	Identifier           string            `json:"identifier" bson:"identifier"` //this is the identifier used in our system to map the user
	ExternalIDs          map[string]string `json:"external_ids" bson:"external_ids"`
	SensitiveExternalIDs []string          `json:"sensitive_external_ids" bson:"sensitive_external_ids"`
	IsEmailVerified      bool              `json:"is_email_verified" bson:"is_email_verified"`

	//these are common fields which should be popuated by the external system
	FirstName  string   `json:"first_name" bson:"first_name"`
	MiddleName string   `json:"middle_name" bson:"middle_name"`
	LastName   string   `json:"last_name" bson:"last_name"`
	Email      string   `json:"email" bson:"email"`
	Roles      []string `json:"roles" bson:"roles"`
	Groups     []string `json:"groups" bson:"groups"`

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
